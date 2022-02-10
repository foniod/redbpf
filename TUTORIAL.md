RedBPF Basic Tutorial
====

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [RedBPF Basic Tutorial](#redbpf-basic-tutorial)
    - [Small background](#small-background)
    - [Let's make our first program using RedBPF](#lets-make-our-first-program-using-redbpf)
        - [Step 1. Generate scaffolds](#step-1-generate-scaffolds)
        - [Step 2. Add a new BPF program](#step-2-add-a-new-bpf-program)
        - [Step 3. Write the BPF program](#step-3-write-the-bpf-program)
        - [Step 4. Compile the BPF program](#step-4-compile-the-bpf-program)
        - [Step 5. Write a userspace program](#step-5-write-a-userspace-program)
        - [Step 6. Compile the userspace program](#step-6-compile-the-userspace-program)
        - [Step 7. Run](#step-7-run)

<!-- markdown-toc end -->

Small background
----

* A **BPF program** is defined by a single rust function and it can be attached
  to instrumentation points. There are many kinds of BPF programs such as
  kprobe, xdp, tracepoint, socket filter and so on. And also there are many
  mechanisms that attach those different kinds of BPF programs to
  instrumentation points. In this tutorial, we are going to define a kprobe BPF
  program and attach it to a kernel function.
* A **BPF maps** is used by both BPF programs and userspace programs to
  communicate with each other. There are many kinds of BPF maps such as
  hashmap, array, perf event array, sockmap and so forth.
* `redbpf-macros` provides attribute macros for defining BPF programs and BPF
  maps.
* `redbpf-probes` provides API for BPF programs that execute in kernel context.
* `redbpf` provides API for userspace programs. Userspace programs load BPF
  programs and BPF maps to kernel space and communicate with BPF programs
  through BPF maps.

### Building LLVM from source

*If you already installed LLVM with a package manager you can skip this this
section. Installing LLVM by a package manager is a simple and preferred way.*

For some reasons, you may want to build LLVM from source code.

When you build LLVM, consider building LLVM with `Release` build mode.

For example, when you build LLVM13 from source code, you can pass
`-DCMAKE_BUILD_TYPE=Release` to the `cmake` command as below:

```console
$ tar -xaf llvm-13.0.0.src.tar.xz
$ mkdir -p llvm-13.0.0.src/build
$ cd llvm-13.0.0.src/build
$ cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/llvm-13-release -DCMAKE_BUILD_TYPE=Release
$ cmake --build . --target install
```

Unless you plan to debug LLVM itself, `Release` or `MinSizeRel` is a good
choice.

If you try compiling BPF programs with a `Debug` LLVM, the memory consumption
can be increased over 20GB! And also it takes more time to finish. See [this
issue](https://github.com/foniod/redbpf/issues/194#issuecomment-940964881) for
more information.

Let's make our first program using RedBPF
----

We are going to make our first BPF program and its corresponding userspace
program. The BPF program will be attached to a `do_sys_open` kernel function
and it will generate a perf event delivering an open filename to userspace
whenever the kernel function is invoked. And its corresponding userspace
program will listen to the perf events and print the filename to stdout
whenever the event occurs.


### Step 1. Generate scaffolds

Install `cargo-bpf` command:
```console
$ cargo install cargo-bpf
```

This command is working as a cargo sub-command: `cargo bpf`.

Let's create a normal cargo project, `redbpf-tutorial`:
```console
$ cargo new redbpf-tutorial
$ cd redbpf-tutorial
$ ls
Cargo.toml  src/
```

Create `probes` sub cargo project directory to contain BPF programs:
```console
$ cargo bpf new probes
$ ls
Cargo.toml  probes/  src/
```

Now you have two cargo project directories: `redbpf-tutorial` and
`redbpf-tutorial/probes`. The former directory is for redbpf userspace programs and
the latter directory is for BPF programs.


### Step 2. Add a new BPF program

In this tutorial, you are going to write a simple BPF program that will be
attached to the `do_sys_open` kernel function. And that program generates
perf events whenever `do_sys_open` is called.

Create a template of a new BPF program by executing this command:
```console
$ cd probes
$ cargo bpf add openmonitor
$ ls src/
lib.rs  openmonitor/
$ cat Cargo.toml

... omitted ...

[[bin]]
name = "openmonitor"
path = "src/openmonitor/main.rs"
required-features = ["probes"]
```

↑ I picked a name `openmonitor` but you may choose another elegant one. As you
can see, `src/openmonitor` directory is just created and it's a new room for
your first BPF program. And also a few lines of configuration are appended to
`Cargo.toml`. It makes the first BPF program get compiled.


### Step 3. Write the BPF program

Open `src/openmonitor/main.rs` with your favorite editor.

```rust
#![no_std]
#![no_main]
```

↑ These two macro attributes are required. Because BPF programs are executed in
kernel context, rust `std` library can not be used. So `#![no_std]` should be
applied.

And `#![no_main]` is applied because a main function is unnecessary. Regard
that a BPF program is just single function that are attached to some
instrumentation point and executed whenever that point is invoked. So the main
function is not used here.

```rust
use redbpf_probes::kprobe::prelude::*;
```

↑ Include necessary symbols by using a kprobe prelude module.

This brings symbols listed below to the current namespace:

- BPF helper functions
- macro attributes like `kprobe`, `kretprobe`, `map` and `program` macro.
- maps API such as `redbpf_probes::maps::HashMap`,
  `redbpf_probes::maps::PerfMap`
- rust bindings for common kernel structures like `struct sock`, `struct file`

```rust
program!(0xFFFFFFFE, "GPL");
```

↑ This macro sets version and license of BPF programs. The license must be GPL
compatible to use GPL-ed functions that the Linux kernel provides. And version
is passed to the Linux kernel when loading the BPF program but it is not used
inside the kernel. Also this macro sets `panic_handler` for BPF programs.

```rust
#[map]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);
```

↑ `PerfMap` is a kind of BPF maps and it is used to pass perf events to
userspace program. This statement defines a static mutable `PerfMap` that
handles a `OpenPath` structure. And `#[map]` macro attribute is applied to the
`OPEN_PATHS` static item to indicate that the item is a BPF map.

```rust
#[kprobe]
fn do_sys_open(regs: Registers) {
    let mut path = OpenPath::default();
    unsafe {
        let filename = regs.parm2() as *const u8;
        if bpf_probe_read_user_str(
            path.filename.as_mut_ptr() as *mut _,
            path.filename.len() as u32,
            filename as *const _,
        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
            return;
        }
        OPEN_PATHS.insert(regs.ctx, &path);
    }
}
```

↑ This is the main logic of the BPF program. `#[kprobe]` macro attribute
indicates that this item is a BPF program, and this can be attached to entry
points of kernel functions using kprobe. The name of a function is merely a
hint. The function name, `do_sys_open`, implies that this function is
intended to be attached to do_sys_open kernel function. Determining where
`do_sys_open` will be attached to is up to userspace program. We will make
userspace part soon.

When you define a function that will be attached to kernel functions using
kprobe, a parameter of the function is always `Registers`. And parameters of
the kernel function can be accessed through it. The signature of the Linux
kernel function do_sys_open is `long do_sys_open(int dfd, const char __user 
*filename, int flags, umode_t mode)` so we can get the `filename` by
calling `Registers::parm2()`.

`bpf_probe_read_user_str` BPF helper function copies a string to a buffer and
returns a copied length including a terminal NUL byte. And `OPEN_PATHS.insert`
inserts `OpenPath` to the perf event array.

If `bpf_probe_read_user_str` returns a negative integer, it means an error. In
this case, this BPF program prints error message to a file
`/sys/kernel/debug/tracing/trace_pipe` by using `bpf_trace_printk`. Note that
the **bytes passed to `bpf_trace_printk` should include terminal `NUL` byte**.

> **NOTE:** Your Linux kernel may not provide `bpf_probe_read_user_str` BPF
> helper function. This function is introduced by the Linux v5.5 so if your
> kernel is older than that, the BPF verifier would complain *"invalid func
> unknown#114"*.
>
> In this situation, you can use `bpf_probe_read_str` instead. It is the old
> version of `bpf_probe_read_user_str`.

The **full source code** of `src/openmonitor/main.rs` is here:

```rust
#![no_std]
#![no_main]

use probes::openmonitor::*;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);

#[kprobe]
fn do_sys_open(regs: Registers) {
    let mut path = OpenPath::default();
    unsafe {
        let filename = regs.parm2() as *const u8;
        if bpf_probe_read_user_str(
            path.filename.as_mut_ptr() as *mut _,
            path.filename.len() as u32,
            filename as *const _,
        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
            return;
        }
        OPEN_PATHS.insert(regs.ctx, &path);
    }
}
```

There's one thing to finish before compiling the first BPF program.

Open `src/openmonitor/mod.rs` with your editor and define the `OpenPath`
structure.

```rust
pub const PATHLEN: usize = 256;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct OpenPath {
    pub filename: [u8; PATHLEN],
}

impl Default for OpenPath {
    fn default() -> OpenPath {
        OpenPath {
            filename: [0; PATHLEN],
        }
    }
}
```

↑ `OpenPath` is a structure with C representation and it holds a `filename`
array. This structure is passed to perf event array and it delivers a filename
between a BPF program and a userspace program.

You just completed the first BPF program! Let's go compile it now.


### Step 4. Compile the BPF program

Compile the BPF program by running this command in the `probes` directory:

```console
$ cargo bpf build --target-dir=../target

... omitted ...

Finished release [optimized] target(s) in 1m 05s
$ ls ../target/bpf/programs/openmonitor/openmonitor.elf
```

↑ By running `cargo bpf build` command, the `openmonitor.elf` file is just
created. It is ELF relocatable file so it's not possible to execute this file
directly. Instead we can parse the BPF program and the BPF map defined in this
file and load them to the Linux kernel by calling redbpf userspace API.

`--target-dir=../target` option is specified here to make redbpf userspace
program readily locate the ELF relocatable file under its default target
directory.


### Step 5. Write a userspace program

Let's go develop a program that utilizes redbpf userspace API.

```console
$ cd ..
$ ls
Cargo.toml  probes/  src/  target/
```

Open `Cargo.toml` with your favorite editor and add dependencies:

```toml
redbpf = { version = "2.3.0", features = ["load"] }
tokio = { version = "1.0", features = ["rt", "signal", "time", "io-util", "net", "sync"] }
tracing-subscriber = "0.2"
tracing = "0.1"
futures = "0.3"

probes = { path = "./probes" }
```

↑ Dependencies to use redbpf:

* `redbpf`: The `load` feature of `redbpf` is optional but it is recommended
  because it helps you load ELF relocatable file (the `openmonitor.elf` file)
  easily. `redbpf` crate is responsible for userspace part.
...* `redbpf-probes` and `redbpf-macros` crates are responsible for BPF
  programs running in kernel context. Check your `probes/Cargo.toml` then you
  will see these crates are listed in dependencies.
* `tokio`: `redbpf` is running in the context of `tokio` run-time, so `tokio`
  is required.
* `futures`: `futures::stream::StreamExt` trait is needed to utilize
  asynchronous tasks.
* `probes`: `probes` is listed here because we need the definition of the
  `OpenPath` structure in `probes/src/openmonitor/mod.rs`. If a BPF program and
  a userspace program communicate with only primitive types so that there are
  no custom structures, then you don't need `probes` dependency here.
* *(optional)* `tracing-subscriber` + `tracing`: `redbpf` records its error
  logs using `tracing` crate. So it is recommended for users to subscribe to
  the error logs of `redbpf`. If you don't subscribe to the error logs, then
  they will be silently discarded.

Open `src/main.rs` with your editor and write a userspace program:

```rust
fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/openmonitor/openmonitor.elf"
    ))
}
```

↑ This includes binary of ELF relocatable file into an executable file of the
userspace program so that you only need the executable file at run-time. The
ELF relocatable file is needless at run-time.

```rust
#[tokio::main(flavor = "current_thread")]
async fn main() {}
```

↑ `redbpf` works in the context of `tokio` run-time so `redbpf` should be called
inside async functions.

```rust
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// ... omitted ...
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
```

↑ It is recommended to subscribe the error logs of `redbpf` for debugging
errors while developing a `redbpf` userspace program. But subscribing to error
logs is entirely optional. You may skip this code. It is up to you.

```rust
use redbpf::load::Loader;

// ... omitted ...

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

    let probe = loaded
        .kprobe_mut("do_sys_open")
        .expect("error on Loaded::kprobe_mut");
    probe
        .attach_kprobe("do_sys_open", 0)
        .expect("error on KProbe::attach_kprobe");
    probe
        .attach_kprobe("do_sys_openat2", 0)
        .expect("error on KProbe::attach_kprobe");
```

↑ `Loader::load` parses an ELF relocatable file and loads all BPF maps and BPF
programs into the Linux kernel automatically. The remainder of the work is to
attach the BPF programs to instrumentation points that you want.

In case of `openmonitor`, we wrote the BPF program that is designed to attached
to do_sys_open kernel function. `Loaded::kprobe_mut` gets a BPF program
whose name is `do_sys_open`. Do you remember that you defined a function of
which name is `do_sys_open` in the previous step? `#[kprobe]` attribute can
assign a name of a BPF program like this: `#[kprobe("CUSTOM_NAME_HERE")]`. If
no custom name is specified explicitly, the function's name is used as a kprobe
BPF program's name instead. So you can get the BPF program by calling
`loaded.kprobe_mut("do_sys_open")`. On some systems, attaching to `do_sys_open`
may not result in any output. Instead, you can attach to do_sys_openat2.
You can also attach to both kernel functions, because the second param for
do_sys_openat2 is the same.

`KProbe::attach_kprobe` attaches a kprobe BPF program to a specified kernel
function.  So `attach_kprobe("do_sys_open", 0)` attaches the kprobe BPF
program to the `do_sys_open` kernel function entry at the offset 0 byte.

```rust
use futures::stream::StreamExt;
use std::{ffi::CStr, ptr};

use probes::openmonitor::OpenPath;

// ... omitted ...

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "OPEN_PATHS" {
            for event in events {
                let open_path = unsafe { ptr::read(event.as_ptr() as *const OpenPath) };
                unsafe {
                    let cfilename = CStr::from_ptr(open_path.filename.as_ptr() as *const _);
                    println!("{}", cfilename.to_string_lossy());
                };
            }
        }
    }
```

↑ A type of `loaded.events` is a
`futures::channel::mpsc::UnboundedReceiver<(String, Vec<Box<[u8]>>)>`. In order
to specify the `next()` method, `futures::stream::StreamExt` trait is imported
here.

In the `while` loop, `loaded.events.next().await` returns `(String,
Vec<Box<[u8]>>)`.

The first element is the name of the `PerfMap`. Do you remember the `PerfMap`
in the BPF program code?

```rust
// This is the PerfMap you defined in the BPF program code
#[map]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);
```

Like `#[kprobe]`, users can specify a custom name of a map like this:
`#[map(link_section = "maps/<MAP_NAME_HERE>")]`. If a custom name is not
specified, then item's name is used as a name of a map. In our program's case,
`OPEN_PATHS` is the map's name.

The second element, `Vec<Box<[u8]>>` is a vector for raw data. You should read
it by a pointer of the `OpenPath` structure.

This is a **complete source code** of the userspace program code, `src/main.rs`:

```rust
use futures::stream::StreamExt;
use std::{ffi::CStr, ptr};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;

use probes::openmonitor::OpenPath;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/openmonitor/openmonitor.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

    let probe = loaded
        .kprobe_mut("do_sys_open")
        .expect("error on Loaded::kprobe_mut");
    probe
        .attach_kprobe("do_sys_open", 0)
        .expect("error on KProbe::attach_kprobe");
    probe
        .attach_kprobe("do_sys_openat2", 0)
        .expect("error on KProbe::attach_kprobe");

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "OPEN_PATHS" {
            for event in events {
                let open_path = unsafe { ptr::read(event.as_ptr() as *const OpenPath) };
                unsafe {
                    let cfilename = CStr::from_ptr(open_path.filename.as_ptr() as *const _);
                    println!("{}", cfilename.to_string_lossy());
                };
            }
        }
    }
}
```

### Step 6. Compile the userspace program

To compile the userspace program, just run this command:

```console
$ ls
Cargo.toml  probes/  src/  target/
$ cargo build
```

### Step 7. Run

Most features of BPF require **root privileges**. So run the program by root.

```console
# cargo run
/proc/driver/nvidia/params
/dev/nvidia0
/proc/driver/nvidia/params
/dev/nvidia0
/proc/driver/nvidia/params
/dev/nvidia0
/etc/localtime
/lib/x86_64-linux-gnu/libcuda.so.1
/lib/x86_64-linux-gnu/libm.so.6
/etc/netconfig
/sys/fs/cgroup/unified/system.slice/systemd-udevd.service/cgroup.procs
/sys/fs/cgroup/unified/system.slice/systemd-udevd.service/cgroup.threads
/proc/3084/cmdline
/proc/3729/cmdline
/proc/3994/cmdline
/proc/8823/cmdline
/proc/2231364/cmdline
/proc/2431788/cmdline
/proc/2560949/cmdline
/sys/class/hwmon
/sys/class/hwmon/hwmon6
/sys/class/hwmon/hwmon4
/sys/class/hwmon/hwmon2
/sys/class/hwmon/hwmon0
/sys/class/hwmon/hwmon7
/sys/class/hwmon/hwmon5

... omitted ...
```

↑ The output shows filenames that are currently open by any processes in the
system wide. Your output will be totally different from mine.

Yes! You just completed the first BPF program and its userspace program using
RedBPF.
