// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Procedural macros to help writing eBPF programs using the `redbpf-probes`
crate.

# Overview

`redbpf-macros` is part of the `redbpf` project. Together with
[`redbpf-probes`](https://redsift.github.io/rust/redbpf/doc/redbpf_probes/), it
provides an idiomatic Rust API to write programs that can be compiled to eBPF
bytecode and executed by the linux in-kernel eBPF virtual machine.

To streamline the process of working with eBPF programs even further,
`redbpf` also provides
[`cargo-bpf`](https://redsift.github.io/rust/redbpf/doc/cargo_bpf/) - a cargo subcommand
to simplify creating and building eBPF programs.

# Example

```
#![no_std]
#![no_main]
use redbpf_macros::{program, kprobe, xdp};
use redbpf_probes::bindings::*;
use redbpf_probes::xdp::{XdpAction, XdpContext};

// configure kernel version compatibility and license
program!(0xFFFFFFFE, "GPL");

#[xdp]
pub extern "C" fn example_xdp_probe(ctx: XdpContext) -> XdpAction {
    ...
    XdpAction::Pass
}

#[kprobe("__x64_sys_clone")]
pub extern "C" fn example_kprobe(ctx: *mut pt_regs) {
    ...
}
```
*/
extern crate proc_macro;
extern crate proc_macro2;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use std::str;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    parse_macro_input, parse_quote, parse_str, Block, Expr, ExprLit, File, FnArg, ItemFn, Lit, Pat,
    PatIdent, PatType, Result, Stmt,
};

fn inline_string_literal(e: &Expr) -> (TokenStream2, TokenStream2) {
    let mut bytes = match e {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value().clone().into_bytes(),
        _ => panic!("expected string literal"),
    };
    bytes.push(0u8);
    let len = bytes.len();
    let bytes = bytes;
    let ty = quote!([u8; #len]);
    let array_lit = quote!([#(#bytes),*]);

    (ty, array_lit)
}

struct Args(Punctuated<Expr, Comma>);

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Args> {
        Ok(Args(Punctuated::parse_terminated(input)?))
    }
}

/// Generates program metadata.
///
/// Takes two arguments, the `LINUX_VERSION_CODE` the program is compatible with,
/// and the license. The special version code `0xFFFFFFFE` can be used to signify
/// any kernel version.
///
/// #Example
///
/// ```
/// program!(0xFFFFFFFE, "GPL");
/// ```
///
#[proc_macro]
pub fn program(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Args);
    let mut args = input.0.iter();
    let version = args.next().expect("no version");
    let license = args.next().expect("no license");
    let (license_ty, license) = inline_string_literal(&license);
    let mut tokens = quote! {
        #[no_mangle]
        #[link_section = "license"]
        pub static _license: #license_ty = #license;

        #[no_mangle]
        #[link_section = "version"]
        pub static _version: u32 = #version;

        #[panic_handler]
        #[no_mangle]
        pub extern "C" fn rust_begin_panic(info: &::core::panic::PanicInfo) -> ! {
            use ::redbpf_probes::helpers::{bpf_trace_printk, TraceMessage, ufmt};

            let mut msg = TraceMessage::new();
            ufmt::uwrite!(&mut msg, "panic in {}\n\0", file!());
            msg.printk();

            unsafe { core::hint::unreachable_unchecked() }
        }
    };

    let mem = str::from_utf8(include_bytes!("mem.rs")).unwrap();
    let mem: File = parse_str(&mem).unwrap();
    tokens.extend(quote! {
        #mem
    });

    tokens.into()
}

#[proc_macro]
pub fn impl_xdp_array(_: TokenStream) -> TokenStream {
    let mut tokens = TokenStream2::new();
    for i in 1..=512usize {
        tokens.extend(quote! {
            impl XdpArray for [u8; #i] {}
        });
    }

    tokens.into()
}

/// Attribute macro that must be used when creating [eBPF
/// maps](https://redsift.github.io/rust/redbpf/doc/redbpf_probes/maps/index.html).
///
/// # Example
/// ```
/// #[map("dns_queries")]
/// static mut queries: PerfMap<Query> = PerfMap::new();
/// ```
#[proc_macro_attribute]
pub fn map(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attrs as Expr);
    let name = match attrs {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value().clone(),
        _ => panic!("expected string literal"),
    };

    let section_name = format!("maps/{}", name);
    let item = TokenStream2::from(item);
    let tokens = quote! {
        #[no_mangle]
        #[link_section = #section_name]
        #item
    };

    tokens.into()
}

fn probe_impl(ty: &str, attrs: TokenStream, item: ItemFn) -> TokenStream {
    let name = if attrs.is_empty() {
        item.sig.ident.to_string()
    } else {
        match parse_macro_input!(attrs as Expr) {
            Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) => s.value().clone(),
            _ => panic!("expected string literal"),
        }
    };

    let section_name = format!("{}/{}", ty, name);
    let tokens = quote! {
        #[no_mangle]
        #[link_section = #section_name]
        #item
    };

    tokens.into()
}

/// Attribute macro that must be used to define [`kprobes`](https://www.kernel.org/doc/Documentation/kprobes.txt).
///
/// # Example
/// ```
/// #[kprobe("__x64_sys_clone")]
/// pub extern "C" fn clone_enter(ctx: *mut pt_regs) {
///     // this is executed when clone() is invoked
///     ...
/// }
/// ```
#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    probe_impl("kprobe", attrs, item).into()
}

/// Attribute macro that must be used to define [`kretprobes`](https://www.kernel.org/doc/Documentation/kprobes.txt).
///
/// # Example
/// ```
/// #[kretprobe("__x64_sys_clone")]
/// pub extern "C" fn clone_exit(ctx: *mut pt_regs) {
///     // this is executed when clone() returns
///     ...
/// }
/// ```
#[proc_macro_attribute]
pub fn kretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    probe_impl("kretprobe", attrs, item).into()
}

/// Attribute macro that must be used to define [`XDP` probes](https://www.iovisor.org/technology/xdp).
///
/// See also the [`XDP` API provided by
/// `redbpf-probes`](https://redsift.github.io/rust/redbpf/doc/redbpf_probes/xdp/index.html).
///
/// # Example
/// ```
/// #[xdp]
/// pub extern "C" fn example_xdp_probe(ctx: XdpContext) -> XdpAction {
///     ...
///     XdpAction::Pass
/// }
/// ```
#[proc_macro_attribute]
pub fn xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let mut item = parse_macro_input!(item as ItemFn);
    let arg = item.sig.inputs.pop().unwrap();
    let pat = match arg.value() {
        FnArg::Typed(PatType { pat, .. }) => pat,
        _ => panic!("unexpected xdp probe signature"),
    };
    let ident = if let Pat::Ident(PatIdent { ident, .. }) = &**pat {
        ident
    } else {
        panic!("unexpected xdp probe signature")
    };
    let raw_ctx = Ident::new(&format!("_raw_{}", ident), Span::call_site());
    let arg: FnArg = parse_quote! { #raw_ctx: *mut xdp_md };
    item.sig.inputs.push(arg);
    let ctx: Stmt = parse_quote! { let #ident = XdpContext { ctx: #raw_ctx }; };
    item.block.stmts.insert(0, ctx);
    probe_impl("xdp", attrs, item).into()
}
