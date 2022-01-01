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
[`redbpf-probes`](../../redbpf_probes/), it provides an idiomatic Rust API to
write programs that can be compiled to eBPF bytecode and executed by the linux
in-kernel eBPF virtual machine.

To streamline the process of working with eBPF programs even further, `redbpf`
also provides [`cargo-bpf`](../../cargo_bpf/) - a cargo subcommand to simplify
creating and building eBPF programs.

# Example

```no_run
#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

// configure kernel version compatibility and license
program!(0xFFFFFFFE, "GPL");

#[xdp]
fn example_xdp_probe(ctx: XdpContext) -> XdpResult {

    // do something here

    Ok(XdpAction::Pass)
}
```
*/

#![cfg_attr(RUSTC_IS_NIGHTLY, feature(proc_macro_diagnostic))]

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
    parse_macro_input, parse_quote, AttributeArgs, Expr, ExprLit, ItemFn,
    ItemStatic, Lit, Meta, NestedMeta, Result,
};
use uuid::Uuid;

fn inline_string_literal(e: &Expr) -> (TokenStream2, TokenStream2) {
    let bytes = match e {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value().into_bytes(),
        _ => panic!("expected string literal"),
    };

    inline_bytes(bytes)
}

fn inline_bytes(mut bytes: Vec<u8>) -> (TokenStream2, TokenStream2) {
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
/// # Example
///
/// ```no_run
/// #![no_std]
/// #![no_main]
/// use redbpf_macros::program;
/// program!(0xFFFFFFFE, "GPL");
/// # fn main() {}
/// ```
///
#[proc_macro]
pub fn program(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Args);
    let mut args = input.0.iter();
    let version = args.next().expect("no version");
    let license = args.next().expect("no license");
    let (license_ty, license) = inline_string_literal(&license);
    let (panic_ty, panic_msg) = inline_bytes(b"panic".to_vec());
    let tokens = quote! {
        #[no_mangle]
        #[link_section = "license"]
        pub static _license: #license_ty = #license;

        #[no_mangle]
        #[link_section = "version"]
        pub static _version: u32 = #version;

        #[panic_handler]
        #[no_mangle]
        pub extern "C" fn rust_begin_panic(info: &::core::panic::PanicInfo) -> ! {
            use ::redbpf_probes::helpers::{bpf_trace_printk};

            let msg: #panic_ty = #panic_msg;
            bpf_trace_printk(&msg);

            unsafe { core::hint::unreachable_unchecked() }
        }
    };

    tokens.into()
}

#[doc(hidden)]
#[proc_macro]
pub fn impl_network_buffer_array(_: TokenStream) -> TokenStream {
    let mut tokens = TokenStream2::new();
    for i in 1..=512usize {
        tokens.extend(quote! {
            impl NetworkBufferArray for [u8; #i] {}
        });
    }

    tokens.into()
}

/// Attribute macro that must be used when creating [eBPF
/// maps](../../redbpf_probes/maps/index.html).
///
/// The default `#[map]` places the map into a section of the resulting
/// ELF binary called `maps/<item_name>`.
///
/// If you wish to set the section name manually for BPF programs that
/// require strict naming conventions use `#[map(link_section = "foo")]`
/// which place the map into a section called `foo`.
///
/// # Example
///
/// ```no_run
/// # use redbpf_probes::kprobe::prelude::*;
/// // Will be linked into the ELF in the section 'maps/counts'
/// #[map]
/// static mut counts: PerfMap<u64> = PerfMap::with_max_entries(10240);
///
/// // Will be linked into the ELF in the section 'dns_queries'
/// #[map(link_section = "dns_queries")]
/// static mut queries: PerfMap<Query> = PerfMap::with_max_entries(1024);
///
/// struct Query {
/// // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn map(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let mut link_section: Option<String> = None;
    for attr in parse_macro_input!(attrs as AttributeArgs) {
        let mut allowed = false;
        match attr {
            NestedMeta::Meta(meta) => {
                if let Meta::NameValue(mnv) = meta {
                    if let Some(id) = mnv.path.get_ident() {
                        // In case of #[map(link_section = "...", something_else = "...")]
                        match id.to_string().as_str() {
                            "link_section" => {
                                if let Lit::Str(name) = mnv.lit {
                                    if link_section.is_some() {
                                        panic!(
                                            "#[map(link_section = \"...\")] is used more than once"
                                        );
                                    }
                                    link_section = Some(name.value());
                                    allowed = true;
                                }
                            }
                            _ => panic!("expected `link_section' as metadata of #[map]"),
                        }
                    }
                }
            }
            NestedMeta::Lit(lit) => {
                // panic if #[map("...")] is declared
                if let Lit::Str(name) = lit {
                    panic!("expected #[map(link_section = \"maps/{}\")]", name.value());
                }
            }
        }

        if !allowed {
            panic!("expected #[map(link_section = \"...\")]");
        }
    }
    let static_item = {
        let item = item.clone();
        parse_macro_input!(item as ItemStatic)
    };
    let section_name = link_section.unwrap_or_else(|| {
        // In case of just #[map] without any metadata
        format!("maps/{}", static_item.ident.to_string())
    });
    let mut tokens = {
        let item = TokenStream2::from(item);
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #item
        }
    };

    let map_type = static_item.ty;
    let mod_name = format!("_{}", Uuid::new_v4().to_simple().to_string());
    let mod_ident = syn::Ident::new(&mod_name, static_item.ident.span());
    // CAUTION: When you change the names (MAP_BTF_XXXX and
    // MAP_VALUE_ALIGN_XXXX) you should consider changing corresponding
    // parts that use them.
    let map_btf_name = format!("MAP_BTF_{}", static_item.ident.to_string());
    let map_btf_ident = syn::Ident::new(&map_btf_name, static_item.ident.span());
    let value_align_name = format!("MAP_VALUE_ALIGN_{}", static_item.ident.to_string());
    let value_align_ident = syn::Ident::new(&value_align_name, static_item.ident.span());
    let btf_type_name = format!("____btf_map_{}", static_item.ident.to_string());
    let btf_map_type = syn::Ident::new(&btf_type_name, static_item.ident.span());
    tokens.extend(quote! {
        mod #mod_ident {
            #[allow(unused_imports)]
            use super::*;
            use core::mem::{self, MaybeUninit};

            #[no_mangle]
            static #value_align_ident: MaybeUninit<<#map_type as ::redbpf_probes::maps::BpfMap>::Value> = MaybeUninit::uninit();

            #[repr(C)]
            struct #btf_map_type {
                key: <#map_type as ::redbpf_probes::maps::BpfMap>::Key,
                value: <#map_type as ::redbpf_probes::maps::BpfMap>::Value,
            }
            // `impl Sync` is needed to allow pointer types of keys and values
            unsafe impl Sync for #btf_map_type {}
            const N: usize = mem::size_of::<#btf_map_type>();
            #[no_mangle]
            #[link_section = "maps.ext"]
            static #map_btf_ident: #btf_map_type = unsafe { mem::transmute::<[u8; N], #btf_map_type>([0u8; N]) };
        }
    });
    tokens.into()
}

fn probe_impl(ty: &str, attrs: TokenStream, item: ItemFn, mut name: String) -> TokenStream {
    if !attrs.is_empty() {
        name = match parse_macro_input!(attrs as Expr) {
            Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) => s.value(),
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

fn probe_pair_impl(pre: &str, attrs: TokenStream, item: ItemFn, mut name: String) -> TokenStream {
    if !attrs.is_empty() {
        name = match parse_macro_input!(attrs as Expr) {
            Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) => s.value(),
            _ => panic!("expected string literal"),
        }
    };

    let ident = item.sig.ident.clone();
    let map_ident = Ident::new(&format!("PARMS_{}", ident), Span::call_site());
    let enter_ident = Ident::new(&format!("enter_{}", ident), Span::call_site());
    let exit_ident = Ident::new(&format!("exit_{}", ident), Span::call_site());
    let probe_ident = Ident::new(&format!("{}probe", pre), Span::call_site());
    let retprobe_ident = Ident::new(&format!("{}retprobe", pre), Span::call_site());

    let tokens = quote! {
        #[map]
        static mut #map_ident: HashMap<u64, [u64; 5]> = HashMap::with_max_entries(10240);

        #[#probe_ident(#name)]
        fn #enter_ident(regs: Registers) {
            let pid_tgid = bpf_get_current_pid_tgid();
            let parms = [regs.parm1(), regs.parm2(), regs.parm3(), regs.parm4(), regs.parm5()];
            unsafe {
                #map_ident.set(&pid_tgid, &parms);
            }
        }

        #[#retprobe_ident(#name)]
        fn #exit_ident(regs: Registers) {
            let pid_tgid = bpf_get_current_pid_tgid();
            let parms = unsafe {
                match #map_ident.get(&pid_tgid) {
                    Some(parms) => {
                        let parms = *parms;
                        #map_ident.delete(&pid_tgid);
                        parms
                    }
                    None => return,
                }
            };
            let _ = unsafe { #ident(regs, parms) };
        }

        #item
    };

    tokens.into()
}

fn wrap_kprobe(item: ItemFn) -> ItemFn {
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    parse_quote! {
        fn #outer_ident(ctx: *mut c_void) -> i32 {
            let regs = ::redbpf_probes::registers::Registers::from(ctx);
            let _ = unsafe { #ident(regs) };
            return 0;

            #item
        }
    }
}

/// Attribute macro that must be used to define [`kprobes`](https://www.kernel.org/doc/Documentation/kprobes.txt).
///
/// # Example
/// ```no_run
/// use redbpf_probes::kprobe::prelude::*;
///
/// #[kprobe("__x64_sys_clone")]
/// fn clone_enter(regs: Registers) {
///     // this is executed when clone() is invoked
/// }
/// ```
#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let wrapper = wrap_kprobe(item);
    probe_impl("kprobe", attrs, wrapper, name)
}

/// Attribute macro that must be used to define [`kretprobes`](https://www.kernel.org/doc/Documentation/kprobes.txt).
///
/// # Example
///
/// ```no_run
/// use redbpf_probes::kprobe::prelude::*;
///
/// #[kretprobe("__x64_sys_clone")]
/// fn clone_exit(regs: Registers) {
///     // this is executed when clone() returns
/// }
/// ```
///
/// # Function parameters
///
/// In general, the `parmX` methods of the `regs` argument do **not**
/// return the original parameter values that the function being probed
/// was called with. The reason is that those parameters are passed
/// via (architecture-dependent) general purpose registers, and the
/// function code most likely overwrites some or all of those registers.
/// RedBPF provides a convenient way to access original function parameters
/// by declaring the retprobe with an additional array argument that
/// receives function parameters 1-5:
///
/// ```no_run
/// use redbpf_probes::kprobe::prelude::*;
///
/// #[kretprobe("__x64_sys_clone")]
/// fn clone_exit(regs: Registers, parms: [u64; 5]) {
///     // this is executed when clone() returns
/// }
/// ```
///
/// To make this possible, RedBPF generates a global map, and an entry probe
/// corresponding to the retprobe which stores the original parameters
/// in that map. A generated retprobe wrapper retrieves the parameters from
/// the map, and calls the provided function with the parameter array as
/// an argument.
///
/// Note that if no parameters for the current thread are found in the map
/// (for example because the capacity of the map has been exhausted, or
/// the retprobe was registered after the function had already been entered),
/// **the retprobe is not called** for that function invocation.
#[proc_macro_attribute]
pub fn kretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    if item.sig.inputs.len() == 2 {
        return probe_pair_impl("k", attrs, item, name);
    }
    let wrapper = wrap_kprobe(item);
    probe_impl("kretprobe", attrs, wrapper, name)
}

/// Attribute macro that must be used to define [`uprobes`](https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt).
///
/// # Example
/// ```no_run
/// use redbpf_probes::uprobe::prelude::*;
///
/// #[uprobe]
/// fn getaddrinfo(regs: Registers) {
///     // this is executed when getaddrinfo() is invoked
/// }
/// ```
#[proc_macro_attribute]
pub fn uprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let wrapper = wrap_kprobe(item);
    probe_impl("uprobe", attrs, wrapper, name)
}

/// Attribute macro that must be used to define [`uretprobes`](https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt).
///
/// # Example
///
/// ```no_run
/// use redbpf_probes::uprobe::prelude::*;
///
/// #[uretprobe]
/// fn getaddrinfo(regs: Registers) {
///     // this is executed when getaddrinfo() returns
/// }
/// ```
///
/// # Function parameters
///
/// In general, the `parmX` methods of the `regs` argument do **not**
/// return the original parameter values that the function being probed
/// was called with. The reason is that those parameters are passed
/// via (architecture-dependent) general purpose registers, and the
/// function code most likely overwrites some or all of those registers.
/// RedBPF provides a convenient way to access original function parameters
/// by declaring the retprobe with an additional array argument that
/// receives function parameters 1-5:
///
/// ```no_run
/// use redbpf_probes::uprobe::prelude::*;
///
/// #[uretprobe]
/// fn getaddrinfo(regs: Registers, parms: [u64; 5]) {
///     // this is executed when getaddrinfo() returns
/// }
/// ```
///
/// To make this possible, RedBPF generates a global map, and an entry probe
/// corresponding to the retprobe which stores the original parameters
/// in that map. A generated retprobe wrapper retrieves the parameters from
/// the map, and calls the provided function with the parameter array as
/// an argument.
///
/// Note that if no parameters for the current thread are found in the map
/// (for example because the capacity of the map has been exhausted, or
/// the retprobe was registered after the function had already been entered),
/// **the retprobe is not called** for that function invocation.
#[proc_macro_attribute]
pub fn uretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    if item.sig.inputs.len() == 2 {
        return probe_pair_impl("u", attrs, item, name);
    }
    let wrapper = wrap_kprobe(item);
    probe_impl("uretprobe", attrs, wrapper, name)
}

/// Attribute macro that must be used to define [`XDP` probes](https://www.iovisor.org/technology/xdp).
///
/// See also the [`XDP` API provided by
/// `redbpf-probes`](../../redbpf_probes/xdp/index.html).
///
/// # Example
/// ```no_run
/// use redbpf_probes::xdp::prelude::*;
///
/// #[xdp]
/// fn probe(ctx: XdpContext) -> XdpResult {
///     // do something with the packet
///
///     Ok(XdpAction::Pass)
/// }
/// ```
#[proc_macro_attribute]
pub fn xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(ctx: *mut ::redbpf_probes::bindings::xdp_md) -> ::redbpf_probes::xdp::XdpAction {
            let ctx = ::redbpf_probes::xdp::XdpContext { ctx };
            return match unsafe { #ident(ctx) } {
                Ok(action) => action,
                Err(_) => ::redbpf_probes::xdp::XdpAction::Pass
            };

            #item
        }
    };
    probe_impl("xdp", attrs, wrapper, name)
}

/// Attribute macro that must be used to define [`socket
/// filter`](https://www.kernel.org/doc/Documentation/networking/filter.txt)
/// probes.
///
/// See also the [`socket filter` API provided by
/// `redbpf-probes`](../../api/redbpf_probes/socket_filter/index.html).
///
/// # Example
/// ```no_run
/// use redbpf_probes::socket_filter::prelude::*;
///
/// #[socket_filter]
/// fn probe(skb: SkBuff) -> SkBuffResult {
///     Ok(SkBuffAction::SendToUserspace)
/// }
/// ```
#[proc_macro_attribute]
pub fn socket_filter(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(skb: *const ::redbpf_probes::bindings::__sk_buff) -> i32 {
            let skb = ::redbpf_probes::socket_filter::SkBuff { skb };
            return match unsafe { #ident(skb) } {
                Ok(::redbpf_probes::socket_filter::SkBuffAction::SendToUserspace) => -1,
                _ => 0
            };

            #item
        }
    };

    probe_impl("socketfilter", attrs, wrapper, name)
}

/// Attribute macro for defining BPF programs of `stream parser`s. A `sockmap`
/// can be attached to the stream parser. The role of stream parsers is to find
/// a message boundary of TCP stream and return the length of a message. If it
/// returns proper length of a message then a `stream verdict` BPF program will
/// be called.
///
/// # Example
/// ```no_run
/// use core::ptr;
/// use memoffset::offset_of;
/// use redbpf_probes::sockmap::prelude::*;
///
/// #[stream_parser]
/// fn parse_message_boundary(skb: SkBuff) -> StreamParserResult {
///     let len: u32 = unsafe {
///         let addr = (skb.skb as usize + offset_of!(__sk_buff, len)) as *const u32;
///         ptr::read(addr)
///     };
///     Ok(StreamParserAction::MessageLength(len))
/// }
/// ```
#[proc_macro_attribute]
pub fn stream_parser(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(skb: *const ::redbpf_probes::bindings::__sk_buff) -> i32 {
            let skb = ::redbpf_probes::socket::SkBuff { skb };
            use ::redbpf_probes::sockmap::StreamParserAction::*;
            return match unsafe { #ident(skb) } {
                Ok(MessageLength(len)) if len > 0 => len as i32,
                Ok(MoreDataWanted) => 0,
                Ok(SendToUserspace) => -86,  // -ESTRPIPE
                _ => -1,  // error
            };

            #item
        }
    };

    probe_impl("streamparser", attrs, wrapper, name)
}

/// Attribute macro for defining BPF programs of `stream verdict`s. A `sockmap`
/// can be attached to the stream verdict. The role of stream verdicts is to
/// predicate to which socket a message should be redirected.
///
/// # Example
/// ```no_run
/// use redbpf_probes::sockmap::prelude::*;
/// #[map(link_section = "maps/echo_sockmap")]
/// static mut SOCKMAP: SockMap = SockMap::with_max_entries(10240);
///
/// #[stream_verdict]
/// fn verdict(skb: SkBuff) -> SkAction {
///     match unsafe { SOCKMAP.redirect(skb.skb as *mut _, 0) } {
///         Ok(_) => SkAction::Pass,
///         Err(_) => SkAction::Drop,
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn stream_verdict(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(skb: *const ::redbpf_probes::bindings::__sk_buff) -> i32 {
            let skb = ::redbpf_probes::socket::SkBuff { skb };
            use ::redbpf_probes::socket::SkAction;

            return match unsafe { #ident(skb) } {
                SkAction::Pass => ::redbpf_probes::bindings::sk_action_SK_PASS,
                SkAction::Drop => ::redbpf_probes::bindings::sk_action_SK_DROP,
            } as i32;

            #item
        }
    };

    probe_impl("streamverdict", attrs, wrapper, name)
}

/// Define [tc action BPF programs](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)
#[proc_macro_attribute]
pub fn tc_action(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(skb: *const ::redbpf_probes::bindings::__sk_buff) -> i32 {
            let skb = ::redbpf_probes::socket::SkBuff { skb };
            return match unsafe { #ident(skb) } {
                Ok(act) => act as i32,
                Err(_) => -1
            };

            #item
        }
    };

    probe_impl("tc_action", attrs, wrapper, name)
}

/// Attribute macro for defining a BPF iterator of `task`
#[proc_macro_attribute]
pub fn task_iter(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = item.sig.ident.to_string();
    let ident = item.sig.ident.clone();
    let outer_ident = Ident::new(&format!("outer_{}", ident), Span::call_site());
    let wrapper = parse_quote! {
        fn #outer_ident(ctx: *mut bpf_iter__task) -> i32 {
            let task_ctx = ::redbpf_probes::bpf_iter::context::TaskIterContext { ctx };
            return match unsafe { #ident(task_ctx) } {
                BPFIterAction::Ok => 0,
                BPFIterAction::Retry => 1,
            };

            #item
        }
    };

    probe_impl("task_iter", attrs, wrapper, name)
}

/// Safe wrapper for bpf_trace_printk helper.
///
/// Maximum three arguments are accepted, only one of
/// them may be string.
///
/// Supported formats:
///  * %d - i32
///  * %u - u32
///  * %x - u32 (hex)
///  * %s - &std::ffi::CStr
///  * %zd - isize
///  * %zu - usize
///  * %zx - usize (hex)
///  * %ld - ::cty::c_long
///  * %lu - ::cty::c_ulong
///  * %lx - ::cty::c_ulong (hex)
///  * %lld - i64
///  * %llu - u64
///  * %llx - u64 (hex)
///  * %p - ::cty::c_void
///  * %% - literal '%'
///
/// # Example
///
/// ```no_run
/// #![no_std]
/// #![no_main]
/// use redbpf_macros::printk;
/// # fn main() {
/// printk!("found %d things: %s", num, msg);
/// # }
/// ```
///
#[proc_macro]
pub fn printk(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Args);
    let mut macro_args = input.0.iter();

    // Parse and validate format string.
    let fmt_arg = macro_args.next().expect("no format string");
    let fmt_str = match fmt_arg {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value(),
        _ => panic!("expected string literal"),
    };

    let placeholders = parse_format_string(&fmt_str);
    if placeholders.len() > 3 {
        panic!("maximum 3 arguments to printk! are supported");
    }
    if placeholders
        .iter()
        .filter(|p| matches!(p, FmtPlaceholder::String))
        .count()
        > 1
    {
        panic!("maximum 1 string argument to printk! is supported");
    }

    let args = macro_args.collect::<Vec<_>>();
    if args.len() != placeholders.len() {
        panic!("number of arguments doesn't match number of placeholders");
    }

    let (_fmt_ty, fmt) = inline_string_literal(&fmt_arg);
    let mut tok_args = args
        .iter()
        .zip(placeholders)
        .map(|(arg, placeholder)| match placeholder {
            FmtPlaceholder::Number(typ) => {
                quote! { ::core::convert::Into::<#typ>::into(#arg) as u64 }
            }
            FmtPlaceholder::String => quote! { AsRef::<::core::ffi::CStr>::as_ref(#arg).as_ptr() },
        })
        .collect::<Vec<_>>();

    // bpf_trace_printk_raw accepts 3 parameters, pass 0 for left ones.
    while tok_args.len() < 3 {
        tok_args.push(quote! { 0u64 });
    }

    let tokens = quote! {
        ::redbpf_probes::helpers::bpf_trace_printk_raw(&#fmt, #(#tok_args),*)
    };

    tokens.into()
}

enum FmtPlaceholder {
    Number(/* type */ TokenStream2),
    String,
}

fn parse_format_string(fmt: &str) -> Vec<FmtPlaceholder> {
    let mut res = Vec::new();
    let mut iter = fmt.bytes();
    while let Some(ch) = iter.next() {
        if ch != b'%' {
            continue;
        }

        match iter.next() {
            Some(b'%') => continue,

            Some(b'd') => res.push(FmtPlaceholder::Number(quote!{i32})),
            Some(b'u' | b'x') => res.push(FmtPlaceholder::Number(quote!{u32})),
            Some(b's') => res.push(FmtPlaceholder::String),
            Some(b'z') => match iter.next() {
                Some(b'd') => res.push(FmtPlaceholder::Number(quote!{isize})),
                Some(b'u' | b'x') => res.push(FmtPlaceholder::Number(quote!{usize})),
                Some(c) => panic!("unsupported format placeholder %z{}, expected %zd, %zu or %zx", c),
                None => panic!("unfinished format string placeholder %z, expected %zd, %zu or %zx"),
            },
            Some(b'l') => match iter.next() {
                Some(b'd') => res.push(FmtPlaceholder::Number(quote!{::cty::c_long})),
                Some(b'u' | b'x') => res.push(FmtPlaceholder::Number(quote!{::cty::c_ulong})),
                Some(b'l') => match iter.next() {
                    Some(b'd') => res.push(FmtPlaceholder::Number(quote!{i64})),
                    Some(b'u' | b'x') => res.push(FmtPlaceholder::Number(quote!{u64})),
                    Some(c) => panic!("unsupported format placeholder %ll{}, expected %lld, %llu or %llx", c),
                    None => panic!("unfinished format string placeholder %ll, expected %lld, %llu or %llx"),
                },
                Some(c) => panic!("unsupported format placeholder %l{}, expected %ld, %lu, %lx, %lld, %llu or %llx", c),
                None => panic!("unfinished format string placeholder %l, expected %ld, %lu, %lx, %lld, %llu or %llx"),
            },
            Some(b'p') => res.push(FmtPlaceholder::Number(quote!{::cty::c_void})),
            Some(c) => panic!("unsupported format placeholder %{}, expected %%, %d, %u, %x, %zd, %zu, %zx, %ld, %lu, %lx, %lld, %llu, %llx or %p", c),
            None => panic!("unfinished format string placeholder %, expected %%, %d, %u, %x, %zd, %zu, %zx, %ld, %lu, %lx, %lld, %llu, %llx or %p"),
        }
    }
    res
}
