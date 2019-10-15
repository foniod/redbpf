extern crate proc_macro;
extern crate proc_macro2;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_macro_input, parse_quote, parse_str, Block, Expr, ExprLit, ItemFn, Lit, Result};

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

#[proc_macro]
pub fn probe(input: TokenStream) -> TokenStream {
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
    };

    tokens.extend(quote! {
        #[start]
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            loop {}
        }

        #[lang = "eh_personality"]
        #[no_mangle]
        pub extern "C" fn rust_eh_personality() {}

        #[lang = "eh_unwind_resume"]
        #[no_mangle]
        pub extern "C" fn rust_eh_unwind_resume() {}

        #[lang = "panic_impl"]
        #[no_mangle]
        pub extern "C" fn rust_begin_panic(_: &::core::panic::PanicInfo) -> ! {
            loop {}
        }
    });
    tokens.into()
}

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

fn bpf_helpers() -> Block {
    let funcs = include!(concat!(env!("OUT_DIR"), "/gen_helper_funcs.rs"));
    let funcs: Block = parse_str(&funcs).unwrap();

    funcs
}

fn bpf_overrides() -> Block {
    parse_quote! {
        {
            let _bpf_get_current_pid_tgid = bpf_get_current_pid_tgid;
            let bpf_get_current_pid_tgid = || {
                unsafe { _bpf_get_current_pid_tgid() }
            };
            let _bpf_get_current_uid_gid = bpf_get_current_uid_gid;
            let bpf_get_current_uid_gid = || {
                unsafe { _bpf_get_current_uid_gid() }
            };
            let _bpf_get_current_comm = bpf_get_current_comm;
            let bpf_get_current_comm = || {
                let mut comm: [c_char; 16usize] = [0i8; 16];
                unsafe { _bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, 16i32) };
                comm
            };
        }
    }
}

fn inject_bpf_helpers(item: &mut ItemFn) {
    let helpers = bpf_helpers();
    let overrides = bpf_overrides();
    let mut stmts = helpers.stmts.clone();
    stmts.extend(overrides.stmts);
    stmts.extend(item.block.stmts.clone());
    item.block.stmts = stmts;
}

fn probe_impl(ty: &str, attrs: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attrs as Expr);
    let name = match attrs {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value().clone(),
        _ => panic!("expected string literal"),
    };

    let section_name = format!("{}/{}", ty, name);
    let mut item = parse_macro_input!(item as ItemFn);
    inject_bpf_helpers(&mut item);
    let tokens = quote! {
        #[no_mangle]
        #[link_section = #section_name]
        #item
    };

    tokens.into()
}

#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe_impl("kprobe", attrs, item).into()
}

#[proc_macro_attribute]
pub fn xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe_impl("xdp", attrs, item).into()
}
