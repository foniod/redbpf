// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use quote::quote;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use syn::visit::Visit;
use syn::{
    self, parse_str, punctuated::Punctuated, token::Comma, AngleBracketedGenericArguments,
    ForeignItemStatic, GenericArgument, Ident, PathArguments::*, Type,
};

use redbpf::build::headers::kernel_headers;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let kernel_headers = kernel_headers().expect("couldn't find kernel headers");
    let mut flags: Vec<String> = kernel_headers
        .iter()
        .map(|dir| format!("-I{}", dir))
        .collect();
    flags.extend(redbpf::build::BUILD_FLAGS.iter().map(|f| f.to_string()));
    flags.push("-Wno-unused-function".to_string());
    flags.push("-Wno-unused-variable".to_string());
    flags.push("-Wno-address-of-packed-member".to_string());
    flags.push("-Wno-gnu-variable-sized-type-not-at-end".to_string());

    let bindings = bindgen::builder()
        .clang_args(&flags)
        .header("./include/redbpf_helpers.h")
        .use_core()
        .ctypes_prefix("::cty")
        // bpf_helpers
        .whitelist_type("pt_regs")
        .whitelist_type("s32")
        .whitelist_type("bpf_.*")
        .whitelist_var("BPF_.*")
        // XDP
        .whitelist_type("xdp_md")
        .whitelist_type("ethhdr")
        .whitelist_type("iphdr")
        .whitelist_type("tcphdr")
        .whitelist_type("udphdr")
        .whitelist_type("xdp_action")
        .whitelist_type("__sk_.*")
        .whitelist_type("sk_.*")
        .whitelist_var("ETH_.*")
        .whitelist_var("IPPROTO_.*")
        .opaque_type("xregs_state")
        .generate()
        .expect("Unable to generate bindings!");
    create_module(
        out_dir.join("gen_bindings.rs"),
        "gen_bindings",
        &bindings.to_string(),
    )
    .unwrap();

    let bindings = bindgen::builder()
        .clang_args(&flags)
        .header("./include/redbpf_helpers.h")
        .ctypes_prefix("::cty")
        .whitelist_var("bpf_.*")
        .generate()
        .expect("Unable to generate bindings!");
    let helpers = gen_helpers(&bindings.to_string());
    create_module(out_dir.join("gen_helpers.rs"), "gen_helpers", &helpers).unwrap();
}

struct RewriteBpfHelpers {
    helpers: Vec<String>,
}

impl Visit<'_> for RewriteBpfHelpers {
    fn visit_foreign_item_static(&mut self, item: &ForeignItemStatic) {
        if let Type::Path(path) = &*item.ty {
            let ident = &item.ident;
            let ident_str = ident.to_string();
            let last = path.path.segments.last().unwrap();
            let ty_ident = last.ident.to_string();
            if ident_str.starts_with("bpf_") && ty_ident == "Option" {
                let fn_ty = match &last.arguments {
                    AngleBracketed(AngleBracketedGenericArguments { args, .. }) => {
                        args.first().unwrap()
                    }
                    _ => panic!(),
                };
                let mut ty_s = quote! {
                    #[inline(always)]
                    pub #fn_ty
                }
                .to_string();
                ty_s = ty_s.replace("fn (", &format!("fn {} (", ident_str));
                let call_idx = self.helpers.len() + 1;
                let args: Punctuated<Ident, Comma> = match fn_ty {
                    GenericArgument::Type(Type::BareFn(f)) => f
                        .inputs
                        .iter()
                        .map(|arg| arg.name.clone().unwrap().0)
                        .collect(),
                    _ => unreachable!(),
                };
                let body = quote! {
                    {
                        let f: #fn_ty = ::core::mem::transmute(#call_idx);
                        f(#args)
                    }
                }
                .to_string();
                ty_s.push_str(&body);
                let mut helper = ty_s;
                if helper.contains("printk") {
                    helper = format!("/* {} */", helper);
                }
                self.helpers.push(helper);
            }
        }
    }
}

fn gen_helpers(helpers: &str) -> String {
    let mut tree: syn::File = parse_str(&helpers).unwrap();
    let mut tx = RewriteBpfHelpers {
        helpers: Vec::new(),
    };
    tx.visit_file(&mut tree);
    let mut out = String::new();
    out.push_str("use crate::bindings::*;\n");
    for helper in &tx.helpers {
        out.push_str(helper);
    }

    out
}
