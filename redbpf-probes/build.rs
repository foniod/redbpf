// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::{bail, Result};
use bindgen::{
    self,
    callbacks::{EnumVariantCustomBehavior, EnumVariantValue, ParseCallbacks},
};
use quote::quote;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use syn::visit::Visit;

use bpf_sys::headers::{
    available_kernel_header_paths, get_custom_header_path, get_custom_header_version,
    set_custom_header_path, ENV_SOURCE_PATH, ENV_SOURCE_VERSION,
};
use bpf_sys::type_gen::{get_custom_vmlinux_path, ENV_VMLINUX_PATH};
use cargo_bpf_lib::bindgen as bpf_bindgen;
use syn::{
    self, parse_str, punctuated::Punctuated, token::Comma, AngleBracketedGenericArguments,
    ForeignItemStatic, GenericArgument, Ident, PathArguments::*, Type,
};
use tracing::{debug, warn, Level};
use tracing_subscriber::FmtSubscriber;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    {
        let mut file = File::create(&path)?;
        writeln!(
            &mut file,
            r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
            name = name,
            bindings = bindings
        )?;
    }
    // for debugging
    let _ = Command::new("rustfmt")
        .arg("--edition=2018")
        .arg("--emit=files")
        .arg(path.to_str().unwrap())
        .status();
    Ok(())
}

fn rerun_if_changed_dir(dir: &str) {
    println!("cargo:rerun-if-changed={}/", dir);
    glob::glob(&format!("./{}/**/*.h", dir))
        .expect("Failed to glob for source files from build.rs")
        .filter_map(|e| e.ok())
        .for_each(|path| println!("cargo:rerun-if-changed={}", path.to_string_lossy()));
}

fn generate_bindings_kernel_headers() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let types = ["pt_regs", "s32", "bpf_.*"];
    let vars = ["BPF_.*"];
    let xdp_types = [
        "xdp_md",
        "ethhdr",
        "iphdr",
        "ipv6hdr",
        "tcphdr",
        "udphdr",
        "xdp_action",
        "__sk_.*",
        "sk_.*",
        "inet_sock",
        "unix_sock",
        "sockaddr",
        "sockaddr_in",
        "in_addr",
        "tcp.*_sock",
        "udp.*_sock",
        "btf_ptr",
        "linux_binprm",
        "^sock_type$",  // for enum of SOCK_*
        "^sock_flags$", // for enum of SOCK_*
    ];
    let xdp_vars = ["ETH_.*", "IPPROTO_.*", "SOCK_.*", "SK_FL_.*", "AF_.*"];

    let mut builder = bpf_bindgen::get_builder_kernel_headers()
        .or_else(|e| bail!("error on Builder::get_builder_kernel_headers: {}", e))?
        .header("include/redbpf_helpers.h")
        .header("include/bpf_helpers.h");

    for ty in types.iter().chain(xdp_types.iter()) {
        builder = builder.allowlist_type(ty);
    }

    for var in vars.iter().chain(xdp_vars.iter()) {
        builder = builder.allowlist_var(var);
    }

    builder = builder.opaque_type("xregs_state");
    let mut bindings = builder
        .generate()
        .or_else(|e| bail!("error on Builder::generate: {:?}", e))?
        .to_string();
    let accessors = bpf_bindgen::generate_read_accessors(
        &bindings,
        &[
            "sock",
            "sockaddr",
            "sockaddr_in",
            "in_addr",
            "file",
            "inode",
            "path",
            "dentry",
            "qstr",
        ],
    );
    bindings.push_str("use crate::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings)?;

    let bindings = bpf_bindgen::get_builder_kernel_headers()
        .or_else(|e| bail!("error on Builder::get_builder: {}", e))?
        .header("include/redbpf_helpers.h")
        .header("include/bpf_helpers.h")
        .allowlist_var("bpf_.*")
        .generate()
        .or_else(|e| {
            bail!(
                "error on Builder::generate while generating helpers: {:?}",
                e
            )
        })?;

    let helpers = gen_helpers(&bindings.to_string());
    create_module(out_dir.join("gen_helpers.rs"), "gen_helpers", &helpers)?;

    Ok(())
}

#[derive(Debug)]
struct HideEnum;
impl ParseCallbacks for HideEnum {
    fn enum_variant_behavior(
        &self,
        _enum_name: Option<&str>,
        _original_variant_name: &str,
        _variant_value: EnumVariantValue,
    ) -> Option<EnumVariantCustomBehavior> {
        Some(EnumVariantCustomBehavior::Hide)
    }
}

fn generate_bindings_vmlinux() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    // patterns of whitelist are used to match type names by regex. They are
    // matched as str::find, not str::starts_with. So ^ and $ should be used to
    // match the exact name.
    let types = ["^pt_regs$", "^s32$", "^bpf_.*"];
    let vars = ["^BPF_.*"];
    let xdp_types = [
        "^xdp_md$",
        "^ethhdr$",
        "^iphdr$",
        "^ipv6hdr$",
        "^tcphdr$",
        "^udphdr$",
        "^xdp_action$",
        "^__sk_.*",
        "^sk_.*",
        "^inet_sock$",
        "^unix_sock$",
        "^sockaddr$",
        "^sockaddr_in$",
        "^in_addr$",
        "^tcp.*_sock$",
        "^udp.*_sock$",
        "^btf_ptr$",
        "^sock_type$",  // for enum of SOCK_*
        "^sock_flags$", // for enum of SOCK_*
    ];
    let xdp_vars = ["^IPPROTO_.*"];
    let mut builder = bpf_bindgen::get_builder_vmlinux(out_dir.join("vmlinux.h"))
        .or_else(|e| bail!("error on bpf_bindgen::get_builder_vmlinux: {}", e))?
        // Since the Linux v5.15, vmlinux contains `struct bpf_timer`. To
        // support older kernel versions, forward declaration of struct
        // bpf_timer should be provided. And it is okay to have the forward
        // declaration even though the definition exists before it.
        .header_contents("bpf_timer.h", "struct bpf_timer;")
        // // Prevent error E0133: `#[derive]` can't be used on a
        // // `#[repr(packed)]` struct that does not derive Copy
        .no_debug("ec_response_motion_sense_fifo_info")
        .no_debug("tpm2_.*")
        .no_debug("pubkey_hdr")
        .no_debug("__pldm.*")
        .no_debug("signature_.*hdr");

    // It is possible to generate bindings of all types of the Linux
    // kernel. And the generated bindings can be used to compile BPF
    // programs. But if all types are generated, compiling BPF programs takes a
    // long time. So keep whitelist types.
    for ty in types.iter().chain(xdp_types.iter()) {
        builder = builder.allowlist_type(ty);
    }

    for var in vars.iter().chain(xdp_vars.iter()) {
        builder = builder.allowlist_var(var);
    }
    builder = builder.opaque_type("xregs_state");
    let mut bindings = builder
        .generate()
        .or_else(|e| bail!("error on Builder::generate: {:?}", e))?
        .to_string();
    let accessors = bpf_bindgen::generate_read_accessors(
        &bindings,
        &[
            "sock",
            "sockaddr",
            "sockaddr_in",
            "in_addr",
            "file",
            "inode",
            "path",
            "dentry",
            "qstr",
        ],
    );
    bindings.push_str("use crate::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    // macro constants and structures of userspace can not be generated by BTF
    // of vmlinux. So missing parts are generated with the supplement header.
    // It is difficult to include the header files along with vmlinux.h to
    // generate gen_bindings.rs at once because lots of redefinitions exist in
    // the supplement header. So another call to bindgen is conducted here.
    let supplement = bindgen::builder()
        .use_core()
        .ctypes_prefix("::cty")
        .header("include/vmlinux_supplement.h")
        .allowlist_var("^AF_.*")
        .allowlist_var("^ETH_.*")
        .allowlist_var("^BPF_.*")
        .allowlist_var("^IPPROTO_.*") // for additional IPPROTO_*
        .allowlist_var("^SOCK_.*")
        .allowlist_type("^bpf_map_def$")
        .blocklist_type("_bindgen_ty.*") // avoid unncessary collision
        .parse_callbacks(Box::new(HideEnum)) // hide enums because they are included before
        .generate()
        .or_else(|e| bail!("error on Builder::generate for supplement: {:?}", e))?
        .to_string();
    bindings.push_str(&supplement);
    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings)?;

    // Generate bindings of BPF helper variables and convert them into functions
    let bindings = bpf_bindgen::get_builder_vmlinux(out_dir.join("vmlinux_helpers.h"))
        .or_else(|e| bail!("error on bpf_bindgen::get_builder_vmlinux: {}", e))?
        .header("include/bpf_helpers.h")
        .allowlist_var("^bpf_.*")
        .generate()
        .or_else(|e| bail!("error on Builder::generate for helper: {:?}", e))?;

    let helpers = gen_helpers(&bindings.to_string());
    create_module(out_dir.join("gen_helpers.rs"), "gen_helpers", &helpers)?;
    Ok(())
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if let Ok(_) = env::var("DOCS_RS") {
        let mut paths = available_kernel_header_paths();
        paths.sort();
        if let Some(path) = paths.pop() {
            set_custom_header_path(path);
        }
    }
    rerun_if_changed_dir("include");
    println!("cargo:rerun-if-env-changed={}", ENV_SOURCE_PATH);
    println!("cargo:rerun-if-env-changed={}", ENV_SOURCE_VERSION);
    println!("cargo:rerun-if-env-changed={}", ENV_VMLINUX_PATH);

    if get_custom_vmlinux_path().is_some() {
        debug!("Generating bindings with BTF of vmlinux");
        generate_bindings_vmlinux().unwrap();
    } else if get_custom_header_path().is_some() || get_custom_header_version().is_some() {
        debug!("Generating bindings with pre-intalled kernel headers");
        generate_bindings_kernel_headers().unwrap();
    } else {
        debug!("Try generating rust bindings with pre-installed kernel headers");
        generate_bindings_kernel_headers()
            .or_else(|e| {
                warn!("error on generate_bindings_kernel_headers: {:?}", e);
                debug!("Try generating rust bindings with vmlinux");
                generate_bindings_vmlinux()
            })
            .unwrap()
    }
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
    let tree: syn::File = parse_str(&helpers).unwrap();
    let mut tx = RewriteBpfHelpers {
        helpers: Vec::new(),
    };
    tx.visit_file(&tree);
    let mut out = String::new();
    out.push_str("use crate::bindings::*;\n");
    for helper in &tx.helpers {
        out.push_str(helper);
    }

    out
}
