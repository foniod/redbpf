use quote::{format_ident, quote};
use std::env;
use std::path::PathBuf;
use syn::visit_mut::VisitMut;
use syn::{
    self, parse_str, AngleBracketedGenericArguments, ForeignItemStatic, Ident, PathArguments::*,
    Type,
};

use redbpf::build::headers::kernel_headers;

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
        .header("../include/bpf_helpers.h")
        .ctypes_prefix("::cty")
        .whitelist_var("bpf_.*")
        .generate()
        .expect("Unable to generate bindings!");
    let helper_funcs = gen_helper_funcs(&bindings.to_string());
    std::fs::write(out_dir.join("gen_helper_funcs.rs"), helper_funcs).unwrap();
}

struct RewriteBpfHelpers {
    helpers: Vec<String>,
}

impl VisitMut for RewriteBpfHelpers {
    fn visit_foreign_item_static_mut(&mut self, item: &mut ForeignItemStatic) {
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
                    _ => unreachable!(),
                };
                let name = ident_str.splitn(2, "_").last().unwrap();
                let func_id = format_ident!("bpf_func_id_BPF_FUNC_{}", name);
                let helper = quote! {
                    let #ident: #fn_ty = unsafe { ::core::mem::transmute(::redbpf_probes::bindings::#func_id as u64) };
                }.to_string();
                self.helpers.push(helper);
                let ident = format!("__{}", ident_str);
                item.ident = Ident::new(&ident, item.ident.span());
            }
        }
    }
}

fn gen_helper_funcs(helpers: &str) -> String {
    let mut tree: syn::File = parse_str(&helpers).unwrap();
    let mut tx = RewriteBpfHelpers {
        helpers: Vec::new(),
    };
    tx.visit_file_mut(&mut tree);
    let mut out = String::from("{ r#\" {");
    for helper in &tx.helpers {
        out.push_str(helper);
    }
    out.push_str("} \"# }");

    out
}
