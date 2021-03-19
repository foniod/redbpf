use proc_macro2::{Ident, Span};
use quote::quote;
use std::collections::{HashMap, HashSet};
use syn::visit::{visit_item_struct, Visit};
use syn::{self, parse_str, Field, File, Item, ItemStruct, ItemUnion, Path, Type, TypePath};

// toplevel syn items
type Items = HashMap<Ident, Item>;

struct CollectItems {
    items: Items,
}

impl CollectItems {
    fn new() -> Self {
        CollectItems {
            items: Items::new(),
        }
    }
}

impl<'ast> Visit<'ast> for CollectItems {
    fn visit_item_struct(&mut self, node: &ItemStruct) {
        self.items
            .insert(node.ident.clone(), Item::Struct(node.clone()));
    }

    fn visit_item_union(&mut self, node: &ItemUnion) {
        self.items
            .insert(node.ident.clone(), Item::Union(node.clone()));
    }
}
struct Accessor {
    prefix: Vec<String>,
    field: Field,
}

struct GenerateAccessors {
    items: Items,
    whitelist: HashSet<String>,
    prefix: Vec<String>,
    accessors: Vec<Accessor>,
    type_accessors: HashMap<String, Vec<Accessor>>,
}

impl GenerateAccessors {
    fn new(items: Items, whitelist: HashSet<String>) -> Self {
        GenerateAccessors {
            items,
            whitelist,
            accessors: Vec::new(),
            type_accessors: HashMap::new(),
            prefix: Vec::new(),
        }
    }

    fn type_item(&self, ty: &Type) -> &Item {
        let ident = match ty {
            Type::Path(TypePath {
                path: Path { ref segments, .. },
                ..
            }) => segments.first().unwrap().ident.clone(),
            _ => panic!(),
        };

        self.items.get(&ident).unwrap()
    }

    fn enter_field(&self, id_s: &str) -> bool {
        id_s.starts_with("__bindgen_anon") || id_s.starts_with("__sk_common")
    }

    fn toplevel_visit(&self) -> bool {
        self.prefix.is_empty()
    }

    fn is_whitelisted(&self, ident: &Ident) -> bool {
        self.whitelist.contains(&ident.to_string())
    }

    fn blacklisted_field(&self, id_s: &str) -> bool {
        if id_s.starts_with("_bindgen") || id_s.starts_with("_bitfield") {
            return true;
        }

        false
    }
}

impl<'ast> Visit<'ast> for GenerateAccessors {
    fn visit_item_struct(&mut self, node: &ItemStruct) {
        let toplevel = self.toplevel_visit();
        if toplevel {
            if !self.is_whitelisted(&node.ident) {
                return;
            }
            self.prefix.push("self".to_string());
        }

        visit_item_struct(self, node);
        // this function is called recursively as types are parsed. We want to
        // generate accessors only when parsing toplevel items.
        if toplevel {
            if !self.accessors.is_empty() {
                self.type_accessors
                    .insert(node.ident.to_string(), self.accessors.drain(..).collect());
            }
            self.prefix.pop();
        }
    }

    fn visit_field(&mut self, node: &Field) {
        if self.prefix.is_empty() {
            // visiting a field for a type for which we're not generating
            // accessors
            return;
        }

        let id_s = match &node.ident {
            Some(i) => i.to_string(),
            None => return,
        };

        if self.enter_field(&id_s) {
            self.prefix.push(id_s);
            let item = self.type_item(&node.ty).clone();
            self.visit_item(&item);
            self.prefix.pop();
        } else if !self.blacklisted_field(&id_s) {
            self.accessors.push(Accessor {
                prefix: self.prefix.clone(),
                field: node.clone(),
            });
        }
    }
}

fn parse_items(tree: &File) -> Items {
    let mut ci = CollectItems::new();
    ci.visit_file(tree);
    ci.items
}

pub fn generate_read_accessors(bindings: &str, whitelist: &[&str]) -> String {
    // parse the bindgen generated bindings
    let tree: File = parse_str(&bindings).unwrap();

    // discover the toplevel items, and generate accessors for the items
    // included in the whitelist
    let whitelist = whitelist.iter().map(|s| String::from(*s)).collect();
    let mut accessors = GenerateAccessors::new(parse_items(&tree), whitelist);
    accessors.visit_file(&tree);

    // for each accessor, generate a getter that automatically reads the data
    // via bpf_probe_read
    let items = accessors
        .type_accessors
        .iter()
        .map(|(item_id, item_accessors)| {
            // first generate a hashmap (`cache`), to ensure every
            // entry is unique. turns out certain distro kernel macros
            // will interfere with this logic, and we generate
            // multiple definitions for accessors
            let functions = item_accessors
                .iter()
                .fold(HashMap::new(), |mut cache, acc| {
                    let ident = acc.field.ident.clone().unwrap();
                    let ty = &acc.field.ty;
                    let prefix = acc.prefix.iter().map(|p| Ident::new(p, Span::call_site()));

                    let _ = cache.entry(ident.to_string()).or_insert_with(|| match ty {
                        Type::Ptr(_) => {
                            quote! {
                                pub fn #ident(&self) -> Option<#ty> {
                                    let v = unsafe { bpf_probe_read(&#(#prefix).*.#ident) }.ok()?;
                                    if v.is_null() {
                                        None
                                    } else {
                                        Some(v)
                                    }
                                }
                            }
                        }
                        _ => {
                            quote! {
                                pub fn #ident(&self) -> Option<#ty> {
                                    unsafe { bpf_probe_read(&#(#prefix).*.#ident) }.ok()
                                }
                            }
                        }
                    });

                    cache
                });

            let accessors = functions.values();
            let ident = Ident::new(item_id, Span::call_site());
            let item = quote! {
                /// Auto-generated read-accessors by cargo_bpf::accessors::generate_read_accessors
                impl #ident {
                    #(#accessors)*
                }
            };
            item.to_string()
        });

    let mut out = String::new();
    for item in items {
        out.push_str(&item);
    }
    out
}
