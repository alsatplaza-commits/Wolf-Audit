//! Read source from stdin and print a syntax inventory.
//!
//! This binary parses with `syn`. It does not expand macros, evaluate `cfg`,
//! resolve names, read module files, spawn processes, or open the network.
//! Token streams inside macros are not parsed, so nested macro bodies are a
//! coverage gap rather than an inventory of their text.
//!
//! If parsing fails on a later line, lines before that error are parsed
//! again. The result also records `rust_syn_parse_failed` and does not print
//! the parser's error text. Parsing does not resume on or after the error.

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::process::ExitCode;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Ident, ItemForeignMod, ItemImpl, ItemMod, Meta, MetaList, Token};

const MAX_INPUT: usize = 1_000_000;
const CFG_ATTR_DEPTH: u8 = 4;

const BUILTIN_ATTRIBUTES: &[&str] = &[
    "allow", "deny", "warn", "forbid", "expect",
    "cfg", "doc", "deprecated", "must_use",
    "inline", "cold", "repr", "unsafe",
    "no_mangle", "export_name", "link_name", "link", "link_section", "used",
    "test", "ignore", "should_panic",
    "path", "non_exhaustive", "target_feature",
    "crate_name", "crate_type", "no_main", "no_std", "feature",
    "recursion_limit", "windows_subsystem",
    "macro_export", "macro_use", "automatically_derived",
];

struct Inventory {
    findings: BTreeSet<(String, usize)>,
    gaps: BTreeSet<(String, usize)>,
}

impl Inventory {
    fn finding(&mut self, rule: &str, line: usize) {
        self.findings.insert((rule.to_string(), line.max(1)));
    }

    fn gap_at(&mut self, reason: &str, line: usize) {
        self.gaps.insert((reason.to_string(), line.max(1)));
    }

    fn classify_attribute(&mut self, attr: &Attribute) {
        self.classify_applied_meta(&attr.meta, CFG_ATTR_DEPTH);
    }

    fn classify_applied_meta(&mut self, meta: &Meta, depth: u8) {
        let line = meta.path().span().start().line.max(1);
        if meta.path().segments.len() != 1 {
            self.gap_at("rust_name_resolution_unresolved", line);
            self.gap_at("rust_macro_not_expanded", line);
            return;
        }
        let name = meta.path().get_ident().map(Ident::to_string).unwrap_or_default();
        match name.as_str() {
            "cfg" => self.gap_at("rust_cfg_unresolved", line),
            "cfg_attr" => {
                self.gap_at("rust_cfg_unresolved", line);
                match meta {
                    Meta::List(list) => self.note_cfg_attr_arguments(list, line, depth),
                    _ => self.gap_at("rust_attribute_body_unclassified", line),
                }
            }
            "derive" => self.gap_at("rust_macro_not_expanded", line),
            "proc_macro" | "proc_macro_derive" | "proc_macro_attribute" => {
                self.gap_at("rust_proc_macro_not_executed", line);
            }
            "no_mangle" | "export_name" | "link_name" => self.finding("RUST_FFI_SYMBOL", line),
            "link" => self.finding("RUST_FFI_BOUNDARY", line),
            "unsafe" => {
                self.finding("RUST_UNSAFE_INVENTORY", line);
                if let Meta::List(list) = meta {
                    self.note_unsafe_arguments(list, line, depth);
                }
            }
            other if BUILTIN_ATTRIBUTES.contains(&other) => {}
            _ => self.gap_at("rust_macro_not_expanded", line),
        }
    }

    fn note_cfg_attr_arguments(&mut self, list: &MetaList, line: usize, depth: u8) {
        if depth == 0 {
            self.gap_at("rust_attribute_body_unclassified", line);
            return;
        }
        let Ok(items) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
            self.gap_at("rust_attribute_body_unclassified", line);
            return;
        };
        let metas: Vec<Meta> = items.into_iter().collect();
        if metas.len() < 2 {
            self.gap_at("rust_attribute_body_unclassified", line);
            return;
        }
        for meta in metas.iter().skip(1) {
            self.classify_applied_meta(meta, depth - 1);
        }
    }

    fn note_unsafe_arguments(&mut self, list: &MetaList, line: usize, depth: u8) {
        if depth == 0 {
            self.gap_at("rust_attribute_body_unclassified", line);
            return;
        }
        let Ok(items) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
            self.gap_at("rust_attribute_body_unclassified", line);
            return;
        };
        for meta in items {
            self.classify_applied_meta(&meta, depth - 1);
        }
    }

    fn note_signature(&mut self, sig: &syn::Signature) {
        if let Some(unsafety) = &sig.unsafety {
            self.finding("RUST_UNSAFE_INVENTORY", unsafety.span.start().line);
        }
        if let Some(abi) = &sig.abi {
            self.finding("RUST_FFI_BOUNDARY", abi.extern_token.span.start().line);
        }
    }
}

impl<'ast> Visit<'ast> for Inventory {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        self.classify_attribute(attr);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.note_signature(&node.sig);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.note_signature(&node.sig);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.note_signature(&node.sig);
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.note_signature(&node.sig);
        syn::visit::visit_foreign_item_fn(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.finding("RUST_UNSAFE_INVENTORY", node.unsafe_token.span.start().line);
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if let Some(token) = &node.unsafety {
            self.finding("RUST_UNSAFE_INVENTORY", token.span.start().line);
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if let Some(token) = &node.unsafety {
            self.finding("RUST_UNSAFE_INVENTORY", token.span.start().line);
        }
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        self.finding("RUST_FFI_BOUNDARY", node.abi.extern_token.span.start().line);
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_none() {
            self.gap_at("rust_module_file_not_read", node.mod_token.span.start().line);
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if matches!(node.mutability, syn::StaticMutability::Mut(_)) {
            self.gap_at("rust_static_mut_not_inventoried", node.static_token.span.start().line);
        }
        syn::visit::visit_item_static(self, node);
    }

    fn visit_foreign_item_static(&mut self, node: &'ast syn::ForeignItemStatic) {
        if matches!(node.mutability, syn::StaticMutability::Mut(_)) {
            self.gap_at("rust_static_mut_not_inventoried", node.static_token.span.start().line);
        }
        syn::visit::visit_foreign_item_static(self, node);
    }

    fn visit_type_bare_fn(&mut self, node: &'ast syn::TypeBareFn) {
        if let Some(unsafety) = &node.unsafety {
            self.finding("RUST_UNSAFE_INVENTORY", unsafety.span.start().line);
        }
        if let Some(abi) = &node.abi {
            self.finding("RUST_FFI_BOUNDARY", abi.extern_token.span.start().line);
        }
        syn::visit::visit_type_bare_fn(self, node);
    }

    fn visit_type_ptr(&mut self, node: &'ast syn::TypePtr) {
        self.gap_at("rust_raw_pointer_not_inventoried", node.star_token.span.start().line);
        syn::visit::visit_type_ptr(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.gap_at("rust_macro_not_expanded", node.bang_token.span.start().line);
        if node.path.segments.len() > 1 {
            self.gap_at(
                "rust_name_resolution_unresolved",
                node.path.span().start().line,
            );
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path.segments.len() > 1 {
            self.gap_at("rust_name_resolution_unresolved", path.span().start().line);
        }
        syn::visit::visit_path(self, path);
    }
}

fn emit(findings: &BTreeSet<(String, usize)>, gaps: &[serde_json::Value]) -> ExitCode {
    let finding_json: Vec<_> = findings
        .iter()
        .map(|(rule, line)| serde_json::json!({"rule": rule, "line": line}))
        .collect();
    let body = serde_json::json!({
        "coverage_claim": false,
        "macros_expanded": false,
        "cfg_evaluated": false,
        "names_resolved": false,
        "findings": finding_json,
        "gaps": gaps,
    });
    println!("{body}");
    ExitCode::SUCCESS
}

fn emit_inventory(inventory: &Inventory) -> ExitCode {
    let gaps: Vec<_> = inventory
        .gaps
        .iter()
        .map(|(reason, line)| serde_json::json!({"reason": reason, "line": line}))
        .collect();
    emit(&inventory.findings, &gaps)
}

fn emit_failure(reason: &str, line: Option<usize>) -> ExitCode {
    let gap = match line {
        Some(line) if line >= 1 => serde_json::json!({"reason": reason, "line": line}),
        _ => serde_json::json!({"reason": reason}),
    };
    emit(&BTreeSet::new(), &[gap])
}

fn emit_recovered_prefix(source: &str, error_line: usize) -> ExitCode {
    let mut inventory = Inventory {
        findings: BTreeSet::new(),
        gaps: BTreeSet::new(),
    };
    if let Some(file) = prefix_before_parse_error(source, error_line) {
        inventory.visit_file(&file);
    }
    inventory.gap_at("rust_syn_parse_failed", error_line);
    emit_inventory(&inventory)
}

/// Keep source lines before the parse error and parse that prefix with the
/// same `syn::parse_file` entry point. An unclosed delimiter fails tokenization
/// of the whole buffer, so the failed line is not resumed or rewritten.
fn prefix_before_parse_error(source: &str, error_line: usize) -> Option<syn::File> {
    let mut line = error_line;
    let mut attempts = 0u8;
    while line > 1 && attempts < 64 {
        attempts += 1;
        let prefix = source_before_line(source, line);
        match syn::parse_file(prefix) {
            Ok(file) => return Some(file),
            Err(error) => {
                let next = error.span().start().line;
                if next == 0 || next >= line {
                    return None;
                }
                line = next;
            }
        }
    }
    None
}

fn source_before_line(source: &str, line: usize) -> &str {
    if line <= 1 {
        return "";
    }
    let mut seen = 1usize;
    for (idx, ch) in source.char_indices() {
        if ch == '\n' {
            seen += 1;
            if seen == line {
                return &source[..idx + ch.len_utf8()];
            }
        }
    }
    source
}

fn main() -> ExitCode {
    let mut input = Vec::new();
    let mut stdin = io::stdin();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = match stdin.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => return emit_failure("rust_syn_parse_failed", None),
        };
        if input.len().saturating_add(read) > MAX_INPUT {
            return emit_failure("rust_syn_input_limit", None);
        }
        input.extend_from_slice(&chunk[..read]);
    }
    let Ok(source) = String::from_utf8(input) else {
        return emit_failure("rust_syn_parse_failed", None);
    };
    let file = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => return emit_recovered_prefix(&source, error.span().start().line),
    };
    let mut inventory = Inventory {
        findings: BTreeSet::new(),
        gaps: BTreeSet::new(),
    };
    inventory.visit_file(&file);
    emit_inventory(&inventory)
}
