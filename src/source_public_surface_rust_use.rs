use super::SpanRanges;
use crate::source_public_surface::{
    SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace, SourcePublicReexport,
    SourcePublicReexportKind, SourcePublicSymbolKind,
};
use std::collections::BTreeSet;
use syn::spanned::Spanned;

pub(super) fn collect(
    item: &syn::ItemUse,
    module_names: &BTreeSet<String>,
    ranges: &SpanRanges<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
    reexports: &mut Vec<SourcePublicReexport>,
) -> Result<(), String> {
    let directive = ranges.range(item.span())?;
    collect_tree(
        &item.tree,
        Vec::new(),
        None,
        module_names,
        directive,
        ranges,
        declarations,
        reexports,
    )
}

fn collect_tree(
    tree: &syn::UseTree,
    mut prefix: Vec<String>,
    module_anchor: Option<crate::source_public_surface::SourceByteRange>,
    module_names: &BTreeSet<String>,
    directive: crate::source_public_surface::SourceByteRange,
    ranges: &SpanRanges<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
    reexports: &mut Vec<SourcePublicReexport>,
) -> Result<(), String> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_tree(
                &path.tree,
                prefix,
                Some(ranges.range(path.ident.span())?),
                module_names,
                directive,
                ranges,
                declarations,
                reexports,
            )
        }
        syn::UseTree::Name(name) => {
            let target = name.ident.to_string();
            if target == "self" {
                return Err(
                    "Rust grouped public `self` re-export requires distinct exposure and compiler anchors"
                        .to_string(),
                );
            }
            let source_module = prefix.join("::");
            if module_names.contains(&target) {
                push_namespace(
                    target.clone(),
                    path_with_target(&prefix, &target),
                    ranges.range(name.ident.span())?,
                    directive,
                    reexports,
                );
                return Ok(());
            }
            push_reference(
                target.clone(),
                target,
                source_module,
                ranges.range(name.ident.span())?,
                declarations,
            );
            Ok(())
        }
        syn::UseTree::Rename(rename) => {
            let target = rename.ident.to_string();
            let exposed = rename.rename.to_string();
            let source_module = prefix.join("::");
            if module_names.contains(&target) {
                push_namespace(
                    exposed,
                    path_with_target(&prefix, &target),
                    ranges.range(rename.rename.span())?,
                    directive,
                    reexports,
                );
                return Ok(());
            }
            push_reference(
                exposed,
                target,
                source_module,
                ranges.range(rename.rename.span())?,
                declarations,
            );
            Ok(())
        }
        syn::UseTree::Glob(_glob) => {
            if prefix.is_empty() {
                return Err("Rust public glob has no source module".to_string());
            }
            let anchor = module_anchor.ok_or_else(|| {
                "Rust public glob has no exact compiler module anchor".to_string()
            })?;
            reexports.push(SourcePublicReexport {
                kind: SourcePublicReexportKind::Wildcard,
                name: None,
                source_module: prefix.join("::"),
                directive,
                exposed_identifier: None,
                compiler_anchor: anchor,
            });
            Ok(())
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_tree(
                    item,
                    prefix.clone(),
                    module_anchor,
                    module_names,
                    directive,
                    ranges,
                    declarations,
                    reexports,
                )?;
            }
            Ok(())
        }
    }
}

fn path_with_target(prefix: &[String], target: &str) -> String {
    prefix
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(target))
        .collect::<Vec<_>>()
        .join("::")
}

fn push_namespace(
    name: String,
    source_module: String,
    anchor: crate::source_public_surface::SourceByteRange,
    directive: crate::source_public_surface::SourceByteRange,
    reexports: &mut Vec<SourcePublicReexport>,
) {
    reexports.push(SourcePublicReexport {
        kind: SourcePublicReexportKind::Namespace,
        name: Some(name),
        source_module,
        directive,
        exposed_identifier: Some(anchor),
        compiler_anchor: anchor,
    });
}

fn push_reference(
    name: String,
    target_name: String,
    source_module: String,
    anchor: crate::source_public_surface::SourceByteRange,
    declarations: &mut Vec<SourcePublicDeclaration>,
) {
    declarations.push(SourcePublicDeclaration {
        name,
        target_name,
        owner: None,
        namespace: SourcePublicNamespace::Module,
        kind: SourcePublicSymbolKind::CompilerDefined,
        exposed_identifier: anchor,
        compiler_anchor: anchor,
        owner_compiler_anchor: None,
        binding: SourcePublicBindingKind::Reference,
        source_module: (!source_module.is_empty()).then_some(source_module),
    });
}
