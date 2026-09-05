use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace,
    SourcePublicReexport, SourcePublicReexportKind, SourcePublicSurface, SourcePublicSymbolKind,
};
use proc_macro2::{LineColumn, Span};
use syn::spanned::Spanned;

#[path = "source_public_surface_rust_use.rs"]
mod use_tree;

pub(super) fn census(file_path: &str, source: &[u8]) -> Result<SourcePublicSurface, String> {
    let source = std::str::from_utf8(source)
        .map_err(|_| format!("Rust public-surface source is not UTF-8: {file_path}"))?;
    let file = syn::parse_file(source)
        .map_err(|error| format!("failed to parse Rust public surface {file_path}: {error}"))?;
    let ranges = SpanRanges::new(source);
    let mut collector = Collector {
        file_path,
        ranges,
        declarations: Vec::new(),
        reexports: Vec::new(),
    };
    collector.collect_items(&file.items)?;
    Ok(SourcePublicSurface {
        declarations: collector.declarations,
        reexports: collector.reexports,
    })
}

struct Collector<'a> {
    file_path: &'a str,
    ranges: SpanRanges<'a>,
    declarations: Vec<SourcePublicDeclaration>,
    reexports: Vec<SourcePublicReexport>,
}

impl Collector<'_> {
    fn collect_items(&mut self, items: &[syn::Item]) -> Result<(), String> {
        for item in items {
            match item {
                syn::Item::Fn(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.sig.ident, None, SourcePublicSymbolKind::Callable)?;
                }
                syn::Item::Struct(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    let owner = item.ident.to_string();
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                    self.collect_fields(&owner, &item.fields, false)?;
                }
                syn::Item::Enum(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    let owner = item.ident.to_string();
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                    for variant in &item.variants {
                        self.reject_conditional(&variant.attrs, variant.span())?;
                        self.member(
                            &variant.ident,
                            &owner,
                            SourcePublicSymbolKind::Constant,
                            SourcePublicNamespace::StaticMember,
                        )?;
                        self.collect_fields(
                            &format!("{owner}::{}", variant.ident),
                            &variant.fields,
                            true,
                        )?;
                    }
                }
                syn::Item::Union(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    let owner = item.ident.to_string();
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                    for field in &item.fields.named {
                        if public(&field.vis) {
                            self.reject_conditional(&field.attrs, field.span())?;
                            if let Some(ident) = &field.ident {
                                self.definition(
                                    ident,
                                    Some(&owner),
                                    SourcePublicSymbolKind::Field,
                                )?;
                            }
                        }
                    }
                }
                syn::Item::Trait(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    let owner = item.ident.to_string();
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                    self.collect_trait_items(&owner, &item.items)?;
                }
                syn::Item::TraitAlias(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                }
                syn::Item::Type(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                }
                syn::Item::Const(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Constant)?;
                }
                syn::Item::Static(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Variable)?;
                }
                syn::Item::Impl(item) => self.collect_impl(item)?,
                syn::Item::Mod(item) => self.collect_module(item)?,
                syn::Item::Use(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    use_tree::collect(
                        item,
                        &self.ranges,
                        &mut self.declarations,
                        &mut self.reexports,
                    )?;
                }
                syn::Item::ExternCrate(item) if public(&item.vis) => {
                    return Err(format!(
                        "Rust public extern crate requires an explicit external-surface contract in {} at byte {}",
                        self.file_path,
                        self.ranges.range(item.span())?.start,
                    ));
                }
                syn::Item::ForeignMod(item) => self.collect_foreign(item)?,
                syn::Item::Macro(item) if macro_exported(&item.attrs) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    let ident = item.ident.as_ref().ok_or_else(|| {
                        format!(
                            "Rust #[macro_export] item has no name in {}",
                            self.file_path
                        )
                    })?;
                    self.definition(ident, None, SourcePublicSymbolKind::CompilerDefined)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_module(&mut self, item: &syn::ItemMod) -> Result<(), String> {
        if !public(&item.vis) {
            return Ok(());
        }
        self.reject_conditional(&item.attrs, item.span())?;
        if item.content.is_some() {
            return Err(format!(
                "inline public Rust module {} cannot yet be enumerated without scoped compiler surfaces in {}",
                item.ident, self.file_path
            ));
        }
        let identifier = self.ranges.range(item.ident.span())?;
        self.reexports.push(SourcePublicReexport {
            kind: SourcePublicReexportKind::Namespace,
            name: Some(item.ident.to_string()),
            source_module: item.ident.to_string(),
            directive: self.ranges.range(item.span())?,
            exposed_identifier: Some(identifier),
            compiler_anchor: identifier,
        });
        Ok(())
    }

    fn collect_fields(
        &mut self,
        owner: &str,
        fields: &syn::Fields,
        inherited_public: bool,
    ) -> Result<(), String> {
        for (index, field) in fields.iter().enumerate() {
            if !inherited_public && !public(&field.vis) {
                continue;
            }
            self.reject_conditional(&field.attrs, field.span())?;
            if let Some(ident) = &field.ident {
                self.definition(ident, Some(owner), SourcePublicSymbolKind::Field)?;
            } else {
                return Err(format!(
                    "public Rust tuple field {owner}::{index} has no exact source identifier for compiler binding in {}",
                    self.file_path
                ));
            }
        }
        Ok(())
    }

    fn collect_trait_items(&mut self, owner: &str, items: &[syn::TraitItem]) -> Result<(), String> {
        for item in items {
            match item {
                syn::TraitItem::Fn(item) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.member(
                        &item.sig.ident,
                        owner,
                        SourcePublicSymbolKind::Method,
                        signature_namespace(&item.sig),
                    )?;
                }
                syn::TraitItem::Const(item) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.member(
                        &item.ident,
                        owner,
                        SourcePublicSymbolKind::Constant,
                        SourcePublicNamespace::StaticMember,
                    )?;
                }
                syn::TraitItem::Type(item) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.member(
                        &item.ident,
                        owner,
                        SourcePublicSymbolKind::Type,
                        SourcePublicNamespace::StaticMember,
                    )?;
                }
                syn::TraitItem::Macro(item) => {
                    return Err(format!(
                        "macro-generated Rust trait surface is unresolved in {} at byte {}",
                        self.file_path,
                        self.ranges.range(item.span())?.start,
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_impl(&mut self, item: &syn::ItemImpl) -> Result<(), String> {
        if item.trait_.is_some() {
            return Ok(());
        }
        let owner = simple_type_name(&item.self_ty).ok_or_else(|| {
            format!(
                "public Rust inherent impl has no stable owner spelling in {} at byte {}",
                self.file_path,
                self.ranges
                    .range(item.self_ty.span())
                    .map_or(0, |range| range.start),
            )
        })?;
        for member in &item.items {
            match member {
                syn::ImplItem::Fn(member) if public(&member.vis) => {
                    self.reject_conditional(&member.attrs, member.span())?;
                    self.member(
                        &member.sig.ident,
                        &owner,
                        SourcePublicSymbolKind::Method,
                        signature_namespace(&member.sig),
                    )?;
                }
                syn::ImplItem::Const(member) if public(&member.vis) => {
                    self.reject_conditional(&member.attrs, member.span())?;
                    self.member(
                        &member.ident,
                        &owner,
                        SourcePublicSymbolKind::Constant,
                        SourcePublicNamespace::StaticMember,
                    )?;
                }
                syn::ImplItem::Type(member) if public(&member.vis) => {
                    self.reject_conditional(&member.attrs, member.span())?;
                    self.member(
                        &member.ident,
                        &owner,
                        SourcePublicSymbolKind::Type,
                        SourcePublicNamespace::StaticMember,
                    )?;
                }
                syn::ImplItem::Macro(member) => {
                    return Err(format!(
                        "macro-generated Rust inherent impl surface is unresolved in {} at byte {}",
                        self.file_path,
                        self.ranges.range(member.span())?.start,
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_foreign(&mut self, item: &syn::ItemForeignMod) -> Result<(), String> {
        for foreign in &item.items {
            match foreign {
                syn::ForeignItem::Fn(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.sig.ident, None, SourcePublicSymbolKind::Callable)?;
                }
                syn::ForeignItem::Static(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Variable)?;
                }
                syn::ForeignItem::Type(item) if public(&item.vis) => {
                    self.reject_conditional(&item.attrs, item.span())?;
                    self.definition(&item.ident, None, SourcePublicSymbolKind::Type)?;
                }
                syn::ForeignItem::Macro(item) => {
                    return Err(format!(
                        "macro-generated Rust foreign surface is unresolved in {} at byte {}",
                        self.file_path,
                        self.ranges.range(item.span())?.start,
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn definition(
        &mut self,
        ident: &syn::Ident,
        owner: Option<&str>,
        kind: SourcePublicSymbolKind,
    ) -> Result<(), String> {
        let namespace = if owner.is_some() {
            SourcePublicNamespace::InstanceMember
        } else {
            SourcePublicNamespace::Module
        };
        self.definition_range(
            ident.to_string(),
            ident.to_string(),
            owner.map(str::to_string),
            namespace,
            kind,
            self.ranges.range(ident.span())?,
        );
        Ok(())
    }

    fn member(
        &mut self,
        ident: &syn::Ident,
        owner: &str,
        kind: SourcePublicSymbolKind,
        namespace: SourcePublicNamespace,
    ) -> Result<(), String> {
        self.definition_range(
            ident.to_string(),
            ident.to_string(),
            Some(owner.to_string()),
            namespace,
            kind,
            self.ranges.range(ident.span())?,
        );
        Ok(())
    }

    fn definition_range(
        &mut self,
        name: String,
        target_name: String,
        owner: Option<String>,
        namespace: SourcePublicNamespace,
        kind: SourcePublicSymbolKind,
        range: SourceByteRange,
    ) {
        self.declarations.push(SourcePublicDeclaration {
            name,
            target_name,
            owner,
            namespace,
            kind,
            exposed_identifier: range,
            compiler_anchor: range,
            binding: SourcePublicBindingKind::Definition,
            source_module: None,
        });
    }

    fn reject_conditional(&self, attrs: &[syn::Attribute], span: Span) -> Result<(), String> {
        if attrs.iter().any(conditional_attr) {
            return Err(format!(
                "conditional Rust public surface requires an explicit build variant in {} at byte {}",
                self.file_path,
                self.ranges.range(span)?.start,
            ));
        }
        Ok(())
    }
}

fn public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

fn conditional_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")
}

fn macro_exported(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("macro_export"))
}

fn signature_namespace(signature: &syn::Signature) -> SourcePublicNamespace {
    if signature.receiver().is_some() {
        SourcePublicNamespace::InstanceMember
    } else {
        SourcePublicNamespace::StaticMember
    }
}

fn simple_type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => simple_type_name(&reference.elem),
        syn::Type::Paren(paren) => simple_type_name(&paren.elem),
        syn::Type::Group(group) => simple_type_name(&group.elem),
        _ => None,
    }
}

pub(super) struct SpanRanges<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SpanRanges<'a> {
    fn new(source: &'a str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            source,
            line_starts,
        }
    }

    pub(super) fn range(&self, span: Span) -> Result<SourceByteRange, String> {
        let start = self.offset(span.start())?;
        let end = self.offset(span.end())?;
        if start >= end || end > self.source.len() {
            return Err("Rust compiler span has an invalid byte range".to_string());
        }
        Ok(SourceByteRange { start, end })
    }

    fn offset(&self, location: LineColumn) -> Result<usize, String> {
        let line = location
            .line
            .checked_sub(1)
            .ok_or_else(|| "Rust compiler span uses an invalid one-based line".to_string())?;
        let start = *self
            .line_starts
            .get(line)
            .ok_or_else(|| "Rust compiler span line exceeds the source".to_string())?;
        let offset = start
            .checked_add(location.column)
            .ok_or_else(|| "Rust compiler span byte offset overflowed".to_string())?;
        if offset > self.source.len() || !self.source.is_char_boundary(offset) {
            return Err("Rust compiler span is not on a UTF-8 boundary".to_string());
        }
        Ok(offset)
    }
}
