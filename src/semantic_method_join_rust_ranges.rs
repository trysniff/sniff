use crate::semantic_index::{
    SemanticPosition, SemanticPositionEncoding, SemanticSourceRange, SemanticUnresolvedReason,
};
use crate::types::{FileRecord, MethodRecord};
use syn::spanned::Spanned;

pub(super) fn definition_range(
    file: &FileRecord,
    method: &MethodRecord,
    encoding: SemanticPositionEncoding,
) -> Result<Option<SemanticSourceRange>, (SemanticUnresolvedReason, String)> {
    if !file.language.eq_ignore_ascii_case("rust") {
        return Ok(None);
    }
    let missing = |detail: String| (SemanticUnresolvedReason::MissingDefinition, detail);
    let ast = syn::parse_file(&file.source)
        .map_err(|error| missing(format!("cannot locate Rust callable: {error}")))?;
    let mut visitor = RustDefinitionVisitor {
        target_line: method.start_line,
        target_name: &method.name,
        definition_spans: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut visitor, &ast);
    match visitor.definition_spans.as_slice() {
        [span] => Ok(Some(SemanticSourceRange {
            start: encoded_position(&file.source, span.start(), encoding)
                .ok_or_else(|| missing("invalid Rust identifier start position".to_string()))?,
            end: encoded_position(&file.source, span.end(), encoding)
                .ok_or_else(|| missing("invalid Rust identifier end position".to_string()))?,
        })),
        [] => Err(missing(
            "no exact Rust callable identity in source".to_string(),
        )),
        _ => Err((
            SemanticUnresolvedReason::Ambiguous,
            "multiple Rust callables share the AST method identity".to_string(),
        )),
    }
}

fn encoded_position(
    source: &str,
    position: proc_macro2::LineColumn,
    encoding: SemanticPositionEncoding,
) -> Option<SemanticPosition> {
    let line = position.line.checked_sub(1)?;
    let text = source.lines().nth(line)?;
    // Syn strips the file-leading BOM before assigning spans; SCIP indexes the original text.
    let column = position
        .column
        .checked_add(usize::from(line == 0 && source.starts_with('\u{feff}')))?;
    if column > text.chars().count() {
        return None;
    }
    let prefix = text.chars().take(column);
    let character = match encoding {
        SemanticPositionEncoding::Utf8 => prefix.map(char::len_utf8).sum(),
        SemanticPositionEncoding::Utf16 => prefix.map(char::len_utf16).sum(),
        SemanticPositionEncoding::Utf32 => column,
    };
    Some(SemanticPosition {
        line: u32::try_from(line).ok()?,
        character: u32::try_from(character).ok()?,
    })
}

#[cfg(test)]
pub(super) fn definition_line(
    file: &FileRecord,
    method: &MethodRecord,
) -> Result<Option<u32>, (SemanticUnresolvedReason, String)> {
    definition_range(file, method, SemanticPositionEncoding::Utf8)
        .map(|range| range.map(|range| range.start.line))
}

struct RustDefinitionVisitor<'a> {
    target_line: usize,
    target_name: &'a str,
    definition_spans: Vec<proc_macro2::Span>,
}

impl RustDefinitionVisitor<'_> {
    fn visit_callable(&mut self, node_start_line: usize, identifier: &syn::Ident) {
        // AST nodes may start at attributes; SCIP definitions start at the identifier.
        // Source syntax locates the identifier, but cannot prove compiler cfg selection.
        let identifier_line = identifier.span().start().line;
        if identifier == self.target_name
            && (node_start_line == self.target_line || identifier_line == self.target_line)
        {
            self.definition_spans.push(identifier.span());
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for RustDefinitionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.visit_callable(node.span().start().line, &node.sig.ident);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.visit_callable(node.span().start().line, &node.sig.ident);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.visit_callable(node.span().start().line, &node.sig.ident);
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.visit_callable(node.span().start().line, &node.sig.ident);
        syn::visit::visit_foreign_item_fn(self, node);
    }
}

#[cfg(test)]
#[path = "tests/semantic_method_join_rust_ranges.rs"]
mod tests;
