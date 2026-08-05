use super::*;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

#[path = "rust_ref_scan.rs"]
pub(crate) mod scan;

pub(super) fn balanced_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0isize;
    let mut started = false;
    let mut in_block_comment = false;
    let mut in_string: Option<char> = None;
    let mut escape = false;

    for (idx, line) in lines.iter().enumerate().skip(start) {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if !started {
                if ch == '{' {
                    started = true;
                    depth = 1;
                }
                continue;
            }

            if in_block_comment {
                if ch == '*' && matches!(chars.peek(), Some('/')) {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }

            if let Some(quote) = in_string {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' {
                    escape = true;
                    continue;
                }
                if ch == quote {
                    in_string = None;
                }
                continue;
            }

            match ch {
                '/' if matches!(chars.peek(), Some('/')) => {
                    break;
                }
                '/' if matches!(chars.peek(), Some('*')) => {
                    chars.next();
                    in_block_comment = true;
                }
                '"' | '`' => in_string = Some(ch),
                '\'' if matches!(
                    chars.peek(),
                    Some(next) if !next.is_ascii_alphanumeric() && *next != '_'
                ) =>
                {
                    // A Rust lifetime such as `'a` is not a character literal.
                    in_string = Some(ch);
                }
                '{' => {
                    depth += 1;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if started && depth <= 0 {
            return idx;
        }
    }

    lines.len().saturating_sub(1)
}

fn strip_rust_visibility_prefix(mut trimmed: &str) -> &str {
    loop {
        let line = trimmed.trim_start();
        if let Some(rest) = line.strip_prefix("pub ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub(")
            && let Some(end) = rest.find(')')
        {
            trimmed = &rest[end + 1..];
            continue;
        }
        return line;
    }
}

fn strip_rust_fn_prefixes(mut trimmed: &str) -> Option<&str> {
    loop {
        let line = trimmed.trim_start();
        if let Some(rest) = line.strip_prefix("fn ") {
            return Some(rest);
        }
        if let Some(rest) = line.strip_prefix("pub ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("async ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("const ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("unsafe ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("default ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("extern ") {
            let rest = rest.trim_start();
            if let Some(after_abi) = rest.strip_prefix('"') {
                let end_quote = after_abi.find('"')?;
                trimmed = &after_abi[end_quote + 1..];
            } else {
                trimmed = rest;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub(") {
            let end = rest.find(')')?;
            trimmed = &rest[end + 1..];
            continue;
        }
        return None;
    }
}

pub(super) fn parse_fn_name(trimmed: &str) -> Option<String> {
    let trimmed = trimmed.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('#') {
        return None;
    }
    let rest = strip_rust_fn_prefixes(trimmed)?;
    Some(
        rest.split(|c: char| c == '(' || c == '<' || c.is_whitespace())
            .next()?
            .trim()
            .to_string(),
    )
}

pub(super) fn parse_struct_name(trimmed: &str) -> Option<String> {
    let rest = strip_rust_visibility_prefix(trimmed);
    let rest = rest.strip_prefix("struct ")?;
    Some(
        rest.split(|c: char| c == '{' || c == ';' || c == '<' || c.is_whitespace())
            .next()?
            .trim()
            .to_string(),
    )
}

fn build_rust_method_record(
    file_path: &str,
    source: String,
    name: String,
    start: usize,
    end: usize,
    param_count: usize,
    is_exported: bool,
) -> MethodRecord {
    MethodRecord {
        name,
        file_path: file_path.to_string(),
        source,
        loc: end.saturating_sub(start) + 1,
        param_count,
        start_line: start,
        end_line: end,
        is_exported,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    }
}

fn build_rust_definition(
    next_id: usize,
    name: String,
    start: usize,
    end: usize,
    is_exported: bool,
    owner_type: Option<String>,
) -> SymbolDefinition {
    SymbolDefinition {
        id: next_id,
        name,
        kind: if owner_type.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
        start_line: start,
        end_line: end,
        is_exported,
        owner_type,
        receiver_type: None,
        value_type: None,
    }
}

fn push_rust_method(
    extractor: &mut RustExtractor<'_>,
    name: String,
    source: String,
    start: usize,
    end: usize,
    param_count: usize,
    is_exported: bool,
) {
    extractor.methods.push(build_rust_method_record(
        &extractor.file_path,
        source,
        name,
        start,
        end,
        param_count,
        is_exported,
    ));
}

fn push_rust_definition(
    extractor: &mut RustExtractor<'_>,
    name: String,
    start: usize,
    end: usize,
    is_exported: bool,
    owner_type: Option<String>,
) {
    extractor.definitions.push(build_rust_definition(
        extractor.next_id,
        name,
        start,
        end,
        is_exported,
        owner_type,
    ));
    extractor.next_id += 1;
}

fn rust_visibility_is_exported(visibility: &syn::Visibility) -> bool {
    !matches!(visibility, syn::Visibility::Inherited)
}

fn push_rust_use_leaf(
    extractor: &mut RustExtractor<'_>,
    prefix: &[String],
    imported_name: String,
    local_name: String,
    is_exported: bool,
) {
    let (source_module, imported_name) = if prefix.is_empty() {
        (imported_name.clone(), "*".to_string())
    } else {
        (prefix.join("::"), imported_name)
    };
    extractor.imports.push(ImportRecord {
        local_name: local_name.clone(),
        source_module: source_module.clone(),
        imported_name: imported_name.clone(),
    });
    if is_exported {
        extractor.exports.push(ExportRecord {
            exported_name: local_name.clone(),
            local_symbol_name: local_name,
            source_module: Some(source_module),
            source_symbol_name: Some(imported_name),
        });
    }
}

fn collect_rust_use_tree(
    extractor: &mut RustExtractor<'_>,
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    is_exported: bool,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_rust_use_tree(extractor, &path.tree, prefix, is_exported);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            if let Some(local_name) = prefix.last().cloned() {
                extractor.imports.push(ImportRecord {
                    local_name: local_name.clone(),
                    source_module: prefix.join("::"),
                    imported_name: "*".to_string(),
                });
                if is_exported {
                    extractor.exports.push(ExportRecord {
                        exported_name: local_name.clone(),
                        local_symbol_name: local_name,
                        source_module: Some(prefix.join("::")),
                        source_symbol_name: Some("*".to_string()),
                    });
                }
            }
        }
        syn::UseTree::Name(name) => push_rust_use_leaf(
            extractor,
            prefix,
            name.ident.to_string(),
            name.ident.to_string(),
            is_exported,
        ),
        syn::UseTree::Rename(rename) => push_rust_use_leaf(
            extractor,
            prefix,
            rename.ident.to_string(),
            rename.rename.to_string(),
            is_exported,
        ),
        syn::UseTree::Glob(_) => push_rust_use_leaf(
            extractor,
            prefix,
            "*".to_string(),
            "*".to_string(),
            is_exported,
        ),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_rust_use_tree(extractor, item, prefix, is_exported);
            }
        }
    }
}

struct RustUseVisitor<'extractor, 'source> {
    extractor: &'extractor mut RustExtractor<'source>,
}

impl<'ast> Visit<'ast> for RustUseVisitor<'_, '_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        collect_rust_use_tree(
            self.extractor,
            &node.tree,
            &mut Vec::new(),
            rust_visibility_is_exported(&node.vis),
        );
    }
}

fn rust_module_source_path(item: &syn::ItemMod) -> Option<String> {
    item.attrs.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        let syn::Expr::Lit(expression) = &name_value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &expression.lit else {
            return None;
        };
        Some(path.value())
    })
}

pub(super) fn record_rust_ast_modules_and_uses(
    extractor: &mut RustExtractor<'_>,
    file: &syn::File,
) {
    extractor.imports.clear();
    extractor.exports.clear();
    extractor.modules.clear();
    for item in &file.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_none() {
            extractor.modules.push(ModuleRecord {
                local_name: module.ident.to_string(),
                source_path: rust_module_source_path(module),
            });
        }
    }
    let mut visitor = RustUseVisitor { extractor };
    visitor.visit_file(file);
}

fn rust_type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => rust_type_name(&reference.elem),
        syn::Type::Paren(paren) => rust_type_name(&paren.elem),
        syn::Type::Group(group) => rust_type_name(&group.elem),
        _ => None,
    }
}

fn record_ast_callable(
    extractor: &mut RustExtractor<'_>,
    name: String,
    span: proc_macro2::Span,
    param_count: usize,
    is_exported: bool,
    owner_type: Option<String>,
) {
    let lines = extractor.source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return;
    }
    let start = span.start().line.max(1).min(lines.len());
    let end = span.end().line.max(start).min(lines.len());
    let source = lines[start - 1..end].join("\n");
    push_rust_definition(extractor, name.clone(), start, end, is_exported, owner_type);
    push_rust_method(
        extractor,
        name,
        source,
        start,
        end,
        param_count,
        is_exported,
    );
}

struct RustCallableVisitor<'extractor, 'source> {
    extractor: &'extractor mut RustExtractor<'source>,
    owner_types: Vec<Option<String>>,
    owner_is_contract: Vec<bool>,
}

impl RustCallableVisitor<'_, '_> {
    fn owner_type(&self) -> Option<String> {
        self.owner_types.last().cloned().flatten()
    }

    fn owner_is_contract(&self) -> bool {
        self.owner_is_contract.last().copied().unwrap_or(false)
    }
}

impl<'ast> Visit<'ast> for RustCallableVisitor<'_, '_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        record_ast_callable(
            self.extractor,
            node.sig.ident.to_string(),
            node.span(),
            node.sig.inputs.len(),
            rust_visibility_is_exported(&node.vis),
            self.owner_type(),
        );
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.owner_types.push(rust_type_name(&node.self_ty));
        self.owner_is_contract.push(node.trait_.is_some());
        syn::visit::visit_item_impl(self, node);
        self.owner_is_contract.pop();
        self.owner_types.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        record_ast_callable(
            self.extractor,
            node.sig.ident.to_string(),
            node.span(),
            node.sig.inputs.len(),
            rust_visibility_is_exported(&node.vis) || self.owner_is_contract(),
            self.owner_type(),
        );
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.owner_types.push(Some(node.ident.to_string()));
        self.owner_is_contract
            .push(rust_visibility_is_exported(&node.vis));
        syn::visit::visit_item_trait(self, node);
        self.owner_is_contract.pop();
        self.owner_types.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        record_ast_callable(
            self.extractor,
            node.sig.ident.to_string(),
            node.span(),
            node.sig.inputs.len(),
            self.owner_is_contract(),
            self.owner_type(),
        );
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        record_ast_callable(
            self.extractor,
            node.sig.ident.to_string(),
            node.span(),
            node.sig.inputs.len(),
            rust_visibility_is_exported(&node.vis),
            None,
        );
        syn::visit::visit_foreign_item_fn(self, node);
    }
}

pub(super) fn record_rust_ast_callables(extractor: &mut RustExtractor<'_>, file: &syn::File) {
    extractor.methods.clear();
    extractor
        .definitions
        .retain(|definition| matches!(&definition.kind, SymbolKind::Class));
    let mut visitor = RustCallableVisitor {
        extractor,
        owner_types: Vec::new(),
        owner_is_contract: Vec::new(),
    };
    visitor.visit_file(file);
}

fn collect_pattern_bindings(pattern: &syn::Pat, bindings: &mut HashSet<String>) {
    match pattern {
        syn::Pat::Ident(ident) => {
            bindings.insert(ident.ident.to_string());
            if let Some((_, subpattern)) = &ident.subpat {
                collect_pattern_bindings(subpattern, bindings);
            }
        }
        syn::Pat::Or(pattern) => {
            for case in &pattern.cases {
                collect_pattern_bindings(case, bindings);
            }
        }
        syn::Pat::Paren(pattern) => collect_pattern_bindings(&pattern.pat, bindings),
        syn::Pat::Reference(pattern) => collect_pattern_bindings(&pattern.pat, bindings),
        syn::Pat::Slice(pattern) => {
            for element in &pattern.elems {
                collect_pattern_bindings(element, bindings);
            }
        }
        syn::Pat::Struct(pattern) => {
            for field in &pattern.fields {
                collect_pattern_bindings(&field.pat, bindings);
            }
        }
        syn::Pat::Tuple(pattern) => {
            for element in &pattern.elems {
                collect_pattern_bindings(element, bindings);
            }
        }
        syn::Pat::TupleStruct(pattern) => {
            for element in &pattern.elems {
                collect_pattern_bindings(element, bindings);
            }
        }
        syn::Pat::Type(pattern) => collect_pattern_bindings(&pattern.pat, bindings),
        _ => {}
    }
}

fn signature_bindings(signature: &syn::Signature) -> HashSet<String> {
    let mut bindings = HashSet::new();
    for input in &signature.inputs {
        match input {
            syn::FnArg::Receiver(_) => {
                bindings.insert("self".to_string());
            }
            syn::FnArg::Typed(argument) => collect_pattern_bindings(&argument.pat, &mut bindings),
        }
    }
    bindings
}

struct RustCallableValueVisitor<'extractor, 'source> {
    extractor: &'extractor mut RustExtractor<'source>,
    scopes: Vec<HashSet<String>>,
}

impl RustCallableValueVisitor<'_, '_> {
    fn is_shadowed(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|scope| scope.contains(name))
    }

    fn push_scope(&mut self, bindings: HashSet<String>) {
        self.scopes.push(bindings);
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn record_path(&mut self, path: &syn::ExprPath) {
        if path.qself.is_some() || path.path.segments.is_empty() {
            return;
        }
        let parts = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if parts.len() == 1 && self.is_shadowed(&parts[0]) {
            return;
        }
        let name = parts.join("::");
        let line = path.span().start().line.max(1);
        if self
            .extractor
            .references
            .iter()
            .any(|reference| reference.line == line && reference.name == name)
        {
            return;
        }
        let snippet = self
            .extractor
            .source
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or_default()
            .trim()
            .to_string();
        self.extractor.references.push(SymbolReference {
            name,
            line,
            snippet,
            is_member_call: false,
            is_callable_value: true,
            resolved_symbol: None,
        });
    }

    fn visit_callable_block(&mut self, signature: &syn::Signature, block: &syn::Block) {
        self.push_scope(signature_bindings(signature));
        self.visit_block(block);
        self.pop_scope();
    }
}

impl<'ast> Visit<'ast> for RustCallableValueVisitor<'_, '_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.visit_callable_block(&node.sig, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.visit_callable_block(&node.sig, &node.block);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if let Some(default) = &node.default {
            self.visit_callable_block(&node.sig, default);
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.push_scope(HashSet::new());
        for statement in &block.stmts {
            self.visit_stmt(statement);
        }
        self.pop_scope();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(initializer) = &local.init {
            self.visit_expr(&initializer.expr);
            if let Some((_, diverge)) = &initializer.diverge {
                self.visit_expr(diverge);
            }
        }
        if let Some(scope) = self.scopes.last_mut() {
            collect_pattern_bindings(&local.pat, scope);
        }
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let mut bindings = HashSet::new();
        for input in &closure.inputs {
            collect_pattern_bindings(input, &mut bindings);
        }
        self.push_scope(bindings);
        self.visit_expr(&closure.body);
        self.pop_scope();
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_expr(&expression.expr);
        let mut bindings = HashSet::new();
        collect_pattern_bindings(&expression.pat, &mut bindings);
        self.push_scope(bindings);
        self.visit_block(&expression.body);
        self.pop_scope();
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let mut bindings = HashSet::new();
        collect_pattern_bindings(&arm.pat, &mut bindings);
        self.push_scope(bindings);
        if let Some((_, guard)) = &arm.guard {
            self.visit_expr(guard);
        }
        self.visit_expr(&arm.body);
        self.pop_scope();
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.visit_expr(&expression.cond);
        let mut bindings = HashSet::new();
        collect_condition_bindings(&expression.cond, &mut bindings);
        self.push_scope(bindings);
        self.visit_block(&expression.then_branch);
        self.pop_scope();
        if let Some((_, alternative)) = &expression.else_branch {
            self.visit_expr(alternative);
        }
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.visit_expr(&expression.cond);
        let mut bindings = HashSet::new();
        collect_condition_bindings(&expression.cond, &mut bindings);
        self.push_scope(bindings);
        self.visit_block(&expression.body);
        self.pop_scope();
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.record_path(path);
        syn::visit::visit_expr_path(self, path);
    }
}

fn collect_condition_bindings(expression: &syn::Expr, bindings: &mut HashSet<String>) {
    match expression {
        syn::Expr::Let(expression) => collect_pattern_bindings(&expression.pat, bindings),
        syn::Expr::Binary(expression) => {
            collect_condition_bindings(&expression.left, bindings);
            collect_condition_bindings(&expression.right, bindings);
        }
        syn::Expr::Group(expression) => collect_condition_bindings(&expression.expr, bindings),
        syn::Expr::Paren(expression) => collect_condition_bindings(&expression.expr, bindings),
        _ => {}
    }
}

pub(super) fn record_rust_ast_callable_values(extractor: &mut RustExtractor<'_>, file: &syn::File) {
    let mut visitor = RustCallableValueVisitor {
        extractor,
        scopes: vec![HashSet::new()],
    };
    visitor.visit_file(file);
}

struct RustTokenReferenceVisitor<'extractor, 'source> {
    extractor: &'extractor mut RustExtractor<'source>,
}

impl RustTokenReferenceVisitor<'_, '_> {
    fn record_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let line = ident.span().start().line.max(1);
                    if self
                        .extractor
                        .references
                        .iter()
                        .any(|reference| reference.line == line && reference.name == name)
                    {
                        continue;
                    }
                    let snippet = self
                        .extractor
                        .source
                        .lines()
                        .nth(line.saturating_sub(1))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    self.extractor.references.push(SymbolReference {
                        name,
                        line,
                        snippet,
                        is_member_call: false,
                        is_callable_value: true,
                        resolved_symbol: None,
                    });
                }
                proc_macro2::TokenTree::Group(group) => self.record_tokens(group.stream()),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for RustTokenReferenceVisitor<'_, '_> {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        match &attribute.meta {
            syn::Meta::List(list) => self.record_tokens(list.tokens.clone()),
            syn::Meta::NameValue(name_value) => {
                syn::visit::visit_expr(self, &name_value.value);
            }
            syn::Meta::Path(_) => {}
        }
    }

    fn visit_macro(&mut self, rust_macro: &'ast syn::Macro) {
        self.record_tokens(rust_macro.tokens.clone());
    }
}

pub(super) fn record_rust_ast_token_references(
    extractor: &mut RustExtractor<'_>,
    file: &syn::File,
) {
    RustTokenReferenceVisitor { extractor }.visit_file(file);
}
