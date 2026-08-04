use super::*;
use crate::types::Reference;
use oxc_ast::Visit;
use oxc_ast::ast::*;
use oxc_ast::visit::walk;
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;

pub(super) struct OxcExtractor<'a> {
    pub source: &'a str,
    pub line_index: LineIndex,
    pub file_path: String,
    pub methods: Vec<MethodRecord>,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub references: Vec<SymbolReference>,
    pub next_id: usize,
    pub current_name_hint: Option<String>,
    pub current_class: Option<String>,
    pub current_class_exported: bool,
    pub current_object: Option<String>,
    pub current_object_exported: bool,
    pub is_exported_context: bool,
    pub callable_depth: usize,
}

impl<'a> OxcExtractor<'a> {
    pub(super) fn visit_program(&mut self, program: &Program<'a>) {
        Visit::visit_program(self, program);
        self.apply_local_exports();
    }

    fn apply_local_exports(&mut self) {
        let local_exports = self
            .exports
            .iter()
            .filter(|export| export.source_module.is_none())
            .map(|export| export.local_symbol_name.clone())
            .collect::<std::collections::HashSet<_>>();
        for definition in &mut self.definitions {
            if local_exports.contains(&definition.name) {
                definition.is_exported = true;
            }
        }
        for method in &mut self.methods {
            if local_exports.contains(&method.name) {
                method.is_exported = true;
            }
        }
    }

    fn line_for_offset(&self, offset: u32) -> usize {
        self.line_index
            .line_starts
            .partition_point(|start| *start <= offset as usize)
            .max(1)
    }

    fn line_snippet(&self, line: usize) -> String {
        let start = self.line_index.line_starts[line.saturating_sub(1)];
        let end = self
            .line_index
            .line_starts
            .get(line)
            .copied()
            .unwrap_or(self.source.len());
        self.source[start..end].trim().to_string()
    }

    fn push_reference(&mut self, name: String, span: Span) {
        self.push_reference_with_kind(name, span, false);
    }

    fn push_reference_with_kind(&mut self, name: String, span: Span, is_member_call: bool) {
        let line = self.line_for_offset(span.start);
        let snippet = self.line_snippet(line);
        if self
            .references
            .iter()
            .any(|reference| reference.name == name && reference.line == line)
        {
            return;
        }
        self.references.push(SymbolReference {
            name,
            line,
            snippet,
            is_member_call,
            is_callable_value: false,
            resolved_symbol: None,
        });
    }

    fn push_method(
        &mut self,
        name: String,
        span: Span,
        param_count: usize,
        is_exported: bool,
        kind: SymbolKind,
        owner_type: Option<String>,
    ) {
        let start_line = self.line_for_offset(span.start);
        let end_offset = span.end.saturating_sub(1).max(span.start);
        let end_line = self.line_for_offset(end_offset);
        if self.methods.iter().any(|method| {
            method.name == name && method.start_line == start_line && method.end_line == end_line
        }) {
            return;
        }

        let start = span.start as usize;
        let end = span.end as usize;
        let method_source = self.source.get(start..end).unwrap_or_default().to_string();
        self.definitions.push(SymbolDefinition {
            id: self.next_id,
            name: name.clone(),
            kind,
            start_line,
            end_line,
            is_exported,
            owner_type,
            receiver_type: None,
            value_type: None,
        });
        self.next_id += 1;
        self.methods.push(MethodRecord {
            name,
            file_path: self.file_path.clone(),
            source: method_source,
            loc: end_line.saturating_sub(start_line) + 1,
            param_count,
            start_line,
            end_line,
            is_exported,
            language: "javascript".to_string(),
            nesting_depth: 0,
            references: Vec::<Reference>::new(),
            real_ref_count: 0,
        });
    }

    fn record_export(&mut self, exported_name: String, local_symbol_name: String) {
        if self.exports.iter().any(|export| {
            export.exported_name == exported_name
                && export.local_symbol_name == local_symbol_name
                && export.source_module.is_none()
        }) {
            return;
        }
        self.exports.push(ExportRecord {
            exported_name,
            local_symbol_name,
            source_module: None,
            source_symbol_name: None,
        });
    }

    fn static_member_name(expr: &StaticMemberExpression<'a>) -> Option<String> {
        let qualifier = match &expr.object {
            Expression::Identifier(identifier) => identifier.name.to_string(),
            Expression::StaticMemberExpression(parent) => Self::static_member_name(parent)?,
            _ => return None,
        };
        Some(format!("{}.{}", qualifier, expr.property.name))
    }

    fn anonymous_name(&self, span: Span) -> String {
        format!("<anonymous@{}>", self.line_for_offset(span.start))
    }

    fn is_direct_callable_expression(expression: &Expression<'a>) -> bool {
        matches!(
            expression,
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        )
    }

    fn import_expression<'b>(expression: &'b Expression<'a>) -> Option<&'b ImportExpression<'a>> {
        match expression {
            Expression::ImportExpression(import) => Some(import),
            Expression::AwaitExpression(await_expression) => {
                Self::import_expression(&await_expression.argument)
            }
            Expression::ParenthesizedExpression(parenthesized) => {
                Self::import_expression(&parenthesized.expression)
            }
            _ => None,
        }
    }

    fn dynamic_import_source(expression: &Expression<'a>) -> Option<String> {
        let import = Self::import_expression(expression)?;
        match &import.source {
            Expression::StringLiteral(source) => Some(source.value.to_string()),
            _ => None,
        }
    }

    fn record_dynamic_import(&mut self, declarator: &VariableDeclarator<'a>) {
        let Some(source_module) = declarator
            .init
            .as_ref()
            .and_then(Self::dynamic_import_source)
        else {
            return;
        };
        match &declarator.id.kind {
            BindingPatternKind::BindingIdentifier(identifier) => self.imports.push(ImportRecord {
                local_name: identifier.name.to_string(),
                source_module,
                imported_name: "*".to_string(),
            }),
            BindingPatternKind::ObjectPattern(pattern) => {
                for property in &pattern.properties {
                    let Some(imported_name) = property.key.static_name() else {
                        continue;
                    };
                    let Some(local_name) = property.value.get_identifier() else {
                        continue;
                    };
                    self.imports.push(ImportRecord {
                        local_name: local_name.to_string(),
                        source_module: source_module.clone(),
                        imported_name: imported_name.to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    fn push_object_binding(&mut self, name: &str, span: Span, is_exported: bool) {
        let start_line = self.line_for_offset(span.start);
        let end_line = self.line_for_offset(span.end.saturating_sub(1).max(span.start));
        if self.definitions.iter().any(|definition| {
            definition.name == name
                && definition.start_line == start_line
                && matches!(definition.kind, SymbolKind::Variable)
        }) {
            return;
        }
        self.definitions.push(SymbolDefinition {
            id: self.next_id,
            name: name.to_string(),
            kind: SymbolKind::Variable,
            start_line,
            end_line,
            is_exported,
            owner_type: None,
            receiver_type: None,
            value_type: None,
        });
        self.next_id += 1;
        if is_exported {
            self.record_export(name.to_string(), name.to_string());
        }
    }

    fn jsx_member_name(expression: &JSXMemberExpression<'a>) -> String {
        let object = match &expression.object {
            JSXMemberExpressionObject::Identifier(identifier) => identifier.name.to_string(),
            JSXMemberExpressionObject::MemberExpression(parent) => Self::jsx_member_name(parent),
        };
        format!("{object}.{}", expression.property.name)
    }
}

impl<'a> Visit<'a> for OxcExtractor<'a> {
    fn visit_function(&mut self, function: &Function<'a>, flags: Option<ScopeFlags>) {
        let is_nested = self.callable_depth > 0;
        let name = function
            .id
            .as_ref()
            .map(|identifier| identifier.name.to_string())
            .or_else(|| self.current_name_hint.clone())
            .unwrap_or_else(|| self.anonymous_name(function.span));
        let previous_hint = self.current_name_hint.take();

        let object_owner = self.current_object.clone();
        let is_exported = object_owner.is_none()
            && !is_nested
            && (self.is_exported_context
                || function.modifiers.contains(ModifierKind::Export)
                || self.current_class_exported);
        let exported_name = if function.modifiers.contains(ModifierKind::Default) {
            "default".to_string()
        } else {
            name.clone()
        };
        self.push_method(
            name.clone(),
            function.span,
            function.params.parameters_count(),
            is_exported,
            if object_owner.is_some() {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            },
            object_owner.or_else(|| (!is_nested).then(|| self.current_class.clone()).flatten()),
        );
        if is_exported && self.current_class.is_none() && self.current_object.is_none() {
            self.record_export(exported_name, name);
        }

        let previous_exported = self.is_exported_context;
        let previous_object = self.current_object.take();
        let previous_object_exported = self.current_object_exported;
        self.is_exported_context = false;
        self.current_object_exported = false;
        self.callable_depth += 1;
        walk::walk_function(self, function, flags);
        self.callable_depth -= 1;
        self.is_exported_context = previous_exported;
        self.current_object = previous_object;
        self.current_object_exported = previous_object_exported;
        self.current_name_hint = previous_hint;
    }

    fn visit_arrow_expression(&mut self, expression: &ArrowFunctionExpression<'a>) {
        let is_nested = self.callable_depth > 0;
        let name = self
            .current_name_hint
            .clone()
            .unwrap_or_else(|| self.anonymous_name(expression.span));
        let previous_hint = self.current_name_hint.take();
        let object_owner = self.current_object.clone();
        self.push_method(
            name.clone(),
            expression.span,
            expression.params.parameters_count(),
            object_owner.is_none() && !is_nested && self.is_exported_context,
            if object_owner.is_some() {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            },
            object_owner.or_else(|| (!is_nested).then(|| self.current_class.clone()).flatten()),
        );
        if !is_nested
            && self.is_exported_context
            && self.current_class.is_none()
            && self.current_object.is_none()
        {
            self.record_export(name.clone(), name);
        }
        let previous_exported = self.is_exported_context;
        let previous_object = self.current_object.take();
        let previous_object_exported = self.current_object_exported;
        self.is_exported_context = false;
        self.current_object_exported = false;
        self.callable_depth += 1;
        walk::walk_arrow_expression(self, expression);
        self.callable_depth -= 1;
        self.is_exported_context = previous_exported;
        self.current_object = previous_object;
        self.current_object_exported = previous_object_exported;
        self.current_name_hint = previous_hint;
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        let previous_hint = self.current_name_hint.clone();
        let previous_object = self.current_object.clone();
        let previous_object_exported = self.current_object_exported;
        self.current_name_hint = None;
        self.current_object = None;
        self.current_object_exported = false;
        self.record_dynamic_import(declarator);
        if let Some(name) = declarator.id.get_identifier() {
            if declarator
                .init
                .as_ref()
                .is_some_and(Self::is_direct_callable_expression)
            {
                self.current_name_hint = Some(name.to_string());
            } else if declarator
                .init
                .as_ref()
                .is_some_and(|expression| matches!(expression, Expression::ObjectExpression(_)))
            {
                let name = name.to_string();
                self.push_object_binding(&name, declarator.span, self.is_exported_context);
                self.current_object = Some(name);
                self.current_object_exported = self.is_exported_context;
            }
        }
        walk::walk_variable_declarator(self, declarator);
        self.current_name_hint = previous_hint;
        self.current_object = previous_object;
        self.current_object_exported = previous_object_exported;
    }

    fn visit_object_expression(&mut self, expression: &ObjectExpression<'a>) {
        let previous_object = self.current_object.clone();
        let previous_object_exported = self.current_object_exported;
        if self.current_object.is_none() {
            self.current_object = Some(format!(
                "<object@{}>",
                self.line_for_offset(expression.span.start)
            ));
            self.current_object_exported = false;
        }
        walk::walk_object_expression(self, expression);
        self.current_object = previous_object;
        self.current_object_exported = previous_object_exported;
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        let previous_hint = self.current_name_hint.clone();
        self.current_name_hint = None;
        if Self::is_direct_callable_expression(&property.value)
            && let Some(name) = property.key.static_name()
        {
            self.current_name_hint = Some(name.to_string());
        }
        walk::walk_object_property(self, property);
        self.current_name_hint = previous_hint;
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        let previous_class = self.current_class.clone();
        let previous_exported = self.current_class_exported;
        self.current_class = class.id.as_ref().map(|id| id.name.to_string());
        self.current_class_exported = self.is_exported_context
            || class.modifiers.contains(ModifierKind::Export)
            || class.modifiers.contains(ModifierKind::Default);
        if let Some(name) = self.current_class.clone() {
            let start_line = self.line_for_offset(class.span.start);
            let end_line = self.line_for_offset(class.span.end.saturating_sub(1));
            self.definitions.push(SymbolDefinition {
                id: self.next_id,
                name: name.clone(),
                kind: SymbolKind::Class,
                start_line,
                end_line,
                is_exported: self.current_class_exported,
                owner_type: None,
                receiver_type: None,
                value_type: None,
            });
            self.next_id += 1;
            if self.current_class_exported {
                self.record_export(name.clone(), name);
            }
        }
        walk::walk_class(self, class);
        self.current_class = previous_class;
        self.current_class_exported = previous_exported;
    }

    fn visit_method_definition(&mut self, definition: &MethodDefinition<'a>) {
        let Some(name) = definition.key.static_name().map(|name| name.to_string()) else {
            walk::walk_method_definition(self, definition);
            return;
        };
        self.push_method(
            name,
            definition.span,
            definition.value.params.parameters_count(),
            self.current_class_exported,
            SymbolKind::Method,
            self.current_class.clone(),
        );
        let flags = definition.kind.scope_flags();
        let previous_exported = self.is_exported_context;
        self.is_exported_context = false;
        self.callable_depth += 1;
        walk::walk_function(self, &definition.value, Some(flags));
        self.callable_depth -= 1;
        self.is_exported_context = previous_exported;
    }

    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.push_reference(identifier.name.to_string(), identifier.span);
    }

    fn visit_static_member_expression(&mut self, expression: &StaticMemberExpression<'a>) {
        if matches!(&expression.object, Expression::ThisExpression(_)) {
            self.push_reference_with_kind(
                expression.property.name.to_string(),
                expression.span,
                true,
            );
        } else if let Some(name) = Self::static_member_name(expression) {
            self.push_reference_with_kind(name, expression.span, true);
        }
        walk::walk_static_member_expression(self, expression);
    }

    fn visit_jsx_opening_element(&mut self, element: &JSXOpeningElement<'a>) {
        let name = match &element.name {
            JSXElementName::Identifier(identifier)
                if identifier
                    .name
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase) =>
            {
                Some(identifier.name.to_string())
            }
            JSXElementName::MemberExpression(expression) => Some(Self::jsx_member_name(expression)),
            _ => None,
        };
        if let Some(name) = name {
            self.push_reference(name, element.span);
        }
        walk::walk_jsx_opening_element(self, element);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        let source_module = declaration.source.value.to_string();
        if let Some(specifiers) = &declaration.specifiers {
            for specifier in specifiers {
                let (local_name, imported_name) = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
                        specifier.local.name.to_string(),
                        specifier.imported.name().to_string(),
                    ),
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                        (specifier.local.name.to_string(), "default".to_string())
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                        (specifier.local.name.to_string(), "*".to_string())
                    }
                };
                self.imports.push(ImportRecord {
                    local_name,
                    source_module: source_module.clone(),
                    imported_name,
                });
            }
        }
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'a>) {
        let exported_name = declaration
            .exported
            .as_ref()
            .map(|name| name.name().to_string())
            .unwrap_or_else(|| "*".to_string());
        self.exports.push(ExportRecord {
            exported_name: exported_name.clone(),
            local_symbol_name: exported_name,
            source_module: Some(declaration.source.value.to_string()),
            source_symbol_name: Some("*".to_string()),
        });
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'a>) {
        let source_module = declaration
            .source
            .as_ref()
            .map(|source| source.value.to_string());
        for specifier in &declaration.specifiers {
            self.exports.push(ExportRecord {
                exported_name: specifier.exported.name().to_string(),
                local_symbol_name: specifier.local.name().to_string(),
                source_module: source_module.clone(),
                source_symbol_name: source_module
                    .as_ref()
                    .map(|_| specifier.local.name().to_string()),
            });
        }

        let previous_exported = self.is_exported_context;
        self.is_exported_context = true;
        walk::walk_export_named_declaration(self, declaration);
        self.is_exported_context = previous_exported;
    }

    fn visit_export_default_declaration(&mut self, declaration: &ExportDefaultDeclaration<'a>) {
        let previous_exported = self.is_exported_context;
        let previous_hint = self.current_name_hint.clone();
        self.is_exported_context = true;
        self.current_name_hint = Some("default".to_string());
        walk::walk_export_default_declaration(self, declaration);
        match &declaration.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                let local_name = function
                    .id
                    .as_ref()
                    .map(|identifier| identifier.name.to_string())
                    .unwrap_or_else(|| "default".to_string());
                self.record_export("default".to_string(), local_name);
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                let local_name = class
                    .id
                    .as_ref()
                    .map(|identifier| identifier.name.to_string())
                    .unwrap_or_else(|| "default".to_string());
                self.record_export("default".to_string(), local_name);
            }
            _ => {}
        }
        self.current_name_hint = previous_hint;
        self.is_exported_context = previous_exported;
    }
}
