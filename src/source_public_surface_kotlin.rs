use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace,
    SourcePublicSurface, SourcePublicSymbolKind,
};
use tree_sitter::{Node, Parser};

pub(super) fn census(file_path: &str, source: &[u8]) -> Result<SourcePublicSurface, String> {
    std::str::from_utf8(source)
        .map_err(|_| format!("Kotlin public-surface source is not UTF-8: {file_path}"))?;
    let mut parser = Parser::new();
    let language = unsafe {
        tree_sitter::Language::from_raw((tree_sitter_kotlin::LANGUAGE.into_raw())() as *const _)
    };
    parser
        .set_language(&language)
        .map_err(|error| format!("failed to initialize Kotlin public-surface parser: {error}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("failed to parse Kotlin public surface {file_path}"))?;
    if tree.root_node().has_error() {
        return Err(format!(
            "Kotlin public surface contains a syntax error: {file_path}"
        ));
    }
    let mut collector = Collector {
        file_path,
        source,
        declarations: Vec::new(),
    };
    collector.collect_declaration_children(tree.root_node(), None, true, false)?;
    Ok(SourcePublicSurface {
        declarations: collector.declarations,
        reexports: Vec::new(),
    })
}

struct Collector<'a> {
    file_path: &'a str,
    source: &'a [u8],
    declarations: Vec<SourcePublicDeclaration>,
}

#[derive(Clone)]
struct Owner {
    surface_name: String,
    compiler_anchor: SourceByteRange,
}

impl Collector<'_> {
    fn collect_declaration_children(
        &mut self,
        scope: Node<'_>,
        owner: Option<&Owner>,
        parent_external: bool,
        static_members: bool,
    ) -> Result<(), String> {
        let mut cursor = scope.walk();
        for child in scope.children(&mut cursor).filter(|child| child.is_named()) {
            self.collect_declaration(child, owner, parent_external, static_members)?;
        }
        Ok(())
    }

    fn collect_declaration(
        &mut self,
        node: Node<'_>,
        owner: Option<&Owner>,
        parent_external: bool,
        static_members: bool,
    ) -> Result<(), String> {
        match node.kind() {
            "class_declaration" | "object_declaration" => {
                let external = parent_external && self.is_external(node);
                let name = self.required_name(node)?;
                let anchor = range(name);
                if external {
                    self.push_definition(
                        name,
                        owner,
                        if owner.is_some() {
                            SourcePublicNamespace::StaticMember
                        } else {
                            SourcePublicNamespace::Module
                        },
                        SourcePublicSymbolKind::Type,
                    )?;
                    self.collect_primary_constructor_properties(
                        node,
                        &Owner {
                            surface_name: self.owned_name(owner, name)?,
                            compiler_anchor: anchor,
                        },
                    )?;
                }
                if let Some(body) = named_child(node, &["class_body", "enum_class_body"]) {
                    let nested_owner = Owner {
                        surface_name: self.owned_name(owner, name)?,
                        compiler_anchor: anchor,
                    };
                    self.collect_declaration_children(body, Some(&nested_owner), external, false)?;
                }
            }
            "function_declaration" if parent_external && self.is_external(node) => {
                let name = self.required_name(node)?;
                self.push_definition(
                    name,
                    owner,
                    self.member_namespace(owner, static_members),
                    if owner.is_some() || self.has_receiver(node, name)? {
                        SourcePublicSymbolKind::Method
                    } else {
                        SourcePublicSymbolKind::Callable
                    },
                )?;
            }
            "property_declaration" if parent_external && self.is_external(node) => {
                if named_child(node, &["multi_variable_declaration"]).is_some() {
                    return Err(format!(
                        "public Kotlin destructuring requires compiler-defined surface expansion in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    ));
                }
                let variable = named_child(node, &["variable_declaration"]).ok_or_else(|| {
                    format!(
                        "public Kotlin property has no exact declaration in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    )
                })?;
                let name = first_identifier(variable).ok_or_else(|| {
                    format!(
                        "public Kotlin property has no exact identifier in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    )
                })?;
                self.push_definition(
                    name,
                    owner,
                    self.member_namespace(owner, static_members),
                    if self.has_modifier(node, "const") {
                        SourcePublicSymbolKind::Constant
                    } else if owner.is_some() {
                        SourcePublicSymbolKind::Field
                    } else if self.has_receiver(node, name)? {
                        SourcePublicSymbolKind::CompilerDefined
                    } else {
                        SourcePublicSymbolKind::Variable
                    },
                )?;
            }
            "type_alias" if parent_external && self.is_external(node) => {
                let name = node.child_by_field_name("type").ok_or_else(|| {
                    format!(
                        "public Kotlin type alias has no exact identifier in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    )
                })?;
                self.push_definition(
                    name,
                    owner,
                    self.member_namespace(owner, static_members),
                    SourcePublicSymbolKind::Type,
                )?;
            }
            "companion_object" if parent_external && self.is_external(node) => {
                let Some(owner) = owner else {
                    return Err(format!(
                        "top-level Kotlin companion object is invalid in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    ));
                };
                if let Some(body) = named_child(node, &["class_body"]) {
                    self.collect_declaration_children(body, Some(owner), true, true)?;
                }
            }
            "enum_entry" if parent_external => {
                let name = first_identifier(node).ok_or_else(|| {
                    format!(
                        "public Kotlin enum entry has no exact identifier in {} at byte {}",
                        self.file_path,
                        node.start_byte()
                    )
                })?;
                self.push_definition(
                    name,
                    owner,
                    SourcePublicNamespace::StaticMember,
                    SourcePublicSymbolKind::Constant,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn collect_primary_constructor_properties(
        &mut self,
        declaration: Node<'_>,
        owner: &Owner,
    ) -> Result<(), String> {
        let Some(constructor) = named_child(declaration, &["primary_constructor"]) else {
            return Ok(());
        };
        let Some(parameters) = named_child(constructor, &["class_parameters"]) else {
            return Ok(());
        };
        let mut cursor = parameters.walk();
        for parameter in parameters
            .children(&mut cursor)
            .filter(|child| child.kind() == "class_parameter")
        {
            let prefix = self.text(parameter)?;
            let declares_property = prefix
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|token| matches!(token, "val" | "var"));
            if !declares_property || !self.is_external(parameter) {
                continue;
            }
            let name = first_identifier(parameter).ok_or_else(|| {
                format!(
                    "public Kotlin constructor property has no exact identifier in {} at byte {}",
                    self.file_path,
                    parameter.start_byte()
                )
            })?;
            self.push_definition(
                name,
                Some(owner),
                SourcePublicNamespace::InstanceMember,
                SourcePublicSymbolKind::Field,
            )?;
        }
        Ok(())
    }

    fn push_definition(
        &mut self,
        identifier: Node<'_>,
        owner: Option<&Owner>,
        namespace: SourcePublicNamespace,
        kind: SourcePublicSymbolKind,
    ) -> Result<(), String> {
        let name = self.text(identifier)?.to_string();
        if name.is_empty() {
            return Err(format!(
                "public Kotlin declaration has an empty name in {}",
                self.file_path
            ));
        }
        self.declarations.push(SourcePublicDeclaration {
            target_name: name.clone(),
            name,
            owner: owner.map(|owner| owner.surface_name.clone()),
            namespace,
            kind,
            exposed_identifier: range(identifier),
            compiler_anchor: range(identifier),
            owner_compiler_anchor: owner.map(|owner| owner.compiler_anchor),
            binding: SourcePublicBindingKind::Definition,
            source_module: None,
        });
        Ok(())
    }

    fn required_name<'tree>(&self, node: Node<'tree>) -> Result<Node<'tree>, String> {
        node.child_by_field_name("name").ok_or_else(|| {
            format!(
                "public Kotlin declaration has no exact identifier in {} at byte {}",
                self.file_path,
                node.start_byte()
            )
        })
    }

    fn owned_name(&self, owner: Option<&Owner>, name: Node<'_>) -> Result<String, String> {
        let name = self.text(name)?;
        Ok(owner.map_or_else(
            || name.to_string(),
            |owner| format!("{}::{name}", owner.surface_name),
        ))
    }

    fn member_namespace(
        &self,
        owner: Option<&Owner>,
        static_members: bool,
    ) -> SourcePublicNamespace {
        match (owner, static_members) {
            (None, _) => SourcePublicNamespace::Module,
            (Some(_), true) => SourcePublicNamespace::StaticMember,
            (Some(_), false) => SourcePublicNamespace::InstanceMember,
        }
    }

    fn is_external(&self, node: Node<'_>) -> bool {
        let Some(modifiers) = named_child(node, &["modifiers"]) else {
            return true;
        };
        !descendants(modifiers).any(|modifier| {
            modifier.kind() == "visibility_modifier"
                && self
                    .text(modifier)
                    .is_ok_and(|value| matches!(value, "private" | "internal"))
        })
    }

    fn has_modifier(&self, node: Node<'_>, expected: &str) -> bool {
        named_child(node, &["modifiers"]).is_some_and(|modifiers| {
            descendants(modifiers).any(|modifier| {
                self.text(modifier)
                    .is_ok_and(|value| value.trim() == expected)
            })
        })
    }

    fn has_receiver(&self, declaration: Node<'_>, name: Node<'_>) -> Result<bool, String> {
        let prefix = self
            .source
            .get(declaration.start_byte()..name.start_byte())
            .ok_or_else(|| format!("Kotlin declaration range changed in {}", self.file_path))?;
        Ok(prefix.iter().rev().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'.'))
    }

    fn text<'a>(&'a self, node: Node<'_>) -> Result<&'a str, String> {
        node.utf8_text(self.source).map_err(|error| {
            format!(
                "Kotlin public-surface identifier is not UTF-8 in {}: {error}",
                self.file_path
            )
        })
    }
}

fn named_child<'tree>(node: Node<'tree>, kinds: &[&str]) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| kinds.contains(&child.kind()))
}

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(node.kind(), "identifier" | "simple_identifier") {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.children(&mut cursor).find_map(first_identifier)
}

fn descendants(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut nodes = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        nodes.push(current);
        let mut cursor = current.walk();
        pending.extend(
            current
                .children(&mut cursor)
                .filter(|child| child.is_named()),
        );
    }
    nodes.into_iter()
}

fn range(node: Node<'_>) -> SourceByteRange {
    SourceByteRange {
        start: node.start_byte(),
        end: node.end_byte(),
    }
}
