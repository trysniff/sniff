use super::*;

#[test]
fn duplicated_branch_detector_finds_python_and_brace_constructs() {
    let python = method(
        "def sample(value):\n    if value:\n        return value\n    else:\n        return value\n",
    );
    let mut rust = method(
        "pub fn sample(value: bool) -> bool {\n    if value {\n        value\n    } else {\n        value\n    }\n}\n",
    );
    rust.language = "rust".to_string();

    assert_eq!(
        duplicated_branch_construct(&python).as_deref(),
        Some("    if value:\n        return value\n    else:\n        return value")
    );
    assert_eq!(
        duplicated_branch_construct(&rust).as_deref(),
        Some("    if value {\n        value\n    } else {\n        value\n    }")
    );
}

#[test]
fn duplicated_branch_detector_finds_python_guard_and_identical_tail() {
    let python = method(
        "def sample(enabled, value):\n    if enabled:\n        return value.strip()\n    return value.strip()\n",
    );

    assert_eq!(
        duplicated_branch_construct(&python).as_deref(),
        Some("    if enabled:\n        return value.strip()\n    return value.strip()")
    );
}

#[test]
fn duplicated_branch_detector_finds_kotlin_inline_expression() {
    let mut kotlin = method(
        "fun sample(value: String?): String? {\n    return if (value != null) value else value\n}\n",
    );
    kotlin.language = "kotlin".to_string();

    assert_eq!(
        duplicated_branch_construct(&kotlin).as_deref(),
        Some("return if (value != null) value else value")
    );
}

#[test]
fn duplicated_branch_detector_rejects_distinct_branches() {
    let method = method(
        "def sample(value):\n    if value:\n        return value\n    else:\n        return None\n",
    );

    assert!(duplicated_branch_construct(&method).is_none());
}

#[test]
fn duplicated_branch_detector_rejects_non_exhaustive_else_if_chain() {
    let mut kotlin = method(
        "fun dismiss(tracked: Long, alarm: Long) {\n    if (tracked == alarm) {\n        clear()\n    } else if (tracked == 0L) {\n        clear()\n    }\n}\n",
    );
    kotlin.language = "kotlin".to_string();

    assert!(duplicated_branch_construct(&kotlin).is_none());
    assert!(rejected_non_exhaustive_duplicate_branch(&kotlin).is_some());
}

#[test]
fn usage_windows_include_multiline_call_arguments() {
    let file = FileRecord {
            file_path: "tests/test_api.py".to_string(),
            source: "def test_call():\n    resolve_preview_rationale_lines(\n        release_label=\"MINOR\",\n        model=\"ignored\",\n        models_token=\"ignored\",\n    )\n"
                .to_string(),
            language: "python".to_string(),
            methods: Vec::new(),
        };

    let window = source_window(&file, 1);
    assert!(window.contains("resolve_preview_rationale_lines("));
    assert!(window.contains("model=\"ignored\""));
    assert!(window.contains("models_token=\"ignored\""));
}

#[test]
fn identifier_search_rejects_substrings_and_case_mismatches() {
    assert!(contains_identifier("return build(value)", "build"));
    assert!(contains_identifier("return service.build (value)", "build"));
    assert!(!contains_identifier("return builder(value)", "build"));
    assert!(!contains_identifier("return rebuild(value)", "build"));
    assert!(!contains_identifier("return Build(value)", "build"));
    assert!(is_lexical_call_site(
        "return service.build (value)",
        "build"
    ));
    assert!(!is_lexical_call_site("return builder(value)", "build"));
}

#[test]
fn string_contract_evidence_requires_an_exact_quoted_identifier() {
    assert!(explicit_string_contract_reference(
        "registry.register(\"build\", handler)",
        "build"
    ));
    assert!(explicit_string_contract_reference(
        "getattr(service, 'build')",
        "build"
    ));
    assert!(!explicit_string_contract_reference(
        "\"The callback method remains compatible.\"",
        "method"
    ));
    assert!(!explicit_string_contract_reference(
        "registry.register(\"builder\", handler)",
        "build"
    ));
}

#[test]
fn js_dependency_receiver_does_not_target_unrelated_top_level_function() {
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: "worker.ts".to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![crate::types::SymbolReference {
            name: "deps.normalizeDomainToken".to_string(),
            line: 12,
            snippet: "deps.normalizeDomainToken(value)".to_string(),
            is_member_call: true,
            is_callable_value: false,
            resolved_symbol: None,
        }],
    });

    let mut target = method("function normalizeDomainToken() {}");
    target.name = "normalizeDomainToken".to_string();
    target.file_path = "dashboard/app.js".to_string();
    target.language = "javascript".to_string();
    assert!(!js_ts_unresolved_reference_may_target(
        &graph,
        &LexicalReferenceQuery {
            line: "deps.normalizeDomainToken(value)",
            method: &target,
            target_owner: None,
            candidate_owner: None,
            allow_unknown_js_ts_member: false,
            candidate_file: "worker.ts",
            candidate_line: 12,
        },
    ));
}

#[test]
fn dynamic_object_contract_keeps_unknown_receiver_as_unconfirmed_evidence() {
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: "consumer.tsx".to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![crate::types::SymbolReference {
            name: "state.updatePrivacyConfig".to_string(),
            line: 8,
            snippet: "useStore((state) => state.updatePrivacyConfig)".to_string(),
            is_member_call: false,
            is_callable_value: false,
            resolved_symbol: None,
        }],
    });

    let mut target = method("updatePrivacyConfig: () => true");
    target.name = "updatePrivacyConfig".to_string();
    target.file_path = "store.ts".to_string();
    target.language = "typescript".to_string();
    assert!(js_ts_unresolved_reference_may_target(
        &graph,
        &LexicalReferenceQuery {
            line: "useStore((state) => state.updatePrivacyConfig)",
            method: &target,
            target_owner: Some("<object@10>"),
            candidate_owner: None,
            allow_unknown_js_ts_member: true,
            candidate_file: "consumer.tsx",
            candidate_line: 8,
        },
    ));
}

#[test]
fn target_name_does_not_invent_callback_or_compatibility_context() {
    let context = context_without_target_identifier(
        "return _legacy_callback(value, event, context)",
        "_legacy_callback",
    );

    assert!(!contains_any(&context, &["legacy", "callback"]));
    assert!(context.contains("event"));
}

#[test]
fn method_symbol_facts_exclude_unrelated_file_inventory() {
    let target = MethodRecord {
        name: "target".to_string(),
        file_path: "src/module.ts".to_string(),
        source: "function target() {}".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 10,
        end_line: 10,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let symbols = crate::types::LocalFileSymbols {
        file_path: target.file_path.clone(),
        definitions: vec![
            SymbolDefinition {
                id: 1,
                name: "target".to_string(),
                kind: crate::types::SymbolKind::Function,
                start_line: 10,
                end_line: 10,
                is_exported: true,
                owner_type: None,
                receiver_type: None,
                value_type: None,
            },
            SymbolDefinition {
                id: 2,
                name: "unrelated".to_string(),
                kind: crate::types::SymbolKind::Function,
                start_line: 20,
                end_line: 40,
                is_exported: true,
                owner_type: None,
                receiver_type: None,
                value_type: None,
            },
        ],
        imports: vec![crate::types::ImportRecord {
            local_name: "unrelated".to_string(),
            source_module: "./other".to_string(),
            imported_name: "unrelated".to_string(),
        }],
        exports: vec![crate::types::ExportRecord {
            exported_name: "target".to_string(),
            local_symbol_name: "target".to_string(),
            source_module: None,
            source_symbol_name: None,
        }],
        modules: vec![],
        types: vec![],
        references: vec![],
    };

    let rendered = render_symbol_facts(&symbols, &target);

    assert!(rendered.contains("target Function lines 10-10"));
    assert!(!rendered.contains("unrelated"));
}

#[test]
fn explicit_python_discard_blocks_trigger_contract_investigation() {
    let method = method("def public_api(model=None):\n    _ = (model,)\n    return 1\n");
    assert_eq!(
        python_parameter_discard_block(&method).as_deref(),
        Some("    _ = (model,)")
    );
}

#[test]
fn typed_stale_discard_proof_requires_closed_pure_caller_updates() {
    let source = "def _legacy_callback(value, event, context):\n    _ = (event, context)\n    return value.strip()\n";
    let mut target = method(source);
    target.name = "_legacy_callback".to_string();
    target.is_exported = false;
    target.param_count = 3;
    target.references = vec![Reference {
        file_path: "src/api.py".to_string(),
        line: 6,
        snippet: "return _legacy_callback(value, object(), object())".to_string(),
    }];
    target.real_ref_count = 1;

    let proof = python_stale_discard_signature_proof(&target)
        .expect("closed private pure caller update should establish typed proof");
    assert_eq!(proof.discarded_parameters, vec!["context", "event"]);

    target.references[0].snippet =
        "return _legacy_callback(value, load_event(), context)".to_string();
    assert!(python_stale_discard_signature_proof(&target).is_none());
}

#[test]
fn typed_stale_discard_proof_rejects_parameters_used_elsewhere() {
    let source = "def _legacy_callback(value, event, context):\n    _ = (event, context)\n    audit(event)\n    return value.strip()\n";
    let mut target = method(source);
    target.name = "_legacy_callback".to_string();
    target.is_exported = false;
    target.param_count = 3;
    target.references = vec![Reference {
        file_path: "src/api.py".to_string(),
        line: 6,
        snippet: "return _legacy_callback(value, event, context)".to_string(),
    }];
    target.real_ref_count = 1;

    assert!(python_stale_discard_signature_proof(&target).is_none());
}

#[test]
fn dossier_follows_imported_callable_through_named_callback_parameter() {
    let target =
        method("def public_api(value, legacy=None):\n    _ = (legacy,)\n    return value\n");
    let target_file = file(target.clone());
    let wire_source = "from .api import public_api as _public_api\n\ndef wire():\n    return run(callback_fn=_public_api)\n";
    let wire_file = FileRecord {
        file_path: "src/wire.py".to_string(),
        source: wire_source.to_string(),
        language: "python".to_string(),
        methods: Vec::new(),
    };
    let planning_source =
        "def run(callback_fn):\n    return callback_fn(\n        value=1,\n    )\n";
    let planning_file = FileRecord {
        file_path: "src/planning.py".to_string(),
        source: planning_source.to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "run".to_string(),
            file_path: "src/planning.py".to_string(),
            source: planning_source.to_string(),
            loc: planning_source.lines().count(),
            param_count: 1,
            start_line: 1,
            end_line: planning_source.lines().count(),
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        }],
    };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: target_file.file_path.clone(),
        definitions: vec![SymbolDefinition {
            id: 7,
            name: "public_api".to_string(),
            kind: crate::types::SymbolKind::Function,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            owner_type: None,
            receiver_type: None,
            value_type: None,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    });
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: wire_file.file_path.clone(),
        definitions: Vec::new(),
        imports: vec![crate::types::ImportRecord {
            local_name: "_public_api".to_string(),
            source_module: ".api".to_string(),
            imported_name: "public_api".to_string(),
        }],
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![crate::types::SymbolReference {
            name: "_public_api".to_string(),
            line: 4,
            snippet: "return run(callback_fn=_public_api)".to_string(),
            is_member_call: false,
            is_callable_value: false,
            resolved_symbol: Some(crate::types::ResolvedSymbol::External {
                file_path: target_file.file_path.clone(),
                symbol_name: "public_api".to_string(),
                definition_id: Some(7),
            }),
        }],
    });
    let files = vec![target_file.clone(), wire_file, planning_file];

    let dossier = build_method_dossier(&target_file, &target, &graph, &files, Vec::new());

    assert!(
        dossier
            .context
            .contains("links `_public_api` to callback parameter `callback_fn`")
    );
    assert!(dossier.context.contains("src/planning.py"));
    assert!(dossier.context.contains("value=1"));
    assert!(dossier.context.contains("full method"));
}

#[test]
fn callback_provenance_rejects_same_named_import_from_another_module() {
    let symbols = crate::types::LocalFileSymbols {
        file_path: "src/wire.py".to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![crate::types::SymbolReference {
            name: "_load".to_string(),
            line: 4,
            snippet: "return run(callback_fn=_load)".to_string(),
            is_member_call: false,
            is_callable_value: false,
            resolved_symbol: Some(crate::types::ResolvedSymbol::External {
                file_path: "src/other_api.py".to_string(),
                symbol_name: "load".to_string(),
                definition_id: Some(4),
            }),
        }],
    };

    assert!(!alias_resolves_to_target(
        &symbols,
        "_load",
        "src/api.py",
        "load",
        Some(2),
    ));
}

#[test]
fn callback_assignment_requires_the_callable_value_not_its_result() {
    assert_eq!(
        callback_parameter_assignment("return run(callback_fn=_public_api)", "_public_api"),
        Some("callback_fn".to_string())
    );
    assert_eq!(
        callback_parameter_assignment("let mut callback = method(\"def demo(): pass\")", "method"),
        None
    );
    assert_eq!(
        callback_parameter_assignment(
            "let inline_callback = is_inline_anonymous_callback(method);",
            "method"
        ),
        None
    );
}

#[test]
fn discard_block_with_expressions_is_not_treated_as_pure_parameter_ceremony() {
    let method = method("def public_api(model=None):\n    _ = (load(model),)\n    return 1\n");
    assert!(python_parameter_discard_block(&method).is_none());
}

#[test]
fn unresolvable_exported_thin_wrapper_requires_external_contract_evidence() {
    let method =
        method("def public_api():\n    from .impl import run as _run\n    return _run()\n");
    let mut facts = empty_facts();
    facts.has_repository_external_visibility = true;
    let requirements = boundary_requirements(&file(method.clone()), &method, &facts);

    assert_eq!(requirements.len(), 1);
    assert!(requirements[0].contains("external consumers"));
}

#[test]
fn rust_restricted_visibility_cannot_invent_external_consumers() {
    let mut restricted =
        method("pub(super) fn finding_label(reason: &str) -> String { reason.to_string() }");
    restricted.file_path = "src/reporter_helpers.rs".to_string();
    restricted.language = "rust".to_string();
    restricted.is_exported = true;
    let file = file(restricted.clone());

    assert!(
        boundary_requirements(&file, &restricted, &empty_facts()).is_empty(),
        "pub(super) methods cannot have consumers outside the repository"
    );
    let restricted_file = file.clone();
    let restricted_graph = SymbolGraph::new(".");
    let restricted_files = [restricted_file];
    let restricted_index = build_dossier_repository_index(&restricted_graph, &restricted_files);
    assert!(visibility(&restricted, &restricted_index).contains("repository-restricted"));
}

#[test]
fn established_external_contract_prevents_automatic_boundary_gap() {
    let method =
        method("def public_api():\n    from .impl import run as _run\n    return _run()\n");
    let mut facts = empty_facts();
    facts.has_external_contract_evidence = true;
    facts.has_repository_external_visibility = true;

    assert!(boundary_requirements(&file(method.clone()), &method, &facts).is_empty());
}

#[test]
fn protocol_evidence_prevents_automatic_protocol_gap() {
    let method = MethodRecord {
        name: "load".to_string(),
        file_path: "src/store.py".to_string(),
        source: "def load(self, key):\n    pass\n".to_string(),
        loc: 2,
        param_count: 2,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let mut facts = empty_facts();
    facts.has_protocol_contract = true;

    assert!(boundary_requirements(&file(method.clone()), &method, &facts).is_empty());
}

#[test]
fn exception_pass_in_real_logic_does_not_create_a_protocol_gap() {
    let method = method(
        "def public_api(content):\n    try:\n        return parse(content)\n    except ValueError:\n        pass\n    return recover(content)\n",
    );

    assert!(boundary_requirements(&file(method.clone()), &method, &empty_facts()).is_empty());
}

#[test]
fn dossier_retains_and_renders_every_resolved_callee() {
    let method = method("def public_api():\n    return _run()\n");
    let file = file(method.clone());
    let graph = SymbolGraph::new(".");
    let callees = vec![
        Reference {
            file_path: "src/impl.py".to_string(),
            line: 4,
            snippet: "Callee Method: _run".to_string(),
        },
        Reference {
            file_path: "src/audit.py".to_string(),
            line: 9,
            snippet: "Callee Method: record".to_string(),
        },
    ];

    let dossier = build_method_dossier(
        &file,
        &method,
        &graph,
        std::slice::from_ref(&file),
        callees.clone(),
    );

    assert_eq!(dossier.callees.len(), 2);
    let rendered = render_references(&dossier.callees);
    assert!(rendered.contains("src/impl.py:4"));
    assert!(rendered.contains("src/audit.py:9"));
}
