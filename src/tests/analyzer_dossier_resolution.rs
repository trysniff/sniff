use super::*;

#[test]
fn rust_associated_method_evidence_is_owner_qualified() {
    let target = MethodRecord {
        name: "new".to_string(),
        file_path: "src/line_index.rs".to_string(),
        source: "pub fn new(source: &str) -> Self {\n    Self { source }\n}".to_string(),
        loc: 3,
        param_count: 1,
        start_line: 2,
        end_line: 4,
        is_exported: true,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let target_file = FileRecord {
        file_path: target.file_path.clone(),
        source: format!("impl LineIndex {{\n{}\n}}", target.source),
        language: "rust".to_string(),
        methods: vec![target.clone()],
    };
    let unrelated_method = MethodRecord {
        name: "allocate".to_string(),
        file_path: "src/unrelated.rs".to_string(),
        source: "fn allocate() {\n    let _ = Vec::new();\n    let _ = Arc::new(0);\n}".to_string(),
        loc: 4,
        param_count: 0,
        start_line: 1,
        end_line: 4,
        is_exported: false,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let unrelated_file = FileRecord {
        file_path: unrelated_method.file_path.clone(),
        source: unrelated_method.source.clone(),
        language: "rust".to_string(),
        methods: vec![unrelated_method],
    };
    let caller_method = MethodRecord {
        name: "build_index".to_string(),
        file_path: "src/consumer.rs".to_string(),
        source: "fn build_index() {\n    let _ = LineIndex::new(\"source\");\n}".to_string(),
        loc: 3,
        param_count: 0,
        start_line: 1,
        end_line: 3,
        is_exported: false,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let caller_file = FileRecord {
        file_path: caller_method.file_path.clone(),
        source: caller_method.source.clone(),
        language: "rust".to_string(),
        methods: vec![caller_method],
    };
    let fixture_method = MethodRecord {
        name: "assert_report".to_string(),
        file_path: "src/fixture.rs".to_string(),
        source:
            "fn assert_report(report: &str) {\n    assert!(report.contains(\"LineIndex::new\"));\n}"
                .to_string(),
        loc: 3,
        param_count: 1,
        start_line: 1,
        end_line: 3,
        is_exported: false,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let fixture_file = FileRecord {
        file_path: fixture_method.file_path.clone(),
        source: fixture_method.source.clone(),
        language: "rust".to_string(),
        methods: vec![fixture_method],
    };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: target_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 1,
            name: "new".to_string(),
            kind: crate::types::SymbolKind::Method,
            start_line: 2,
            end_line: 4,
            is_exported: true,
            owner_type: Some("LineIndex".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: vec![crate::types::TypeRecord {
            name: "LineIndex".to_string(),
            bases: Vec::new(),
            constructor_is_private: false,
        }],
        references: Vec::new(),
    });
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: "src/other_index.rs".to_string(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 2,
            name: "new".to_string(),
            kind: crate::types::SymbolKind::Method,
            start_line: 2,
            end_line: 4,
            is_exported: true,
            owner_type: Some("OtherIndex".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: vec![crate::types::TypeRecord {
            name: "OtherIndex".to_string(),
            bases: Vec::new(),
            constructor_is_private: false,
        }],
        references: Vec::new(),
    });
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: unrelated_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 3,
            name: "allocate".to_string(),
            kind: crate::types::SymbolKind::Function,
            start_line: 1,
            end_line: 4,
            is_exported: false,
            owner_type: None,
            receiver_type: None,
            value_type: None,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![
            crate::types::SymbolReference {
                name: "Vec::new".to_string(),
                line: 2,
                snippet: "let _ = Vec::new();".to_string(),
                is_member_call: false,
                is_callable_value: false,
                resolved_symbol: None,
            },
            crate::types::SymbolReference {
                name: "Arc::new".to_string(),
                line: 3,
                snippet: "let _ = Arc::new(0);".to_string(),
                is_member_call: false,
                is_callable_value: false,
                resolved_symbol: None,
            },
        ],
    });
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: caller_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 4,
            name: "build_index".to_string(),
            kind: crate::types::SymbolKind::Function,
            start_line: 1,
            end_line: 3,
            is_exported: false,
            owner_type: None,
            receiver_type: None,
            value_type: None,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: vec![crate::types::SymbolReference {
            name: "LineIndex::new".to_string(),
            line: 2,
            snippet: "let _ = LineIndex::new(\"source\");".to_string(),
            is_member_call: false,
            is_callable_value: false,
            resolved_symbol: None,
        }],
    });
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: fixture_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 5,
            name: "assert_report".to_string(),
            kind: crate::types::SymbolKind::Function,
            start_line: 1,
            end_line: 3,
            is_exported: false,
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
    let files = vec![
        target_file.clone(),
        unrelated_file,
        caller_file,
        fixture_file,
    ];

    let dossier = build_method_dossier(&target_file, &target, &graph, &files, Vec::new());

    assert!(dossier.context.contains("src/consumer.rs:2"));
    assert!(dossier.context.contains("LineIndex::new"));
    assert!(!dossier.context.contains("src/unrelated.rs"));
    assert!(!dossier.context.contains("src/fixture.rs"));
    assert!(!dossier.context.contains("OtherIndex"));
    assert!(
        dossier
            .context
            .contains("same-name implementations/overrides: none established")
    );
}

#[test]
fn dossier_records_unresolved_lexical_call_sites_without_calling_them_resolved() {
    let method =
        method("def public_api():\n    from .impl import run as _run\n    return _run()\n");
    let caller = MethodRecord {
        name: "use_api".to_string(),
        file_path: method.file_path.clone(),
        source: "def use_api():\n    return public_api()\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 5,
        end_line: 6,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: method.file_path.clone(),
        source: format!("{}\n{}", method.source, caller.source),
        language: "python".to_string(),
        methods: vec![method.clone(), caller],
    };
    let graph = SymbolGraph::new(".");

    let dossier = build_method_dossier(&file, &method, &graph, std::slice::from_ref(&file), vec![]);

    assert!(
        dossier
            .context
            .contains("lexical call-site candidates not confirmed by the symbol graph")
    );
    assert!(
        dossier
            .context
            .contains("src/api.py:6: return public_api()")
    );
    assert!(dossier.boundary_requirements.is_empty());
}

#[test]
fn dossier_marks_only_closed_world_private_methods_for_unused_adjudication() {
    let mut private_method = method("def _stale_delegate(value):\n    return value\n");
    private_method.name = "_stale_delegate".to_string();
    private_method.is_exported = false;
    let private_file = file(private_method.clone());
    let private_dossier = build_method_dossier(
        &private_file,
        &private_method,
        &SymbolGraph::new("."),
        std::slice::from_ref(&private_file),
        vec![],
    );
    assert!(private_dossier.repository_private_unused_candidate);

    let exported_method = method("def public_boundary(value):\n    return value\n");
    let exported_file = file(exported_method.clone());
    let exported_dossier = build_method_dossier(
        &exported_file,
        &exported_method,
        &SymbolGraph::new("."),
        std::slice::from_ref(&exported_file),
        vec![],
    );
    assert!(!exported_dossier.repository_private_unused_candidate);

    let mut callback = method("(value) => value.trim()");
    callback.name = "<anonymous@12>".to_string();
    callback.file_path = "src/app.ts".to_string();
    callback.language = "typescript".to_string();
    callback.is_exported = false;
    callback.start_line = 12;
    callback.end_line = 12;
    let callback_file = file(callback.clone());
    let callback_dossier = build_method_dossier(
        &callback_file,
        &callback,
        &SymbolGraph::new("."),
        std::slice::from_ref(&callback_file),
        vec![],
    );
    assert!(!callback_dossier.repository_private_unused_candidate);
    assert!(
            callback_dossier
                .context
                .contains(
                    "inline callback contract: this synthetic anonymous symbol is consumed by its containing expression; zero separate graph callers is expected and does not require a parent caller"
                )
        );

    let mut factory = method(
        "export function createRuntime() {\n  const handlers = { onPing: () => true };\n  return handlers;\n}",
    );
    factory.name = "createRuntime".to_string();
    factory.file_path = "src/runtime.ts".to_string();
    factory.language = "typescript".to_string();
    factory.start_line = 1;
    factory.end_line = 4;
    let mut nested_member = method("() => true");
    nested_member.name = "onPing".to_string();
    nested_member.file_path = factory.file_path.clone();
    nested_member.language = factory.language.clone();
    nested_member.start_line = 2;
    nested_member.end_line = 2;
    nested_member.is_exported = false;
    let nested_file = FileRecord {
        file_path: factory.file_path.clone(),
        source: factory.source.clone(),
        language: factory.language.clone(),
        methods: vec![factory, nested_member.clone()],
    };
    let nested_dossier = build_method_dossier(
        &nested_file,
        &nested_member,
        &SymbolGraph::new("."),
        std::slice::from_ref(&nested_file),
        vec![],
    );
    assert!(!nested_dossier.repository_private_unused_candidate);
    assert!(
        nested_dossier
            .context
            .contains("nested callable has no resolved owner")
    );

    let class_source = "class Boundary {\n  render() { return null; }\n}\n";
    let mut render = method("render() { return null; }");
    render.name = "render".to_string();
    render.file_path = "src/App.tsx".to_string();
    render.language = "typescript".to_string();
    render.start_line = 2;
    render.end_line = 2;
    render.is_exported = false;
    let class_file = FileRecord {
        file_path: render.file_path.clone(),
        source: class_source.to_string(),
        language: render.language.clone(),
        methods: vec![render.clone()],
    };
    let mut class_graph = SymbolGraph::new(".");
    class_graph.add_file(crate::types::LocalFileSymbols {
        file_path: class_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 0,
            name: "render".to_string(),
            kind: crate::types::SymbolKind::Method,
            start_line: 2,
            end_line: 2,
            is_exported: false,
            owner_type: Some("Boundary".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: vec![],
        exports: vec![],
        modules: vec![],
        types: vec![],
        references: vec![],
    });
    let class_dossier = build_method_dossier(
        &class_file,
        &render,
        &class_graph,
        std::slice::from_ref(&class_file),
        vec![],
    );
    assert!(class_dossier.repository_private_unused_candidate);
}

#[test]
fn resolved_callers_satisfy_callback_module_boundary_investigation() {
    let mut target = method("internal fun buildCallbacks(): String = \"ready\"");
    target.name = "buildCallbacks".to_string();
    target.file_path = "src/HostCallbacks.kt".to_string();
    target.language = "kotlin".to_string();
    target.is_exported = false;
    target.real_ref_count = 1;
    target.references = vec![Reference {
        file_path: "src/HostRuntime.kt".to_string(),
        line: 10,
        snippet: "return buildCallbacks()".to_string(),
    }];
    let callback_file = FileRecord {
            file_path: target.file_path.clone(),
            source: "data class HostCallbacks(\n  val first: () -> Unit,\n  val second: () -> Unit,\n  val third: () -> Unit,\n)\n\ninternal fun buildCallbacks(): String = \"ready\"\n".to_string(),
            language: "kotlin".to_string(),
            methods: vec![target.clone()],
        };

    let dossier = build_method_dossier(
        &callback_file,
        &target,
        &SymbolGraph::new("."),
        std::slice::from_ref(&callback_file),
        Vec::new(),
    );

    assert!(dossier.boundary_requirements.is_empty());
}

#[test]
fn kotlin_override_is_direct_protocol_contract_evidence() {
    let mut target =
        method("override suspend fun persistToken(token: String) {\n  store(token)\n}");
    target.name = "persistToken".to_string();
    target.file_path = "src/FakeTokenStore.kt".to_string();
    target.language = "kotlin".to_string();
    target.is_exported = false;
    let target_file = file(target.clone());

    let dossier = build_method_dossier(
        &target_file,
        &target,
        &SymbolGraph::new("."),
        std::slice::from_ref(&target_file),
        Vec::new(),
    );

    assert!(!dossier.repository_private_unused_candidate);
    assert!(dossier.context.contains(
            "the Kotlin declaration explicitly uses `override`, establishing an interface or superclass contract"
        ));
}

#[test]
fn js_ts_exports_in_private_packages_can_be_closed_world_unused() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-private-js-package-{nonce}"));
    let package_root = root.join("ui");
    let source_path = package_root.join("src/dead.ts");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"private-ui","private":true}"#,
    )
    .unwrap();

    let source = "export function staleAction() { return true; }";
    let method = MethodRecord {
        name: "staleAction".to_string(),
        file_path: source_path.to_string_lossy().to_string(),
        source: source.to_string(),
        loc: 1,
        param_count: 0,
        start_line: 1,
        end_line: 1,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: method.file_path.clone(),
        source: source.to_string(),
        language: method.language.clone(),
        methods: vec![method.clone()],
    };
    let root_text = root.to_string_lossy().to_string();
    let mut graph = SymbolGraph::new(&root_text);
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 1,
            name: method.name.clone(),
            kind: crate::types::SymbolKind::Function,
            start_line: 1,
            end_line: 1,
            is_exported: true,
            owner_type: None,
            receiver_type: None,
            value_type: None,
        }],
        imports: vec![],
        exports: vec![crate::types::ExportRecord {
            exported_name: method.name.clone(),
            local_symbol_name: method.name.clone(),
            source_module: None,
            source_symbol_name: None,
        }],
        modules: vec![],
        types: vec![],
        references: vec![],
    });
    let dossier = build_method_dossier(
        &file,
        &method,
        &graph,
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(dossier.repository_private_unused_candidate);
    assert!(dossier.boundary_requirements.is_empty());
    assert!(dossier.context.contains("module-exported inside a private"));
    assert!(
        dossier
            .context
            .contains("exports and re-exports involving this method")
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn unused_private_factory_return_members_are_coordinated_removal_candidates() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-private-returned-member-{nonce}"));
    let package_root = root.join("ui");
    let source_path = package_root.join("src/runtime.ts");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"private-ui","private":true}"#,
    )
    .unwrap();

    let source = "export function createRegistry() {\n  function snapshot() {\n    return {};\n  }\n  return {\n    snapshot,\n  };\n}";
    let file_path = source_path.to_string_lossy().to_string();
    let factory = MethodRecord {
        name: "createRegistry".to_string(),
        file_path: file_path.clone(),
        source: source.to_string(),
        loc: 8,
        param_count: 0,
        start_line: 1,
        end_line: 8,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let member = MethodRecord {
        name: "snapshot".to_string(),
        file_path: file_path.clone(),
        source: "function snapshot() {\n    return {};\n  }".to_string(),
        loc: 3,
        param_count: 0,
        start_line: 2,
        end_line: 4,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: vec![crate::types::Reference {
            file_path: file_path.clone(),
            line: 6,
            snippet: "return { snapshot };".to_string(),
        }],
        real_ref_count: 1,
    };
    let file = FileRecord {
        file_path: file_path.clone(),
        source: source.to_string(),
        language: "typescript".to_string(),
        methods: vec![factory, member.clone()],
    };
    let root_text = root.to_string_lossy().to_string();
    let dossier = build_method_dossier(
        &file,
        &member,
        &SymbolGraph::new(&root_text),
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(dossier.repository_private_unused_candidate);
    assert!(
        dossier
            .context
            .contains("private returned-object surface entries requiring coordinated removal")
    );
    assert!(
        !dossier
            .context
            .contains("nested callable has no resolved owner")
    );

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn inline_object_argument_members_are_consumed_callback_contracts() {
    let source = "export function boot() {\n  init({ beforeSend(event) { return event; } });\n}";
    let callback = MethodRecord {
        name: "beforeSend".to_string(),
        file_path: "src/boot.ts".to_string(),
        source: "beforeSend(event) { return event; }".to_string(),
        loc: 1,
        param_count: 1,
        start_line: 2,
        end_line: 2,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: callback.file_path.clone(),
        source: source.to_string(),
        language: callback.language.clone(),
        methods: vec![callback.clone()],
    };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 1,
            name: callback.name.clone(),
            kind: crate::types::SymbolKind::Method,
            start_line: 2,
            end_line: 2,
            is_exported: false,
            owner_type: Some("<object@2>".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: vec![],
        exports: vec![],
        modules: vec![],
        types: vec![],
        references: vec![],
    });

    let dossier = build_method_dossier(
        &file,
        &callback,
        &graph,
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(!dossier.repository_private_unused_candidate);
    assert!(
        dossier
            .context
            .contains("consumed through its containing expression")
    );
}

#[test]
fn typed_object_callback_defaults_are_not_private_unused() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-object-callback-{nonce}"));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("normalize.ts");
    std::fs::write(
        &path,
        r#"type RetryOptions = {
	delay: (attemptCount: number) => number;
};

const defaultRetryOptions: RetryOptions = {
	delay: attemptCount => 0.3 * (2 ** (attemptCount - 1)) * 1000,
};

export const normalizeRetryOptions = (): RetryOptions => ({
	...defaultRetryOptions,
});
"#,
    )
    .unwrap();

    let path_text = path.to_string_lossy().to_string();
    let mut file = crate::parser::parse_file_checked(&path_text).expect("parse TypeScript file");
    let mut graph = SymbolGraph::new(root.to_string_lossy().as_ref());
    graph.add_file(
        crate::parser::parse_file_symbols_checked(&path_text).expect("index TypeScript symbols"),
    );
    graph.resolve_all();
    let context_files = [file.clone()];
    crate::callgraph::build_references_with_context(
        std::slice::from_mut(&mut file),
        &context_files,
        &graph,
    );
    let delay = file
        .methods
        .iter()
        .find(|method| method.name == "delay")
        .expect("extract delay callback")
        .clone();
    let dossier = build_method_dossier(
        &file,
        &delay,
        &graph,
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(
        !dossier.repository_private_unused_candidate,
        "object callback was incorrectly considered unused:\n{}",
        dossier.context
    );
    assert!(
        dossier
            .context
            .contains("member of repository object `defaultRetryOptions`")
    );

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn implicit_return_object_members_can_be_closed_world_unused() {
    let source =
        "export const useStore = create()((set) => ({\n  setTier: (tier) => set({ tier }),\n}));";
    let member = MethodRecord {
        name: "setTier".to_string(),
        file_path: "src/store.ts".to_string(),
        source: "setTier: (tier) => set({ tier })".to_string(),
        loc: 1,
        param_count: 1,
        start_line: 2,
        end_line: 2,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: member.file_path.clone(),
        source: source.to_string(),
        language: member.language.clone(),
        methods: vec![member.clone()],
    };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 1,
            name: member.name.clone(),
            kind: crate::types::SymbolKind::Method,
            start_line: 2,
            end_line: 2,
            is_exported: false,
            owner_type: Some("<object@1>".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: vec![],
        exports: vec![],
        modules: vec![],
        types: vec![],
        references: vec![],
    });

    let dossier = build_method_dossier(
        &file,
        &member,
        &graph,
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(dossier.repository_private_unused_candidate);
}

#[test]
fn js_ts_exports_in_publishable_packages_remain_external() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-public-js-package-{nonce}"));
    let source_path = root.join("src/api.ts");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    std::fs::write(root.join("package.json"), r#"{"name":"public-api"}"#).unwrap();

    let source = "export function publicAction() { return true; }";
    let method = MethodRecord {
        name: "publicAction".to_string(),
        file_path: source_path.to_string_lossy().to_string(),
        source: source.to_string(),
        loc: 1,
        param_count: 0,
        start_line: 1,
        end_line: 1,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: method.file_path.clone(),
        source: source.to_string(),
        language: method.language.clone(),
        methods: vec![method.clone()],
    };
    let root_text = root.to_string_lossy().to_string();
    let graph = SymbolGraph::new(&root_text);
    let dossier = build_method_dossier(
        &file,
        &method,
        &graph,
        std::slice::from_ref(&file),
        Vec::new(),
    );

    assert!(!dossier.repository_private_unused_candidate);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn dossier_treats_only_actual_rust_test_methods_as_test_runner_consumers() {
    let source = "#[cfg(test)]\nfn isolated_test() {}\n\nfn production_helper() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn runner_test() {}\n}\n";
    let make_method = |name: &str, method_source: &str, line: usize| MethodRecord {
        name: name.to_string(),
        file_path: "src/demo.rs".to_string(),
        source: method_source.to_string(),
        loc: 1,
        param_count: 0,
        start_line: line,
        end_line: line,
        is_exported: false,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let isolated_test = make_method("isolated_test", "fn isolated_test() {}", 2);
    let production = make_method("production_helper", "fn production_helper() {}", 4);
    let runner_test = make_method("runner_test", "fn runner_test() {}", 9);
    let file = FileRecord {
        file_path: "src/demo.rs".to_string(),
        source: source.to_string(),
        language: "rust".to_string(),
        methods: vec![
            isolated_test.clone(),
            production.clone(),
            runner_test.clone(),
        ],
    };
    let graph = SymbolGraph::new(".");

    let isolated_dossier = build_method_dossier(
        &file,
        &isolated_test,
        &graph,
        std::slice::from_ref(&file),
        vec![],
    );
    let production_dossier = build_method_dossier(
        &file,
        &production,
        &graph,
        std::slice::from_ref(&file),
        vec![],
    );
    let runner_dossier = build_method_dossier(
        &file,
        &runner_test,
        &graph,
        std::slice::from_ref(&file),
        vec![],
    );

    assert!(!isolated_dossier.repository_private_unused_candidate);
    assert!(
        isolated_dossier
            .context
            .contains("method-level role consumer: Rust test method invoked by the test runner")
    );
    assert!(production_dossier.repository_private_unused_candidate);
    assert!(
        !production_dossier
            .context
            .contains("method-level role consumer:")
    );
    assert!(!runner_dossier.repository_private_unused_candidate);
    assert!(
        runner_dossier
            .context
            .contains("method-level role consumer: Rust test method invoked by the test runner")
    );
}

#[test]
fn file_role_alone_does_not_excuse_an_unused_private_script_helper() {
    let mut script_method = method("def run():\n    return 1\n");
    script_method.name = "run".to_string();
    script_method.file_path = "scripts/run.py".to_string();
    script_method.is_exported = false;
    let script_file = file(script_method.clone());
    let script_dossier = build_method_dossier(
        &script_file,
        &script_method,
        &SymbolGraph::new("."),
        std::slice::from_ref(&script_file),
        vec![],
    );

    assert!(script_dossier.repository_private_unused_candidate);
    assert!(
        !script_dossier
            .context
            .contains("method-level role consumer:")
    );
}

#[test]
fn protocol_stub_declaration_is_direct_contract_evidence_in_a_mixed_file() {
    let mut protocol_method = method("def load(self, key: str) -> str: ...\n");
    protocol_method.name = "load".to_string();
    protocol_method.is_exported = false;
    let implementation = MethodRecord {
        name: "load".to_string(),
        source: "def load(self, key: str) -> str:\n    return self.values[key]\n".to_string(),
        start_line: 6,
        end_line: 7,
        ..protocol_method.clone()
    };
    let file = FileRecord {
            file_path: "src/store.py".to_string(),
            source: "from typing import Protocol\n\nclass Store(Protocol):\n    def load(self, key: str) -> str: ...\n\nclass MemoryStore:\n    def load(self, key: str) -> str:\n        return self.values[key]\n".to_string(),
            language: "python".to_string(),
            methods: vec![protocol_method.clone(), implementation],
        };
    let graph = SymbolGraph::new(".");
    let dossier = build_method_dossier(
        &file,
        &protocol_method,
        &graph,
        std::slice::from_ref(&file),
        vec![],
    );

    assert!(dossier.boundary_requirements.is_empty());
    assert!(!dossier.repository_private_unused_candidate);
}
