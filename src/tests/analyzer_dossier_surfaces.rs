use super::*;

#[test]
fn repository_index_shares_authoritative_files_across_method_dossiers() {
    let source =
        "# AUTHORITATIVE_SENTINEL\ndef first():\n    return 1\n\ndef second():\n    return 2\n";
    let mut first = method("def first():\n    return 1\n");
    first.name = "first".to_string();
    first.end_line = 3;
    let mut second = method("def second():\n    return 2\n");
    second.name = "second".to_string();
    second.start_line = 5;
    second.end_line = 6;
    let file = FileRecord {
        file_path: "src/api.py".to_string(),
        source: source.to_string(),
        language: "python".to_string(),
        methods: vec![first.clone(), second.clone()],
    };
    let graph = SymbolGraph::new("");
    let files = [file.clone()];
    let index = build_dossier_repository_index(&graph, &files);

    let first_dossier = build_method_dossier_with_index(&file, &first, &index, Vec::new());
    let second_dossier = build_method_dossier_with_index(&file, &second, &index, Vec::new());

    assert!(Arc::ptr_eq(
        &first_dossier.full_file,
        &second_dossier.full_file
    ));
    assert!(first_dossier.full_file.contains("AUTHORITATIVE_SENTINEL"));
    assert!(!first_dossier.context.contains("AUTHORITATIVE_SENTINEL"));
    assert!(first_dossier.context.contains("Method dossier:"));
    assert!(second_dossier.context.contains("Method dossier:"));
}

#[test]
fn exported_factory_return_object_members_are_external_contract_evidence() {
    let source = "export function createRuntime() {\n  function returnedHelper() {}\n  function hiddenHelper() {}\n  return {\n    directMember() {},\n    returnedHelper,\n  };\n}\n";
    let mut outer = method(source);
    outer.name = "createRuntime".to_string();
    outer.file_path = "src/runtime.ts".to_string();
    outer.language = "typescript".to_string();
    outer.end_line = 8;

    let mut returned = method("function returnedHelper() {}");
    returned.name = "returnedHelper".to_string();
    returned.file_path = outer.file_path.clone();
    returned.language = outer.language.clone();
    returned.start_line = 2;
    returned.end_line = 2;
    returned.is_exported = false;

    let mut hidden = method("function hiddenHelper() {}");
    hidden.name = "hiddenHelper".to_string();
    hidden.file_path = outer.file_path.clone();
    hidden.language = outer.language.clone();
    hidden.start_line = 3;
    hidden.end_line = 3;
    hidden.is_exported = false;

    let mut direct = method("directMember() {}");
    direct.name = "directMember".to_string();
    direct.file_path = outer.file_path.clone();
    direct.language = outer.language.clone();
    direct.start_line = 5;
    direct.end_line = 5;
    direct.is_exported = false;

    let file = FileRecord {
        file_path: outer.file_path.clone(),
        source: source.to_string(),
        language: outer.language.clone(),
        methods: vec![outer, returned.clone(), hidden.clone(), direct.clone()],
    };

    assert!(externally_returned_member_evidence(&file, &returned).is_some());
    assert!(externally_returned_member_evidence(&file, &direct).is_some());
    assert!(externally_returned_member_evidence(&file, &hidden).is_none());

    let graph = SymbolGraph::new("");
    let files = [file.clone()];
    let index = build_dossier_repository_index(&graph, &files);
    let direct_dossier = build_method_dossier_with_index(&file, &direct, &index, Vec::new());
    assert!(!direct_dossier.repository_private_unused_candidate);
    assert!(
        direct_dossier
            .context
            .contains("returns this member through an externally visible object contract")
    );
}

#[test]
fn returned_object_members_follow_only_concrete_factory_result_aliases() {
    let source =
        "export function createLogger() {\n  return {\n    debug() {},\n    info() {},\n  };\n}";
    let factory = MethodRecord {
        name: "createLogger".to_string(),
        file_path: "src/logger.ts".to_string(),
        source: source.to_string(),
        loc: 6,
        param_count: 0,
        start_line: 1,
        end_line: 6,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let member = |name: &str, line: usize| MethodRecord {
        name: name.to_string(),
        file_path: factory.file_path.clone(),
        source: format!("{name}() {{}}"),
        loc: 1,
        param_count: 0,
        start_line: line,
        end_line: line,
        is_exported: false,
        language: factory.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let debug = member("debug", 3);
    let info = member("info", 4);
    let logger_file = FileRecord {
        file_path: factory.file_path.clone(),
        source: source.to_string(),
        language: factory.language.clone(),
        methods: vec![factory, debug.clone(), info.clone()],
    };
    let consumer = FileRecord {
        file_path: "src/app.ts".to_string(),
        source: "const logger = createLogger();\nlogger.debug('ready');\nconsole.info('other');"
            .to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let graph = SymbolGraph::new(".");
    let files = vec![logger_file.clone(), consumer];
    let index = build_dossier_repository_index(&graph, &files);

    let debug_usage = returned_member_usage_evidence(&logger_file, &debug, &index);
    let info_usage = returned_member_usage_evidence(&logger_file, &info, &index);

    assert_eq!(debug_usage.len(), 1);
    assert!(debug_usage[0].contains("logger.debug('ready')"));
    assert!(info_usage.is_empty());
}

#[test]
fn returned_object_members_follow_multiline_factory_destructuring() {
    let source = "export function createRuntime() {\n  function start() {}\n  return { start };\n}";
    let factory = MethodRecord {
        name: "createRuntime".to_string(),
        file_path: "src/runtime.ts".to_string(),
        source: source.to_string(),
        loc: 4,
        param_count: 0,
        start_line: 1,
        end_line: 4,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let start = MethodRecord {
        name: "start".to_string(),
        file_path: factory.file_path.clone(),
        source: "function start() {}".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 2,
        end_line: 2,
        is_exported: false,
        language: factory.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let runtime_file = FileRecord {
        file_path: factory.file_path.clone(),
        source: source.to_string(),
        language: factory.language.clone(),
        methods: vec![factory, start.clone()],
    };
    let consumer = FileRecord {
        file_path: "src/app.ts".to_string(),
        source: "const {\n  start,\n} = createRuntime({\n  value: true,\n});\nstart();".to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let graph = SymbolGraph::new(".");
    let files = vec![runtime_file.clone(), consumer];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = returned_member_usage_evidence(&runtime_file, &start, &index);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("destructured from `createRuntime` across lines 1-3"));
}

#[test]
fn named_return_objects_follow_composed_store_surfaces() {
    let source = "export function createProfileActions() {\n  const actions = {\n    loadFromPortfolio() {},\n    unusedAction() {},\n  };\n  return actions;\n}";
    let factory = MethodRecord {
        name: "createProfileActions".to_string(),
        file_path: "src/profile-actions.ts".to_string(),
        source: source.to_string(),
        loc: 7,
        param_count: 0,
        start_line: 1,
        end_line: 7,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let member = |name: &str, line: usize| MethodRecord {
        name: name.to_string(),
        file_path: factory.file_path.clone(),
        source: format!("{name}() {{}}"),
        loc: 1,
        param_count: 0,
        start_line: line,
        end_line: line,
        is_exported: false,
        language: factory.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let used = member("loadFromPortfolio", 3);
    let unused = member("unusedAction", 4);
    let factory_file = FileRecord {
        file_path: factory.file_path.clone(),
        source: source.to_string(),
        language: factory.language.clone(),
        methods: vec![factory, used.clone(), unused.clone()],
    };
    let consumer = FileRecord {
            file_path: "src/store.ts".to_string(),
            source: "export const useProfileStore = create()((set) => ({\n  ...createProfileActions(set),\n}));\nawait useProfileStore.getState().loadFromPortfolio('id');"
                .to_string(),
            language: "typescript".to_string(),
            methods: Vec::new(),
        };
    let graph = SymbolGraph::new(".");
    let files = vec![factory_file.clone(), consumer];
    let index = build_dossier_repository_index(&graph, &files);

    let used_evidence = returned_member_usage_evidence(&factory_file, &used, &index);
    let unused_evidence = returned_member_usage_evidence(&factory_file, &unused, &index);

    assert!(
        used_evidence
            .iter()
            .any(|evidence| evidence.contains("useProfileStore"))
    );
    assert!(unused_evidence.is_empty());
}

#[test]
fn private_typed_members_require_coordinated_signature_removal() {
    let source = "type Logger = {\n  info: (...args: unknown[]) => void;\n};\nfunction createLogger(): Logger {\n  return {\n    info: (...args) => console.info(...args),\n  };\n}";
    let method = MethodRecord {
        name: "info".to_string(),
        file_path: "src/logger.ts".to_string(),
        source: "info: (...args) => console.info(...args)".to_string(),
        loc: 1,
        param_count: 1,
        start_line: 6,
        end_line: 6,
        is_exported: false,
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
    let graph = SymbolGraph::new(".");
    let files = [file.clone()];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = private_js_ts_surface_declaration_evidence(&file, &method, &index);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("info: (...args: unknown[]) => void;"));
}

#[test]
fn class_construction_protocol_and_owner_calls_are_repository_evidence() {
    let class_source = "class EngineSkeleton {\n  constructor() {}\n  start() {}\n}";
    let constructor = MethodRecord {
        name: "constructor".to_string(),
        file_path: "src/engine.ts".to_string(),
        source: "constructor() {}".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 2,
        end_line: 2,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let mut start = constructor.clone();
    start.name = "start".to_string();
    start.source = "start() {}".to_string();
    start.start_line = 3;
    start.end_line = 3;
    let class_file = FileRecord {
        file_path: constructor.file_path.clone(),
        source: class_source.to_string(),
        language: constructor.language.clone(),
        methods: vec![constructor.clone(), start.clone()],
    };
    let consumer = FileRecord {
        file_path: "src/main.ts".to_string(),
        source: "const engine = new EngineSkeleton();\nEngineSkeleton.getInstance().start();"
            .to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let protocol_file = FileRecord {
        file_path: "src/boundary.tsx".to_string(),
        source: "class LocalErrorBoundary extends Component {\n  render() {}\n}".to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let graph = SymbolGraph::new(".");
    let files = vec![class_file.clone(), consumer, protocol_file.clone()];
    let index = build_dossier_repository_index(&graph, &files);

    assert_eq!(
        js_ts_owner_invocation_evidence(&constructor, Some("EngineSkeleton"), &index).len(),
        1
    );
    assert_eq!(
        js_ts_owner_invocation_evidence(&start, Some("EngineSkeleton"), &index).len(),
        1
    );
    assert!(class_contract_evidence(&protocol_file, "LocalErrorBoundary").is_some());
}

#[test]
fn class_members_follow_returned_constructor_factories_to_instance_calls() {
    let source = "export function createRuntimeDomScanner() {\n  class DomScanner {\n    start() {}\n    stop() {}\n  }\n  function createDomScanner() {\n    return new DomScanner();\n  }\n  return { createDomScanner };\n}";
    let outer = MethodRecord {
        name: "createRuntimeDomScanner".to_string(),
        file_path: "ui/content-scripts/runtime/runtime-dom-scanner.js".to_string(),
        source: source.to_string(),
        loc: 10,
        param_count: 0,
        start_line: 1,
        end_line: 10,
        is_exported: true,
        language: "javascript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let stop = MethodRecord {
        name: "stop".to_string(),
        file_path: outer.file_path.clone(),
        source: "stop() {}".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 4,
        end_line: 4,
        is_exported: false,
        language: outer.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let constructor_factory = MethodRecord {
        name: "createDomScanner".to_string(),
        file_path: outer.file_path.clone(),
        source: "function createDomScanner() {\n    return new DomScanner();\n  }".to_string(),
        loc: 3,
        param_count: 0,
        start_line: 6,
        end_line: 8,
        is_exported: false,
        language: outer.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let runtime_file = FileRecord {
        file_path: outer.file_path.clone(),
        source: source.to_string(),
        language: outer.language.clone(),
        methods: vec![outer, stop.clone(), constructor_factory],
    };
    let consumer = FileRecord {
            file_path: "tests/runtime-dom-scanner.test.js".to_string(),
            source: "const { createRuntimeDomScanner } = require('../ui/content-scripts/runtime/runtime-dom-scanner.js');\nconst runtimeDomScanner = createRuntimeDomScanner({});\nconst scanner = runtimeDomScanner.createDomScanner();\nscanner.start();\nscanner.stop();\nother.stop();"
                .to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: runtime_file.file_path.clone(),
        definitions: vec![crate::types::SymbolDefinition {
            id: 0,
            name: "stop".to_string(),
            kind: crate::types::SymbolKind::Method,
            start_line: 4,
            end_line: 4,
            is_exported: false,
            owner_type: Some("DomScanner".to_string()),
            receiver_type: None,
            value_type: None,
        }],
        imports: vec![],
        exports: vec![],
        modules: vec![],
        types: vec![],
        references: vec![],
    });
    let files = vec![runtime_file.clone(), consumer];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence =
        factory_constructed_class_member_usage_evidence(&runtime_file, &stop, "DomScanner", &index);
    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("scanner.stop()"));

    let dossier = build_method_dossier_with_index(&runtime_file, &stop, &index, Vec::new());
    assert!(!dossier.repository_private_unused_candidate);
    assert!(dossier.context.contains("scanner.stop()"));
}

#[test]
fn dynamic_import_evidence_requires_the_import_to_target_the_method_file() {
    let method = MethodRecord {
        name: "DashboardTab".to_string(),
        file_path: "ui/src/components/DashboardTab.tsx".to_string(),
        source: "export function DashboardTab() { return null; }".to_string(),
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
    let target = FileRecord {
        file_path: method.file_path.clone(),
        source: method.source.clone(),
        language: method.language.clone(),
        methods: vec![method.clone()],
    };
    let consumer = FileRecord {
            file_path: "ui/src/navigation.tsx".to_string(),
            source: "const DashboardTab = lazy(() => import('@/components/DashboardTab').then(({ DashboardTab }) => ({ default: DashboardTab })));\nconst Other = lazy(() => import('@/other/DashboardTab').then(({ DashboardTab }) => ({ default: DashboardTab })));"
                .to_string(),
            language: "typescript".to_string(),
            methods: Vec::new(),
        };
    let graph = SymbolGraph::new(".");
    let files = vec![target, consumer];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = dynamic_import_evidence(&method, &index);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("@/components/DashboardTab"));
}

#[test]
fn commonjs_destructuring_is_path_resolved_to_the_exported_method() {
    let method = MethodRecord {
        name: "scoreFieldSemantic".to_string(),
        file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
        source: "export function scoreFieldSemantic() { return 1; }".to_string(),
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
    let target = FileRecord {
        file_path: method.file_path.clone(),
        source: method.source.clone(),
        language: method.language.clone(),
        methods: vec![method.clone()],
    };
    let test_file = FileRecord {
            file_path: "tests/heuristics.test.js".to_string(),
            source: "const {\n  scoreFieldSemantic,\n  optionMatchesType,\n} = require('../ui/src/lib/smart-filler/heuristics.ts');\nscoreFieldSemantic();"
                .to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let unrelated = FileRecord {
        file_path: "tests/unrelated.test.js".to_string(),
        source: "const { scoreFieldSemantic } = require('../ui/src/lib/other.ts');".to_string(),
        language: "javascript".to_string(),
        methods: Vec::new(),
    };
    let graph = SymbolGraph::new(".");
    let files = vec![target, test_file, unrelated];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = commonjs_require_evidence(&method, &index);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("heuristics.ts"));
    assert!(!evidence[0].contains("other.ts"));
}

#[test]
fn source_inspection_tests_are_contracts_but_existence_checks_are_not() {
    let safety = FileRecord {
        file_path: "ui/src/components/tabs/SafetyTab.tsx".to_string(),
        source: "export function SafetyTab() { return 'Trademarkia'; }".to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let gallery = FileRecord {
        file_path: "ui/src/components/ComponentGallery.tsx".to_string(),
        source: "export function ComponentGallery() { return null; }".to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let safety_test = FileRecord {
            file_path: "tests/safety.test.js".to_string(),
            source: "const safetyPath = path.join('SafetyTab.tsx');\nconst content = fs.readFileSync(safetyPath, 'utf-8');\nexpect(content).toContain('Trademarkia');"
                .to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let gallery_test = FileRecord {
            file_path: "tests/gallery.test.js".to_string(),
            source: "const galleryPath = path.join('ComponentGallery.tsx');\nexpect(fs.existsSync(galleryPath)).toBe(true);"
                .to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let graph = SymbolGraph::new(".");
    let files = vec![safety.clone(), gallery.clone(), safety_test, gallery_test];
    let index = build_dossier_repository_index(&graph, &files);
    let safety_method = MethodRecord {
        name: "SafetyTab".to_string(),
        file_path: safety.file_path.clone(),
        source: safety.source.clone(),
        loc: 1,
        param_count: 0,
        start_line: 1,
        end_line: 1,
        is_exported: true,
        language: safety.language.clone(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let mut gallery_method = safety_method.clone();
    gallery_method.name = "ComponentGallery".to_string();
    gallery_method.file_path = gallery.file_path.clone();
    gallery_method.source = gallery.source.clone();

    assert_eq!(
        file_content_test_contract_evidence(&safety, &safety_method, &index).len(),
        1
    );
    assert!(file_content_test_contract_evidence(&gallery, &gallery_method, &index).is_empty());
}

#[test]
fn source_inspection_tests_preserve_returned_compatibility_aliases() {
    let source = "function useAuth() {\n  const continueWithGoogle = async () => {}\n  const signUpWithGoogle = async () => {\n    return continueWithGoogle()\n  }\n  return { continueWithGoogle, signUpWithGoogle }\n}";
    let method = MethodRecord {
        name: "signUpWithGoogle".to_string(),
        file_path: "ui/src/hooks/useAuth.ts".to_string(),
        source: "const signUpWithGoogle = async () => {\n    return continueWithGoogle()\n  }"
            .to_string(),
        loc: 3,
        param_count: 0,
        start_line: 3,
        end_line: 5,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let target = FileRecord {
        file_path: method.file_path.clone(),
        source: source.to_string(),
        language: method.language.clone(),
        methods: vec![method.clone()],
    };
    let contract_test = FileRecord {
            file_path: "tests/auth_continue_flow.test.js".to_string(),
            source: "const filePath = path.join(__dirname, '../ui/src/hooks/useAuth.ts');\nconst content = fs.readFileSync(filePath, 'utf-8');\nexpect(content).toContain('return continueWithGoogle()');"
                .to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let graph = SymbolGraph::new(".");
    let files = vec![target.clone(), contract_test];
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = file_content_test_contract_evidence(&target, &method, &index);

    assert_eq!(evidence.len(), 1);
    let dossier = build_method_dossier_with_index(&target, &method, &index, Vec::new());
    assert!(!dossier.repository_private_unused_candidate);
}

#[test]
fn external_configuration_and_object_values_establish_framework_contracts() {
    let config_source = "import { defineConfig } from 'vite';\nfunction createSanitizePlugin() {\n  return {\n    transform() {}\n  };\n}\nexport default defineConfig({ plugins: [createSanitizePlugin()] });";
    let factory = MethodRecord {
        name: "createSanitizePlugin".to_string(),
        file_path: "ui/vite.config.ts".to_string(),
        source: "function createSanitizePlugin() {\n  return {\n    transform() {}\n  };\n}"
            .to_string(),
        loc: 5,
        param_count: 0,
        start_line: 2,
        end_line: 6,
        is_exported: false,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let mut transform = factory.clone();
    transform.name = "transform".to_string();
    transform.source = "transform() {}".to_string();
    transform.start_line = 4;
    transform.end_line = 4;
    let config_file = FileRecord {
        file_path: factory.file_path.clone(),
        source: config_source.to_string(),
        language: factory.language.clone(),
        methods: vec![factory, transform.clone()],
    };

    let adapter_source = "import { createClient } from '@supabase/supabase-js';\nconst storageAdapter = {\n  getItem() {}\n};\nexport const client = createClient(url, key, {\n  auth: { storage: storageAdapter }\n});";
    let adapter_file = FileRecord {
        file_path: "src/supabase.ts".to_string(),
        source: adapter_source.to_string(),
        language: "typescript".to_string(),
        methods: Vec::new(),
    };
    let mut graph = SymbolGraph::new(".");
    for (file, local_name, module) in [
        (&config_file, "defineConfig", "vite"),
        (&adapter_file, "createClient", "@supabase/supabase-js"),
    ] {
        graph.add_file(crate::types::LocalFileSymbols {
            file_path: file.file_path.clone(),
            definitions: Vec::new(),
            imports: vec![crate::types::ImportRecord {
                local_name: local_name.to_string(),
                source_module: module.to_string(),
                imported_name: local_name.to_string(),
            }],
            exports: Vec::new(),
            modules: Vec::new(),
            types: Vec::new(),
            references: Vec::new(),
        });
    }
    let files = vec![config_file.clone(), adapter_file.clone()];
    let index = build_dossier_repository_index(&graph, &files);

    assert!(external_framework_contract_evidence(&config_file, &transform, &index).is_some());
    assert!(external_object_escape_evidence(&adapter_file, "storageAdapter", &index).is_some());
}

#[test]
fn namespace_framework_calls_and_actual_entrypoint_surfaces_are_consumed() {
    let source = "import * as Sentry from '@sentry/cloudflare';\nexport default Sentry.withSentry(\n  () => ({}),\n  { async fetch() { return new Response('ok'); } },\n);";
    let default_method = MethodRecord {
        name: "default".to_string(),
        file_path: "worker/src/index.ts".to_string(),
        source: "export default Sentry.withSentry(\n  () => ({})".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 2,
        end_line: 3,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let mut stale_helper = default_method.clone();
    stale_helper.name = "staleHelper".to_string();
    stale_helper.source = "function staleHelper() {}".to_string();
    stale_helper.start_line = 6;
    stale_helper.end_line = 6;
    stale_helper.is_exported = false;
    let file = FileRecord {
        file_path: default_method.file_path.clone(),
        source: format!("{source}\nfunction staleHelper() {{}}"),
        language: default_method.language.clone(),
        methods: vec![default_method.clone(), stale_helper.clone()],
    };
    let mut graph = SymbolGraph::new(".");
    graph.add_file(crate::types::LocalFileSymbols {
        file_path: file.file_path.clone(),
        definitions: Vec::new(),
        imports: vec![crate::types::ImportRecord {
            local_name: "Sentry".to_string(),
            source_module: "@sentry/cloudflare".to_string(),
            imported_name: "*".to_string(),
        }],
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    });
    let files = [file.clone()];
    let index = build_dossier_repository_index(&graph, &files);

    let spans = external_call_line_spans(&file, &index);
    assert!(spans.iter().any(|(_, _, call)| call == "Sentry.withSentry"));
    let default_dossier =
        build_method_dossier_with_index(&file, &default_method, &index, Vec::new());
    let helper_dossier = build_method_dossier_with_index(&file, &stale_helper, &index, Vec::new());
    assert!(!default_dossier.repository_private_unused_candidate);
    assert!(
        default_dossier
            .context
            .contains("external framework configuration evidence")
    );
    assert!(helper_dossier.repository_private_unused_candidate);
}

#[test]
fn exported_object_member_dossier_preserves_dynamic_enumeration_evidence() {
    let source =
        "export const affiliateLinks = {\n  optionalBuilder: () => 'https://example.com',\n};\n";
    let test_source = "test('all builders', () => {\n  Object.entries(affiliateLinks).map(([key, builder]) => {\n    const value = builder();\n    return [key, value];\n  });\n});\n";
    let files = [
        FileRecord {
            file_path: "src/affiliates.ts".to_string(),
            source: source.to_string(),
            language: "typescript".to_string(),
            methods: Vec::new(),
        },
        FileRecord {
            file_path: "tests/affiliates.test.ts".to_string(),
            source: test_source.to_string(),
            language: "typescript".to_string(),
            methods: Vec::new(),
        },
    ];
    let graph = SymbolGraph::new(".");
    let index = build_dossier_repository_index(&graph, &files);

    let evidence = object_enumeration_evidence("affiliateLinks", &index);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].contains("Object.entries(affiliateLinks)"));
    assert!(evidence[0].contains("const value = builder();"));
    assert!(
        object_enumeration_invocation_proof("affiliateLinks", &evidence)
            .is_some_and(|proof| proof.contains("every member participates"))
    );

    let enumeration_only =
        ["Object.entries(affiliateLinks).map(([key, builder]) => key);".to_string()];
    assert!(object_enumeration_invocation_proof("affiliateLinks", &enumeration_only).is_none());
}

#[test]
fn exported_method_dossier_preserves_file_level_test_contract_without_inventing_a_caller() {
    let mut gallery = method("export default function ComponentGallery() { return null; }");
    gallery.name = "ComponentGallery".to_string();
    gallery.file_path = "src/components/ComponentGallery.tsx".to_string();
    gallery.language = "typescript".to_string();
    gallery.is_exported = true;
    let gallery_file = FileRecord {
        file_path: gallery.file_path.clone(),
        source: gallery.source.clone(),
        language: gallery.language.clone(),
        methods: vec![gallery.clone()],
    };
    let test_file = FileRecord {
            file_path: "tests/verify_component_gallery.test.js".to_string(),
            source: "test('ComponentGallery.tsx should exist', () => expect('ComponentGallery.tsx').toBeTruthy());\n".to_string(),
            language: "javascript".to_string(),
            methods: Vec::new(),
        };
    let files = [gallery_file.clone(), test_file];
    let graph = SymbolGraph::new(".");
    let index = build_dossier_repository_index(&graph, &files);
    assert!(contains_identifier(
        files[1].source.as_str(),
        "ComponentGallery.tsx"
    ));
    assert!(is_test_path(&files[1].file_path.to_lowercase()));
    assert!(
        !index.source_locations("ComponentGallery.tsx").is_empty(),
        "filename source lookup returned no locations"
    );
    assert_eq!(file_test_contract_evidence(&gallery_file, &index).len(), 1);

    let dossier = build_method_dossier_with_index(&gallery_file, &gallery, &index, Vec::new());

    assert!(gallery.references.is_empty());
    assert!(
        dossier
            .context
            .contains("file-level test contract evidence (not a method caller)")
    );
    assert!(
        dossier
            .context
            .contains("ComponentGallery.tsx should exist"),
        "{}",
        dossier.context
    );
}
