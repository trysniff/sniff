use super::*;

#[test]
fn dossier_carries_typed_stale_discard_signature_proof() {
    let file_source = "def invoke(value):\n    return _legacy_callback(value, object(), object())\n\ndef _legacy_callback(value, event, context):\n    _ = (event, context)\n    return value.strip()\n";
    let caller = MethodRecord {
        name: "invoke".to_string(),
        file_path: "src/api.py".to_string(),
        source: "def invoke(value):\n    return _legacy_callback(value, object(), object())\n"
            .to_string(),
        loc: 2,
        param_count: 1,
        start_line: 1,
        end_line: 2,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let target = MethodRecord {
            name: "_legacy_callback".to_string(),
            file_path: "src/api.py".to_string(),
            source: "def _legacy_callback(value, event, context):\n    _ = (event, context)\n    return value.strip()\n"
                .to_string(),
            loc: 3,
            param_count: 3,
            start_line: 4,
            end_line: 6,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![Reference {
                file_path: "src/api.py".to_string(),
                line: 2,
                snippet: "return _legacy_callback(value, object(), object())".to_string(),
            }],
            real_ref_count: 1,
        };
    let file = FileRecord {
        file_path: "src/api.py".to_string(),
        source: file_source.to_string(),
        language: "python".to_string(),
        methods: vec![caller, target.clone()],
    };

    let dossier = build_method_dossier(
        &file,
        &target,
        &SymbolGraph::new("."),
        std::slice::from_ref(&file),
        vec![],
    );

    assert!(dossier.stale_discard_signature_proof.is_some());
    assert!(
        dossier
            .context
            .contains("closed-world stale discarded-parameter signature proof: established")
    );
}

#[test]
fn restricted_rust_visibility_and_unrelated_same_name_exports_are_not_contracts() {
    let target = MethodRecord {
        name: "helper".to_string(),
        file_path: "src/target.rs".to_string(),
        source: "pub(super) fn helper() {}".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 1,
        end_line: 1,
        is_exported: true,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let target_file = file(target.clone());
    let mut graph = SymbolGraph::new(".");
    for path in ["src/target.rs", "src/unrelated.rs"] {
        graph.add_file(crate::types::LocalFileSymbols {
            file_path: path.to_string(),
            definitions: vec![SymbolDefinition {
                id: 1,
                name: "helper".to_string(),
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
                exported_name: "helper".to_string(),
                local_symbol_name: "helper".to_string(),
                source_module: None,
                source_symbol_name: None,
            }],
            modules: vec![],
            types: vec![],
            references: vec![],
        });
    }

    let dossier = build_method_dossier(
        &target_file,
        &target,
        &graph,
        std::slice::from_ref(&target_file),
        vec![],
    );

    assert!(dossier.repository_private_unused_candidate);
    assert!(
        dossier
            .context
            .contains("exports and re-exports involving this method: none established")
    );
}

#[test]
fn dossier_expands_dynamic_call_through_resolved_upstream_callers() {
    let target = MethodRecord {
        name: "print_case_results".to_string(),
        file_path: "src/reporting.py".to_string(),
        source: "def print_case_results(results):\n    print(results)\n".to_string(),
        loc: 2,
        param_count: 1,
        start_line: 1,
        end_line: 2,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let target_file = FileRecord {
        file_path: target.file_path.clone(),
        source: target.source.clone(),
        language: target.language.clone(),
        methods: vec![target.clone()],
    };
    let finalize = MethodRecord {
            name: "finalize".to_string(),
            file_path: "src/eval_gates.py".to_string(),
            source: "def finalize(runtime, results):\n    runtime.eval_reporting.print_case_results(results)\n"
                .to_string(),
            loc: 2,
            param_count: 2,
            start_line: 10,
            end_line: 11,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![Reference {
                file_path: "src/eval_pipeline.py".to_string(),
                line: 21,
                snippet: "return finalize(runtime, results)".to_string(),
            }],
            real_ref_count: 1,
        };
    let finalize_file = FileRecord {
        file_path: finalize.file_path.clone(),
        source: format!("{}{}", "\n".repeat(9), finalize.source),
        language: finalize.language.clone(),
        methods: vec![finalize],
    };
    let run = MethodRecord {
        name: "run".to_string(),
        file_path: "src/eval_pipeline.py".to_string(),
        source: "def run(runtime, results):\n    return finalize(runtime, results)\n".to_string(),
        loc: 2,
        param_count: 2,
        start_line: 20,
        end_line: 21,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![Reference {
            file_path: "src/eval.py".to_string(),
            line: 31,
            snippet: "return run(runtime=sys.modules[__name__])".to_string(),
        }],
        real_ref_count: 1,
    };
    let run_file = FileRecord {
        file_path: run.file_path.clone(),
        source: format!("{}{}", "\n".repeat(19), run.source),
        language: run.language.clone(),
        methods: vec![run],
    };
    let main_method = MethodRecord {
        name: "main".to_string(),
        file_path: "src/eval.py".to_string(),
        source: "def main():\n    return run(runtime=sys.modules[__name__])\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 30,
        end_line: 31,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let main_file = FileRecord {
        file_path: main_method.file_path.clone(),
        source: format!("{}{}", "\n".repeat(29), main_method.source),
        language: main_method.language.clone(),
        methods: vec![main_method],
    };
    let files = vec![target_file.clone(), finalize_file, run_file, main_file];

    let dossier = build_method_dossier(
        &target_file,
        &target,
        &SymbolGraph::new("."),
        &files,
        vec![],
    );

    assert!(
        dossier
            .context
            .contains("lexical call-site provenance chains")
    );
    assert!(dossier.context.contains("eval_gates.py::finalize"));
    assert!(dossier.context.contains("eval_pipeline.py::run"));
    assert!(dossier.context.contains("eval.py::main"));
    assert!(dossier.context.contains("runtime=sys.modules[__name__]"));
}

#[test]
fn dossier_does_not_repeat_graph_resolved_calls_as_lexical_candidates() {
    let mut method =
        method("def public_api():\n    from .impl import run as _run\n    return _run()\n");
    method.references = vec![Reference {
        file_path: "src/api.py".to_string(),
        line: 6,
        snippet: "return public_api()".to_string(),
    }];
    method.real_ref_count = 1;
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

    assert_eq!(method.references.len(), 1);
    assert_eq!(method.references[0].file_path, "src/api.py");
    assert!(dossier.context.contains(
        "lexical call-site candidates not confirmed by the symbol graph: none established"
    ));
}

#[test]
fn dossier_excludes_same_name_calls_resolved_to_another_definition() {
    use crate::types::{
        LocalFileSymbols, ResolvedSymbol, SymbolDefinition, SymbolKind, SymbolReference,
    };

    let mut target = method("def _normalize_repo_path(path):\n    return path.strip()\n");
    target.name = "_normalize_repo_path".to_string();
    target.is_exported = false;
    let target_file = file(target.clone());

    let other_definition = MethodRecord {
        name: "_normalize_repo_path".to_string(),
        file_path: "src/recommendations.py".to_string(),
        source: "def _normalize_repo_path(path):\n    return path.replace('\\\\', '/')\n"
            .to_string(),
        loc: 2,
        param_count: 1,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 1,
    };
    let caller = MethodRecord {
        name: "normalize_input".to_string(),
        file_path: "src/recommendations.py".to_string(),
        source: "def normalize_input(path):\n    return _normalize_repo_path(path)  # protocol\n"
            .to_string(),
        loc: 2,
        param_count: 1,
        start_line: 4,
        end_line: 5,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let other_file = FileRecord {
        file_path: "src/recommendations.py".to_string(),
        source: format!("{}\n{}", other_definition.source, caller.source),
        language: "python".to_string(),
        methods: vec![other_definition, caller],
    };
    let mut graph = SymbolGraph::new(".");
    graph.files.insert(
        other_file.file_path.clone(),
        LocalFileSymbols {
            file_path: other_file.file_path.clone(),
            definitions: vec![SymbolDefinition {
                id: 7,
                name: "_normalize_repo_path".to_string(),
                kind: SymbolKind::Function,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                owner_type: None,
                receiver_type: None,
                value_type: None,
            }],
            imports: vec![],
            exports: vec![],
            modules: vec![],
            types: vec![],
            references: vec![SymbolReference {
                name: "_normalize_repo_path".to_string(),
                line: 5,
                snippet: "return _normalize_repo_path(path)  # protocol".to_string(),
                is_member_call: false,
                is_callable_value: false,
                resolved_symbol: Some(ResolvedSymbol::Local(7)),
            }],
        },
    );

    let files = vec![target_file.clone(), other_file];
    let dossier = build_method_dossier(&target_file, &target, &graph, &files, vec![]);

    assert!(dossier.context.contains(
        "lexical call-site candidates not confirmed by the symbol graph: none established"
    ));
    assert!(
        !dossier
            .context
            .contains("src/recommendations.py:5: return _normalize_repo_path(path)")
    );
    assert!(
        dossier
            .context
            .contains("interface/protocol/override evidence: none established")
    );
}

#[test]
fn example_role_is_explicit_contract_evidence() {
    assert!(role_contract_evidence(FileRole::Example).contains("human consumer"));
    assert!(role_contract_evidence(FileRole::Script).contains("zero internal callers"));
}

#[test]
fn ordinary_symbol_history_is_not_a_compatibility_contract() {
    assert!(!history_describes_compatibility(
        "56642a7 Extract release note rendering"
    ));
    assert!(history_describes_compatibility(
        "12abc34 Preserve legacy alias during migration"
    ));
}

#[test]
fn documentation_search_does_not_attach_comments_across_blank_lines() {
    let source = "# unrelated module note\n\ndef public_api():\n    return 1\n";
    let method = MethodRecord {
        start_line: 3,
        end_line: 4,
        source: "def public_api():\n    return 1\n".to_string(),
        ..method("def public_api():\n    return 1\n")
    };
    let file = FileRecord {
        file_path: "src/api.py".to_string(),
        source: source.to_string(),
        language: "python".to_string(),
        methods: vec![method.clone()],
    };

    let graph = SymbolGraph::new("");
    let files = [file.clone()];
    let index = build_dossier_repository_index(&graph, &files);
    assert!(method_documentation(&file, &method, &index).is_empty());
}

#[test]
#[ignore = "set SNIFF_LIVE_DOSSIER_REPO to inspect a real repository without LLM calls"]
fn live_repository_reports_largest_method_dossiers() {
    let root = std::env::var("SNIFF_LIVE_DOSSIER_REPO")
        .expect("SNIFF_LIVE_DOSSIER_REPO must name a repository");
    let config = crate::config::ResolvedConfig::default();
    let paths = crate::walker::walk(&root, &config).expect("walk live repository");
    let mut context_paths = paths.clone();
    context_paths
        .extend(crate::walker::walk_evidence(&root, &config).expect("walk live evidence files"));
    context_paths.sort();
    context_paths.dedup();
    if let Ok(expected_evidence_path) = std::env::var("SNIFF_LIVE_DOSSIER_EXPECT_EVIDENCE_PATH") {
        let expected = expected_evidence_path.replace('\\', "/").to_lowercase();
        assert!(
            context_paths
                .iter()
                .any(|path| { path.replace('\\', "/").to_lowercase().ends_with(&expected) }),
            "live evidence inventory did not include {expected_evidence_path}"
        );
        println!("LIVE_PROFILE evidence path present: {expected_evidence_path}");
    }
    let mut files = paths
        .iter()
        .map(|path| crate::parser::parse_file_checked(path).expect("parse live source"))
        .collect::<Vec<_>>();
    let context_files = context_paths
        .iter()
        .map(|path| crate::parser::parse_file_checked(path).expect("parse live context"))
        .collect::<Vec<_>>();
    let mut graph = SymbolGraph::new(&root);
    for path in &context_paths {
        graph.add_file(crate::parser::parse_file_symbols_checked(path).expect("index live source"));
    }
    graph.resolve_all();
    if let Ok(debug_symbols) = std::env::var("SNIFF_LIVE_DOSSIER_GRAPH_DEBUG") {
        let debug_symbols = debug_symbols
            .split(';')
            .map(str::trim)
            .filter(|symbol| !symbol.is_empty())
            .collect::<std::collections::HashSet<_>>();
        let mut matching_references = 0usize;
        for (path, symbols) in &graph.files {
            for definition in symbols
                .definitions
                .iter()
                .filter(|definition| debug_symbols.contains(definition.name.as_str()))
            {
                println!(
                    "GRAPH_DEBUG definition {}:{} kind={:?} owner={:?} package={:?}",
                    path,
                    definition.start_line,
                    definition.kind,
                    definition.owner_type,
                    symbols.modules
                );
            }
            let references = symbols.references.iter().filter(|reference| {
                reference
                    .name
                    .rsplit('.')
                    .next()
                    .is_some_and(|leaf| debug_symbols.contains(leaf))
            });
            for reference in references {
                matching_references += 1;
                if matching_references <= 20 {
                    println!(
                        "GRAPH_DEBUG reference {}:{} name={} resolved={:?} package={:?} imports={:?}",
                        path,
                        reference.line,
                        reference.name,
                        reference.resolved_symbol,
                        symbols.modules,
                        symbols
                            .imports
                            .iter()
                            .filter(|import| {
                                debug_symbols.contains(import.local_name.as_str())
                                    || debug_symbols.contains(import.imported_name.as_str())
                            })
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        println!("GRAPH_DEBUG matching references: {matching_references}");
    }
    crate::callgraph::build_references_with_context(&mut files, &context_files, &graph);
    let callees = crate::callgraph::build_callee_context(&files, &graph);
    println!(
        "LIVE_PROFILE inventory files={} methods={}",
        files.len(),
        files.iter().map(|file| file.methods.len()).sum::<usize>()
    );
    let selected_files = std::env::var("SNIFF_LIVE_DOSSIER_FILES")
        .ok()
        .map(|value| {
            value
                .split(';')
                .map(|path| path.trim().replace('\\', "/").to_lowercase())
                .filter(|path| !path.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let selected_methods = std::env::var("SNIFF_LIVE_DOSSIER_METHOD")
        .ok()
        .map(|value| {
            value
                .split(';')
                .map(str::trim)
                .filter(|method| !method.is_empty())
                .map(str::to_string)
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();
    let expected_context = std::env::var("SNIFF_LIVE_DOSSIER_EXPECT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let print_context = std::env::var("SNIFF_LIVE_DOSSIER_PRINT").as_deref() == Ok("1");
    let print_candidates = std::env::var("SNIFF_LIVE_DOSSIER_CANDIDATES").as_deref() == Ok("1");
    let minimum_callers = std::env::var("SNIFF_LIVE_DOSSIER_MIN_CALLERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let production_paths = files
        .iter()
        .map(|file| file.file_path.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut dossier_files = files.clone();
    dossier_files.extend(
        context_files
            .iter()
            .filter(|file| !production_paths.contains(file.file_path.as_str()))
            .cloned(),
    );
    let dossier_index = build_dossier_repository_index(&graph, &dossier_files);
    let mut sizes = files
            .iter()
            .filter(|file| {
                selected_files.is_empty()
                    || selected_files.iter().any(|selected| {
                        file.file_path
                            .replace('\\', "/")
                            .to_lowercase()
                            .ends_with(selected)
                    })
            })
            .flat_map(|file| {
                file.methods.iter().map(|method| {
                    let method_callees = callees
                        .get(&(
                            method.file_path.clone(),
                            method.name.clone(),
                            method.start_line,
                        ))
                        .cloned()
                        .unwrap_or_default();
                    let dossier = build_method_dossier_with_index(
                        file,
                        method,
                        &dossier_index,
                        method_callees,
                    );
                    let is_selected = selected_methods.contains(&method.name);
                    if is_selected {
                        if let Some(minimum) = minimum_callers {
                            assert!(
                                method.references.len() >= minimum,
                                "{}::{} has {} resolved callers; expected at least {minimum}",
                                method.file_path,
                                method.name,
                                method.references.len()
                            );
                        }
                        if let Some(expected) = expected_context.as_deref() {
                            assert!(
                                dossier.context.contains(expected),
                                "{}::{} dossier did not contain expected evidence: {expected}",
                                method.file_path,
                                method.name
                            );
                        }
                        if print_context {
                            println!("{}", dossier.context);
                        }
                    }
                    let repository_chars = dossier
                        .context
                        .split_once("- repository evidence:\n")
                        .map(|(_, repository)| repository.len())
                        .unwrap_or(0);
                    let rendered_caller_chars =
                        super::super::super::method_review::render_reference_context(
                            &method.references,
                        )
                            .len();
                    if is_selected {
                        println!(
                            "SELECTED\t{}\trepository={}\tcallers={}/{}/rendered={}\tcallees={}\t{}:{}\t{}",
                            dossier.context.len(),
                            repository_chars,
                            method.references.len(),
                            method
                                .references
                                .iter()
                                .map(|reference| reference.snippet.len())
                                .sum::<usize>(),
                            rendered_caller_chars,
                            dossier.callees.len(),
                            method.file_path,
                            method.start_line,
                            method.name
                        );
                    }
                    if print_candidates && dossier.repository_private_unused_candidate {
                        println!(
                            "PRIVATE_UNUSED\t{}:{}\t{}",
                            method.file_path, method.start_line, method.name
                        );
                    }
                    (
                        dossier.context.len(),
                        method.file_path.clone(),
                        method.name.clone(),
                        method.start_line,
                        method.references.len(),
                        method
                            .references
                            .iter()
                            .map(|reference| reference.snippet.len())
                            .sum::<usize>(),
                        dossier.callees.len(),
                        repository_chars,
                        rendered_caller_chars,
                    )
                })
            })
            .collect::<Vec<_>>();
    sizes.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (
        size,
        path,
        method,
        line,
        callers,
        caller_chars,
        callees,
        repository_chars,
        rendered_caller_chars,
    ) in sizes.into_iter().take(30)
    {
        println!(
            "{size}\trepository={repository_chars}\tcallers={callers}/{caller_chars}/rendered={rendered_caller_chars}\tcallees={callees}\t{path}:{line}\t{method}"
        );
    }
}
