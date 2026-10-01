use super::super::go_model_output::parse_world;
use super::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn fixture() -> TempDir {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/model\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        root.path().join("main.go"),
        "package model\nfunc mainValue() int { return 1 }\n",
    )
    .unwrap();
    root
}

fn context() -> GoCompilerContext {
    GoCompilerContext {
        goos: "linux".to_string(),
        goarch: "amd64".to_string(),
        cgo_enabled: false,
        build_tags: Vec::new(),
        architecture: GoCompilerArchitecture::Default,
        query: GoCompilerQuery::ModulePackages,
    }
}

fn environment(context: &GoCompilerContext) -> BTreeMap<String, String> {
    let mut environment = explicit_environment(context);
    environment
        .entry("GOAMD64".to_string())
        .or_insert_with(|| "v1".to_string());
    environment
}

fn output(files: &[&str], tests: &[&str], ignored: &[&str]) -> String {
    serde_json::json!({"Dir":"/workspace", "ImportPath":"example.test/model", "Name":"model", "Module":{"Path":"example.test/model", "Dir":"/workspace", "GoMod":"/workspace/go.mod", "Main":true}, "GoFiles": files, "TestGoFiles": tests, "IgnoredGoFiles": ignored}).to_string()
}

fn census(
    root: &Path,
    contexts: Vec<GoCompilerContext>,
    outputs: Vec<String>,
) -> (GoRepositoryScope, Vec<ModuleCensus>) {
    let scope = super::super::go_model_scope::discover(root).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let worlds = contexts
        .iter()
        .zip(outputs)
        .map(|(context, stdout)| {
            parse_world(
                root,
                module.clone(),
                context.clone(),
                environment(context),
                &scope.modules[&module.project],
                &stdout,
            )
            .unwrap()
        })
        .collect();
    (
        scope,
        vec![ModuleCensus {
            module,
            expected_contexts: contexts,
            worlds,
        }],
    )
}

fn plans(
    scope: &GoRepositoryScope,
    census: &[ModuleCensus],
    required: &[&str],
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    plans_from_census(
        census,
        scope,
        &required
            .iter()
            .map(|path| RepositoryPath((*path).to_string()))
            .collect(),
        &"a".repeat(64),
        &CompilerInputBindings {
            project_model: &"b".repeat(64),
            executable: &"c".repeat(64),
            sdk: &"d".repeat(64),
            dependencies: &"e".repeat(64),
        },
    )
}

#[test]
fn source_equivalent_architecture_contexts_remain_distinct_worlds() {
    let root = fixture();
    let mut explicit = context();
    explicit.architecture = GoCompilerArchitecture::Explicit {
        environment_variable: "GOAMD64".to_string(),
        value: "v1".to_string(),
    };
    let (scope, census) = census(
        root.path(),
        vec![context(), explicit],
        vec![output(&["main.go"], &[], &[]); 2],
    );
    let plans = plans(&scope, &census, &["main.go"]).unwrap();
    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].selected_documents, plans[1].selected_documents);
    assert_eq!(plans[0].environment, plans[1].environment);
    assert_ne!(plans[0].identity, plans[1].identity);
}

#[test]
fn normal_world_identity_binds_sdk_inputs_and_requires_a_valid_digest() {
    let root = fixture();
    let (scope, census) = census(
        root.path(),
        vec![context()],
        vec![output(&["main.go"], &[], &[])],
    );
    let required = BTreeSet::from([RepositoryPath("main.go".to_string())]);
    let resolve = |sdk: &str| {
        plans_from_census(
            &census,
            &scope,
            &required,
            &"a".repeat(64),
            &CompilerInputBindings {
                project_model: &"b".repeat(64),
                executable: &"c".repeat(64),
                sdk,
                dependencies: &"e".repeat(64),
            },
        )
    };
    let first = resolve(&"d".repeat(64)).unwrap().remove(0);
    let second = resolve(&"e".repeat(64)).unwrap().remove(0);
    assert_eq!(first.dimensions["compiler_sdk_sha256"], "d".repeat(64));
    assert_ne!(first.identity, second.identity);
    for invalid in ["", "unknown", &"D".repeat(64), &"g".repeat(64)] {
        assert!(resolve(invalid).unwrap_err().contains("provenance digest"));
    }
}

#[test]
fn compiler_tests_refine_production_plans_without_losing_required_coverage() {
    let root = fixture();
    fs::write(
        root.path().join("main_test.go"),
        "package model\nfunc helper() int { return 1 }\n",
    )
    .unwrap();
    let (scope, census) = census(
        root.path(),
        vec![context()],
        vec![output(&["main.go"], &["main_test.go"], &[])],
    );
    let plan = plans(&scope, &census, &["main.go", "main_test.go"])
        .unwrap()
        .remove(0);
    assert_eq!(
        plan.selected_documents,
        BTreeSet::from([RepositoryPath("main.go".to_string())])
    );
    assert!(
        plan.ignored_documents
            .contains(&RepositoryPath("main_test.go".to_string()))
    );
}

#[test]
fn normal_world_identity_binds_dependency_contents_and_validates_the_commitment() {
    let root = fixture();
    let (scope, census) = census(
        root.path(),
        vec![context()],
        vec![output(&["main.go"], &[], &[])],
    );
    let required = BTreeSet::from([RepositoryPath("main.go".to_string())]);
    let resolve = |dependencies: &str| {
        plans_from_census(
            &census,
            &scope,
            &required,
            &"a".repeat(64),
            &CompilerInputBindings {
                project_model: &"b".repeat(64),
                executable: &"c".repeat(64),
                sdk: &"d".repeat(64),
                dependencies,
            },
        )
    };
    let first = resolve(&"e".repeat(64)).unwrap().remove(0);
    let second = resolve(&"f".repeat(64)).unwrap().remove(0);
    assert_eq!(
        first.dimensions["compiler_dependencies_sha256"],
        "e".repeat(64)
    );
    assert_ne!(first.identity, second.identity);
    assert_eq!(first.selected_documents, second.selected_documents);
    assert!(resolve("unknown").is_err());
}

#[test]
fn missing_repeated_or_reassigned_context_receipts_fail_closed() {
    let root = fixture();
    let (scope, mut census) = census(
        root.path(),
        vec![context()],
        vec![output(&["main.go"], &[], &[])],
    );
    census[0].worlds[0]
        .environment
        .insert("GOOS".to_string(), "windows".to_string());
    assert!(
        plans(&scope, &census, &["main.go"])
            .unwrap_err()
            .contains("assignment")
    );
    census[0].worlds[0].environment = environment(&context());
    census[0].expected_contexts.push(context());
    assert!(plans(&scope, &census, &["main.go"]).is_err());
    census[0].expected_contexts.pop();
    census[0].worlds.clear();
    assert!(plans(&scope, &census, &["main.go"]).is_err());
}

#[test]
fn unavailable_source_is_not_absence_or_clean() {
    let root = fixture();
    let (scope, census) = census(
        root.path(),
        vec![context()],
        vec![output(&[], &[], &["main.go"])],
    );
    assert!(
        plans(&scope, &census, &["main.go"])
            .unwrap_err()
            .contains("omitted required source coverage")
    );
}

#[test]
fn accepted_empty_contexts_are_not_collapsed_out_of_a_covered_census() {
    let root = fixture();
    let mut tagged = context();
    tagged.build_tags.push("feature".to_string());
    let (scope, census) = census(
        root.path(),
        vec![context(), tagged],
        vec![String::new(), output(&["main.go"], &[], &[])],
    );
    let plans = plans(&scope, &census, &["main.go"]).unwrap();
    assert_eq!(plans.len(), 2);
    assert_eq!(
        plans
            .iter()
            .filter(|plan| plan.selected_documents.is_empty())
            .count(),
        1
    );
}

#[test]
fn malformed_tail_cannot_be_reclassified_as_a_rejected_context() {
    let root = fixture();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let raw = format!(
        "{}{{",
        serde_json::json!({"Dir":"/workspace", "ImportPath":"example.test/model", "Name":"", "Incomplete":true, "Error":{"Err":"bad context"}})
    );
    assert!(
        parse_world(
            root.path(),
            module,
            context(),
            environment(&context()),
            &scope.modules[&RepositoryPath("go.mod".to_string())],
            &raw
        )
        .is_err()
    );
}

#[test]
fn dependency_scope_retains_a_neighbor_rejected_in_every_context() {
    let root = fixture();
    let (_, mut ledger) = census(
        root.path(),
        vec![context()],
        vec![output(&["main.go"], &[], &[])],
    );
    fs::create_dir(root.path().join("neighbor")).unwrap();
    fs::write(
        root.path().join("neighbor/go.mod"),
        "module example.test/neighbor\ngo 1.23\n",
    )
    .unwrap();
    fs::write(root.path().join("neighbor/main.go"), "package neighbor\n").unwrap();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/neighbor".to_string(),
        project: RepositoryPath("neighbor/go.mod".to_string()),
    };
    let rejected = parse_world(root.path(), module.clone(), context(), environment(&context()), &scope.modules[&module.project],
        &serde_json::json!({"Dir":"/workspace/neighbor", "ImportPath":"example.test/neighbor", "Incomplete":true, "Error":{"Err":"rejected neighbor"}}).to_string()).unwrap();
    assert!(matches!(rejected.outcome, ContextOutcome::Rejected { .. }));
    ledger.push(ModuleCensus {
        module,
        expected_contexts: vec![context()],
        worlds: vec![rejected],
    });
    let plans = plans(&scope, &ledger, &["main.go"]).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(
        plans[0].compiler_project,
        Some(RepositoryPath("go.mod".to_string()))
    );
    assert_eq!(
        plans[0].dimensions["compiler_dependency_projects"],
        r#"["go.mod","neighbor/go.mod"]"#
    );
    let roots = super::super::go_runner::dependency_module_roots(
        super::super::pinned_indexer(super::super::SemanticIndexerKind::Go).unwrap(),
        root.path(),
        &plans,
    )
    .unwrap();
    assert_eq!(roots, vec![".", "neighbor"]);
}

#[test]
fn rejected_streams_still_validate_complete_rows_and_typed_test_facts() {
    let root = fixture();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let rejected = serde_json::json!({"Dir":"/workspace", "ImportPath":"example.test/model", "Incomplete":true, "Error":{"Err":"compiler context rejected"}});
    let mut foreign: serde_json::Value =
        serde_json::from_str(&output(&["main.go"], &[], &[])).unwrap();
    foreign["Module"]["Path"] = "example.test/foreign".into();
    let raw = format!("{foreign}{rejected}");
    assert!(
        parse_world(
            root.path(),
            module.clone(),
            context(),
            environment(&context()),
            &scope.modules[&module.project],
            &raw
        )
        .is_err()
    );
    let mut invalid_test = rejected.clone();
    invalid_test["TestGoFiles"] = serde_json::json!([42]);
    assert!(
        parse_world(
            root.path(),
            module.clone(),
            context(),
            environment(&context()),
            &scope.modules[&module.project],
            &invalid_test.to_string()
        )
        .is_err()
    );
    let witness = parse_world(
        root.path(),
        module.clone(),
        context(),
        environment(&context()),
        &scope.modules[&module.project],
        &rejected.to_string(),
    )
    .unwrap();
    assert!(matches!(witness.outcome, ContextOutcome::Rejected { .. }));
}

#[test]
fn rejected_streams_do_not_hide_repeated_or_conflicting_source_facts() {
    let root = fixture();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let mut rejected: serde_json::Value =
        serde_json::from_str(&output(&["main.go"], &[], &[])).unwrap();
    rejected["Incomplete"] = true.into();
    rejected["Error"] = serde_json::json!({"Err":"compiler context rejected"});
    let repeated = format!("{rejected}{rejected}");
    let mut conflicting = rejected.clone();
    conflicting["IgnoredGoFiles"] = serde_json::json!(["main.go"]);
    let mut duplicate_source = rejected.clone();
    duplicate_source["GoFiles"] = serde_json::json!(["main.go", "main.go"]);
    for raw in [
        repeated,
        conflicting.to_string(),
        duplicate_source.to_string(),
    ] {
        assert!(
            parse_world(
                root.path(),
                module.clone(),
                context(),
                environment(&context()),
                &scope.modules[&module.project],
                &raw,
            )
            .is_err(),
            "accepted invalid rejected stream: {raw}"
        );
    }
}

#[test]
fn rejected_exact_source_queries_still_require_one_package() {
    let root = fixture();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let mut exact = context();
    exact.query = GoCompilerQuery::StandaloneSource {
        source_repository_path: "main.go".to_string(),
    };
    let rejected =
        serde_json::json!({"Incomplete":true, "Error":{"Err":"exact query rejected"}}).to_string();
    let owned = &scope.modules[&module.project];
    assert!(matches!(
        parse_world(
            root.path(),
            module.clone(),
            exact.clone(),
            environment(&exact),
            owned,
            &rejected
        )
        .unwrap()
        .outcome,
        ContextOutcome::Rejected { .. }
    ));
    for raw in [String::new(), format!("{rejected}{rejected}")] {
        assert!(
            parse_world(
                root.path(),
                module.clone(),
                exact.clone(),
                environment(&exact),
                owned,
                &raw
            )
            .unwrap_err()
            .contains("one compiler package")
        );
    }
}

#[test]
fn rejected_contexts_remain_committed_witnesses_without_becoming_graphs() {
    let root = fixture();
    let mut rejected = context();
    rejected.build_tags.push("unsupported".to_string());
    let rejection = serde_json::json!({"Dir":"/workspace", "ImportPath":"example.test/model", "Name":"", "Incomplete":true, "Error":{"Err":"compiler context rejected"}}).to_string();
    let (scope, mut census) = census(
        root.path(),
        vec![context(), rejected],
        vec![output(&["main.go"], &[], &[]), rejection],
    );
    let first = plans(&scope, &census, &["main.go"]).unwrap();
    assert_eq!(first.len(), 1);
    let ContextOutcome::Rejected { diagnostics } = &mut census[0].worlds[1].outcome else {
        panic!("context lost its rejection")
    };
    diagnostics[0].push_str(" changed");
    let second = plans(&scope, &census, &["main.go"]).unwrap();
    assert_ne!(
        first[0].dimensions["project_model_census_sha256"],
        second[0].dimensions["project_model_census_sha256"]
    );
    assert_ne!(first[0].identity, second[0].identity);
}

#[test]
fn temporary_snapshot_paths_do_not_change_normal_world_identity() {
    let first = fixture();
    let second = fixture();
    let actual_output = |root: &Path| {
        let mut output: serde_json::Value =
            serde_json::from_str(&output(&["main.go"], &[], &[])).unwrap();
        output["Dir"] = root.to_string_lossy().into_owned().into();
        output["Module"]["Dir"] = root.to_string_lossy().into_owned().into();
        output["Module"]["GoMod"] = root.join("go.mod").to_string_lossy().into_owned().into();
        output.to_string()
    };
    let (scope_a, census_a) = census(
        first.path(),
        vec![context()],
        vec![actual_output(first.path())],
    );
    let (scope_b, census_b) = census(
        second.path(),
        vec![context()],
        vec![actual_output(second.path())],
    );
    assert_eq!(
        plans(&scope_a, &census_a, &["main.go"]).unwrap(),
        plans(&scope_b, &census_b, &["main.go"]).unwrap()
    );
}

#[test]
fn wrong_module_or_import_directory_ownership_fails_before_planning() {
    let root = fixture();
    let scope = super::super::go_model_scope::discover(root.path()).unwrap();
    let module = ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let mut raw: serde_json::Value = serde_json::from_str(&output(&["main.go"], &[], &[])).unwrap();
    raw["ImportPath"] = "example.test/other".into();
    assert!(
        parse_world(
            root.path(),
            module.clone(),
            context(),
            environment(&context()),
            &scope.modules[&module.project],
            &raw.to_string()
        )
        .is_err()
    );
    raw["ImportPath"] = "example.test/model".into();
    raw["Module"]["Main"] = false.into();
    assert!(
        parse_world(
            root.path(),
            module.clone(),
            context(),
            environment(&context()),
            &scope.modules[&module.project],
            &raw.to_string()
        )
        .is_err()
    );
}
