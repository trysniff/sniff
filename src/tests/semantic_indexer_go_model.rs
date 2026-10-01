use super::*;
use crate::compiler_go_model::GoCompilerArchitecture;
use tempfile::TempDir;

fn platform() -> &'static str {
    r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true}]"#
}

#[test]
fn normal_exact_source_queries_retain_each_declared_compiler_context() {
    let tags = GoConstraintTagDomain {
        custom_build_tags: vec!["feature".to_string()],
        architecture_feature_tags: vec!["amd64.v2".to_string()],
        standalone_source_repository_paths: vec!["gen.go".to_string()],
    };
    let contexts = contexts(platform(), &tags).unwrap();
    let packages = contexts
        .iter()
        .filter(|context| matches!(context.query, GoCompilerQuery::ModulePackages))
        .count();
    assert_eq!(contexts.len(), packages * 2);
    assert!(contexts.iter().any(|context| matches!(
        context.architecture,
        GoCompilerArchitecture::Explicit { .. }
    )));
    assert!(contexts.iter().any(|context| context.cgo_enabled
        && context.build_tags == ["feature"]
        && matches!(context.query, GoCompilerQuery::StandaloneSource { .. })));
}

#[test]
fn exact_generator_contexts_are_not_limited_to_linux() {
    let platforms = r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true},{"GOOS":"windows","GOARCH":"arm64","CgoSupported":true,"FirstClass":true}]"#;
    let tags = GoConstraintTagDomain {
        custom_build_tags: vec!["feature".to_string()],
        architecture_feature_tags: Vec::new(),
        standalone_source_repository_paths: vec!["gen.go".to_string()],
    };
    let contexts = contexts(platforms, &tags).unwrap();
    for platform in ["linux", "windows"] {
        for cgo in [false, true] {
            for build_tags in [Vec::new(), vec!["feature".to_string()]] {
                assert!(contexts.iter().any(|context| context.goos == platform
                    && context.cgo_enabled == cgo
                    && context.build_tags == build_tags
                    && matches!(context.query, GoCompilerQuery::StandaloneSource { .. })));
            }
        }
    }
}

#[test]
fn combined_exact_query_domain_has_no_sampling_or_repeated_query_escape() {
    let tags = GoConstraintTagDomain {
        custom_build_tags: Vec::new(),
        architecture_feature_tags: Vec::new(),
        standalone_source_repository_paths: vec!["gen.go".to_string(); GO_VARIANT_LIMIT],
    };
    assert!(
        contexts(platform(), &tags)
            .unwrap_err()
            .contains("strict limit")
    );
    let tags = GoConstraintTagDomain {
        standalone_source_repository_paths: vec!["gen.go".to_string(); 2],
        ..tags
    };
    assert!(
        contexts(platform(), &tags)
            .unwrap_err()
            .contains("repeated")
    );
}

#[tokio::test]
async fn normal_go_discovery_rejects_stale_ast_before_any_compiler_execution() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/model\ngo 1.23\n",
    )
    .unwrap();
    let path = root.path().join("main.go");
    fs::write(&path, "package model\nfunc value() int { return 1 }\n").unwrap();
    let file = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
    fs::write(&path, "package model\nfunc value() int { return 2 }\n").unwrap();
    let failure = run_required_indexers_with_discovered_worlds(
        root.path(),
        std::slice::from_ref(&file),
        std::slice::from_ref(&file),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn normal_scan_discovers_every_go_context_without_git_or_model_calls() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/model\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        root.path().join("main.go"),
        "package model\nfunc value() int { return 1 }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("feature_test.go"),
        "//go:build feature\n\npackage model\nfunc helper() int { return value() }\n",
    )
    .unwrap();
    let files = ["main.go", "feature_test.go"]
        .iter()
        .map(|path| {
            crate::parser::parse_file_checked(root.path().join(path).to_str().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
    let outcome = run_required_indexers_with_discovered_worlds(root.path(), &files, &files)
        .await
        .unwrap();
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    let crate::semantic_index::SemanticIndexSet::Qualified { variants } =
        &outcome.indexes[&SemanticIndexerKind::Go]
    else {
        panic!("normal Go scan used an unqualified graph")
    };
    assert!(variants.len() > 2);
    let mut sdk_bindings = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for qualified in variants.values() {
        let crate::semantic_index::SemanticIndexVariant::Qualified { dimensions, .. } =
            &qualified.index.variant
        else {
            panic!("Go compiler world lost qualification")
        };
        sdk_bindings.insert(dimensions["compiler_sdk_sha256"].clone());
        let context: serde_json::Value =
            serde_json::from_str(&dimensions["compiler_context"]).unwrap();
        tags.insert(context["build_tags"].to_string());
        if context["build_tags"] == serde_json::json!([]) {
            assert!(
                qualified
                    .ignored_documents
                    .contains(&RepositoryPath("feature_test.go".to_string()))
            );
        } else {
            assert!(
                qualified
                    .index
                    .documents
                    .contains_key(&RepositoryPath("feature_test.go".to_string()))
            );
            assert!(
                !qualified
                    .ignored_documents
                    .contains(&RepositoryPath("feature_test.go".to_string()))
            );
        }
    }
    assert_eq!(sdk_bindings.len(), 1);
    assert_eq!(sdk_bindings.first().unwrap().len(), 64);
    assert_eq!(
        tags,
        BTreeSet::from(["[]".to_string(), "[\"feature\"]".to_string()])
    );
    let evidence = crate::semantic_method_join::build_compiler_method_evidence(
        root.path(),
        &files,
        &outcome.indexes,
    )
    .unwrap();
    assert_eq!(evidence.contexts.len(), 2);
    assert_eq!(
        repository_snapshot::repository_content_digest(root.path()).unwrap(),
        before
    );
    assert!(!root.path().join(".git").exists());
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}
