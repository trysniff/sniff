use super::*;

const PLATFORMS: &str = r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true},{"GOOS":"wasip1","GOARCH":"wasm","CgoSupported":false,"FirstClass":false}]"#;

fn domain(custom: &[&str], architecture: &[&str]) -> GoConstraintTagDomain {
    GoConstraintTagDomain {
        custom_build_tags: custom.iter().map(|tag| (*tag).to_string()).collect(),
        architecture_feature_tags: architecture.iter().map(|tag| (*tag).to_string()).collect(),
        standalone_source_repository_paths: Vec::new(),
    }
}

#[test]
fn neutral_go_contexts_keep_every_platform_cgo_and_custom_tag_assignment() {
    let contexts =
        parse_go_dist_variants(PLATFORMS, &domain(&["enterprise", "purego"], &[])).unwrap();
    assert_eq!(contexts.len(), 12);
    assert!(contexts.windows(2).all(|pair| pair[0] < pair[1]));
    for (goos, goarch, cgo) in [
        ("linux", "amd64", false),
        ("linux", "amd64", true),
        ("wasip1", "wasm", false),
    ] {
        for tags in [
            vec![],
            vec!["enterprise"],
            vec!["purego"],
            vec!["enterprise", "purego"],
        ] {
            assert!(contexts.iter().any(|context| {
                context.goos == goos
                    && context.goarch == goarch
                    && context.cgo_enabled == cgo
                    && context.build_tags == tags
                    && context.architecture == GoCompilerArchitecture::Default
                    && context.query == GoCompilerQuery::ModulePackages
            }));
        }
    }
}

#[test]
fn neutral_go_architecture_contexts_are_not_collapsed_into_default() {
    let contexts = parse_go_dist_variants(
        PLATFORMS,
        &domain(&[], &["amd64.v3", "wasm.satconv", "wasm.signext"]),
    )
    .unwrap();
    assert_eq!(contexts.len(), 10);
    for value in ["v2", "v3"] {
        assert!(contexts.iter().any(|context| context.architecture
            == GoCompilerArchitecture::Explicit {
                environment_variable: "GOAMD64".to_string(),
                value: value.to_string()
            }));
    }
    assert!(contexts.iter().any(|context| context.architecture
        == GoCompilerArchitecture::Explicit {
            environment_variable: "GOWASM".to_string(),
            value: "satconv,signext".to_string()
        }));
}

#[test]
fn neutral_go_discovery_rejects_invalid_repeated_or_broken_platforms() {
    for platforms in [
        "[]",
        "null",
        "{}",
        r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true,"Broken":true}]"#,
        r#"[{"GOOS":"Linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true}]"#,
        r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true},{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true}]"#,
    ] {
        assert!(
            parse_go_dist_variants(platforms, &domain(&[], &[])).is_err(),
            "{platforms}"
        );
    }
}

#[test]
fn neutral_go_discovery_rejects_unbounded_or_reordered_domains_without_sampling() {
    assert!(parse_go_dist_variants(PLATFORMS, &domain(&["z", "a"], &[])).is_err());
    assert!(
        parse_go_dist_variants(PLATFORMS, &domain(&[], &["wasm.signext", "wasm.satconv"])).is_err()
    );
    let mut tags = domain(&[], &[]);
    tags.custom_build_tags = (0..15).map(|index| format!("tag{index:02}")).collect();
    assert!(
        parse_go_dist_variants(PLATFORMS, &tags)
            .unwrap_err()
            .contains("strict limit")
    );
}

#[test]
fn neutral_go_constraint_staging_keeps_protocol_bytes_and_refuses_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("runtime");
    fs::create_dir(&cache).unwrap();
    let sources = ["api/api.go".to_string()];
    let invocation = stage_go_constraint_invocation(root.path(), &cache, &sources).unwrap();
    assert_eq!(
        invocation.helper_repository_path,
        "runtime/sniff-source-facts.go"
    );
    assert_eq!(
        invocation.request_repository_path,
        "runtime/sniff-source-facts-request.json"
    );
    assert_eq!(
        fs::read(root.path().join(invocation.helper_repository_path)).unwrap(),
        GO_CONSTRAINT_HELPER_SOURCE.as_bytes()
    );
    assert_eq!(
        fs::read(root.path().join(invocation.request_repository_path)).unwrap(),
        br#"{"schema_version":2,"source_repository_paths":["api/api.go"]}"#
    );
    assert!(
        stage_go_constraint_invocation(root.path(), &cache, &sources)
            .err()
            .unwrap()
            .contains("already exists")
    );
}

#[test]
fn neutral_go_pipeline_keeps_frozen_original_helper_digest() {
    let expected = if GO_CONSTRAINT_HELPER_SOURCE.contains("\r\n") {
        "40ab1d8ec55afbb4a24505967870edf45749ae69566e05737677c0970369a7df"
    } else {
        "6b264afe50bdbcd04209ed7b8f59e843899aeb766a9a53fbc0768cfdbaedaf11"
    };
    assert_eq!(
        go_project_model_pipeline_identity(&"a".repeat(64), &"b".repeat(64)).unwrap(),
        expected
    );
}
