use super::super::typescript_model_output::pinned_compiler_version;
use super::*;
use serde_json::{Value, json};

fn bindings(project_model: &str) -> CompilerInputBindings<'_> {
    CompilerInputBindings {
        project_model,
        runtime: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        installation: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    }
}

fn output() -> Value {
    json!({
        "schemaVersion": 2,
        "typescriptVersion": pinned_compiler_version().unwrap(),
        "worlds": [{
            "rootConfig": "tsconfig.json", "rootSourceFiles": ["src/main.ts"],
            "inferred": false, "configClosure": ["tsconfig.json"], "diagnostics": [],
            "projects": [{
                "configPath": "tsconfig.json", "configReads": ["tsconfig.json"],
                "diagnostics": [], "effectiveOptions": {"strict": true},
                "references": [], "selectedSourceFiles": ["src/main.ts"]
            }],
            "selectedSourceFiles": ["src/main.ts"], "ignoredSourceFiles": []
        }]
    })
}

fn plans(value: &Value) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    plans_from_output(
        &serde_json::to_vec(value).unwrap(),
        &["tsconfig.json".to_string()],
        &["src/main.ts".to_string()],
        &"a".repeat(64),
        &bindings(&"b".repeat(64)),
        |_| Ok(()),
    )
}

#[test]
fn configured_world_is_qualified_and_bound_to_source_and_runtime() {
    let result = plans(&output()).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].compiler_project,
        Some(RepositoryPath("tsconfig.json".to_string()))
    );
    assert_eq!(
        result[0].dimensions["source_snapshot_sha256"],
        "a".repeat(64)
    );
    assert_eq!(
        result[0].dimensions["discovery_scope"],
        "conventional-config-roots-and-compiler-reference-closure"
    );
    let changed = plans_from_output(
        &serde_json::to_vec(&output()).unwrap(),
        &["tsconfig.json".to_string()],
        &["src/main.ts".to_string()],
        &"c".repeat(64),
        &bindings(&"b".repeat(64)),
        |_| Ok(()),
    )
    .unwrap();
    assert_ne!(result[0].identity, changed[0].identity);
    let mut options_changed = output();
    options_changed["worlds"][0]["projects"][0]["effectiveOptions"] = json!({"strict": false});
    assert_ne!(
        result[0].identity,
        plans(&options_changed).unwrap()[0].identity
    );
}

#[test]
fn execution_runtime_and_installation_are_independently_bound_to_world_identity() {
    let value = output();
    let original = plans(&value).unwrap();
    assert_eq!(
        original[0].dimensions["compiler_runtime_sha256"],
        "c".repeat(64)
    );
    assert_eq!(
        original[0].dimensions["compiler_installation_sha256"],
        "d".repeat(64)
    );
    for change_runtime in [false, true] {
        let mut changed =
            bindings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        if change_runtime {
            changed.runtime = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        } else {
            changed.installation =
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        }
        let generated = plans_from_output(
            &serde_json::to_vec(&value).unwrap(),
            &["tsconfig.json".into()],
            &["src/main.ts".into()],
            &"a".repeat(64),
            &changed,
            |_| Ok(()),
        )
        .unwrap();
        assert_ne!(original[0].identity, generated[0].identity);
    }
}

#[test]
fn diagnostics_and_bad_provider_identity_fail_without_inferred_fallback() {
    for (key, value) in [
        ("schemaVersion", json!(1)),
        ("typescriptVersion", json!("0.0.0")),
        ("unknown", json!(true)),
    ] {
        let mut model = output();
        model[key] = value;
        assert!(plans(&model).is_err());
    }
    let mut model = output();
    model["worlds"][0]["projects"][0]["diagnostics"] = json!([{"message":"bad config"}]);
    assert!(plans(&model).unwrap_err().contains("identity or options"));
}

#[test]
fn invented_omitted_overlapping_and_unsorted_sources_are_rejected() {
    for value in [
        json!([]),
        json!(["src/other.ts"]),
        json!(["src/main.ts", "src/main.ts"]),
        json!(["../src/main.ts"]),
    ] {
        let mut model = output();
        model["worlds"][0]["selectedSourceFiles"] = value;
        assert!(plans(&model).is_err());
    }
    let mut model = output();
    model["worlds"][0]["ignoredSourceFiles"] = json!(["src/main.ts"]);
    assert!(plans(&model).is_err());
    let mut model = output();
    model["worlds"][0]["projects"][0]["selectedSourceFiles"] = json!([]);
    assert!(plans(&model).unwrap_err().contains("source union"));
}

#[test]
fn omitted_or_disconnected_project_closure_is_rejected() {
    let mut model = output();
    model["worlds"][0]["projects"][0]["references"] = json!(["tsconfig.other.json"]);
    assert!(plans(&model).unwrap_err().contains("referenced project"));
    let mut other = model["worlds"][0]["projects"][0].clone();
    other["configPath"] = json!("tsconfig.other.json");
    other["configReads"] = json!(["tsconfig.other.json"]);
    other["references"] = json!([]);
    other["selectedSourceFiles"] = json!([]);
    model["worlds"][0]["projects"][0]["references"] = json!([]);
    model["worlds"][0]["projects"]
        .as_array_mut()
        .unwrap()
        .push(other);
    model["worlds"][0]["configClosure"] = json!(["tsconfig.json", "tsconfig.other.json"]);
    assert!(plans(&model).unwrap_err().contains("disconnected"));
}

#[test]
fn config_reads_must_exist_and_cover_discovered_configurations() {
    let bytes = serde_json::to_vec(&output()).unwrap();
    let failure = plans_from_output(
        &bytes,
        &[
            "tsconfig.base.json".to_string(),
            "tsconfig.json".to_string(),
        ],
        &["src/main.ts".to_string()],
        &"a".repeat(64),
        &bindings(&"b".repeat(64)),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(failure.contains("omitted"));
    let failure = plans_from_output(
        &bytes,
        &["tsconfig.json".to_string()],
        &["src/main.ts".to_string()],
        &"a".repeat(64),
        &bindings(&"b".repeat(64)),
        |path| {
            if path == "tsconfig.json" {
                Err("missing config".to_string())
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(failure, "missing config");
}

#[test]
fn compiler_inferred_project_is_exact_and_not_a_failed_config_replacement() {
    let mut model = output();
    let world = &mut model["worlds"][0];
    world["rootConfig"] = Value::Null;
    world["inferred"] = json!(true);
    world["configClosure"] = json!([]);
    world["projects"][0]["configPath"] = Value::Null;
    world["projects"][0]["configReads"] = json!([]);
    let result = plans_from_output(
        &serde_json::to_vec(&model).unwrap(),
        &[],
        &["src/main.ts".to_string()],
        &"a".repeat(64),
        &bindings(&"b".repeat(64)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(result[0].compiler_project.is_none());
    assert!(matches!(
        result[0].compiler_query,
        SemanticIndexerCompilerQuery::ExactSources { .. }
    ));
    assert!(plans(&model).unwrap_err().contains("omitted"));
}

#[test]
fn duplicate_worlds_and_unrelated_partial_scan_worlds_are_handled_explicitly() {
    let mut model = output();
    let world = model["worlds"][0].clone();
    model["worlds"].as_array_mut().unwrap().push(world);
    assert!(plans(&model).unwrap_err().contains("identity"));
    let mut unrelated = model["worlds"][0].clone();
    unrelated["rootConfig"] = json!("tsconfig.other.json");
    unrelated["rootSourceFiles"] = json!([]);
    unrelated["configClosure"] = json!(["tsconfig.other.json"]);
    unrelated["selectedSourceFiles"] = json!([]);
    unrelated["ignoredSourceFiles"] = json!(["src/main.ts"]);
    unrelated["projects"][0]["configPath"] = json!("tsconfig.other.json");
    unrelated["projects"][0]["configReads"] = json!(["tsconfig.other.json"]);
    unrelated["projects"][0]["selectedSourceFiles"] = json!([]);
    model["worlds"][1] = unrelated;
    assert_eq!(
        plans_from_output(
            &serde_json::to_vec(&model).unwrap(),
            &[
                "tsconfig.json".to_string(),
                "tsconfig.other.json".to_string()
            ],
            &["src/main.ts".to_string()],
            &"a".repeat(64),
            &bindings(&"b".repeat(64)),
            |_| Ok(())
        )
        .unwrap()
        .len(),
        1
    );
}
