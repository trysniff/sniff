use super::*;
use crate::benchmark::{
    HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION, HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
    HistoricalV2PublicSurfaceDelta, HistoricalV2QualificationOutcome,
};

#[test]
fn exact_upstream_recipe_schema_is_committed() {
    let config = r#"{"base_image_name":"node_16","install":["npm install"],"log_parser":"parse_log_js_4","test_cmd":"cd packages/core && npx jest --no-color"}"#;
    let payload = payload(Some(config));
    let identity = fixture_identity(&payload);
    let qualification = fixture_qualification(&identity);

    let recipe = prepare_validated_test_recipe(&payload, &identity, &qualification).unwrap();

    assert!(matches!(
        &recipe.outcome,
        HistoricalV2TestRecipeOutcome::Selected {
            base_image_name,
            install_commands,
            test_commands,
            log_parser,
        } if base_image_name == "node_16"
            && install_commands == &["npm install"]
            && test_commands == &["cd packages/core && npx jest --no-color"]
            && log_parser == "parse_log_js_4"
    ));
    let mut changed = recipe.clone();
    changed.test_recipe_sha256 = digest('f');
    assert_ne!(recipe, changed);
}

#[test]
fn upstream_test_command_lists_preserve_order() {
    let config = r#"{"base_image_name":"c:latest","install":["cmake ."],"log_parser":"parse_log_cmake","test_cmd":["ctest -R unit","ctest -R integration"]}"#;
    let payload = payload(Some(config));
    let identity = fixture_identity(&payload);
    let recipe =
        prepare_validated_test_recipe(&payload, &identity, &fixture_qualification(&identity))
            .unwrap();
    assert!(matches!(
        recipe.outcome,
        HistoricalV2TestRecipeOutcome::Selected { test_commands, .. }
            if test_commands == ["ctest -R unit", "ctest -R integration"]
    ));
}

#[test]
fn missing_recipe_is_a_typed_terminal_exclusion() {
    let payload = payload(None);
    let identity = fixture_identity(&payload);
    let qualification = fixture_qualification(&identity);
    let recipe = prepare_validated_test_recipe(&payload, &identity, &qualification).unwrap();
    assert_eq!(
        recipe.outcome,
        HistoricalV2TestRecipeOutcome::Excluded {
            reason: HistoricalV2TestRecipeExclusionReason::MissingInstallConfig,
        }
    );
}

#[test]
fn unknown_upstream_fields_fail_closed() {
    let config = r#"{"base_image_name":"rust_1","install":[],"log_parser":"rust","test_cmd":"cargo test","labels":["forbidden"]}"#;
    let payload = payload(Some(config));
    let identity = fixture_identity(&payload);
    let qualification = fixture_qualification(&identity);
    let recipe = prepare_validated_test_recipe(&payload, &identity, &qualification).unwrap();
    assert_eq!(
        recipe.outcome,
        HistoricalV2TestRecipeOutcome::Excluded {
            reason: HistoricalV2TestRecipeExclusionReason::InvalidInstallConfigJson,
        }
    );
}

#[test]
fn unsafe_names_and_commands_are_typed_exclusions() {
    let bad_name = payload(Some(
        r#"{"base_image_name":"node 16","install":[],"log_parser":"js","test_cmd":"npm test"}"#,
    ));
    let identity = fixture_identity(&bad_name);
    assert_eq!(
        prepare_validated_test_recipe(&bad_name, &identity, &fixture_qualification(&identity))
            .unwrap()
            .outcome,
        HistoricalV2TestRecipeOutcome::Excluded {
            reason: HistoricalV2TestRecipeExclusionReason::InvalidBaseImageName,
        }
    );

    let nul = payload(Some(
        "{\"base_image_name\":\"node_16\",\"install\":[],\"log_parser\":\"js\",\"test_cmd\":\"npm\\u0000test\"}",
    ));
    let identity = fixture_identity(&nul);
    assert_eq!(
        prepare_validated_test_recipe(&nul, &identity, &fixture_qualification(&identity))
            .unwrap()
            .outcome,
        HistoricalV2TestRecipeOutcome::Excluded {
            reason: HistoricalV2TestRecipeExclusionReason::InvalidTestCommand,
        }
    );
}

#[test]
fn cross_slot_or_unqualified_inputs_are_rejected() {
    let payload = payload(Some(
        r#"{"base_image_name":"go_1","install":[],"log_parser":"go","test_cmd":"go test ./..."}"#,
    ));
    let mut identity = fixture_identity(&payload);
    let qualification = fixture_qualification(&identity);
    identity.instance_id = "another".to_string();
    assert!(
        prepare_validated_test_recipe(&payload, &identity, &qualification)
            .unwrap_err()
            .contains("cross slot")
    );

    let identity = fixture_identity(&payload);
    let mut qualification = fixture_qualification(&identity);
    qualification.outcome = HistoricalV2QualificationOutcome::Excluded {
        reasons: Vec::new(),
    };
    assert!(
        prepare_validated_test_recipe(&payload, &identity, &qualification)
            .unwrap_err()
            .contains("requires a qualified")
    );
}

fn payload(config: Option<&str>) -> HistoricalV2SelectedPayload {
    HistoricalV2SelectedPayload {
        language: "rust".to_string(),
        slot_number: 1,
        source_shard_index: 0,
        source_row_index: 0,
        global_row_index: 7,
        instance_id: "owner__repo-1".to_string(),
        patch: "diff --git a/src/lib.rs b/src/lib.rs".to_string(),
        patch_sha256: digest('1'),
        install_config: config.map(str::to_string),
        install_config_sha256: config.map(|value| sha256(value.as_bytes())),
        test_patch: None,
        test_patch_sha256: None,
        payload_sha256: digest('2'),
    }
}

fn fixture_identity(payload: &HistoricalV2SelectedPayload) -> HistoricalV2AssessmentIdentity {
    HistoricalV2AssessmentIdentity {
        schema_version: HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
        assessment_identity_contract: "fixture".to_string(),
        protocol_sha256: digest('3'),
        frame_sha256: digest('4'),
        exclusion_manifest_sha256: digest('5'),
        selection_sha256: digest('6'),
        payloads_sha256: digest('7'),
        language: payload.language.clone(),
        slot_number: payload.slot_number,
        global_row_index: payload.global_row_index,
        instance_id: payload.instance_id.clone(),
        canonical_repository: "github.com/owner/repo".to_string(),
        pull_number: 1,
        base_revision: "a".repeat(40),
        rank_sha256: digest('8'),
        payload_sha256: payload.payload_sha256.clone(),
        historical_patch_sha256: payload.patch_sha256.clone(),
        install_config_sha256: payload.install_config_sha256.clone(),
        test_patch_sha256: None,
        materialization_sha256: digest('9'),
        test_materialization_sha256: None,
        source_census_sha256: digest('a'),
        base_source_snapshot_sha256: digest('b'),
        patched_source_snapshot_sha256: digest('c'),
        semantic_census_sha256: digest('d'),
        base_semantic_snapshot_sha256: digest('e'),
        patched_semantic_snapshot_sha256: digest('f'),
        assessment_identity_sha256: digest('0'),
    }
}

fn fixture_qualification(identity: &HistoricalV2AssessmentIdentity) -> HistoricalV2Qualification {
    HistoricalV2Qualification {
        schema_version: HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
        qualification_contract: "fixture".to_string(),
        assessment_identity_sha256: identity.assessment_identity_sha256.clone(),
        language: identity.language.clone(),
        slot_number: identity.slot_number,
        patch_changed_paths: vec!["src/lib.rs".to_string()],
        git_changed_paths: vec!["src/lib.rs".to_string()],
        qualified_paths: Vec::new(),
        repository_production_method_count: 20,
        repository_method_minimum: 20,
        repository_method_maximum: 500,
        changed_methods: Vec::new(),
        unresolved_changed_methods: Vec::new(),
        production_non_whitespace_lines_before: 10,
        production_non_whitespace_lines_after: 9,
        public_surface: HistoricalV2PublicSurfaceDelta {
            base_entries: Vec::new(),
            patched_entries: Vec::new(),
            removed: Vec::new(),
            added: Vec::new(),
            changed: Vec::new(),
            preserved: true,
            delta_sha256: digest('1'),
        },
        outcome: HistoricalV2QualificationOutcome::Qualified,
        qualification_sha256: digest('2'),
    }
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}
