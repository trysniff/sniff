use super::super::{RankedSourceCandidate, SourceAssessmentEvidence, SourceRepositoryDraft};
use super::*;

const RESPONSE: &[u8] =
    include_bytes!("../sniffbench/historical-v3-blind-prior-identities-response.json");

#[test]
fn pinned_graphql_projection_has_twelve_immutable_identities() {
    assert_eq!(sha256(RESPONSE), GRAPHQL_RESPONSE_SHA256);
    let nodes = parse_graphql_nodes(RESPONSE).unwrap();
    assert_eq!(nodes.len(), 12);
    assert_eq!(nodes["R_kgDOSZZcTQ"].database_id, 1234590797);
    assert_eq!(nodes["R_kgDOSZZcTQ"].created_at, "2026-05-10T11:40:34Z");
    assert_eq!(
        nodes["R_kgDOSZZcTQ"].name_with_owner,
        "albinchristo04/BassRide"
    );
}

#[test]
fn selected_witness_rejects_changed_id_date_source_and_cutoff() {
    let payload = r#"{"id":123,"node_id":"R_test","created_at":"2020-01-01T00:00:00Z","full_name":"Owner/Repo"}"#;
    let assessment = SourceCandidateAssessment {
        candidate: RankedSourceCandidate {
            rank: 1,
            repository: "github.com/owner/repo".to_string(),
            rank_sha256: "a".repeat(64),
        },
        selection_quota_language: "kotlin".to_string(),
        observed_method_count: Some(2),
        facts: None,
        evidence: vec![SourceAssessmentEvidence {
            kind: SourceAssessmentEvidenceKind::RawSource,
            source: "https://api.github.com/repos/owner/repo".to_string(),
            observed_at: "unix:1".to_string(),
            payload: payload.to_string(),
            payload_sha256: sha256(payload.as_bytes()),
        }],
        disposition: Some(SourceSelectionDisposition::Selected),
        exclusion_reason: None,
        selected_repository: Some(SourceRepositoryDraft {
            repository: "https://github.com/owner/repo".to_string(),
            revision: "b".repeat(40),
            license_path: "LICENSE".to_string(),
            selection_language: "kotlin".to_string(),
            observed_method_count: 2,
            context_paths: Vec::new(),
        }),
    };
    let mut nodes = BTreeMap::from([(
        "R_test".to_string(),
        GraphqlRepository {
            id: "R_test".to_string(),
            database_id: 123,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            name_with_owner: "Owner/Repo".to_string(),
        },
    )]);
    let cutoff = parse_utc_second(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC).unwrap();
    let witness = witness_selected(&assessment, "component", &nodes, cutoff).unwrap();
    assert_eq!(witness.canonical_repository, "owner/repo");
    nodes.get_mut("R_test").unwrap().database_id = 124;
    assert!(witness_selected(&assessment, "component", &nodes, cutoff).is_err());
    nodes.get_mut("R_test").unwrap().database_id = 123;
    nodes.get_mut("R_test").unwrap().created_at = "2020-01-02T00:00:00Z".to_string();
    assert!(witness_selected(&assessment, "component", &nodes, cutoff).is_err());
    nodes.get_mut("R_test").unwrap().created_at = "2020-01-01T00:00:00Z".to_string();
    nodes.get_mut("R_test").unwrap().name_with_owner = "Other/Repo".to_string();
    assert!(witness_selected(&assessment, "component", &nodes, cutoff).is_err());
    nodes.get_mut("R_test").unwrap().name_with_owner = "Owner/Repo".to_string();
    assert!(witness_selected(&assessment, "component", &nodes, cutoff + 1).is_ok());
    assert!(witness_selected(&assessment, "component", &nodes, 0).is_err());
    let mut wrong_source = assessment;
    wrong_source.evidence[0].source = "https://api.github.com/repos/other/repo".to_string();
    assert!(witness_selected(&wrong_source, "component", &nodes, cutoff).is_err());
}

#[test]
fn graphql_projection_rejects_null_duplicate_and_missing_nodes() {
    let original: serde_json::Value = serde_json::from_slice(RESPONSE).unwrap();
    let mut missing = original.clone();
    missing["nodes"].as_array_mut().unwrap().pop();
    assert!(parse_graphql_nodes(&serde_json::to_vec(&missing).unwrap()).is_err());

    let mut null = original.clone();
    null["nodes"][0] = serde_json::Value::Null;
    assert!(parse_graphql_nodes(&serde_json::to_vec(&null).unwrap()).is_err());

    let mut duplicate = original;
    duplicate["nodes"][1]["id"] = duplicate["nodes"][0]["id"].clone();
    assert!(parse_graphql_nodes(&serde_json::to_vec(&duplicate).unwrap()).is_err());
}

#[test]
#[ignore = "requires the exact public blind-OSS source-seal archive extracted on disk"]
fn verifies_real_blind_prior_temporal_proof() {
    let path = std::env::var_os("SNIFF_BLIND_SEAL_PATH")
        .expect("set SNIFF_BLIND_SEAL_PATH to the extracted blind-source-seal.json");
    let path = Path::new(&path);
    let proof = derive_blind_prior_temporal_proof(path, RESPONSE).unwrap();
    assert_eq!(proof.witnesses.len(), 12);
    assert_eq!(proof.selection_recorded_at_utc, "2026-08-13T11:59:38Z");
    assert_eq!(proof.latest_witness_utc, "2026-05-10T11:40:34Z");
    validate_blind_prior_temporal_proof(path, RESPONSE, &proof).unwrap();
    let mut tampered = proof;
    tampered.witnesses[0].github_repository_id += 1;
    assert!(
        validate_blind_prior_temporal_proof(path, RESPONSE, &tampered)
            .unwrap_err()
            .contains("does not replay")
    );
}
