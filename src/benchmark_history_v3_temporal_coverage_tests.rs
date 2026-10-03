use super::super::{
    BlindPriorRepositoryWitness, HistoricalV3PriorArtifactBinding, HistoricalV3PriorV2PrWitness,
    SmallPriorRepositoryWitness, prepare_historical_v3_prior_identity_seal,
};
use super::*;

fn fixture() -> (
    HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3PriorV2TemporalProof,
    BlindPriorTemporalProof,
    SmallPriorTemporalProof,
) {
    let seal = prepare_historical_v3_prior_identity_seal(
        [
            ("blind-oss-v1", vec!["old/blind"]),
            ("historical-v1", vec!["old/unknown"]),
            ("historical-v2", vec!["old/pr"]),
            ("intentional-boundary-v1", vec!["old/unknown"]),
            ("slopcodebench", vec!["old/harness", "old/problems"]),
            ("synthetic-gold-v1", vec!["old/gold"]),
        ]
        .into_iter()
        .map(|(id, names)| HistoricalV3PriorArtifactBinding {
            artifact_id: id.to_string(),
            artifact_sha256: "a".repeat(64),
            repositories: names.into_iter().map(str::to_string).collect(),
        })
        .collect(),
    )
    .unwrap();
    let v2 = HistoricalV3PriorV2TemporalProof {
        schema_version: 1,
        contract: "fixture-v2".to_string(),
        prior_seal_sha256: seal.seal_sha256.clone(),
        frame_file_sha256: "a".repeat(64),
        selection_file_sha256: "a".repeat(64),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses: vec![HistoricalV3PriorV2PrWitness {
            canonical_repository: "old/pr".to_string(),
            global_row_index: 42,
            pull_number: 5,
            created_at_utc: "2026-01-01T00:00:00Z".to_string(),
        }],
        latest_witness_utc: "2026-01-01T00:00:00Z".to_string(),
        proof_sha256: "b".repeat(64),
    };
    let blind = BlindPriorTemporalProof {
        contract: "fixture-blind".to_string(),
        source_seal_file_sha256: "a".repeat(64),
        source_seal_commitment_sha256: "a".repeat(64),
        selection_audit_file_sha256: "a".repeat(64),
        selection_recorded_at_utc: "2026-08-13T00:00:00Z".to_string(),
        graphql_response_sha256: "a".repeat(64),
        graphql_query_sha256: "a".repeat(64),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses: vec![BlindPriorRepositoryWitness {
            canonical_repository: "old/blind".to_string(),
            source_component: "original-component".to_string(),
            github_repository_id: 123,
            github_node_id: "original-node".to_string(),
            created_at_utc: "2026-01-01T00:00:00Z".to_string(),
            raw_source_payload_sha256: "c".repeat(64),
        }],
        latest_witness_utc: "2026-01-01T00:00:00Z".to_string(),
        proof_sha256: "c".repeat(64),
    };
    let small = SmallPriorTemporalProof {
        contract: "fixture-small".to_string(),
        policy_sha256: "a".repeat(64),
        exclusions_sha256: "a".repeat(64),
        response_sha256: "a".repeat(64),
        query_sha256: "a".repeat(64),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses: [
            ("slopcodebench", "old/harness"),
            ("slopcodebench", "old/problems"),
            ("synthetic-gold-v1", "old/gold"),
        ]
        .into_iter()
        .map(|(partition, name)| SmallPriorRepositoryWitness {
            source_partition: partition.to_string(),
            repository: name.to_string(),
            github_repository_id: 456,
            github_node_id: "original-small-node".to_string(),
            created_at_utc: "2026-01-01T00:00:00Z".to_string(),
            source_revision: "d".repeat(40),
            gold_tree_oid: None,
        })
        .collect(),
        proof_sha256: "d".repeat(64),
    };
    (seal, v2, blind, small)
}

#[test]
fn records_original_obligations_without_counting_retrieval_as_proof() {
    let (seal, v2, blind, small) = fixture();
    let coverage = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    assert_eq!(coverage.obligations.len(), 7);
    assert_eq!(coverage.source_replayed_obligation_count, 5);
    assert_eq!(coverage.unresolved_obligation_count, 2);
    assert_eq!(coverage.fully_witnessed_repository_count, 5);
    assert_eq!(coverage.unresolved_repository_count, 1);
    assert!(!coverage.publication_qualified);
    for row in &coverage.obligations {
        assert_eq!(row.source_artifact_sha256, "a".repeat(64));
        if row.prior_name == "old/unknown" {
            assert_eq!(
                row.evidence,
                HistoricalV3PriorTemporalObligationStatus::UnresolvedOriginalEntity
            );
        }
    }
    let row = coverage
        .obligations
        .iter()
        .find(|row| row.partition == "blind-oss-v1")
        .unwrap();
    let HistoricalV3PriorTemporalObligationStatus::SourceReplayed { witness, .. } = &row.evidence
    else {
        panic!("expected source-replayed blind witness");
    };
    assert_eq!(
        witness,
        &HistoricalV3PriorTemporalWitness::BlindRepository(blind.witnesses[0].clone())
    );
}

#[test]
fn a_witness_in_one_partition_cannot_clear_another_original_entity_obligation() {
    let (seal, mut v2, blind, small) = fixture();
    let mut partitions = seal.inputs;
    partitions
        .iter_mut()
        .find(|p| p.artifact_id == "historical-v2")
        .unwrap()
        .repositories = vec!["old/unknown".to_string()];
    let seal = prepare_historical_v3_prior_identity_seal(partitions).unwrap();
    v2.prior_seal_sha256 = seal.seal_sha256.clone();
    v2.witnesses[0].canonical_repository = "old/unknown".to_string();
    let coverage = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    assert_eq!(coverage.source_replayed_obligation_count, 5);
    assert_eq!(coverage.fully_witnessed_repository_count, 4);
    assert_eq!(coverage.unresolved_repository_count, 1);
    assert_eq!(coverage.unresolved_obligation_count, 2);
}

#[test]
fn requires_exact_witness_membership_and_original_partition() {
    let (seal, mut v2, mut blind, mut small) = fixture();
    blind.witnesses.push(blind.witnesses[0].clone());
    assert!(
        assemble_coverage(&seal, &v2, &blind, &small)
            .unwrap_err()
            .contains("repeats")
    );
    blind.witnesses.pop();
    small.witnesses[0].source_partition = "historical-v1".to_string();
    assert!(assemble_coverage(&seal, &v2, &blind, &small).is_err());
    small.witnesses[0].source_partition = "slopcodebench".to_string();
    small.witnesses.pop();
    assert!(
        assemble_coverage(&seal, &v2, &blind, &small)
            .unwrap_err()
            .contains("missing")
    );
    let (_, _, _, small) = fixture();
    v2.witnesses[0].canonical_repository = "current/unrelated".to_string();
    assert!(assemble_coverage(&seal, &v2, &blind, &small).is_err());
}

#[test]
fn rejects_extra_witnesses_wrong_seal_and_changed_cutoffs() {
    let (seal, mut v2, mut blind, mut small) = fixture();
    let mut extra = v2.witnesses[0].clone();
    extra.canonical_repository = "old/extra".to_string();
    v2.witnesses.push(extra);
    assert!(
        assemble_coverage(&seal, &v2, &blind, &small)
            .unwrap_err()
            .contains("unsealed")
    );
    v2.witnesses.pop();
    v2.prior_seal_sha256 = "f".repeat(64);
    assert!(assemble_coverage(&seal, &v2, &blind, &small).is_err());
    v2.prior_seal_sha256 = seal.seal_sha256.clone();
    for index in 0..3 {
        let cutoff = match index {
            0 => &mut v2.cutoff_utc,
            1 => &mut blind.cutoff_utc,
            _ => &mut small.cutoff_utc,
        };
        *cutoff = "2026-08-08T00:00:00Z".to_string();
        assert!(assemble_coverage(&seal, &v2, &blind, &small).is_err());
        match index {
            0 => v2.cutoff_utc = HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
            1 => blind.cutoff_utc = HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
            _ => small.cutoff_utc = HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        }
    }
}

#[test]
fn preserves_canonical_seal_order_original_witness_coordinates_and_stable_commitment() {
    let (seal, v2, blind, small) = fixture();
    let mut coverage = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    assert_eq!(
        coverage,
        assemble_coverage(&seal, &v2, &blind, &small).unwrap()
    );
    for partition in &seal.inputs {
        let rows = coverage
            .obligations
            .iter()
            .filter(|row| row.partition == partition.artifact_id)
            .collect::<Vec<_>>();
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row.seal_entry_index, index);
            assert_eq!(row.prior_name, partition.repositories[index]);
        }
    }
    let row = coverage
        .obligations
        .iter()
        .find(|row| row.partition == "historical-v2")
        .unwrap();
    let HistoricalV3PriorTemporalObligationStatus::SourceReplayed { witness, .. } = &row.evidence
    else {
        panic!("expected PR witness");
    };
    let HistoricalV3PriorTemporalWitness::SelectedPr(witness) = witness else {
        panic!("expected PR witness");
    };
    assert_eq!(witness.global_row_index, 42);
    assert_eq!(witness.pull_number, 5);
    let hash = std::mem::take(&mut coverage.coverage_sha256);
    assert_eq!(hash, sha256(&serde_json::to_vec(&coverage).unwrap()));
}

#[test]
fn stores_create_new_and_reads_only_bounded_structured_coverage() {
    let (seal, v2, blind, small) = fixture();
    let coverage = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("coverage.json");
    write_historical_v3_prior_temporal_coverage_new(&path, &coverage).unwrap();
    assert_eq!(
        read_historical_v3_prior_temporal_coverage(&path).unwrap(),
        coverage
    );
    let original = std::fs::read(&path).unwrap();
    assert!(write_historical_v3_prior_temporal_coverage_new(&path, &coverage).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(
        write_historical_v3_prior_temporal_coverage_new(Path::new("coverage.json"), &coverage)
            .is_err()
    );
    for bytes in [
        b"{}".as_slice(),
        b"{\"schema_version\":1,\"schema_version\":2}",
        b"{} {}",
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(read_historical_v3_prior_temporal_coverage(&path).is_err());
    }
    std::fs::File::create(&path)
        .unwrap()
        .set_len(MAX_COVERAGE_BYTES + 1)
        .unwrap();
    assert!(read_historical_v3_prior_temporal_coverage(&path).is_err());
    assert!(read_historical_v3_prior_temporal_coverage(root.path()).is_err());
}

#[test]
fn full_replay_comparison_rejects_claims_counts_identity_and_membership_tampering() {
    let (seal, v2, blind, small) = fixture();
    let expected = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    require_coverage_match(&expected, &expected).unwrap();
    let mut variants = Vec::new();
    let mut changed = expected.clone();
    changed.publication_qualified = true;
    variants.push(changed);
    let mut changed = expected.clone();
    changed.unresolved_obligation_count = 0;
    variants.push(changed);
    let mut changed = expected.clone();
    changed.obligations[0].seal_entry_index += 1;
    variants.push(changed);
    let mut changed = expected.clone();
    changed.obligations.pop();
    variants.push(changed);
    let mut changed = expected.clone();
    if let HistoricalV3PriorTemporalObligationStatus::SourceReplayed {
        witness: HistoricalV3PriorTemporalWitness::BlindRepository(witness),
        ..
    } = &mut changed.obligations[0].evidence
    {
        witness.github_repository_id += 1;
    } else {
        panic!("expected original blind row");
    }
    variants.push(changed);
    let mut changed = expected.clone();
    changed.coverage_sha256 = "f".repeat(64);
    variants.push(changed);
    for changed in variants {
        assert!(
            require_coverage_match(&changed, &expected)
                .unwrap_err()
                .contains("does not replay")
        );
    }
}

#[test]
fn caller_supplied_coverage_never_substitutes_for_missing_original_sources() {
    let (seal, v2, blind, small) = fixture();
    let mut coverage = assemble_coverage(&seal, &v2, &blind, &small).unwrap();
    coverage.publication_qualified = true;
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let inputs = HistoricalV3PriorTemporalCoverageInputs {
        artifact_root: &missing,
        dataset_root: &missing,
        frame: &missing,
        exclusions: &missing,
        selection: &missing,
        blind_source_seal: &missing,
        source_repository: &missing,
    };
    assert!(validate_frozen_historical_v3_prior_temporal_coverage(&inputs, &coverage).is_err());
    assert!(derive_frozen_historical_v3_prior_temporal_coverage(&inputs).is_err());
}

#[test]
#[ignore = "requires pinned Parquet shards, frozen v2 inputs and the original blind source seal"]
fn verifies_real_source_replayed_temporal_coverage() {
    let path = |name| std::path::PathBuf::from(std::env::var_os(name).expect(name));
    let artifact_root = path("SNIFF_HISTORICAL_V2_SOURCE_ROOT");
    let dataset_root = path("SNIFF_HISTORICAL_V2_DATASET_ROOT");
    let directory = path("SNIFF_HISTORICAL_V2_FRAME_DIR");
    let frame = directory.join("frame.json");
    let exclusions = directory.join("exclusions.json");
    let selection = directory.join("selection.json");
    let blind_source_seal = path("SNIFF_BLIND_SEAL_PATH");
    let inputs = HistoricalV3PriorTemporalCoverageInputs {
        artifact_root: &artifact_root,
        dataset_root: &dataset_root,
        frame: &frame,
        exclusions: &exclusions,
        selection: &selection,
        blind_source_seal: &blind_source_seal,
        source_repository: Path::new(env!("CARGO_MANIFEST_DIR")),
    };
    let coverage = derive_frozen_historical_v3_prior_temporal_coverage(&inputs).unwrap();
    assert_eq!(coverage.obligations.len(), 1879);
    assert_eq!(coverage.source_replayed_obligation_count, 679);
    assert_eq!(coverage.unresolved_obligation_count, 1200);
    assert_eq!(coverage.fully_witnessed_repository_count, 679);
    assert_eq!(coverage.unresolved_repository_count, 600);
    assert!(!coverage.publication_qualified);
    validate_frozen_historical_v3_prior_temporal_coverage(&inputs, &coverage).unwrap();
}
