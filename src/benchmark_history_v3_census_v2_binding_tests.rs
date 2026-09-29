use super::*;
use crate::benchmark::release::history_v3_census_binding::tests::fixture as v1_fixture;
use crate::benchmark::release::public_id_census_v2::six_language_census_v2_fixture;
use crate::benchmark::release::seal_historical_v3_protocol;
use std::fs;

pub(crate) fn fixture() -> (
    tempfile::TempDir,
    PublicIdCensusV2Manifest,
    HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol,
) {
    let (_old_root, _old_manifest, prior, mut protocol) = v1_fixture();
    let (root, manifest) = six_language_census_v2_fixture();
    protocol.schema_version = HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_PROTOCOL_SCHEMA_VERSION;
    protocol.protocol_contract =
        "sniffbench-historical-v3-public-id-census-v2-protocol-v9".to_string();
    protocol.source_kind = Some(HistoricalV3SourceKind::PublicIdCensusV2);
    for (binding, frame) in protocol.source_frames.iter_mut().zip(&manifest.frames) {
        binding.frame_id = frame.frame_id.clone();
        binding.policy_sha256 = manifest.policy_sha256.clone();
        binding.manifest_sha256 = manifest.manifest_sha256.clone();
        binding.frame_sha256 = frame.artifact_sha256.clone();
        binding.repository_count = frame.repository_count;
    }
    let protocol = seal_historical_v3_protocol(protocol).unwrap();
    (root, manifest, prior, protocol)
}

#[test]
fn binds_replayed_resolvable_population_with_null_ledger() {
    let (root, manifest, prior, protocol) = fixture();
    let artifact = HistoricalV3PublicIdCensusV2Artifact {
        manifest: &manifest,
        artifact_root: root.path(),
    };
    let audit =
        bind_historical_v3_public_id_census_v2_frames(&protocol, &prior, &artifact).unwrap();
    assert_eq!(audit.schema_version, 4);
    assert_eq!(audit.frames.len(), 6);
    assert!(audit.frames.iter().all(|frame| frame.repository_count == 1));
    let population = audit.resolvable_population.as_ref().unwrap();
    assert_eq!(population.crawled_null_count, 1);
    assert_eq!(population.probe_only_null_count, 0);
    assert_eq!(population.resolved_in_window_count, 6);
    assert_eq!(
        audit.prior_identity_proof_status,
        Some(HistoricalV3PriorIdentityProofStatus::NameOnlyUnproven)
    );
    validate_historical_v3_public_id_census_v2_audit(&protocol, &prior, &artifact, &audit).unwrap();
}

#[test]
fn rejects_v1_source_and_mutated_population_or_frame_commitments() {
    let (root, manifest, prior, protocol) = fixture();
    let artifact = HistoricalV3PublicIdCensusV2Artifact {
        manifest: &manifest,
        artifact_root: root.path(),
    };
    let mut old_kind = protocol.clone();
    old_kind.source_kind = Some(HistoricalV3SourceKind::PublicIdCensus);
    assert!(seal_historical_v3_protocol(old_kind).is_err());
    let mut changed_frame = protocol.clone();
    changed_frame.source_frames[0].manifest_sha256 = "f".repeat(64);
    assert!(seal_historical_v3_protocol(changed_frame).is_err());
    let mut changed_manifest = manifest.clone();
    changed_manifest.crawled_null_count = 0;
    assert!(
        bind_historical_v3_public_id_census_v2_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusV2Artifact {
                manifest: &changed_manifest,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
    let mut audit =
        bind_historical_v3_public_id_census_v2_frames(&protocol, &prior, &artifact).unwrap();
    audit
        .resolvable_population
        .as_mut()
        .unwrap()
        .crawled_null_count = 0;
    assert!(
        validate_historical_v3_public_id_census_v2_audit(&protocol, &prior, &artifact, &audit)
            .is_err()
    );
    let mut audit =
        bind_historical_v3_public_id_census_v2_frames(&protocol, &prior, &artifact).unwrap();
    audit.prior_identity_proof_status = None;
    assert!(
        validate_historical_v3_public_id_census_v2_audit(&protocol, &prior, &artifact, &audit)
            .is_err()
    );
}

#[test]
fn rejects_changed_raw_null_ledger_or_contract_preflight() {
    let (root, manifest, prior, protocol) = fixture();
    fs::write(root.path().join(&manifest.null_ledger_artifact_path), b"{}").unwrap();
    assert!(
        bind_historical_v3_public_id_census_v2_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusV2Artifact {
                manifest: &manifest,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
    let (root, manifest, prior, protocol) = fixture();
    fs::write(
        root.path().join(&manifest.contract_preflight_artifact_path),
        b"{}",
    )
    .unwrap();
    assert!(
        bind_historical_v3_public_id_census_v2_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusV2Artifact {
                manifest: &manifest,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
}
