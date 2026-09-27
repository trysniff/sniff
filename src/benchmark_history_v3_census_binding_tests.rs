use super::*;
use crate::benchmark::release::history_v3_source_binding::tests::{
    fixtures, prior_identity_seal, protocol as search_protocol,
};
use crate::benchmark::release::public_id_census::replay::tests::{
    capacity_six_language_transcript, preflight_fixture, six_language_transcript,
};
use crate::benchmark::release::{
    HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION, HistoricalV3ModelReviewPolicy,
    PublicIdCensusExchange, bind_historical_v3_source_frames, committed_public_id_census_policy,
    prepare_public_id_census_manifest, replay_public_id_census, seal_historical_v3_protocol,
};
use std::collections::BTreeMap;
use std::fs;

pub(crate) fn fixture() -> (
    tempfile::TempDir,
    PublicIdCensusManifest,
    HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol,
) {
    fixture_from_transcript(six_language_transcript())
}

pub(crate) fn capacity_fixture() -> (
    tempfile::TempDir,
    PublicIdCensusManifest,
    HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol,
) {
    fixture_from_transcript(capacity_six_language_transcript())
}

fn fixture_from_transcript(
    exchanges: Vec<PublicIdCensusExchange>,
) -> (
    tempfile::TempDir,
    PublicIdCensusManifest,
    HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol,
) {
    let root = tempfile::tempdir().unwrap();
    let policy = committed_public_id_census_policy().unwrap();
    let preflight = preflight_fixture();
    let derived = replay_public_id_census(&policy, &preflight, &exchanges).unwrap();
    fs::create_dir(root.path().join("raw")).unwrap();
    fs::create_dir(root.path().join("frames")).unwrap();
    fs::write(
        root.path().join("preflight.json"),
        serde_json::to_vec(&preflight).unwrap(),
    )
    .unwrap();
    let exchange_paths = exchanges
        .iter()
        .enumerate()
        .map(|(index, exchange)| {
            let relative = format!("raw/{index:08}.json");
            fs::write(
                root.path().join(&relative),
                serde_json::to_vec(exchange).unwrap(),
            )
            .unwrap();
            relative
        })
        .collect::<Vec<_>>();
    let frame_paths = policy
        .languages
        .iter()
        .map(|language| {
            let relative = format!("frames/{}.csv", language.to_ascii_lowercase());
            fs::write(root.path().join(&relative), &derived.frames[language]).unwrap();
            (language.clone(), relative)
        })
        .collect::<BTreeMap<_, _>>();
    let manifest = prepare_public_id_census_manifest(
        policy,
        preflight,
        root.path(),
        &exchange_paths,
        &frame_paths,
    )
    .unwrap();

    let prior = prior_identity_seal();
    let mut protocol = search_protocol(&prior, &fixtures());
    protocol.schema_version = HISTORICAL_V3_PUBLIC_ID_CENSUS_PROTOCOL_SCHEMA_VERSION;
    protocol.protocol_contract =
        "sniffbench-historical-v3-public-id-census-protocol-v8".to_string();
    protocol.source_kind = Some(HistoricalV3SourceKind::PublicIdCensus);
    protocol.human_review_policy = None;
    protocol.model_review_policy = Some(HistoricalV3ModelReviewPolicy {
        source_only_review: true,
        independent_reviewers: 2,
        approved_prompt_sha256: "a".repeat(64),
        prompt_public_url:
            "https://raw.githubusercontent.com/trysniff/sniff/0000000000000000000000000000000000000000/sniffbench/HISTORICAL_V3_AGENT_REVIEW_PROMPT.md".to_string(),
        exact_presented_material_record_required: true,
        invocation_response_record_required: true,
        disagreements_remain_unresolved: true,
        human_gold_claim_forbidden: true,
    });
    protocol.model_access_forbidden = false;
    protocol.candidate_window.merged_at_or_after_utc = "2026-08-15T00:00:00Z".to_string();
    protocol.candidate_window.merged_before_utc = "2026-09-27T00:00:00Z".to_string();
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
fn binds_six_census_frames_from_one_replayed_manifest() {
    let (root, manifest, prior, protocol) = fixture();
    let artifact = HistoricalV3PublicIdCensusArtifact {
        manifest: &manifest,
        artifact_root: root.path(),
    };
    let audit = bind_historical_v3_public_id_census_frames(&protocol, &prior, &artifact).unwrap();
    assert_eq!(
        audit.schema_version,
        HISTORICAL_V3_PUBLIC_ID_CENSUS_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(audit.frames.len(), 6);
    assert!(audit.frames.iter().all(|frame| frame.repository_count == 1));
    validate_historical_v3_public_id_census_audit(&protocol, &prior, &artifact, &audit).unwrap();
}

#[test]
fn rejects_search_artifacts_and_mismatched_census_sources() {
    let (root, manifest, prior, protocol) = fixture();
    assert!(bind_historical_v3_source_frames(&protocol, &prior, &[]).is_err());
    let artifact = HistoricalV3PublicIdCensusArtifact {
        manifest: &manifest,
        artifact_root: root.path(),
    };
    let mut changed_protocol = protocol.clone();
    changed_protocol.source_frames[1].manifest_sha256 = "f".repeat(64);
    assert!(seal_historical_v3_protocol(changed_protocol).is_err());
    let mut old_kind = protocol.clone();
    old_kind.schema_version = HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION;
    old_kind.protocol_contract = "sniffbench-historical-v3-model-judged-protocol-v7".to_string();
    assert!(seal_historical_v3_protocol(old_kind).is_err());
    let mut swapped = manifest.clone();
    swapped.frames.swap(0, 1);
    assert!(
        bind_historical_v3_public_id_census_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusArtifact {
                manifest: &swapped,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
    assert!(bind_historical_v3_public_id_census_frames(&protocol, &prior, &artifact).is_ok());
}

#[test]
fn rejects_tampered_raw_exchange_or_frame() {
    let (root, manifest, prior, protocol) = fixture();
    fs::write(
        root.path().join(&manifest.exchanges[0].artifact_path),
        b"{}",
    )
    .unwrap();
    assert!(
        bind_historical_v3_public_id_census_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusArtifact {
                manifest: &manifest,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
    let (root, manifest, prior, protocol) = fixture();
    fs::write(
        root.path().join(&manifest.frames[0].artifact_path),
        b"repo,metadata\n",
    )
    .unwrap();
    assert!(
        bind_historical_v3_public_id_census_frames(
            &protocol,
            &prior,
            &HistoricalV3PublicIdCensusArtifact {
                manifest: &manifest,
                artifact_root: root.path(),
            },
        )
        .is_err()
    );
}
