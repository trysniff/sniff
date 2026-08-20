use super::*;
use crate::product_contract::SlopPattern;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tempfile::TempDir;

#[path = "benchmark_history_v2_corpus_fixture_case.rs"]
mod fixture_case;
use fixture_case::*;

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const SELECTION_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct FixtureTemplate {
    root: TempDir,
    artifact_binding: HistoricalV2CorpusArtifactBinding,
    cases: Vec<ReleaseBenchmarkCase>,
    sources: Vec<SourceSnapshot>,
}

pub(crate) fn install_test_historical_v2_corpus(
    corpus_root: &Path,
) -> (
    HistoricalV2CorpusArtifactBinding,
    Vec<ReleaseBenchmarkCase>,
    Vec<SourceSnapshot>,
) {
    static TEMPLATE: OnceLock<FixtureTemplate> = OnceLock::new();
    let template = TEMPLATE.get_or_init(build_template);
    copy_tree(
        &template.root.path().join("historical-v2"),
        &corpus_root.join("historical-v2"),
    );
    (
        template.artifact_binding.clone(),
        template.cases.clone(),
        template.sources.clone(),
    )
}

fn build_template() -> FixtureTemplate {
    let root = tempfile::tempdir().expect("create historical-v2 fixture root");
    let artifact_root = root.path().join("historical-v2");
    fs::create_dir(&artifact_root).expect("create historical-v2 fixture artifacts");
    let protocol = validate_historical_v2_protocol(PROTOCOL).expect("validate protocol");
    let protocol_path = artifact_root.join("protocol.json");
    fs::write(&protocol_path, PROTOCOL).expect("write historical-v2 protocol fixture");
    let mut slots = Vec::with_capacity(768);
    let mut bindings = Vec::with_capacity(240);
    for language in &protocol.protocol.selection.supported_languages {
        for slot_number in 1..=protocol.protocol.selection.slots_per_language {
            let outcome = if slot_number <= 40 {
                let binding = build_case(
                    &protocol,
                    root.path(),
                    &artifact_root,
                    language,
                    slot_number,
                );
                let outcome = accepted_outcome(&binding);
                bindings.push(binding);
                outcome
            } else {
                HistoricalV2ReleaseSlotOutcome::Unfilled
            };
            slots.push(HistoricalV2ReleaseSlotEvidence {
                language: language.clone(),
                slot_number,
                outcome,
            });
        }
    }
    let evidence = build_test_historical_v2_release_evidence(SELECTION_SHA256, slots);
    let evidence_path = artifact_root.join("release-evidence.json");
    write_json(&evidence_path, &evidence);
    let evidence_bytes = fs::read(&evidence_path).expect("read release evidence fixture");
    let mut bundle = HistoricalV2CorpusBundle {
        schema_version: HISTORICAL_V2_CORPUS_BUNDLE_SCHEMA_VERSION,
        corpus_contract: CORPUS_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256,
        selection_sha256: SELECTION_SHA256.to_string(),
        release_evidence_artifact_path: "historical-v2/release-evidence.json".to_string(),
        release_evidence_artifact_sha256: file_sha256(&evidence_bytes),
        release_evidence_sha256: evidence.evidence_sha256,
        accepted_count: bindings.len(),
        cases: bindings,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = corpus_bundle_sha256(&bundle).expect("hash corpus fixture");
    validate_historical_v2_corpus_bundle(PROTOCOL, root.path(), &bundle)
        .expect("validate historical-v2 corpus fixture");
    let bundle_path = artifact_root.join("corpus-bundle.json");
    persist_corpus_bundle(&bundle_path, &bundle).expect("persist corpus fixture");
    let cases = historical_v2_release_cases(&bundle);
    let sources = cases.iter().flat_map(|case| case.before.clone()).collect();
    FixtureTemplate {
        artifact_binding: HistoricalV2CorpusArtifactBinding {
            protocol_artifact_path: "historical-v2/protocol.json".to_string(),
            protocol_artifact_sha256: file_sha256(PROTOCOL),
            corpus_bundle_artifact_path: "historical-v2/corpus-bundle.json".to_string(),
            corpus_bundle_artifact_sha256: file_sha256(
                &fs::read(&bundle_path).expect("read corpus fixture"),
            ),
        },
        root,
        cases,
        sources,
    }
}

fn build_case(
    protocol: &ValidatedHistoricalV2Protocol,
    corpus_root: &Path,
    artifact_root: &Path,
    language: &str,
    slot_number: usize,
) -> HistoricalV2CorpusCaseBinding {
    let identity = format!("{language}-{slot_number:03}");
    let bundle_root = artifact_root.join("reviews").join(&identity);
    fs::create_dir_all(&bundle_root).expect("create review fixture");
    let source = source_fixture(language, slot_number);
    let mut bundle = source_bundle(protocol, &bundle_root, language, slot_number, &source);
    bundle.bundle_sha256 = test_historical_v2_source_bundle_sha256(&bundle);
    write_json(&bundle_root.join("manifest.json"), &bundle);
    let worksheets = reviewer_worksheets(protocol, &bundle_root, &bundle, slot_number, &source);
    let audit = audit_historical_v2_label_reviews(protocol, &bundle_root, &bundle, &worksheets)
        .expect("audit historical-v2 fixture labels");
    let resolution = prepare_historical_v2_label_resolution(
        protocol,
        &bundle_root,
        &bundle,
        &worksheets,
        &audit,
    )
    .expect("prepare historical-v2 fixture resolution");
    let final_label = resolve_historical_v2_label(
        protocol,
        &bundle_root,
        &bundle,
        &worksheets,
        &audit,
        &resolution,
    )
    .expect("resolve historical-v2 fixture label");
    let accepted = accepted_outcome_parts(&bundle, &audit, &final_label);
    let reviewed = HistoricalV2ReviewedSlotArtifacts {
        language,
        slot_number,
        bundle_root: &bundle_root,
        bundle: &bundle,
        worksheets: &worksheets,
        audit: &audit,
        resolution: &resolution,
        final_label: &final_label,
    };
    build_historical_v2_corpus_binding(protocol, corpus_root, &reviewed, &accepted)
        .expect("build historical-v2 fixture case")
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create copied historical-v2 fixture directory");
    for entry in fs::read_dir(source).expect("read historical-v2 fixture directory") {
        let entry = entry.expect("read historical-v2 fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("inspect fixture entry").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy historical-v2 fixture file");
        }
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize historical-v2 fixture");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write historical-v2 fixture");
}

fn accepted_outcome(binding: &HistoricalV2CorpusCaseBinding) -> HistoricalV2ReleaseSlotOutcome {
    let HistoricalV2FinalLabelOutcome::Accepted {
        basis,
        pattern,
        other_pattern,
    } = &binding.final_label.outcome
    else {
        panic!("historical-v2 fixture binding must be accepted");
    };
    HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256: binding.terminal_checkpoint_sha256.clone(),
        review_item_id: binding.review_item_id.clone(),
        source_bundle_sha256: binding.source_bundle_sha256.clone(),
        label_audit_sha256: binding.label_audit_sha256.clone(),
        final_label_sha256: binding.final_label_sha256.clone(),
        basis: *basis,
        pattern: *pattern,
        other_pattern: other_pattern.clone(),
    }
}
