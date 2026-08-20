use super::*;
use std::collections::BTreeSet;

pub fn validate_historical_v2_corpus_bundle(
    protocol_bytes: &[u8],
    corpus_root: &Path,
    bundle: &HistoricalV2CorpusBundle,
) -> Result<(), String> {
    let corpus_root = canonical_plain_directory(corpus_root, "historical-v2 corpus root")?;
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;
    if bundle.schema_version != HISTORICAL_V2_CORPUS_BUNDLE_SCHEMA_VERSION
        || bundle.corpus_contract != CORPUS_CONTRACT
        || bundle.protocol_sha256 != protocol.protocol_sha256
        || bundle.bundle_sha256 != corpus_bundle_sha256(bundle)?
    {
        return Err("historical-v2 corpus bundle commitment changed".into());
    }
    let evidence_path = safe_join(&corpus_root, &bundle.release_evidence_artifact_path)?;
    if relative_plain_file(
        &corpus_root,
        &evidence_path,
        "historical-v2 release evidence artifact",
    )? != bundle.release_evidence_artifact_path
    {
        return Err("historical-v2 release evidence path changed".into());
    }
    let evidence_bytes = load_plain_file(
        &evidence_path,
        MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
        "historical-v2 release evidence artifact",
    )?;
    if file_sha256(&evidence_bytes) != bundle.release_evidence_artifact_sha256 {
        return Err("historical-v2 release evidence artifact changed".into());
    }
    let evidence = load_historical_v2_release_evidence(protocol_bytes, &evidence_path)?;
    if evidence.status != HistoricalV2ReleaseGateStatus::Passed
        || evidence.evidence_sha256 != bundle.release_evidence_sha256
        || evidence.selection_sha256 != bundle.selection_sha256
        || evidence.accepted_count != bundle.accepted_count
        || bundle.cases.len() != bundle.accepted_count
    {
        return Err("historical-v2 corpus is not backed by passed release evidence".into());
    }

    let accepted = evidence.slots.iter().filter(|slot| {
        matches!(
            slot.outcome,
            HistoricalV2ReleaseSlotOutcome::Accepted { .. }
        )
    });
    let mut source_paths = BTreeSet::new();
    let mut source_bundles = BTreeSet::new();
    for (slot, binding) in accepted.zip(&bundle.cases) {
        validate_binding_identity(slot, binding)?;
        if !source_paths.insert(binding.source_bundle_artifact_path.clone())
            || !source_bundles.insert(binding.source_bundle_sha256.clone())
        {
            return Err("historical-v2 corpus repeats a source review bundle".into());
        }
        validate_binding(&protocol, &corpus_root, binding, &slot.outcome)?;
    }
    if source_paths.len() != bundle.accepted_count {
        return Err("historical-v2 corpus omits an accepted release slot".into());
    }
    Ok(())
}

fn validate_binding_identity(
    slot: &HistoricalV2ReleaseSlotEvidence,
    binding: &HistoricalV2CorpusCaseBinding,
) -> Result<(), String> {
    let HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256,
        review_item_id,
        source_bundle_sha256,
        label_audit_sha256,
        final_label_sha256,
        ..
    } = &slot.outcome
    else {
        return Err("historical-v2 corpus binding is not accepted".into());
    };
    if binding.language != slot.language
        || binding.slot_number != slot.slot_number
        || binding.terminal_checkpoint_sha256 != *terminal_checkpoint_sha256
        || binding.review_item_id != *review_item_id
        || binding.source_bundle_sha256 != *source_bundle_sha256
        || binding.label_audit_sha256 != *label_audit_sha256
        || binding.final_label_sha256 != *final_label_sha256
    {
        return Err("historical-v2 corpus binding changed accepted slot identity".into());
    }
    Ok(())
}

pub(super) fn validate_binding(
    protocol: &ValidatedHistoricalV2Protocol,
    corpus_root: &Path,
    binding: &HistoricalV2CorpusCaseBinding,
    accepted: &HistoricalV2ReleaseSlotOutcome,
) -> Result<(), String> {
    let bundle_root = safe_join(corpus_root, &binding.source_bundle_artifact_path)?;
    if relative_plain_directory(corpus_root, &bundle_root)? != binding.source_bundle_artifact_path {
        return Err("historical-v2 source bundle path changed".into());
    }
    let manifest_path = safe_join(&bundle_root, "manifest.json")?;
    let manifest_bytes = load_plain_file(
        &manifest_path,
        MAX_SOURCE_BUNDLE_MANIFEST_BYTES,
        "historical-v2 source bundle manifest",
    )?;
    let source_bundle =
        serde_json::from_slice::<HistoricalV2SourceReviewBundle>(&manifest_bytes)
            .map_err(|error| format!("invalid historical-v2 source bundle manifest: {error}"))?;
    let reviewed = HistoricalV2ReviewedSlotArtifacts {
        language: &binding.language,
        slot_number: binding.slot_number,
        bundle_root: &bundle_root,
        bundle: &source_bundle,
        worksheets: &binding.worksheets,
        audit: &binding.audit,
        resolution: &binding.resolution,
        final_label: &binding.final_label,
    };
    let expected = build_historical_v2_corpus_binding(protocol, corpus_root, &reviewed, accepted)?;
    if binding != &expected {
        return Err("historical-v2 corpus case changed from its reviewed source".into());
    }
    Ok(())
}
