use super::store;
use super::{language_slug, render_progress};
use crate::benchmark::{
    HistoricalV3CandidateCollection, HistoricalV3LabelWorksheet, HistoricalV3Language,
    HistoricalV3NextStep, HistoricalV3Protocol, HistoricalV3ReplayProgress,
    HistoricalV3ResolutionWorksheet, HistoricalV3ReviewDecision, HistoricalV3ReviewRecordPaths,
    HistoricalV3VerifiedSourceReview, audit_historical_v3_label_reviews,
    prepare_historical_v3_label_resolution, prepare_historical_v3_label_review,
    read_historical_v3_label_audit, read_historical_v3_label_worksheet,
    read_historical_v3_resolution_worksheet, replay_historical_v3_ordered_progress,
    resolve_historical_v3_label, validate_historical_v3_label_review,
    verify_historical_v3_final_review_from_disk, verify_historical_v3_source_review_rank,
};
use std::path::{Path, PathBuf};

struct ReviewContext {
    protocol: HistoricalV3Protocol,
    collection: HistoricalV3CandidateCollection,
    source: HistoricalV3VerifiedSourceReview,
    paths: HistoricalV3ReviewRecordPaths,
    journal_root: PathBuf,
    review_root: PathBuf,
    stop_path: PathBuf,
}

pub(crate) fn prepare_review(config: &str, language: HistoricalV3Language) -> Result<i32, String> {
    let context = load_current_review(config, language)?;
    prepare_review_context(&context, language)
}

fn prepare_review_context(
    context: &ReviewContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    ensure_review_directory(context)?;
    let inputs = context
        .source
        .inputs(&context.protocol, &context.collection);
    let blank = prepare_historical_v3_label_review(&inputs, context.source.bundle())?;
    let source_bundle = context
        .paths
        .reviewer_one
        .parent()
        .expect("reviewer path has a parent")
        .join("source-bundle.json");
    store::write_json_durable(&source_bundle, context.source.bundle())?;
    for path in [&context.paths.reviewer_one, &context.paths.reviewer_two] {
        if path.exists() {
            let mut existing: HistoricalV3LabelWorksheet =
                store::read_json(path, 64 * 1024 * 1024, "historical-v3 reviewer worksheet")?;
            existing.reviewer = None;
            existing.task.decision = HistoricalV3ReviewDecision::blank();
            if existing != blank {
                return Err(
                    "historical-v3 reviewer worksheet changed its source-only task".to_string(),
                );
            }
        } else {
            store::write_json_durable(path, &blank)?;
        }
    }
    println!(
        "historical-v3 {}: review rank {} using {}; independent worksheets: {} and {}",
        language_slug(language),
        context.source.rank().stream_rank,
        source_bundle.display(),
        context.paths.reviewer_one.display(),
        context.paths.reviewer_two.display()
    );
    Ok(0)
}

pub(crate) fn validate_review(
    config: &str,
    language: HistoricalV3Language,
    reviewer: u8,
) -> Result<i32, String> {
    let context = load_current_review(config, language)?;
    validate_review_context(&context, language, reviewer)
}

fn validate_review_context(
    context: &ReviewContext,
    language: HistoricalV3Language,
    reviewer: u8,
) -> Result<i32, String> {
    let path = reviewer_path(&context.paths, reviewer)?;
    let worksheet = read_historical_v3_label_worksheet(path)?;
    let inputs = context
        .source
        .inputs(&context.protocol, &context.collection);
    validate_historical_v3_label_review(&inputs, context.source.bundle(), &worksheet)?;
    println!(
        "historical-v3 {}: reviewer {} validated for rank {}",
        language_slug(language),
        reviewer,
        context.source.rank().stream_rank
    );
    Ok(0)
}

pub(crate) fn audit_review(config: &str, language: HistoricalV3Language) -> Result<i32, String> {
    let context = load_current_review(config, language)?;
    audit_review_context(&context, language)
}

fn audit_review_context(
    context: &ReviewContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let worksheets = completed_worksheets(&context.paths)?;
    let inputs = context
        .source
        .inputs(&context.protocol, &context.collection);
    let audit = audit_historical_v3_label_reviews(&inputs, context.source.bundle(), &worksheets)?;
    store::write_json_durable(&context.paths.audit, &audit)?;
    println!(
        "historical-v3 {}: review audit {:?} for rank {} at {}",
        language_slug(language),
        audit.status,
        context.source.rank().stream_rank,
        context.paths.audit.display()
    );
    Ok(0)
}

pub(crate) fn prepare_resolution(
    config: &str,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let context = load_current_review(config, language)?;
    prepare_resolution_context(&context, language)
}

fn prepare_resolution_context(
    context: &ReviewContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let worksheets = completed_worksheets(&context.paths)?;
    let audit = read_historical_v3_label_audit(&context.paths.audit)?;
    let inputs = context
        .source
        .inputs(&context.protocol, &context.collection);
    let blank = prepare_historical_v3_label_resolution(
        &inputs,
        context.source.bundle(),
        &worksheets,
        &audit,
    )?;
    if context.paths.resolution.exists() {
        let mut existing: HistoricalV3ResolutionWorksheet = store::read_json(
            &context.paths.resolution,
            64 * 1024 * 1024,
            "historical-v3 resolution worksheet",
        )?;
        existing.resolver = None;
        existing.item.decision = blank.item.decision.clone();
        if existing != blank {
            return Err("historical-v3 resolution worksheet changed its task".to_string());
        }
    } else {
        store::write_json_durable(&context.paths.resolution, &blank)?;
    }
    println!(
        "historical-v3 {}: resolution task for rank {} at {}",
        language_slug(language),
        context.source.rank().stream_rank,
        context.paths.resolution.display()
    );
    Ok(0)
}

pub(crate) fn finalize_review(config: &str, language: HistoricalV3Language) -> Result<i32, String> {
    let context = load_current_review(config, language)?;
    finalize_review_context(&context, language)
}

fn finalize_review_context(
    context: &ReviewContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let worksheets = completed_worksheets(&context.paths)?;
    let audit = read_historical_v3_label_audit(&context.paths.audit)?;
    let resolution = read_historical_v3_resolution_worksheet(&context.paths.resolution)?;
    let inputs = context
        .source
        .inputs(&context.protocol, &context.collection);
    let label = resolve_historical_v3_label(
        &inputs,
        context.source.bundle(),
        &worksheets,
        &audit,
        &resolution,
    )?;
    store::write_json_durable(&context.paths.final_label, &label)?;
    verify_historical_v3_final_review_from_disk(
        &context.protocol,
        &context.collection,
        context.source.rank().stream_rank,
        &context.journal_root,
        &context.review_root,
    )?;
    println!(
        "historical-v3 {}: final label sealed for rank {} at {}",
        language_slug(language),
        context.source.rank().stream_rank,
        context.paths.final_label.display()
    );
    let progress = replay_historical_v3_ordered_progress(
        &context.protocol,
        &context.collection,
        language,
        &context.journal_root,
        &context.review_root,
        &context.stop_path,
    )?;
    render_progress(language, &progress)
}

fn load_current_review(
    config: &str,
    language: HistoricalV3Language,
) -> Result<ReviewContext, String> {
    let bound = store::load_bound(Path::new(config))?;
    let collection = bound.collection()?;
    let progress = replay_historical_v3_ordered_progress(
        &bound.unbound.protocol,
        &collection,
        language,
        &bound.journal_root(),
        &bound.review_root(),
        &bound.stop_path(language_slug(language)),
    )?;
    let HistoricalV3ReplayProgress::PendingRank {
        rank,
        next: HistoricalV3NextStep::HumanReview,
        ..
    } = progress
    else {
        return Err("historical-v3 current rank does not require human review".to_string());
    };
    let source = verify_historical_v3_source_review_rank(
        &bound.unbound.protocol,
        &collection,
        rank.stream_rank,
        &bound.journal_root(),
    )
    .map_err(|error| error.to_string())?;
    if source.rank() != &rank {
        return Err("historical-v3 review rank changed during replay".to_string());
    }
    let review_root = bound.review_root();
    let paths = HistoricalV3ReviewRecordPaths::new(&review_root, source.rank());
    Ok(ReviewContext {
        protocol: bound.unbound.protocol.clone(),
        collection,
        source,
        paths,
        journal_root: bound.journal_root(),
        review_root,
        stop_path: bound.stop_path(language_slug(language)),
    })
}

fn ensure_review_directory(context: &ReviewContext) -> Result<(), String> {
    let root = &context.review_root;
    store::require_plain_directory(root, "review root")?;
    let task = root.join(&context.source.rank().stream_task_sha256);
    store::ensure_child_directory(&task, "review task directory")?;
    let rank = task.join(&context.source.rank().rank_sha256);
    store::ensure_child_directory(&rank, "review rank directory")
}

fn reviewer_path(paths: &HistoricalV3ReviewRecordPaths, reviewer: u8) -> Result<&PathBuf, String> {
    match reviewer {
        1 => Ok(&paths.reviewer_one),
        2 => Ok(&paths.reviewer_two),
        _ => Err("historical-v3 reviewer number must be 1 or 2".to_string()),
    }
}

fn completed_worksheets(
    paths: &HistoricalV3ReviewRecordPaths,
) -> Result<[HistoricalV3LabelWorksheet; 2], String> {
    Ok([
        read_historical_v3_label_worksheet(&paths.reviewer_one)?,
        read_historical_v3_label_worksheet(&paths.reviewer_two)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{HistoricalV3ReviewerVerdict, historical_v3_review_fixture};

    #[tokio::test]
    async fn operator_handoff_seals_a_verified_consensus_label() {
        let fixture = historical_v3_review_fixture::review_fixture().await;
        let inputs = fixture.inputs();
        let rank = inputs.qualification.rank.stream_rank;
        let language = inputs.qualification.rank.language();
        let source = verify_historical_v3_source_review_rank(
            inputs.protocol,
            inputs.collection,
            rank,
            fixture.journal_path(),
        )
        .unwrap();
        let review = tempfile::tempdir().unwrap();
        let paths = HistoricalV3ReviewRecordPaths::new(review.path(), source.rank());
        let context = ReviewContext {
            protocol: inputs.protocol.clone(),
            collection: inputs.collection.clone(),
            source,
            paths,
            journal_root: fixture.journal_path().to_path_buf(),
            review_root: review.path().to_path_buf(),
            stop_path: review.path().join("stop.json"),
        };

        prepare_review_context(&context, language).unwrap();
        assert!(context.paths.reviewer_one.is_file());
        assert!(context.paths.reviewer_two.is_file());
        assert!(validate_review_context(&context, language, 1).is_err());
        for (path, reviewer) in [
            (&context.paths.reviewer_one, "reviewer-a"),
            (&context.paths.reviewer_two, "reviewer-b"),
        ] {
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &fixture.worksheet(reviewer, HistoricalV3ReviewerVerdict::Slop),
                )
                .unwrap(),
            )
            .unwrap();
        }
        validate_review_context(&context, language, 1).unwrap();
        validate_review_context(&context, language, 2).unwrap();
        audit_review_context(&context, language).unwrap();
        prepare_resolution_context(&context, language).unwrap();
        finalize_review_context(&context, language).unwrap();
        assert!(context.paths.final_label.is_file());
        verify_historical_v3_final_review_from_disk(
            &context.protocol,
            &context.collection,
            rank,
            &context.journal_root,
            &context.review_root,
        )
        .unwrap();
    }
}
