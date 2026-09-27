use super::{language_slug, precommit, render_progress, store};
use crate::benchmark::{
    HistoricalV3AgentReviewSubmission, HistoricalV3CandidateCollection, HistoricalV3Language,
    HistoricalV3NextStep, HistoricalV3Protocol, HistoricalV3ReplayProgress,
    HistoricalV3ReviewRecordPaths, HistoricalV3VerifiedSourceReview,
    audit_historical_v3_agent_reviews, historical_v3_agent_invocation_request,
    replay_historical_v3_ordered_progress, seal_historical_v3_agent_review,
    verify_historical_v3_source_review_rank,
};
use std::path::{Path, PathBuf};

const MAX_INVOCATION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SUBMISSION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_AUDIT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

struct AgentContext {
    protocol: HistoricalV3Protocol,
    collection: HistoricalV3CandidateCollection,
    source: HistoricalV3VerifiedSourceReview,
    paths: HistoricalV3ReviewRecordPaths,
    prompt: Vec<u8>,
    review_root: PathBuf,
    journal_root: PathBuf,
    stop_path: PathBuf,
}

pub(crate) fn prepare_agent_review(
    config: &str,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let context = load_current_agent_review(config, language)?;
    prepare_agent_review_context(&context, language)
}

fn prepare_agent_review_context(
    context: &AgentContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    ensure_review_directory(context)?;
    let invocation =
        historical_v3_agent_invocation_request(&context.prompt, context.source.bundle())?;
    store::write_bytes_durable_limited(
        &context.paths.agent_invocation,
        invocation.as_bytes(),
        MAX_INVOCATION_BYTES,
    )?;
    println!(
        "historical-v3 {}: present {} to two fresh independent agents for rank {}",
        language_slug(language),
        context.paths.agent_invocation.display(),
        context.source.rank().stream_rank,
    );
    Ok(0)
}

pub(crate) fn submit_agent_review(
    config: &str,
    language: HistoricalV3Language,
    agent: u8,
    response_path: &str,
) -> Result<i32, String> {
    let context = load_current_agent_review(config, language)?;
    submit_agent_review_context(&context, language, agent, response_path)
}

fn submit_agent_review_context(
    context: &AgentContext,
    language: HistoricalV3Language,
    agent: u8,
    response_path: &str,
) -> Result<i32, String> {
    require_prepared_invocation(context)?;
    let raw_response = store::read_plain(
        Path::new(response_path),
        MAX_RESPONSE_BYTES,
        "historical-v3 agent raw response",
    )?;
    let raw_response = String::from_utf8(raw_response)
        .map_err(|_| "historical-v3 agent raw response must be UTF-8".to_string())?;
    let submission = seal_historical_v3_agent_review(
        &context
            .source
            .inputs(&context.protocol, &context.collection),
        context.source.bundle(),
        &context.prompt,
        raw_response,
    )?;
    let path = submission_path(&context.paths, agent)?;
    let peer = submission_path(&context.paths, if agent == 1 { 2 } else { 1 })?;
    if peer.exists() {
        let other: HistoricalV3AgentReviewSubmission =
            store::read_json(peer, MAX_SUBMISSION_BYTES, "other agent submission")?;
        let (first, second) = if agent == 1 {
            (&submission, &other)
        } else {
            (&other, &submission)
        };
        audit_historical_v3_agent_reviews(
            &context
                .source
                .inputs(&context.protocol, &context.collection),
            context.source.bundle(),
            &context.prompt,
            first,
            second,
        )?;
    }
    store::write_json_durable_limited(path, &submission, MAX_SUBMISSION_BYTES)?;
    println!(
        "historical-v3 {}: sealed independent agent {} for rank {} at {}",
        language_slug(language),
        agent,
        context.source.rank().stream_rank,
        path.display(),
    );
    Ok(0)
}

pub(crate) fn audit_agent_review(
    config: &str,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    let context = load_current_agent_review(config, language)?;
    audit_agent_review_context(&context, language)
}

fn audit_agent_review_context(
    context: &AgentContext,
    language: HistoricalV3Language,
) -> Result<i32, String> {
    require_prepared_invocation(context)?;
    let first: HistoricalV3AgentReviewSubmission = store::read_json(
        &context.paths.agent_one,
        MAX_SUBMISSION_BYTES,
        "first agent submission",
    )?;
    let second: HistoricalV3AgentReviewSubmission = store::read_json(
        &context.paths.agent_two,
        MAX_SUBMISSION_BYTES,
        "second agent submission",
    )?;
    let audit = audit_historical_v3_agent_reviews(
        &context
            .source
            .inputs(&context.protocol, &context.collection),
        context.source.bundle(),
        &context.prompt,
        &first,
        &second,
    )?;
    store::write_json_durable_limited(&context.paths.agent_audit, &audit, MAX_AUDIT_BYTES)?;
    println!(
        "historical-v3 {}: agent audit sealed for rank {} at {}; tier_agreement={}, pattern_agreement={}",
        language_slug(language),
        context.source.rank().stream_rank,
        context.paths.agent_audit.display(),
        audit.tier_agreement,
        audit.slop_pattern_agreement,
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

fn load_current_agent_review(
    config: &str,
    language: HistoricalV3Language,
) -> Result<AgentContext, String> {
    let bound = store::load_bound(Path::new(config))?;
    if bound.unbound.protocol.model_review_policy.is_none() {
        return Err(
            "historical-v3 agent commands require model-judged protocol authority".to_string(),
        );
    }
    let prompt = precommit::verified_agent_prompt_bytes(&bound)?;
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
        next: HistoricalV3NextStep::AgentReview,
        ..
    } = progress
    else {
        return Err("historical-v3 current rank does not require agent review".to_string());
    };
    let source = verify_historical_v3_source_review_rank(
        &bound.unbound.protocol,
        &collection,
        rank.stream_rank,
        &bound.journal_root(),
    )
    .map_err(|error| error.to_string())?;
    if source.rank() != &rank {
        return Err("historical-v3 agent review rank changed during replay".to_string());
    }
    let review_root = bound.review_root();
    let paths = HistoricalV3ReviewRecordPaths::new(&review_root, source.rank());
    Ok(AgentContext {
        protocol: bound.unbound.protocol.clone(),
        collection,
        source,
        paths,
        prompt,
        review_root,
        journal_root: bound.journal_root(),
        stop_path: bound.stop_path(language_slug(language)),
    })
}

fn ensure_review_directory(context: &AgentContext) -> Result<(), String> {
    store::require_plain_directory(&context.review_root, "review root")?;
    let task = context
        .review_root
        .join(&context.source.rank().stream_task_sha256);
    store::ensure_child_directory(&task, "review task directory")?;
    let rank = task.join(&context.source.rank().rank_sha256);
    store::ensure_child_directory(&rank, "review rank directory")
}

fn require_prepared_invocation(context: &AgentContext) -> Result<(), String> {
    let expected =
        historical_v3_agent_invocation_request(&context.prompt, context.source.bundle())?;
    let stored = store::read_plain(
        &context.paths.agent_invocation,
        MAX_INVOCATION_BYTES,
        "historical-v3 agent invocation",
    )?;
    if stored != expected.as_bytes() {
        return Err(
            "historical-v3 agent invocation differs from its exact presented bytes".to_string(),
        );
    }
    Ok(())
}

fn submission_path(paths: &HistoricalV3ReviewRecordPaths, agent: u8) -> Result<&PathBuf, String> {
    match agent {
        1 => Ok(&paths.agent_one),
        2 => Ok(&paths.agent_two),
        _ => Err("historical-v3 agent number must be 1 or 2".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{
        HistoricalV3ReviewerVerdict, historical_v3_agent_review_fixture as agent_fixture,
        historical_v3_review_fixture, read_historical_v3_stop_artifact,
    };

    #[tokio::test]
    async fn operator_seals_exact_source_only_agent_responses_and_audit() {
        let fixture = agent_fixture::agent_fixture().await;
        let inputs = fixture.inputs();
        let source = verify_historical_v3_source_review_rank(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let language = source.rank().language();
        let paths = HistoricalV3ReviewRecordPaths::new(root.path(), source.rank());
        let context = AgentContext {
            protocol: inputs.protocol.clone(),
            collection: inputs.collection.clone(),
            source,
            paths,
            prompt: agent_fixture::PROMPT.to_vec(),
            review_root: root.path().to_path_buf(),
            journal_root: fixture.journal_path().to_path_buf(),
            stop_path: root.path().join("stop.json"),
        };
        let decision = historical_v3_review_fixture::decision_for_methods(
            &fixture.bundle.methods,
            HistoricalV3ReviewerVerdict::Slop,
        );
        let first = agent_fixture::response(
            agent_fixture::reviewer("agent-a", "run-a"),
            decision.clone(),
        );
        let second = agent_fixture::response(agent_fixture::reviewer("agent-b", "run-b"), decision);
        let first_path = root.path().join("first-response.json");
        let repeated_path = root.path().join("repeated-response.json");
        let second_path = root.path().join("second-response.json");
        std::fs::write(&first_path, first.as_bytes()).unwrap();
        std::fs::write(&repeated_path, first.as_bytes()).unwrap();
        std::fs::write(&second_path, second.as_bytes()).unwrap();
        assert!(
            submit_agent_review_context(&context, language, 1, first_path.to_str().unwrap(),)
                .is_err()
        );
        prepare_agent_review_context(&context, language).unwrap();
        let expected =
            historical_v3_agent_invocation_request(agent_fixture::PROMPT, context.source.bundle())
                .unwrap();
        assert_eq!(
            store::read_plain(
                &context.paths.agent_invocation,
                MAX_INVOCATION_BYTES,
                "invocation"
            )
            .unwrap(),
            expected.as_bytes(),
        );
        submit_agent_review_context(&context, language, 1, first_path.to_str().unwrap()).unwrap();
        assert!(
            submit_agent_review_context(&context, language, 2, repeated_path.to_str().unwrap(),)
                .unwrap_err()
                .contains("repeats")
        );
        assert!(!context.paths.agent_two.exists());
        submit_agent_review_context(&context, language, 2, second_path.to_str().unwrap()).unwrap();
        audit_agent_review_context(&context, language).unwrap();
        assert!(context.paths.agent_audit.exists());
        assert!(matches!(
            replay_historical_v3_ordered_progress(
                &context.protocol,
                &context.collection,
                language,
                &context.journal_root,
                &context.review_root,
                &context.stop_path,
            )
            .unwrap(),
            HistoricalV3ReplayProgress::AwaitingStopPublication { .. }
        ));
        assert!(read_historical_v3_stop_artifact(&context.stop_path).is_err());
    }
}
