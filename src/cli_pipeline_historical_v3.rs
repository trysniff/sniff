#[path = "cli_pipeline_historical_v3_precommit.rs"]
mod precommit;
#[path = "cli_pipeline_historical_v3_review.rs"]
mod review;
#[path = "cli_pipeline_historical_v3_store.rs"]
mod store;

use crate::benchmark::{
    DockerHistoricalV3TestExecutor, GithubHistoricalV3CandidateTransport,
    HistoricalV3CandidateCollection, HistoricalV3CandidatePageTransport, HistoricalV3Language,
    HistoricalV3NextStep, HistoricalV3OrderedStopStatus, HistoricalV3Protocol,
    HistoricalV3ReplayProgress, HistoricalV3RunPaths, advance_historical_v3_ordered_step,
    collect_historical_v3_candidates, replay_historical_v3_ordered_progress,
    seal_historical_v3_protocol, write_historical_v3_candidate_collection_manifest_new,
};
use std::path::Path;

pub(crate) use review::{
    audit_review, finalize_review, prepare_resolution, prepare_review, validate_review,
};

pub(crate) fn seal_prior(inputs: &str, output: &str) -> Result<i32, String> {
    let sources: store::PriorSourcePaths =
        store::read_json(Path::new(inputs), 64 * 1024, "prior source paths")?;
    let seal = sources.derive()?;
    store::write_json_durable(Path::new(output), &seal)?;
    println!("historical-v3 prior identity seal: {}", seal.seal_sha256);
    Ok(0)
}

pub(crate) fn seal_protocol(draft: &str, output: &str) -> Result<i32, String> {
    let protocol: HistoricalV3Protocol =
        store::read_json(Path::new(draft), 64 * 1024 * 1024, "protocol draft")?;
    let protocol = seal_historical_v3_protocol(protocol)?;
    store::write_json_durable(Path::new(output), &protocol)?;
    println!("historical-v3 protocol: {}", protocol.protocol_sha256);
    Ok(0)
}

pub(crate) fn init(config: &str) -> Result<i32, String> {
    let bound = store::initialize(Path::new(config))?;
    println!(
        "historical-v3 operator bound: protocol={} sources={} root={}",
        bound.unbound.protocol.protocol_sha256,
        bound.audit.audit_sha256,
        bound.root.display()
    );
    Ok(0)
}

pub(crate) async fn preflight(config: &str) -> Result<i32, String> {
    let bound = store::load_bound(Path::new(config))?;
    preflight_bound(&bound, &mut precommit::GithubRawTransport::new()).await?;
    println!(
        "historical-v3 public precommit verified: {}",
        bound.root.join("public-precommit-proof.json").display()
    );
    Ok(0)
}

async fn preflight_bound<T: precommit::PublicArtifactTransport>(
    bound: &store::BoundInputs,
    transport: &mut T,
) -> Result<(), String> {
    precommit::ensure_public_precommit(bound, transport).await
}

pub(crate) async fn collect(config: &str) -> Result<i32, String> {
    let bound = store::load_bound(Path::new(config))?;
    precommit::validate_public_precommit(&bound)?;
    let manifest_path = bound.root.join("candidate-manifest.json");
    if manifest_path.exists() {
        let collection = bound.collection()?;
        println!(
            "historical-v3 collection already verified: {} candidates",
            collection.candidates.len()
        );
        return Ok(0);
    }
    let token = std::env::var(&bound.unbound.config.github_token_env).map_err(|_| {
        format!(
            "historical-v3 requires {} for GitHub collection",
            bound.unbound.config.github_token_env
        )
    })?;
    let mut transport = GithubHistoricalV3CandidateTransport::new(token)?;
    let collection = collect_bound(&bound, &mut transport).await?;
    println!(
        "historical-v3 collection sealed: {} candidates; manifest={}",
        collection.candidates.len(),
        collection.manifest.manifest_sha256
    );
    Ok(0)
}

async fn collect_bound<T: HistoricalV3CandidatePageTransport>(
    bound: &store::BoundInputs,
    transport: &mut T,
) -> Result<HistoricalV3CandidateCollection, String> {
    precommit::validate_public_precommit(bound)?;
    let manifest_path = bound.root.join("candidate-manifest.json");
    if manifest_path.exists() {
        return bound.collection();
    }
    let collection = collect_historical_v3_candidates(
        &bound.unbound.protocol,
        &bound.unbound.prior,
        &bound.unbound.artifacts(),
        &bound.audit,
        &bound.root.join("candidate-state"),
        transport,
    )
    .await?;
    write_historical_v3_candidate_collection_manifest_new(
        &manifest_path,
        &bound.unbound.protocol,
        &bound.unbound.prior,
        &bound.unbound.artifacts(),
        &bound.audit,
        &bound.root.join("candidate-state"),
        &collection,
    )?;
    Ok(collection)
}

pub(crate) fn status(config: &str, language: HistoricalV3Language) -> Result<i32, String> {
    let bound = store::load_bound(Path::new(config))?;
    status_bound(&bound, language)
}

fn status_bound(bound: &store::BoundInputs, language: HistoricalV3Language) -> Result<i32, String> {
    let collection = bound.collection()?;
    let progress = replay_historical_v3_ordered_progress(
        &bound.unbound.protocol,
        &collection,
        language,
        &bound.journal_root(),
        &bound.review_root(),
        &bound.stop_path(language_slug(language)),
    )?;
    render_progress(language, &progress)
}

pub(crate) async fn advance(config: &str, language: HistoricalV3Language) -> Result<i32, String> {
    let bound = store::load_bound(Path::new(config))?;
    let collection = bound.collection()?;
    let journal_root = bound.journal_root();
    let workspace_root = bound.workspace_root();
    let review_root = bound.review_root();
    let stop_path = bound.stop_path(language_slug(language));
    let executor = DockerHistoricalV3TestExecutor::new(&bound.unbound.config.docker_program);
    let progress = advance_historical_v3_ordered_step(
        &bound.unbound.protocol,
        &collection,
        language,
        HistoricalV3RunPaths {
            journal_root: &journal_root,
            workspace_root: &workspace_root,
            review_root: &review_root,
            stop_path: &stop_path,
        },
        &executor,
    )
    .await?;
    render_progress(language, &progress)
}

pub(crate) async fn run(
    config: &str,
    language: HistoricalV3Language,
    max_steps: Option<usize>,
) -> Result<i32, String> {
    let bound = store::load_bound(Path::new(config))?;
    let collection = bound.collection()?;
    let journal_root = bound.journal_root();
    let workspace_root = bound.workspace_root();
    let review_root = bound.review_root();
    let stop_path = bound.stop_path(language_slug(language));
    let executor = DockerHistoricalV3TestExecutor::new(&bound.unbound.config.docker_program);
    let mut steps = 0;
    let mut progress = replay_historical_v3_ordered_progress(
        &bound.unbound.protocol,
        &collection,
        language,
        &journal_root,
        &review_root,
        &stop_path,
    )?;
    loop {
        match &progress {
            HistoricalV3ReplayProgress::Terminal { .. }
            | HistoricalV3ReplayProgress::PendingRank {
                next: HistoricalV3NextStep::HumanReview,
                ..
            } => return render_progress(language, &progress),
            _ => {}
        }
        if max_steps.is_some_and(|limit| steps >= limit) {
            return render_progress(language, &progress);
        }
        let before_rank = match &progress {
            HistoricalV3ReplayProgress::PendingRank {
                processed_ranks, ..
            } => *processed_ranks,
            _ => 0,
        };
        progress = advance_historical_v3_ordered_step(
            &bound.unbound.protocol,
            &collection,
            language,
            HistoricalV3RunPaths {
                journal_root: &journal_root,
                workspace_root: &workspace_root,
                review_root: &review_root,
                stop_path: &stop_path,
            },
            &executor,
        )
        .await?;
        steps += 1;
        if let HistoricalV3ReplayProgress::PendingRank {
            processed_ranks, ..
        } = &progress
            && *processed_ranks > before_rank
        {
            println!(
                "historical-v3 {}: {} ranks verified",
                language_slug(language),
                processed_ranks
            );
        }
    }
}

pub(super) fn language_slug(language: HistoricalV3Language) -> &'static str {
    match language {
        HistoricalV3Language::Go => "go",
        HistoricalV3Language::JavaScript => "javascript",
        HistoricalV3Language::Kotlin => "kotlin",
        HistoricalV3Language::Python => "python",
        HistoricalV3Language::Rust => "rust",
        HistoricalV3Language::TypeScript => "typescript",
    }
}

fn render_progress(
    language: HistoricalV3Language,
    progress: &HistoricalV3ReplayProgress,
) -> Result<i32, String> {
    let language = language_slug(language);
    match progress {
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks,
            rank,
            next,
        } => {
            let next = match next {
                HistoricalV3NextStep::RankStage(stage) => format!("{stage:?}"),
                HistoricalV3NextStep::RepositoryReviewCap => "repository_review_cap".to_string(),
                HistoricalV3NextStep::HumanReview => "human_review".to_string(),
            };
            println!(
                "historical-v3 {language}: pending rank {} ({} processed), next={next}",
                rank.stream_rank, processed_ranks
            );
            Ok(0)
        }
        HistoricalV3ReplayProgress::AwaitingStopPublication { artifact } => {
            println!(
                "historical-v3 {language}: awaiting stop publication, status={}",
                serde_json::to_string(&artifact.status).map_err(|error| error.to_string())?
            );
            Ok(0)
        }
        HistoricalV3ReplayProgress::Terminal { artifact } => {
            println!(
                "historical-v3 {language}: terminal status={}",
                serde_json::to_string(&artifact.status).map_err(|error| error.to_string())?
            );
            Ok(
                if matches!(
                    artifact.status,
                    HistoricalV3OrderedStopStatus::TargetReached { .. }
                ) {
                    0
                } else {
                    2
                },
            )
        }
    }
}
