use crate::benchmark::{
    BenchmarkCorpus, BenchmarkSubmission, IntentionalBoundaryFrameTask, NonBlindHistoryAssessment,
    NonBlindSourceSeal, assess_non_blind_history, assess_non_blind_history_slice, evaluate_release,
    freeze_corpus, freeze_non_blind_source_seal, prepare_intentional_boundary_frame_task,
    prepare_non_blind_history, prepare_non_blind_history_assessment,
    validate_historical_v2_protocol, validate_intentional_boundary_frame_task,
    validate_intentional_boundary_protocol,
};
use crate::benchmark::{
    BenchmarkSourceSeal, LabelResolutionManifest, LabelReviewAudit, LabelReviewWorksheet,
    SourceFrameCollectionPolicy, SourceSamplingPolicy, SourceSelectionAudit,
    SourceSelectionComponentAudit, SourceSelectionCompositePolicy, SourceSelectionWorksheet,
    assess_source_selection, audit_label_reviews, audit_source_selection,
    audit_source_selection_component, build_blind_case_bundle, collect_source_frame,
    combine_source_selections, create_composite_source_seal, create_source_seal,
    extend_source_selection, inspect_label_review_progress, prepare_label_resolution,
    prepare_label_review, prepare_source_selection, prepare_source_selection_extension,
    source_selection_draft, validate_label_review, validate_label_review_audit,
    validate_source_frame_manifest, validate_source_seal,
};
use crate::benchmark_import::{BenchmarkRunReview, import_reviewed_run, prepare_run_review};
use std::fs;
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::Path;

/// Evaluate a complete external benchmark ledger without loading configuration
/// or contacting an LLM provider.
pub(crate) fn benchmark(
    cases_path: &str,
    predictions_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(cases_path)?;
    let submission = read_json::<BenchmarkSubmission>(predictions_path)?;
    let corpus_root = Path::new(cases_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let metrics = evaluate_release(&corpus, &submission, corpus_root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark ledger is invalid: {error}"),
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    match metrics.assert_release_gate() {
        Ok(()) => {
            eprintln!("SniffBench release gate passed.");
            Ok(0)
        }
        Err(error) => {
            eprintln!("SniffBench release gate failed: {error}");
            Ok(1)
        }
    }
}

pub(crate) fn freeze_benchmark(
    draft_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let draft = read_json::<BenchmarkCorpus>(draft_path)?;
    let corpus_root = Path::new(draft_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let frozen = freeze_corpus(draft, corpus_root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark corpus cannot be frozen: {error}"),
        )
    })?;
    let bytes = serde_json::to_vec_pretty(&frozen)?;
    write_new_file(Path::new(output_path), &bytes)?;
    eprintln!(
        "Frozen SniffBench corpus written to {output_path}\nSource commitment: {}\nLabel commitment: {}",
        frozen.source_commitment_sha256, frozen.label_commitment_sha256
    );
    Ok(0)
}

pub(crate) fn seal_non_blind_benchmark_sources(
    draft_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let draft = read_json::<NonBlindSourceSeal>(draft_path)?;
    let artifact_root = Path::new(draft_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let frozen = freeze_non_blind_source_seal(draft, artifact_root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("non-blind benchmark sources cannot be sealed: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&frozen)?)?;
    eprintln!(
        "Frozen non-blind SniffBench source seal written to {output_path}\nSeal commitment: {}",
        frozen.seal_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_non_blind_benchmark_history(
    policy_path: &str,
    frame_path: &str,
    blind_seal_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let frame = fs::read(frame_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let worksheet = prepare_non_blind_history(&policy, &frame, &blind_seal).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("non-blind history worksheet cannot be prepared: {error}"),
        )
    })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&worksheet)?,
    )?;
    eprintln!(
        "Non-blind history worksheet written to {output_path}\nCandidates: {}\nExcluded blind repositories: {}\nTask commitment: {}",
        worksheet.candidates.len(),
        worksheet.excluded_blind_repositories.len(),
        worksheet.task_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_non_blind_benchmark_history_assessment(
    policy_path: &str,
    worksheet_path: &str,
    protocol_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let worksheet = fs::read(worksheet_path)?;
    let protocol = fs::read(protocol_path)?;
    let assessment =
        prepare_non_blind_history_assessment(&policy, &worksheet, &protocol).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("non-blind history assessment cannot be prepared: {error}"),
            )
        })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&assessment)?,
    )?;
    eprintln!(
        "Non-blind history assessment written to {output_path}\nRepositories: {}\nLanguage quotas: {}\nTask commitment: {}",
        assessment.assessments.len(),
        assessment.quota_target.len(),
        assessment.task_sha256
    );
    Ok(0)
}

pub(crate) fn validate_intentional_boundary_benchmark_protocol(
    policy_path: &str,
    population_path: &str,
    blind_seal_path: &str,
    protocol_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let population = fs::read(population_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let protocol = fs::read(protocol_path)?;
    let validated =
        validate_intentional_boundary_protocol(&policy, &population, &blind_seal, &protocol)
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("intentional-boundary protocol is invalid: {error}"),
                )
            })?;
    eprintln!(
        "Intentional-boundary protocol validated\nCategories: {}\nFixed slots: {}\nProtocol SHA-256: {}",
        validated.protocol.category_contracts.len(),
        validated.protocol.slot_contract.total_slots,
        validated.protocol_sha256
    );
    Ok(0)
}

pub(crate) fn validate_historical_v2_benchmark_protocol(
    protocol_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let protocol = fs::read(protocol_path)?;
    let validated = validate_historical_v2_protocol(&protocol).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("historical-v2 protocol is invalid: {error}"),
        )
    })?;
    eprintln!(
        "Historical-v2 protocol validated\nLanguages: {}\nFixed slots: {}\nMinimum accepted cases: {}\nProtocol SHA-256: {}",
        validated.protocol.selection.supported_languages.len(),
        validated.protocol.selection.total_slots,
        validated.protocol.review.minimum_total_accepted,
        validated.protocol_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_intentional_boundary_benchmark_frame_task(
    policy_path: &str,
    population_path: &str,
    blind_seal_path: &str,
    protocol_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let population = fs::read(population_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let protocol = fs::read(protocol_path)?;
    let task =
        prepare_intentional_boundary_frame_task(&policy, &population, &blind_seal, &protocol)
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("intentional-boundary frame task cannot be prepared: {error}"),
                )
            })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&task)?)?;
    eprintln!(
        "Blank intentional-boundary frame task written to {output_path}\nRepositories: {}\nTask commitment: {}",
        task.repositories.len(),
        task.task_sha256
    );
    Ok(0)
}

pub(crate) fn validate_intentional_boundary_benchmark_frame_task(
    policy_path: &str,
    population_path: &str,
    blind_seal_path: &str,
    protocol_path: &str,
    task_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let population = fs::read(population_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let protocol = fs::read(protocol_path)?;
    let task = read_json::<IntentionalBoundaryFrameTask>(task_path)?;
    validate_intentional_boundary_frame_task(&policy, &population, &blind_seal, &protocol, &task)
        .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("intentional-boundary frame task is invalid: {error}"),
        )
    })?;
    eprintln!(
        "Intentional-boundary frame task validated\nRepositories: {}\nTask commitment: {}",
        task.repositories.len(),
        task.task_sha256
    );
    Ok(0)
}

pub(crate) async fn assess_non_blind_benchmark_history(
    policy_path: &str,
    worksheet_path: &str,
    protocol_path: &str,
    assessment_path: &str,
    state_directory: &str,
    output_path: &str,
    maximum_new_ranks: Option<usize>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = fs::read(policy_path)?;
    let worksheet = fs::read(worksheet_path)?;
    let protocol = fs::read(protocol_path)?;
    let assessment = read_json::<NonBlindHistoryAssessment>(assessment_path)?;
    let completed = match maximum_new_ranks {
        Some(maximum) => {
            assess_non_blind_history_slice(
                &policy,
                &worksheet,
                &protocol,
                assessment,
                Path::new(state_directory),
                maximum,
            )
            .await
        }
        None => {
            assess_non_blind_history(
                &policy,
                &worksheet,
                &protocol,
                assessment,
                Path::new(state_directory),
            )
            .await
        }
    }
    .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("non-blind history assessment failed: {error}"),
        )
    })?;
    let completed_ranks = completed
        .assessments
        .iter()
        .take_while(|assessment| assessment.disposition.is_some())
        .count();
    if completed_ranks < completed.assessments.len() {
        eprintln!(
            "Non-blind history assessment checkpointed in {state_directory}\nRepositories complete: {completed_ranks}/{}\nFinal output not written; rerun the same command to resume.",
            completed.assessments.len()
        );
        return Ok(0);
    }
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&completed)?,
    )?;
    let selected = completed
        .assessments
        .iter()
        .filter(|assessment| {
            assessment.disposition
                == Some(crate::benchmark::HistoricalAssessmentDisposition::Selected)
        })
        .count();
    eprintln!(
        "Completed non-blind history assessment written to {output_path}\nRepositories: {}\nSelected: {selected}\nEvidence root: {state_directory}",
        completed.assessments.len()
    );
    Ok(0)
}

pub(crate) async fn collect_benchmark_source_frame(
    policy_path: &str,
    state_directory: &str,
    frame_output: &str,
    manifest_output: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceFrameCollectionPolicy>(policy_path)?;
    let token = std::env::var("GH_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    let manifest = collect_source_frame(
        policy,
        Path::new(state_directory),
        Path::new(frame_output),
        Path::new(manifest_output),
        token.as_deref(),
    )
    .await
    .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source frame cannot be collected: {error}"),
        )
    })?;
    eprintln!(
        "Frozen SniffBench source frame written to {frame_output}\nRepositories: {}\nFrame commitment: {}\nManifest commitment: {}",
        manifest.repository_count, manifest.frame_sha256, manifest.manifest_sha256
    );
    Ok(0)
}

pub(crate) fn validate_benchmark_source_frame(
    manifest_path: &str,
    artifact_root: &str,
    frame_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let manifest = read_json(manifest_path)?;
    let frame = fs::read(frame_path)?;
    validate_source_frame_manifest(&manifest, Path::new(artifact_root), &frame).map_err(
        |error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark source frame is invalid: {error}"),
            )
        },
    )?;
    eprintln!("Source frame manifest and raw-page replay are valid.");
    Ok(0)
}

pub(crate) fn seal_benchmark_sources(
    audit_path: &str,
    frame_path: &str,
    checkout_root: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let audit_bytes = fs::read(audit_path)?;
    let audit: SourceSelectionAudit = serde_json::from_slice(&audit_bytes)?;
    let frame = fs::read(frame_path)?;
    let draft = source_selection_draft(&audit, &frame).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source selection audit is invalid: {error}"),
        )
    })?;
    let seal = create_source_seal(
        draft,
        &audit_bytes,
        &frame,
        Path::new(checkout_root),
        Path::new(output_path),
    )
    .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark sources cannot be sealed: {error}"),
        )
    })?;
    eprintln!(
        "Label-free SniffBench source seal written to {output_path}\nSources: {}\nEligible methods: {}\nSeal commitment: {}",
        seal.sources.len(),
        seal.methods.len(),
        seal.seal_sha256
    );
    Ok(0)
}

pub(crate) fn seal_composite_benchmark_sources(
    audit_path: &str,
    checkout_root: &str,
    output_path: &str,
    frame_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let audit_bytes = fs::read(audit_path)?;
    let frames = frame_paths
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    let seal = create_composite_source_seal(
        &audit_bytes,
        &frames,
        Path::new(checkout_root),
        Path::new(output_path),
    )
    .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("composite benchmark sources cannot be sealed: {error}"),
        )
    })?;
    eprintln!(
        "Composite label-free SniffBench source seal written to {output_path}\nComponents: {}\nSources: {}\nEligible methods: {}\nSeal commitment: {}",
        seal.selection_components.len(),
        seal.sources.len(),
        seal.methods.len(),
        seal.seal_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_source_selection(
    policy_path: &str,
    frame_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_path)?;
    let frame = fs::read(frame_path)?;
    let worksheet = prepare_source_selection(policy, &frame).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source selection cannot be prepared: {error}"),
        )
    })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&worksheet)?,
    )?;
    eprintln!(
        "SniffBench source-selection worksheet written to {output_path}. Ranked candidates: {}. No labels or Sniff output were used.",
        worksheet.candidates.len()
    );
    Ok(0)
}

pub(crate) fn extend_benchmark_source_selection(
    policy_path: &str,
    frame_path: &str,
    prior_worksheet_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_path)?;
    let frame = fs::read(frame_path)?;
    let prior = read_json::<SourceSelectionWorksheet>(prior_worksheet_path)?;
    let inherited = prior.candidates.len();
    let worksheet = extend_source_selection(policy, &frame, prior).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source selection cannot be extended: {error}"),
        )
    })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&worksheet)?,
    )?;
    eprintln!(
        "Extended SniffBench source-selection worksheet written to {output_path}. Inherited candidates: {inherited}. New candidates: {}. No labels or Sniff output were used.",
        worksheet.candidates.len() - inherited
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_source_selection_extension(
    policy_draft_path: &str,
    frame_path: &str,
    prior_worksheet_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_draft_path)?;
    let frame = fs::read(frame_path)?;
    let prior = read_json::<SourceSelectionWorksheet>(prior_worksheet_path)?;
    let policy = prepare_source_selection_extension(policy, &frame, &prior).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source-selection extension cannot be prepared: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&policy)?)?;
    eprintln!(
        "Finalized SniffBench source-selection extension policy written to {output_path}. Prior candidates: {}. Committed endpoint: {}. No new ranks were generated.",
        prior.candidates.len(),
        policy.assessment_prefix
    );
    Ok(0)
}

pub(crate) async fn assess_benchmark_source_selection(
    policy_path: &str,
    frame_path: &str,
    worksheet_path: &str,
    state_directory: &str,
    checkout_root: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_path)?;
    let frame = fs::read(frame_path)?;
    let worksheet = read_json::<SourceSelectionWorksheet>(worksheet_path)?;
    let token = std::env::var("GH_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    let completed = assess_source_selection(
        policy,
        &frame,
        worksheet,
        Path::new(state_directory),
        Path::new(checkout_root),
        token.as_deref(),
    )
    .await
    .map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source selection cannot be assessed: {error}"),
        )
    })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&completed)?,
    )?;
    eprintln!(
        "Completed SniffBench source assessment written to {output_path}. Assessed candidates: {}.",
        completed.candidates.len()
    );
    Ok(0)
}

pub(crate) fn audit_benchmark_source_selection(
    policy_path: &str,
    frame_path: &str,
    worksheet_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_path)?;
    let frame = fs::read(frame_path)?;
    let worksheet = read_json::<SourceSelectionWorksheet>(worksheet_path)?;
    let audit = audit_source_selection(policy, &frame, worksheet).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source selection is invalid: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&audit)?)?;
    eprintln!(
        "Verified SniffBench source-selection audit written to {output_path}. Selected repositories: {}. Audit commitment: {}",
        audit.selected_repositories.len(),
        audit.audit_sha256
    );
    Ok(0)
}

pub(crate) fn audit_benchmark_source_selection_component(
    policy_path: &str,
    frame_path: &str,
    worksheet_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSamplingPolicy>(policy_path)?;
    let frame = fs::read(frame_path)?;
    let worksheet = read_json::<SourceSelectionWorksheet>(worksheet_path)?;
    let audit = audit_source_selection_component(policy, &frame, worksheet).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source-selection component is invalid: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&audit)?)?;
    eprintln!(
        "Verified SniffBench source-selection component written to {output_path}. Selected repositories: {}. Component commitment: {}",
        audit.selected_repositories.len(),
        audit.component_audit_sha256
    );
    Ok(0)
}

pub(crate) fn combine_benchmark_source_selections(
    policy_path: &str,
    output_path: &str,
    component_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let policy = read_json::<SourceSelectionCompositePolicy>(policy_path)?;
    let components = component_paths
        .iter()
        .map(|path| read_json::<SourceSelectionComponentAudit>(path))
        .collect::<Result<Vec<_>, _>>()?;
    let audit = combine_source_selections(policy, components).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark composite source selection is invalid: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&audit)?)?;
    eprintln!(
        "Verified SniffBench composite source selection written to {output_path}. Components: {}. Selected repositories: {}. Composite commitment: {}",
        audit.components.len(),
        audit.selected_repositories.len(),
        audit.composite_audit_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_labels(
    seal_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let seal_root = Path::new(seal_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let worksheet =
        prepare_label_review(&seal, seal_root, &sha256(&seal_bytes)).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark labels cannot be prepared: {error}"),
            )
        })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&worksheet)?,
    )?;
    eprintln!(
        "Source-only SniffBench label worksheet written to {output_path}. Methods: {}. Complete it independently without Sniff output.",
        worksheet.methods.len()
    );
    Ok(0)
}

pub(crate) fn validate_benchmark_labels(
    seal_path: &str,
    review_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let seal_root = Path::new(seal_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let review = read_json::<LabelReviewWorksheet>(review_path)?;
    validate_label_review(&seal, seal_root, &sha256(&seal_bytes), &review).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark label worksheet is invalid: {error}"),
        )
    })?;
    let reviewer = review
        .reviewer
        .as_ref()
        .expect("validated label worksheet has reviewer identity");
    eprintln!(
        "Verified complete source-only label worksheet {review_path}. Reviewer: {}. Methods: {}.",
        reviewer.reviewer_id,
        review.methods.len()
    );
    Ok(0)
}

pub(crate) fn benchmark_label_status(
    seal_path: &str,
    review_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal_manifest(seal_path)?;
    let review = read_json::<LabelReviewWorksheet>(review_path)?;
    let progress =
        inspect_label_review_progress(&seal, &sha256(&seal_bytes), &review).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark label worksheet is invalid: {error}"),
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&progress)?);
    Ok(0)
}

pub(crate) fn audit_benchmark_labels(
    seal_path: &str,
    output_path: &str,
    review_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let seal_root = Path::new(seal_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let reviews = review_paths
        .iter()
        .map(|path| read_json::<LabelReviewWorksheet>(path))
        .collect::<Result<Vec<_>, _>>()?;
    let audit =
        audit_label_reviews(&seal, seal_root, &sha256(&seal_bytes), &reviews).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark label worksheets cannot be audited: {error}"),
            )
        })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&audit)?)?;
    eprintln!(
        "Verified SniffBench label audit written to {output_path}. Agreements: {}. Disputes requiring resolution: {}.",
        audit.agreement_count, audit.disputed_count
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_label_resolution(
    seal_path: &str,
    audit_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let audit = read_json::<LabelReviewAudit>(audit_path)?;
    let draft = prepare_label_resolution(&seal, &sha256(&seal_bytes), &audit).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark label resolution cannot be prepared: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&draft)?)?;
    eprintln!(
        "SniffBench label-resolution draft written to {output_path}. Cases: {}. Complete resolver identity, disputes, and finding proof artifacts.",
        draft.cases.len()
    );
    Ok(0)
}

pub(crate) fn resolve_benchmark_labels(
    seal_path: &str,
    audit_path: &str,
    resolution_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let audit = read_json::<LabelReviewAudit>(audit_path)?;
    validate_label_review_audit(&seal, &sha256(&seal_bytes), &audit).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark label audit is invalid: {error}"),
        )
    })?;
    let resolution = read_json::<LabelResolutionManifest>(resolution_path)?;
    let root = Path::new(resolution_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let bundle = build_blind_case_bundle(&seal, &sha256(&seal_bytes), &audit, &resolution, root)
        .map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark labels cannot be resolved: {error}"),
            )
        })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&bundle)?)?;
    eprintln!(
        "Verified SniffBench blind-case bundle written to {output_path}. Cases: {}. Bundle commitment: {}",
        bundle.cases.len(),
        bundle.bundle_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_run(
    corpus_path: &str,
    output_path: &str,
    artifact_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(corpus_path)?;
    let corpus_root = Path::new(corpus_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let artifacts = artifact_paths
        .iter()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    let review = prepare_run_review(&corpus, corpus_root, &artifacts).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark run cannot be prepared: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&review)?)?;
    eprintln!(
        "Label-blind SniffBench review worksheet written to {output_path}. Complete only reviews, actual cost provenance, and wall-clock time."
    );
    Ok(0)
}

pub(crate) fn import_benchmark_run(
    corpus_path: &str,
    review_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(corpus_path)?;
    let review = read_json::<BenchmarkRunReview>(review_path)?;
    let corpus_root = Path::new(corpus_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let run = import_reviewed_run(&corpus, corpus_root, &review).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark run cannot be imported: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&run)?)?;
    eprintln!("Verified SniffBench run written to {output_path}.");
    Ok(0)
}

pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), IoError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            IoError::new(
                error.kind(),
                format!(
                    "failed to create frozen benchmark file {}: {error}",
                    path.display()
                ),
            )
        })?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

pub(super) fn read_json<T>(path: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let text = fs::read_to_string(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read benchmark file {path}: {error}"),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("failed to parse benchmark JSON {path}: {error}"),
        )
        .into()
    })
}

fn read_source_seal(
    path: &str,
) -> Result<(BenchmarkSourceSeal, Vec<u8>), Box<dyn std::error::Error>> {
    let (seal, bytes) = read_source_seal_manifest(path)?;
    let root = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    validate_source_seal(&seal, root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source seal is invalid: {error}"),
        )
    })?;
    Ok((seal, bytes))
}

fn read_source_seal_manifest(
    path: &str,
) -> Result<(BenchmarkSourceSeal, Vec<u8>), Box<dyn std::error::Error>> {
    let bytes = fs::read(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read benchmark source seal {path}: {error}"),
        )
    })?;
    let seal = serde_json::from_slice::<BenchmarkSourceSeal>(&bytes).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("failed to parse benchmark source seal {path}: {error}"),
        )
    })?;
    Ok((seal, bytes))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        audit_benchmark_source_selection, benchmark, prepare_benchmark_source_selection,
        seal_benchmark_sources, write_new_file,
    };
    use crate::benchmark::{
        SOURCE_SAMPLING_POLICY_SCHEMA_VERSION, SourceAssessmentEvidence,
        SourceAssessmentEvidenceKind, SourceAssessmentFacts, SourceSamplingPolicy,
        SourceSelectionDisposition, SourceSelectionWorksheet,
    };
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sniff-benchmark-cli-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn legacy_arrays_are_rejected_as_release_proof() {
        let cases = temp_path("cases");
        let predictions = temp_path("predictions");
        fs::write(
            &cases,
            r#"[{"case_id":"clean-1","language":"python","expected_tier":"clean","expected_pattern":"none"}]"#,
        )
        .expect("write benchmark cases");
        fs::write(
            &predictions,
            r#"[{"case_id":"clean-1","tier":"clean","pattern":"none","evidence_valid":false}]"#,
        )
        .expect("write benchmark predictions");

        let error = benchmark(
            cases.to_str().expect("cases path should be UTF-8"),
            predictions
                .to_str()
                .expect("predictions path should be UTF-8"),
        )
        .expect_err("legacy arrays must not be accepted as release proof");
        assert!(error.to_string().contains("failed to parse benchmark JSON"));
        let _ = fs::remove_file(cases);
        let _ = fs::remove_file(predictions);
    }

    #[test]
    fn malformed_ledger_fails_before_metrics_are_emitted() {
        let cases = temp_path("invalid-cases");
        let predictions = temp_path("invalid-predictions");
        fs::write(&cases, "not json").expect("write invalid cases");
        fs::write(&predictions, "[]").expect("write predictions");

        assert!(
            benchmark(
                cases.to_str().expect("cases path should be UTF-8"),
                predictions
                    .to_str()
                    .expect("predictions path should be UTF-8")
            )
            .is_err()
        );
        let _ = fs::remove_file(cases);
        let _ = fs::remove_file(predictions);
    }

    #[test]
    fn frozen_manifest_writer_never_overwrites_an_existing_file() {
        let output = temp_path("existing-frozen");
        fs::write(&output, "existing").expect("write existing output");

        let error = write_new_file(&output, b"replacement").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&output).unwrap(), "existing");
        let _ = fs::remove_file(output);
    }

    #[test]
    fn source_sealing_is_an_offline_create_new_workflow() {
        let bundle = temp_path("source-seal-bundle");
        fs::create_dir_all(&bundle).unwrap();
        let definitions = [
            (
                "go",
                "main.go",
                "package fixture\nfunc Sealed() int { return 1 }\n",
            ),
            ("javascript", "main.js", "function sealed() { return 1; }\n"),
            ("kotlin", "Main.kt", "fun sealed(): Int = 1\n"),
            ("python", "main.py", "def sealed():\n    return 1\n"),
            ("rust", "main.rs", "pub fn sealed() -> i32 { 1 }\n"),
            (
                "typescript",
                "main.ts",
                "function sealed(): number { return 1; }\n",
            ),
        ];
        let checkout_root = bundle.join("checkouts");
        let mut checkouts = HashMap::new();
        for (language, path, source) in definitions {
            let repository = checkout_root
                .join("example")
                .join(format!("{language}-fixture"));
            fs::create_dir_all(&repository).unwrap();
            fs::write(repository.join(path), source).unwrap();
            fs::write(repository.join("LICENSE"), "test license\n").unwrap();
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["init"])
                .output()
                .unwrap();
            assert!(output.status.success());
            for args in [
                ["config", "user.email", "seal@example.test"].as_slice(),
                ["config", "user.name", "Seal Test"].as_slice(),
                ["add", "."].as_slice(),
                ["commit", "-m", "fixture"].as_slice(),
            ] {
                assert!(
                    std::process::Command::new("git")
                        .arg("-C")
                        .arg(&repository)
                        .args(args)
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
            }
            let revision = std::process::Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap();
            checkouts.insert(
                language.to_string(),
                String::from_utf8(revision.stdout)
                    .unwrap()
                    .trim()
                    .to_string(),
            );
        }
        let frame = definitions.iter().fold(
            String::from("repo,metadata\n"),
            |mut frame, (language, _, _)| {
                frame.push_str(&format!("github.com/example/{language}-fixture,test\n"));
                frame
            },
        );
        let frame_path = bundle.join("projects.csv");
        fs::write(&frame_path, &frame).unwrap();
        let policy = SourceSamplingPolicy {
            schema_version: SOURCE_SAMPLING_POLICY_SCHEMA_VERSION,
            selection_id: "offline-seal".to_string(),
            selected_at: "2026-08-12T00:00:00Z".to_string(),
            frame_source: "https://github.com/ossf/scorecard/projects.csv".to_string(),
            frame_revision: "1".repeat(40),
            frame_blob_sha: "2".repeat(40),
            frame_sha256: format!("{:x}", Sha256::digest(frame.as_bytes())),
            seed: "offline-seal-seed".to_string(),
            assessment_prefix: 6,
            minimum_methods: 1,
            maximum_methods: 10,
            language_quotas: definitions
                .iter()
                .map(|(language, _, _)| (language.to_string(), 1))
                .collect::<BTreeMap<_, _>>(),
            attestation: "Selected before labels and Sniff output.".to_string(),
            continuation: None,
        };
        let policy_path = bundle.join("policy.json");
        let worksheet_path = bundle.join("selection-review.json");
        let audit_path = bundle.join("selection-audit.json");
        let output_path = bundle.join("seal.json");
        fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();

        prepare_benchmark_source_selection(
            policy_path.to_str().unwrap(),
            frame_path.to_str().unwrap(),
            worksheet_path.to_str().unwrap(),
        )
        .unwrap();
        let mut worksheet: SourceSelectionWorksheet =
            serde_json::from_slice(&fs::read(&worksheet_path).unwrap()).unwrap();
        for candidate in &mut worksheet.candidates {
            let language = definitions
                .iter()
                .find(|(language, _, _)| candidate.candidate.repository.contains(*language))
                .map(|(language, _, _)| *language)
                .unwrap();
            let revision = &checkouts[language];
            candidate.selection_quota_language = language.to_string();
            candidate.observed_method_count = Some(1);
            let facts = SourceAssessmentFacts {
                repository: candidate.candidate.repository.clone(),
                selection_quota_language: language.to_string(),
                observed_method_count: Some(1),
                assessed_revision: Some(revision.clone()),
                method_counts: BTreeMap::from([(language.to_string(), 1)]),
                method_census_contract: Some(
                    crate::benchmark::SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                ),
                repository_empty: false,
                accessible: true,
                archived: Some(false),
                fork: Some(false),
                license_path: Some("LICENSE".to_string()),
                supported_project_shape: Some(true),
            };
            let payload = serde_json::to_string(&facts).unwrap();
            candidate.facts = Some(facts);
            let raw_payload = format!("raw metadata for {}", candidate.candidate.repository);
            let census_payload = format!("census for {}", candidate.candidate.repository);
            candidate.evidence = vec![
                SourceAssessmentEvidence {
                    kind: SourceAssessmentEvidenceKind::StructuredFacts,
                    source: "derived:source-assessment-facts-v2".to_string(),
                    observed_at: "2026-08-12T00:00:00Z".to_string(),
                    payload_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
                    payload,
                },
                SourceAssessmentEvidence {
                    kind: SourceAssessmentEvidenceKind::RawSource,
                    source: "https://example.test/source-selection-metadata".to_string(),
                    observed_at: "2026-08-12T00:00:00Z".to_string(),
                    payload_sha256: format!("{:x}", Sha256::digest(raw_payload.as_bytes())),
                    payload: raw_payload,
                },
                SourceAssessmentEvidence {
                    kind: SourceAssessmentEvidenceKind::DerivedCensus,
                    source: crate::benchmark::SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                    observed_at: "2026-08-12T00:00:00Z".to_string(),
                    payload_sha256: format!("{:x}", Sha256::digest(census_payload.as_bytes())),
                    payload: census_payload,
                },
            ];
            candidate.disposition = Some(SourceSelectionDisposition::Selected);
            candidate.selected_repository = Some(crate::benchmark::SourceRepositoryDraft {
                repository: format!("https://{}", candidate.candidate.repository),
                revision: revision.clone(),
                license_path: "LICENSE".to_string(),
                selection_language: language.to_string(),
                observed_method_count: 1,
                context_paths: Vec::new(),
            });
        }
        fs::write(
            &worksheet_path,
            serde_json::to_vec_pretty(&worksheet).unwrap(),
        )
        .unwrap();
        audit_benchmark_source_selection(
            policy_path.to_str().unwrap(),
            frame_path.to_str().unwrap(),
            worksheet_path.to_str().unwrap(),
            audit_path.to_str().unwrap(),
        )
        .unwrap();

        let code = seal_benchmark_sources(
            audit_path.to_str().unwrap(),
            frame_path.to_str().unwrap(),
            checkout_root.to_str().unwrap(),
            output_path.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(code, 0);
        assert!(output_path.is_file());
        assert!(bundle.join("seal.sources").read_dir().unwrap().count() >= 6);
        let error = seal_benchmark_sources(
            audit_path.to_str().unwrap(),
            frame_path.to_str().unwrap(),
            checkout_root.to_str().unwrap(),
            output_path.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        let _ = fs::remove_dir_all(bundle);
    }
}
