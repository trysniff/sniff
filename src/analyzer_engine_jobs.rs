use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, MethodRecord};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Analyzer, ReviewProgress, ReviewProgressCallback};

pub(super) enum ReviewJob {
    Method {
        index: usize,
        method: MethodRecord,
        static_signals: Vec<String>,
        file_context: String,
    },
    File {
        index: usize,
        file: FileRecord,
        static_signals: Vec<String>,
    },
}

struct ReviewOutcome {
    index: usize,
    verdict: Option<LLMVerdict>,
    in_tok: usize,
    out_tok: usize,
}

impl ReviewJob {
    fn label(&self) -> String {
        match self {
            Self::Method { method, .. } => format!("method {}::{}", method.file_path, method.name),
            Self::File { file, .. } => format!("file {}", file.file_path),
        }
    }
}

async fn run_review_job(
    analyzer: Arc<Analyzer>,
    job: ReviewJob,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<ReviewOutcome, String> {
    match job {
        ReviewJob::Method {
            index,
            method,
            static_signals,
            file_context,
        } => match analyzer
            .analyze_method_review_with_context(
                &method,
                &static_signals,
                &file_context,
                on_progress,
            )
            .await
        {
            Ok((verdict, in_tok, out_tok)) => Ok(ReviewOutcome {
                index,
                verdict,
                in_tok,
                out_tok,
            }),
            Err(err) => Err(format!(
                "LLM review failed: method {}::{}: {}",
                method.file_path, method.name, err
            )),
        },
        ReviewJob::File {
            index,
            file,
            static_signals,
        } => match analyzer
            .analyze_file_with_progress(&file, &static_signals, on_progress)
            .await
        {
            Ok((verdict, in_tok, out_tok)) => Ok(ReviewOutcome {
                index,
                verdict,
                in_tok,
                out_tok,
            }),
            Err(err) => Err(format!(
                "LLM review failed: file {}: {}",
                file.file_path, err
            )),
        },
    }
}

pub(super) async fn run_review_jobs(
    analyzer: Arc<Analyzer>,
    jobs: Vec<ReviewJob>,
    on_progress: Option<ReviewProgressCallback>,
) -> Result<Vec<LLMVerdict>, String> {
    let mut outcomes = Vec::with_capacity(jobs.len());
    for job in jobs {
        let analyzer = Arc::clone(&analyzer);
        if let Some(callback) = on_progress.as_ref() {
            callback(ReviewProgress::Started { label: job.label() });
        }
        let outcome = run_review_job(analyzer.clone(), job, on_progress.as_ref()).await?;
        analyzer.in_tok.fetch_add(outcome.in_tok, Ordering::SeqCst);
        analyzer
            .out_tok
            .fetch_add(outcome.out_tok, Ordering::SeqCst);
        if let Some(op) = on_progress.as_ref() {
            op(ReviewProgress::Completed);
        }
        outcomes.push(outcome);
    }

    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes
        .into_iter()
        .filter_map(|outcome| outcome.verdict)
        .collect())
}
