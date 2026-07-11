use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, MethodRecord};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::Analyzer;

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

async fn run_review_job(analyzer: Arc<Analyzer>, job: ReviewJob) -> Result<ReviewOutcome, String> {
    match job {
        ReviewJob::Method {
            index,
            method,
            static_signals,
            file_context,
        } => match analyzer
            .analyze_method_review_with_context(&method, &static_signals, &file_context)
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
        } => match analyzer.analyze_file(&file, &static_signals).await {
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

pub(super) async fn run_review_jobs<F>(
    analyzer: Arc<Analyzer>,
    jobs: Vec<ReviewJob>,
    on_progress: Option<Arc<F>>,
) -> Result<Vec<LLMVerdict>, String>
where
    F: Fn() + Send + Sync + 'static,
{
    let mut outcomes = Vec::with_capacity(jobs.len());
    for job in jobs {
        let analyzer = Arc::clone(&analyzer);
        let outcome = run_review_job(analyzer.clone(), job).await?;
        analyzer.in_tok.fetch_add(outcome.in_tok, Ordering::SeqCst);
        analyzer
            .out_tok
            .fetch_add(outcome.out_tok, Ordering::SeqCst);
        if let Some(op) = on_progress.as_ref() {
            op();
        }
        outcomes.push(outcome);
    }

    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes
        .into_iter()
        .filter_map(|outcome| outcome.verdict)
        .collect())
}
