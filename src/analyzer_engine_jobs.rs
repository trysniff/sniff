use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, MethodRecord};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::task::JoinSet;

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

async fn abort_review_jobs(jobs: &mut JoinSet<Result<ReviewOutcome, String>>) {
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}

pub(super) async fn run_review_jobs<F>(
    analyzer: Arc<Analyzer>,
    jobs: Vec<ReviewJob>,
    on_progress: Option<Arc<F>>,
) -> Result<Vec<LLMVerdict>, String>
where
    F: Fn() + Send + Sync + 'static,
{
    let mut running = JoinSet::new();
    for job in jobs {
        let analyzer = Arc::clone(&analyzer);
        let on_progress = on_progress.clone();
        running.spawn(async move {
            let outcome = run_review_job(Arc::clone(&analyzer), job).await?;
            analyzer.in_tok.fetch_add(outcome.in_tok, Ordering::SeqCst);
            analyzer
                .out_tok
                .fetch_add(outcome.out_tok, Ordering::SeqCst);
            if let Some(op) = on_progress.as_ref() {
                op();
            }
            Ok(outcome)
        });
    }

    let mut outcomes = Vec::new();
    while let Some(joined) = running.join_next().await {
        match joined {
            Ok(Ok(outcome)) => outcomes.push(outcome),
            Ok(Err(err)) => {
                abort_review_jobs(&mut running).await;
                return Err(err);
            }
            Err(err) => {
                abort_review_jobs(&mut running).await;
                return Err(format!("LLM review task failed: {err}"));
            }
        }
    }

    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes
        .into_iter()
        .filter_map(|outcome| outcome.verdict)
        .collect())
}
