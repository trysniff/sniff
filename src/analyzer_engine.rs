use crate::config::ResolvedConfig;
use crate::env_value;
use crate::llm::LLMClient;
use crate::report_types::{LLMVerdict, StaticFlag};
use crate::types::{FileRecord, MethodRecord};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "analyzer_prompts.rs"]
mod analyzer_prompts;
#[path = "analyzer_file.rs"]
mod file_review;
#[path = "analyzer_method.rs"]
mod method_review;
#[path = "analyzer_verdicts.rs"]
mod verdicts;

#[path = "analyzer_support.rs"]
mod support;
use support::review_key;

#[path = "analyzer_engine_jobs.rs"]
mod jobs;
#[path = "analyzer_signal_maps.rs"]
mod signal_maps;

pub struct Analyzer {
    pub llm_client: Arc<LLMClient>,
    pub in_tok: AtomicUsize,
    pub out_tok: AtomicUsize,
}

impl Analyzer {
    pub async fn analyze_method_review(
        &self,
        method: &MethodRecord,
        static_signals: &[String],
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        method_review::analyze_method_review(self, method, static_signals).await
    }

    async fn analyze_method_review_with_context(
        &self,
        method: &MethodRecord,
        static_signals: &[String],
        file_context: &str,
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        method_review::analyze_method_review_with_context(
            self,
            method,
            static_signals,
            file_context,
        )
        .await
    }

    pub async fn analyze_file(
        &self,
        file: &FileRecord,
        static_signals: &[String],
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        file_review::analyze_file(self, file, static_signals).await
    }
}

pub async fn analyze_with_client<F>(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    client: Arc<LLMClient>,
    only_files: bool,
    on_progress: Option<F>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String>
where
    F: Fn() + Send + Sync + 'static,
{
    let analyzer = Arc::new(Analyzer {
        llm_client: client,
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    });

    let (method_signals, file_signals) = signal_maps::build_static_signal_maps(static_flags);

    let mut jobs = Vec::new();
    let mut review_index = 0usize;

    if !only_files {
        for file in file_records {
            for method in file
                .methods
                .iter()
                .filter(|method| !support::is_rust_cfg_test_method(file, method))
            {
                let static_signals = method_signals
                    .get(&review_key(&method.file_path, &method.name))
                    .cloned()
                    .unwrap_or_default();
                jobs.push(jobs::ReviewJob::Method {
                    index: review_index,
                    method: method.clone(),
                    static_signals,
                    file_context: support::surrounding_file_context(file, method),
                });
                review_index += 1;
            }
        }
    }

    for file in file_records.iter().cloned() {
        let static_signals = file_signals
            .get(&file.file_path)
            .cloned()
            .unwrap_or_default();
        jobs.push(jobs::ReviewJob::File {
            index: review_index,
            file,
            static_signals,
        });
        review_index += 1;
    }

    let on_progress = on_progress.map(Arc::new);
    let verdicts = jobs::run_review_jobs(Arc::clone(&analyzer), jobs, on_progress).await?;

    let total_in = analyzer.in_tok.load(Ordering::SeqCst);
    let total_out = analyzer.out_tok.load(Ordering::SeqCst);
    Ok((verdicts, total_in, total_out))
}

pub async fn analyze<F>(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    config: ResolvedConfig,
    only_files: bool,
    on_progress: Option<F>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String>
where
    F: Fn() + Send + Sync + 'static,
{
    let api_key = env_value::read("SNIFF_API_KEY");
    if api_key.is_none() {
        if file_records.is_empty() {
            return Ok((Vec::new(), 0, 0));
        }
        return Err(
            "AI config is missing; set SNIFF_API_KEY and SNIFF_ENDPOINT before running Sniff."
                .to_string(),
        );
    }

    let client = LLMClient::try_new(config, api_key)
        .map_err(|err| format!("LLM client initialization failed: {err}"))?;

    analyze_with_client(
        file_records,
        static_flags,
        Arc::new(client),
        only_files,
        on_progress,
    )
    .await
}

#[cfg(test)]
#[path = "tests/analyzer.rs"]
mod tests;
