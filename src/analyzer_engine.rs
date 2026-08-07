use crate::config::ResolvedConfig;
use crate::env_value;
use crate::llm::LLMClient;
use crate::report_types::{LLMVerdict, MethodReviewRecord, StaticFlag};
use crate::types::{FileRecord, MethodRecord};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{ReviewProgress, ReviewProgressCallback};

#[path = "analyzer_prompts.rs"]
mod analyzer_prompts;
#[path = "analyzer_file.rs"]
mod file_review;
#[path = "analyzer_method_batch.rs"]
mod method_batch_review;
#[path = "analyzer_method.rs"]
mod method_review;
#[path = "analyzer_verdicts.rs"]
mod verdicts;

#[path = "analyzer_support.rs"]
mod support;
use support::review_key;

#[path = "analyzer_dossier.rs"]
mod dossier;
#[path = "analyzer_engine_jobs.rs"]
mod jobs;
use crate::review_journal as journal;
pub use crate::review_journal::JournalSummary;
#[path = "analyzer_signal_maps.rs"]
mod signal_maps;

pub struct Analyzer {
    pub llm_client: Arc<LLMClient>,
    pub in_tok: AtomicUsize,
    pub out_tok: AtomicUsize,
}

pub struct AnalysisRun<'a> {
    pub file_records: &'a [FileRecord],
    pub context_file_records: &'a [FileRecord],
    pub static_flags: &'a [StaticFlag],
    pub with_file_reviews: bool,
    pub graph: Option<&'a crate::symbol_graph::SymbolGraph>,
    pub journal_path: Option<&'a std::path::Path>,
    pub scan_id: Option<&'a str>,
    pub budget_usd: Option<f64>,
}

pub struct AnalysisResult {
    pub verdicts: Vec<LLMVerdict>,
    pub method_records: Vec<MethodReviewRecord>,
}

pub fn summarize_journal(path: &std::path::Path) -> Result<JournalSummary, String> {
    journal::summarize(path)
}

impl Analyzer {
    pub async fn analyze_method_review(
        &self,
        method: &MethodRecord,
        static_signals: &[String],
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        self.analyze_method_review_with_context(
            method,
            static_signals,
            method_review::MethodReviewContext {
                file_context: "",
                project_root: None,
                callee_context: &[],
                boundary_requirements: &[],
                repository_private_unused_candidate: false,
                stale_discard_signature_proof: None,
            },
            None,
        )
        .await
    }

    async fn analyze_method_review_with_context(
        &self,
        method: &MethodRecord,
        static_signals: &[String],
        context: method_review::MethodReviewContext<'_>,
        on_progress: Option<&ReviewProgressCallback>,
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        method_review::analyze_method_review_with_context(
            self,
            method,
            static_signals,
            context,
            on_progress,
        )
        .await
    }

    async fn analyze_method_review_batch(
        &self,
        items: &[method_batch_review::BatchMethodReview],
        on_progress: Option<&ReviewProgressCallback>,
        on_usage: Option<&method_batch_review::BatchUsageCallback>,
        on_completed: Option<&method_batch_review::BatchCompletionCallback>,
    ) -> Result<
        (
            Vec<(LLMVerdict, verdicts::SemanticMethodReview)>,
            usize,
            usize,
        ),
        String,
    > {
        method_batch_review::analyze_method_review_batch(
            self,
            items,
            on_progress,
            on_usage,
            on_completed,
        )
        .await
    }

    async fn analyze_method_record_with_context(
        &self,
        method: &MethodRecord,
        static_signals: &[String],
        context: method_review::MethodReviewContext<'_>,
        on_progress: Option<&ReviewProgressCallback>,
    ) -> Result<(Option<method_review::MethodReviewAnalysis>, usize, usize), String> {
        method_review::analyze_method_record_with_context(
            self,
            method,
            static_signals,
            context,
            on_progress,
        )
        .await
    }

    pub async fn analyze_file(
        &self,
        file: &FileRecord,
        static_signals: &[String],
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        file_review::analyze_file(self, file, static_signals, None).await
    }

    async fn analyze_file_with_progress(
        &self,
        file: &FileRecord,
        static_signals: &[String],
        on_progress: Option<&ReviewProgressCallback>,
    ) -> Result<(Option<LLMVerdict>, usize, usize), String> {
        file_review::analyze_file(self, file, static_signals, on_progress).await
    }
}

pub async fn analyze_with_client(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    client: Arc<LLMClient>,
    with_file_reviews: bool,
    on_progress: Option<ReviewProgressCallback>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
    analyze_with_client_and_graph(
        file_records,
        static_flags,
        client,
        with_file_reviews,
        on_progress,
        None,
    )
    .await
}

pub async fn analyze_with_client_and_graph(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    client: Arc<LLMClient>,
    with_file_reviews: bool,
    on_progress: Option<ReviewProgressCallback>,
    graph: Option<&crate::symbol_graph::SymbolGraph>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
    analyze_with_client_and_graph_and_journal(
        file_records,
        static_flags,
        client,
        with_file_reviews,
        on_progress,
        graph,
        None,
    )
    .await
}

pub async fn analyze_with_client_and_graph_and_journal(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    client: Arc<LLMClient>,
    with_file_reviews: bool,
    on_progress: Option<ReviewProgressCallback>,
    graph: Option<&crate::symbol_graph::SymbolGraph>,
    journal_path: Option<&std::path::Path>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
    analyze_with_client_and_graph_and_journal_with_context(
        AnalysisRun {
            file_records,
            context_file_records: file_records,
            static_flags,
            with_file_reviews,
            graph,
            journal_path,
            scan_id: None,
            budget_usd: None,
        },
        client,
        on_progress,
    )
    .await
}

pub async fn analyze_with_client_and_graph_and_journal_with_context(
    run: AnalysisRun<'_>,
    client: Arc<LLMClient>,
    on_progress: Option<ReviewProgressCallback>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
    let (result, total_in, total_out) =
        analyze_with_client_and_graph_and_journal_with_context_and_records(
            run,
            client,
            on_progress,
        )
        .await?;
    Ok((result.verdicts, total_in, total_out))
}

pub async fn analyze_with_client_and_graph_and_journal_with_context_and_records(
    run: AnalysisRun<'_>,
    client: Arc<LLMClient>,
    on_progress: Option<ReviewProgressCallback>,
) -> Result<(AnalysisResult, usize, usize), String> {
    let AnalysisRun {
        file_records,
        context_file_records,
        static_flags,
        with_file_reviews,
        graph,
        journal_path,
        scan_id,
        budget_usd,
    } = run;
    let analyzer = Arc::new(Analyzer {
        llm_client: client,
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    });

    let (method_signals, file_signals) = signal_maps::build_static_signal_maps(static_flags);
    let empty_graph = crate::symbol_graph::SymbolGraph::new("");
    let dossier_graph = graph.unwrap_or(&empty_graph);
    let callee_contexts = crate::callgraph::build_callee_context(file_records, dossier_graph);
    let dossier_index =
        dossier::build_dossier_repository_index(dossier_graph, context_file_records);

    let mut jobs = Vec::new();
    let mut review_index = 0usize;

    for file in file_records {
        for method in &file.methods {
            let static_signals = method_signals
                .get(&review_key(&method.file_path, &method.name))
                .cloned()
                .unwrap_or_default();
            let callee_context = callee_contexts
                .get(&(
                    method.file_path.clone(),
                    method.name.clone(),
                    method.start_line,
                ))
                .cloned()
                .unwrap_or_default();
            let dossier = dossier::build_method_dossier_with_index(
                file,
                method,
                &dossier_index,
                callee_context,
            );
            jobs.push(jobs::ReviewJob::Method {
                index: review_index,
                method: method.clone(),
                static_signals,
                dossier,
            });
            review_index += 1;
        }
    }

    if with_file_reviews {
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
    }

    let review_context_key = analyzer.llm_client.review_context_key();
    let result = jobs::run_review_jobs_with_records(
        Arc::clone(&analyzer),
        jobs,
        on_progress,
        &review_context_key,
        journal_path,
        scan_id,
        budget_usd,
    )
    .await?;

    let total_in = analyzer.in_tok.load(Ordering::SeqCst);
    let total_out = analyzer.out_tok.load(Ordering::SeqCst);
    Ok((
        AnalysisResult {
            verdicts: result.verdicts,
            method_records: result.method_records,
        },
        total_in,
        total_out,
    ))
}

pub async fn analyze(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    config: ResolvedConfig,
    with_file_reviews: bool,
    on_progress: Option<ReviewProgressCallback>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
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
        with_file_reviews,
        on_progress,
    )
    .await
}

#[cfg(test)]
#[path = "tests/analyzer.rs"]
mod tests;
