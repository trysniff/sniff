use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewProgress {
    Started { label: String },
    RetryingEvidence { label: String },
    Completed,
}

pub type ReviewProgressCallback = Arc<dyn Fn(ReviewProgress) + Send + Sync>;

#[path = "analyzer_engine.rs"]
mod core;

pub use core::{
    AnalysisRun, Analyzer, analyze, analyze_with_client, analyze_with_client_and_graph,
    analyze_with_client_and_graph_and_journal,
    analyze_with_client_and_graph_and_journal_with_context,
};
