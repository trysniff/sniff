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

pub use core::{Analyzer, analyze, analyze_with_client};
