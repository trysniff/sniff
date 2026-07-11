#[path = "analyzer_engine.rs"]
mod core;

pub use core::{Analyzer, analyze, analyze_with_client};
