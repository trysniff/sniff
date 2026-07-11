#[path = "file_verdicts_builder.rs"]
mod builder;
#[path = "file_verdicts_merge.rs"]
mod merge;
#[path = "file_verdicts_signals.rs"]
mod signals;

pub use merge::build_file_verdicts;
