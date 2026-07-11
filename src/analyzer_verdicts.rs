#[path = "analyzer_file_verdicts.rs"]
mod file_verdicts;
#[path = "analyzer_result.rs"]
mod result;

pub(crate) use file_verdicts::{clear_unsupported_verdict, normalize_file_verdict};
pub(crate) use result::{build_file_verdict, build_method_verdict, evidence_is_exact_substring};
