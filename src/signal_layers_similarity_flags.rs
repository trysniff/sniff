use crate::report_types::StaticFlag;
use crate::types::FileRecord;

#[path = "signal_layers_similarity_duplicates.rs"]
mod similarity_duplicates;
#[path = "signal_layers_similarity_test_coupling.rs"]
mod similarity_test_coupling;
#[path = "signal_layers_similarity_text.rs"]
mod similarity_text;
#[path = "signal_layers_similarity_tokens.rs"]
mod similarity_tokens;
#[path = "signal_layers_similarity_utils.rs"]
mod similarity_utils;

pub(crate) use similarity_utils::make_file_flag;

pub(crate) fn supporting_similarity_flags(file_records: &[FileRecord]) -> Vec<StaticFlag> {
    let prepared = similarity_duplicates::build_prepared_methods(file_records);
    let mut flags = Vec::new();
    flags.extend(similarity_duplicates::duplicate_flags(&prepared));
    flags.extend(similarity_test_coupling::test_coupling_flags(&prepared));
    flags
}
