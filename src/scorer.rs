use crate::config::ResolvedConfig;
use crate::report_types::StaticFlag;
use crate::types::FileRecord;

#[path = "scorer_control_flow.rs"]
mod control_flow;
#[path = "scorer_file.rs"]
mod file;
#[path = "scorer_method.rs"]
mod method;
#[path = "scorer_rules.rs"]
mod rules;
#[path = "scorer_tiers.rs"]
mod tiers;

fn score_file_record(file: &FileRecord, config: &ResolvedConfig) -> Vec<StaticFlag> {
    let mut flags = file::build_file_flags(file, config);
    method::collect_method_flags(method::MethodFlagInput {
        file,
        config,
        flags: &mut flags,
    });

    flags
}

pub fn score(file_records: &[FileRecord], config: &ResolvedConfig) -> Vec<StaticFlag> {
    let mut flags = Vec::new();

    for file in file_records {
        let mut file_flags = score_file_record(file, config);
        flags.append(&mut file_flags);
    }

    flags
}
