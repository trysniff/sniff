use crate::config::ResolvedConfig;
use crate::report_types::StaticFlag;
use crate::types::FileRecord;
use std::path::Path;

#[path = "signal_layers_architecture.rs"]
mod architecture;
#[path = "signal_layers_churn.rs"]
mod churn;
#[path = "signal_layers_provenance.rs"]
mod provenance;
#[path = "signal_layers_similarity_flags.rs"]
mod similarity_flags;
#[path = "signal_layers_similarity_roles.rs"]
mod similarity_roles;

mod similarity {
    pub(crate) use super::similarity_flags::{make_file_flag, supporting_similarity_flags};
    pub(crate) use super::similarity_roles::normalize_path;
}

pub fn collect_supporting_flags(
    file_records: &[FileRecord],
    config: &ResolvedConfig,
    repo_root: &Path,
) -> Vec<StaticFlag> {
    let mut flags = Vec::new();

    flags.extend(similarity::supporting_similarity_flags(file_records));
    flags.extend(architecture::architecture_flags(file_records, config));
    flags.extend(churn::churn_flags(file_records, repo_root));
    flags.extend(provenance::provenance_flags(file_records));

    flags
}
