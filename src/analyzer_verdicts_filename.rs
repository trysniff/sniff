use crate::llm::LLMClient;
use crate::slop_reason::{self, ReasonKind};
use crate::types::FileRecord;
use crate::types::FindingTier;
use std::path::Path;

pub(super) fn is_generic_file_name(file_path: &str, client: &LLMClient) -> bool {
    let stem = Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if stem.is_empty() {
        return false;
    }
    if stem == "llm" {
        return false;
    }

    client
        .config()
        .generic_file_names
        .iter()
        .any(|name| name.to_lowercase() == stem)
}

pub(super) fn normalize_vague_filename_verdict(
    file: &FileRecord,
    client: &LLMClient,
    reason: &str,
) -> Option<FindingTier> {
    if !slop_reason::is(reason, ReasonKind::FilenameVague) {
        return None;
    }

    if is_generic_file_name(&file.file_path, client) {
        return Some(FindingTier::KindaSlop);
    }

    Some(FindingTier::Clean)
}

#[cfg(test)]
mod tests {
    use super::{is_generic_file_name, normalize_vague_filename_verdict};
    use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
    use crate::llm::LLMClient;
    use crate::types::{FileRecord, FindingTier, MethodRecord};

    fn client_with_generic_llm_name() -> LLMClient {
        let config = ResolvedConfig {
            thresholds: ThresholdsConfig::default(),
            ignore: vec![],
            generic_names: vec![],
            generic_file_names: vec!["llm".to_string()],
            model: "test-model".to_string(),
            llm: LLMConfig {
                system_context: String::new(),
                endpoint: "http://127.0.0.1:9".to_string(),
            },
        };
        LLMClient::new(config, Some("test-key".to_string()))
    }

    fn llm_file() -> FileRecord {
        FileRecord {
            file_path: "src/llm.rs".to_string(),
            source: "pub fn build_payload() {}".to_string(),
            language: "rust".to_string(),
            methods: vec![MethodRecord {
                name: "build_payload".to_string(),
                file_path: "src/llm.rs".to_string(),
                source: "pub fn build_payload() {}".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
        }
    }

    #[test]
    fn llm_filename_is_not_generic_even_if_config_lists_it() {
        let client = client_with_generic_llm_name();
        assert!(!is_generic_file_name("src/llm.rs", &client));
    }

    #[test]
    fn llm_filename_vagueness_normalizes_to_clean() {
        let client = client_with_generic_llm_name();
        let verdict =
            normalize_vague_filename_verdict(&llm_file(), &client, "filename is vague 'llm'");

        assert_eq!(verdict, Some(FindingTier::Clean));
    }
}
