use super::super::intentional_boundary_source_census::INTENTIONAL_BOUNDARY_PARSER_ERROR_LIMIT;
use super::super::{
    BoundaryGitEntryKind, IntentionalBoundarySourceCensusFailureEvidence,
    IntentionalBoundaryTrackedEntry,
};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub(super) fn validate_failure_inventory_binding(
    failure: &IntentionalBoundarySourceCensusFailureEvidence,
    entry: &IntentionalBoundaryTrackedEntry,
) -> Result<(), String> {
    let valid = match failure {
        IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink { .. } => {
            entry.kind == BoundaryGitEntryKind::Gitlink
        }
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            entry_kind,
            ..
        } => entry.kind == *entry_kind,
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            byte_length,
            ..
        }
        | IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            byte_length,
            ..
        } => entry.kind.is_file_blob() && entry.byte_length == Some(*byte_length),
    };
    if !valid {
        return Err("historical-v3 source failure contradicts its inventory".to_string());
    }
    Ok(())
}

pub(super) fn validate_failure(
    failure: &IntentionalBoundarySourceCensusFailureEvidence,
    object_id_length: usize,
) -> Result<(), String> {
    let (path, object_id) = failure_identity(failure);
    if !valid_repository_path(path)
        || object_id.len() != object_id_length
        || !object_id.bytes().all(lower_hex)
    {
        return Err("historical-v3 source failure identity changed".to_string());
    }
    match failure {
        IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink { .. } => {}
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            entry_kind,
            ..
        } => {
            if matches!(
                entry_kind,
                BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
            ) {
                return Err("historical-v3 non-blob evidence names a regular blob".to_string());
            }
        }
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            byte_length,
            source_sha256,
            language,
            valid_up_to,
            error_length,
            ..
        } => {
            if *byte_length == 0
                || !valid_sha256(source_sha256)
                || language.is_empty()
                || *valid_up_to >= *byte_length as usize
                || error_length.is_some_and(|length| length == 0)
            {
                return Err("historical-v3 UTF-8 evidence changed".to_string());
            }
        }
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            byte_length,
            source_sha256,
            language,
            parser_error_sha256,
            retained_parser_error,
            parser_error_truncated,
            ..
        } => {
            if *byte_length == 0
                || !valid_sha256(source_sha256)
                || language.is_empty()
                || !valid_sha256(parser_error_sha256)
                || retained_parser_error.is_empty()
                || retained_parser_error.len() > INTENTIONAL_BOUNDARY_PARSER_ERROR_LIMIT
                || (!parser_error_truncated
                    && sha256(retained_parser_error.as_bytes()) != *parser_error_sha256)
            {
                return Err("historical-v3 parser evidence changed".to_string());
            }
        }
    }
    Ok(())
}

pub(super) fn failure_key(failure: &IntentionalBoundarySourceCensusFailureEvidence) -> (&str, u8) {
    match failure {
        IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink {
            repository_path,
            ..
        } => (repository_path, 0),
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            repository_path,
            ..
        } => (repository_path, 1),
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            repository_path,
            ..
        } => (repository_path, 2),
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            repository_path,
            ..
        } => (repository_path, 3),
    }
}

pub(super) fn failure_identity(
    failure: &IntentionalBoundarySourceCensusFailureEvidence,
) -> (&str, &str) {
    match failure {
        IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink {
            repository_path,
            object_id,
        }
        | IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            repository_path,
            object_id,
            ..
        }
        | IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            repository_path,
            object_id,
            ..
        }
        | IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            repository_path,
            object_id,
            ..
        } => (repository_path, object_id),
    }
}

fn valid_repository_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !value.contains('\\')
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
