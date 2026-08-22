#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AstDerivationErrorKind {
    InvalidInput,
    SourceParserRejected,
    CensusIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AstDerivationError {
    pub kind: AstDerivationErrorKind,
    pub language: String,
    pub repository_path: Option<String>,
    pub detail: String,
}

pub(super) fn ast_invalid(
    language: &str,
    repository_path: Option<&str>,
    detail: impl Into<String>,
) -> AstDerivationError {
    ast_error(
        AstDerivationErrorKind::InvalidInput,
        language,
        repository_path,
        detail,
    )
}

pub(super) fn ast_parser_rejected(
    language: &str,
    repository_path: &str,
    detail: impl Into<String>,
) -> AstDerivationError {
    ast_error(
        AstDerivationErrorKind::SourceParserRejected,
        language,
        Some(repository_path),
        detail,
    )
}

pub(super) fn ast_incomplete(
    language: &str,
    repository_path: Option<&str>,
    detail: impl Into<String>,
) -> AstDerivationError {
    ast_error(
        AstDerivationErrorKind::CensusIncomplete,
        language,
        repository_path,
        detail,
    )
}

fn ast_error(
    kind: AstDerivationErrorKind,
    language: &str,
    repository_path: Option<&str>,
    detail: impl Into<String>,
) -> AstDerivationError {
    AstDerivationError {
        kind,
        language: language.to_string(),
        repository_path: repository_path.map(str::to_string),
        detail: detail.into(),
    }
}
