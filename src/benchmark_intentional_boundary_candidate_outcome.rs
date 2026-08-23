#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateDerivationErrorKind {
    InvalidInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CandidateDerivationError {
    pub kind: CandidateDerivationErrorKind,
    pub detail: String,
}

pub(super) fn candidate_invalid(detail: impl Into<String>) -> CandidateDerivationError {
    CandidateDerivationError {
        kind: CandidateDerivationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

pub(super) fn legacy_candidate_error(error: CandidateDerivationError) -> String {
    error.detail
}
