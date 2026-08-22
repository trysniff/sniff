#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvidenceDerivationErrorKind {
    InvalidInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EvidenceDerivationError {
    pub kind: EvidenceDerivationErrorKind,
    pub detail: String,
}

pub(super) fn evidence_invalid(detail: impl Into<String>) -> EvidenceDerivationError {
    EvidenceDerivationError {
        kind: EvidenceDerivationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
