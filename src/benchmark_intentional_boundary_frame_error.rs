#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryFrameErrorKind {
    InvalidInput,
    CorruptState,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryFrameError {
    pub kind: IntentionalBoundaryFrameErrorKind,
    pub detail: String,
}

impl IntentionalBoundaryFrameError {
    pub(super) fn invalid(detail: impl Into<String>) -> Self {
        Self {
            kind: IntentionalBoundaryFrameErrorKind::InvalidInput,
            detail: detail.into(),
        }
    }

    pub(super) fn corrupt(detail: impl Into<String>) -> Self {
        Self {
            kind: IntentionalBoundaryFrameErrorKind::CorruptState,
            detail: detail.into(),
        }
    }

    pub(super) fn infrastructure(detail: impl Into<String>) -> Self {
        Self {
            kind: IntentionalBoundaryFrameErrorKind::InfrastructureFailed,
            detail: detail.into(),
        }
    }

    pub(super) fn into_corrupt(mut self) -> Self {
        self.kind = IntentionalBoundaryFrameErrorKind::CorruptState;
        self
    }
}
