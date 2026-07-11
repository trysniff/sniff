use crate::types::FindingTier;

pub(crate) fn tier_for_reason(reason: &str) -> FindingTier {
    let reason = reason.to_lowercase();
    if reason.contains("file does too much")
        || reason.contains("file does too much across concern families")
        || reason.contains("function is too big")
        || reason.contains("control flow is tangled")
        || reason.contains("too many parameters")
        || reason.contains("placeholder implementation")
        || reason.contains("stub implementation")
    {
        FindingTier::Slop
    } else {
        FindingTier::KindaSlop
    }
}

pub(crate) fn tier_for_reasons(reasons: &[String]) -> FindingTier {
    if reasons
        .iter()
        .any(|r| matches!(tier_for_reason(r), FindingTier::Slop))
    {
        FindingTier::Slop
    } else {
        FindingTier::KindaSlop
    }
}
