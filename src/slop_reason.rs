//! Central vocabulary for interpreting model and static reason labels.
//!
//! The model still supplies the semantic judgment. This module only maps the
//! allowed vocabulary to policy categories so cleanup and rendering do not
//! each maintain their own substring rules.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReasonKind {
    SupportingOnly,
    WrapperNoise,
    FilenameVague,
    ControlFlow,
    StrongSlop,
}

pub(crate) fn is(reason: &str, kind: ReasonKind) -> bool {
    let lower = reason.to_lowercase();
    match kind {
        ReasonKind::SupportingOnly => contains_any(
            &lower,
            &[
                "orphaned export",
                "overbuilt helper",
                "copy-pasted method body",
                "duplicate method body",
                "test mirrors production implementation",
                "architecture sprawl",
                "high churn",
                "generated-style marker present",
            ],
        ),
        ReasonKind::WrapperNoise => contains_any(
            &lower,
            &[
                "trivial delegation wrapper",
                "thin wrapper",
                "trivial wrapper",
                "tiny wrapper",
                "unnecessary indirection",
                "pass-through",
                "delegation wrapper",
                "wrapper adds no logic",
                "delegates entirely",
                "one-line delegation",
            ],
        ),
        ReasonKind::FilenameVague => {
            lower.contains("filename is vague")
                || lower.contains("vague filename")
                || lower.contains("filename suggests")
                || (lower.contains("filename") && lower.contains("vague"))
                || (lower.starts_with("filename '") && lower.contains(" is vague"))
        }
        ReasonKind::ControlFlow => contains_any(
            &lower,
            &[
                "branchy control flow",
                "loop-heavy control flow",
                "control flow is tangled",
                "tangled control flow",
                "excessive branching",
                "too many branches",
            ],
        ),
        ReasonKind::StrongSlop => contains_any(
            &lower,
            &[
                "function is too big",
                "function is too large",
                "sprawling function",
                "too much code",
                "bloated function",
                "too many parameters",
                "argument pile-up",
                "file does too much",
                "module does too much",
                "module mixes",
                "responsibility sprawl",
                "too many responsibilities",
                "unrelated responsibilities",
                "dumping ground",
                "hides intent",
                "hidden intent",
                "unnecessary abstraction",
                "low-value abstraction",
                "generic plumbing",
                "excessive nesting",
                "repeated logic",
                "fallback chain",
                "unnecessary fallback",
                "comments restate",
                "restates the code",
            ],
        ),
    }
}

pub(crate) fn any(reason: &str, kinds: &[ReasonKind]) -> bool {
    kinds.iter().any(|kind| is(reason, *kind))
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{ReasonKind, any, is};

    #[test]
    fn shared_taxonomy_classifies_common_labels_once() {
        assert!(is("function is too big", ReasonKind::StrongSlop));
        assert!(is("tangled control flow", ReasonKind::ControlFlow));
        assert!(is("filename is vague", ReasonKind::FilenameVague));
        assert!(is("thin wrapper", ReasonKind::WrapperNoise));
        assert!(is("architecture sprawl", ReasonKind::SupportingOnly));
        assert!(any(
            "filename is vague",
            &[ReasonKind::FilenameVague, ReasonKind::StrongSlop]
        ));
    }

    #[test]
    fn unrelated_labels_are_not_promoted() {
        assert!(!is("normal resolver", ReasonKind::StrongSlop));
        assert!(!is("normal resolver", ReasonKind::ControlFlow));
    }
}
