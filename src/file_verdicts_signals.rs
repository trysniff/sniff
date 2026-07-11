use crate::roles::FileRole;
use crate::slop_reason::{self, ReasonKind};
use std::collections::BTreeSet;

pub(super) fn is_supporting_only_reason(reason: &str) -> bool {
    slop_reason::is(reason, ReasonKind::SupportingOnly)
}

pub(super) fn is_wrapper_noise_reason(reason: &str) -> bool {
    slop_reason::is(reason, ReasonKind::WrapperNoise)
}

pub(super) fn is_cli_entrypoint_noise_reason(reason: &str) -> bool {
    is_wrapper_noise_reason(reason)
}

pub(super) fn visible_reasons<'a>(
    role: FileRole,
    reasons: &'a BTreeSet<String>,
) -> Vec<&'a String> {
    let mut visible: Vec<&'a String> = reasons
        .iter()
        .filter(|reason| {
            !(is_supporting_only_reason(reason)
                || matches!(role, FileRole::Entrypoint | FileRole::Script)
                    && is_cli_entrypoint_noise_reason(reason))
        })
        .collect();

    if visible.len() > 1 {
        let non_wrapper: Vec<&'a String> = visible
            .iter()
            .copied()
            .filter(|reason| !is_wrapper_noise_reason(reason))
            .collect();
        if !non_wrapper.is_empty() {
            visible = non_wrapper;
        }
    }

    visible
}

pub(super) fn join_visible_reasons(reasons: &[&String]) -> String {
    reasons
        .iter()
        .map(|reason| (*reason).as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::visible_reasons;
    use crate::roles::FileRole;
    use std::collections::BTreeSet;

    #[test]
    fn wrapper_noise_is_hidden_when_stronger_reasons_exist() {
        let reasons = BTreeSet::from([
            "trivial pass-through wrapper".to_string(),
            "function is too big (199 LOC > 100)".to_string(),
        ]);

        let visible = visible_reasons(FileRole::Library, &reasons);
        assert_eq!(visible.len(), 1);
        assert!(visible[0].contains("function is too big"));
    }

    #[test]
    fn wrapper_only_reason_stays_visible() {
        let reasons = BTreeSet::from(["thin wrapper".to_string()]);

        let visible = visible_reasons(FileRole::Library, &reasons);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0], "thin wrapper");
    }

    #[test]
    fn copy_pasted_method_body_is_supporting_only() {
        assert!(super::is_supporting_only_reason("copy-pasted method body"));
    }
}
