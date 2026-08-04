use crate::roles::{FileRole, file_role_label};
use crate::slop_reason::{self, ReasonKind};
use crate::types::FindingTier;
use std::collections::{BTreeMap, BTreeSet};

use super::signals::{join_visible_reasons, visible_reasons};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SignalSeverity {
    Mild,
    Severe,
}

#[derive(Debug, Clone)]
struct SignalGroup {
    severity: SignalSeverity,
    reasons: BTreeSet<String>,
}

impl SignalGroup {
    fn new() -> Self {
        Self {
            severity: SignalSeverity::Mild,
            reasons: BTreeSet::new(),
        }
    }

    fn add_reason(&mut self, severity: SignalSeverity, reason: impl Into<String>) {
        self.severity = self.severity.max(severity);
        let reason = reason.into().trim().to_string();
        if !reason.is_empty() {
            self.reasons.insert(reason);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct FileVerdictBuilder {
    pub(super) file_path: String,
    pub(super) role: FileRole,
    method_count: usize,
    file_signals: SignalGroup,
    method_signals: BTreeMap<String, SignalGroup>,
    llm_clean_methods: BTreeSet<String>,
    file_observations_enabled: bool,
    llm_reviewed: bool,
    llm_file_reviewed: bool,
    llm_method_review_count: usize,
    llm_smelly: bool,
    unresolved_methods: BTreeMap<String, String>,
    unresolved_file: Option<String>,
}

impl FileVerdictBuilder {
    pub(super) fn new(file_path: String, role: FileRole, method_count: usize) -> Self {
        Self {
            file_path,
            role,
            method_count,
            file_signals: SignalGroup::new(),
            method_signals: BTreeMap::new(),
            llm_clean_methods: BTreeSet::new(),
            file_observations_enabled: true,
            llm_reviewed: false,
            llm_file_reviewed: false,
            llm_method_review_count: 0,
            llm_smelly: false,
            unresolved_methods: BTreeMap::new(),
            unresolved_file: None,
        }
    }

    pub(super) fn mark_llm_review(&mut self, smelly: bool, method_name: Option<&str>) {
        self.llm_reviewed = true;
        if let Some(method_name) = method_name {
            self.llm_method_review_count += 1;
            if smelly {
                self.llm_clean_methods.remove(method_name);
            } else {
                self.llm_clean_methods.insert(method_name.to_string());
            }
        } else {
            self.llm_file_reviewed = true;
        }
        if smelly {
            self.llm_smelly = true;
        }
    }

    pub(super) fn add_unresolved_method(
        &mut self,
        method_name: Option<&str>,
        reason: impl Into<String>,
    ) {
        let Some(method_name) = method_name else {
            self.unresolved_file = Some(reason.into());
            return;
        };
        self.unresolved_methods
            .insert(method_name.to_string(), reason.into());
    }

    fn llm_clean_override(&self) -> bool {
        let method_review_complete =
            self.llm_method_review_count == 0 || self.llm_method_review_count >= self.method_count;
        self.llm_reviewed
            && self.llm_file_reviewed
            && !self.llm_smelly
            && self.unresolved_methods.is_empty()
            && self.unresolved_file.is_none()
            && method_review_complete
    }

    pub(super) fn add_file_reason(&mut self, severity: SignalSeverity, reason: impl Into<String>) {
        if !self.file_observations_enabled {
            return;
        }
        self.file_signals.add_reason(severity, reason);
    }

    pub(super) fn disable_file_observations(&mut self) {
        self.file_observations_enabled = false;
    }

    pub(super) fn file_observations_enabled(&self) -> bool {
        self.file_observations_enabled
    }

    pub(super) fn add_method_reason(
        &mut self,
        method_name: impl Into<String>,
        severity: SignalSeverity,
        reason: impl Into<String>,
    ) {
        let method_name = method_name.into();
        self.method_signals
            .entry(method_name)
            .or_insert_with(SignalGroup::new)
            .add_reason(severity, reason);
    }

    fn signal_lines(&self) -> Vec<(SignalSeverity, String)> {
        if self.llm_clean_override() {
            return Vec::new();
        }

        let method_finding_present = self.has_visible_method_reason();
        let mut lines = Vec::new();

        for (method_name, reason) in &self.unresolved_methods {
            lines.push((
                SignalSeverity::Severe,
                format!("{method_name}: unresolved review: {reason}"),
            ));
        }
        if let Some(reason) = &self.unresolved_file {
            lines.push((
                SignalSeverity::Severe,
                format!("unresolved file review: {reason}"),
            ));
        }

        // Once a method has an evidence-backed semantic finding, keep the
        // user-facing report method-first. File review remains available in
        // raw LLM results, but must not drown out or amplify that finding.
        if !method_finding_present {
            let file_reasons = visible_reasons(self.role, &self.file_signals.reasons);
            if !file_reasons.is_empty() {
                let reason = join_visible_reasons(&file_reasons);
                lines.push((self.file_signals.severity, reason));
            }
        }

        for (method_name, group) in &self.method_signals {
            if self.llm_clean_methods.contains(method_name) {
                continue;
            }
            let reasons = method_reasons(&group.reasons);
            if reasons.is_empty() {
                continue;
            }
            let reason = format!("{method_name}: {}", join_visible_reasons(&reasons));
            lines.push((group.severity, reason));
        }

        lines.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        lines
    }

    fn flagged_methods(&self) -> Vec<String> {
        if self.llm_clean_override() {
            return Vec::new();
        }

        let mut methods = self.unresolved_methods.keys().cloned().collect::<Vec<_>>();
        methods.extend(
            self.method_signals
                .iter()
                .filter(|(method_name, group)| {
                    if self.llm_clean_methods.contains(*method_name) {
                        return false;
                    }
                    let reasons = method_reasons(&group.reasons);
                    if reasons.is_empty() {
                        return false;
                    }
                    true
                })
                .map(|(method, _)| method.clone())
                .collect::<Vec<_>>(),
        );
        methods.sort();
        methods.dedup();
        methods
    }

    fn mild_file_reason_count(&self) -> usize {
        if self.file_signals.severity == SignalSeverity::Mild {
            visible_reasons(self.role, &self.file_signals.reasons).len()
        } else {
            0
        }
    }

    fn mild_method_group_count(&self) -> usize {
        self.method_signals
            .iter()
            .filter(|(method_name, group)| {
                !self.llm_clean_methods.contains(*method_name)
                    && group.severity == SignalSeverity::Mild
                    && !method_reasons(&group.reasons).is_empty()
            })
            .count()
    }

    fn has_visible_method_reason(&self) -> bool {
        self.method_signals.iter().any(|(method_name, group)| {
            !self.llm_clean_methods.contains(method_name)
                && !method_reasons(&group.reasons).is_empty()
        })
    }

    fn method_verdict(&self) -> Option<FindingTier> {
        if !self.unresolved_methods.is_empty() || self.unresolved_file.is_some() {
            return Some(FindingTier::Unresolved);
        }
        if !self.has_visible_method_reason() {
            return None;
        }

        let severe = self.method_signals.iter().any(|(method_name, group)| {
            !self.llm_clean_methods.contains(method_name)
                && group.severity == SignalSeverity::Severe
                && !method_reasons(&group.reasons).is_empty()
        });
        if severe {
            Some(FindingTier::Slop)
        } else {
            Some(FindingTier::KindaSlop)
        }
    }

    fn severe_signal_count(&self) -> usize {
        usize::from(self.file_signals.severity == SignalSeverity::Severe)
            + self
                .method_signals
                .iter()
                .filter(|(method_name, group)| {
                    !self.llm_clean_methods.contains(*method_name)
                        && group.severity == SignalSeverity::Severe
                        && !method_reasons(&group.reasons).is_empty()
                })
                .count()
    }

    fn lone_file_reason_is_vague_or_supporting(&self) -> bool {
        self.file_signals.reasons.iter().any(|reason| {
            slop_reason::any(
                reason,
                &[ReasonKind::FilenameVague, ReasonKind::SupportingOnly],
            )
        })
    }

    fn verdict(&self) -> FindingTier {
        if !self.unresolved_methods.is_empty() || self.unresolved_file.is_some() {
            return FindingTier::Unresolved;
        }
        if self.llm_clean_override() {
            return FindingTier::Clean;
        }

        if let Some(method_verdict) = self.method_verdict() {
            return method_verdict;
        }

        let mild_file_count = self.mild_file_reason_count();
        let mild_method_count = self.mild_method_group_count();
        let severe_count = self.severe_signal_count();

        if severe_count > 0 {
            FindingTier::Slop
        } else if mild_file_count == 1 && mild_method_count == 0 {
            if self.lone_file_reason_is_vague_or_supporting() {
                return FindingTier::Clean;
            }
            FindingTier::KindaSlop
        } else if mild_file_count + mild_method_count >= 3 {
            FindingTier::Slop
        } else if mild_file_count + mild_method_count >= 1 {
            FindingTier::KindaSlop
        } else {
            FindingTier::Clean
        }
    }

    fn recommended_action(&self, top_reasons: &[String], flagged_methods: &[String]) -> String {
        if !flagged_methods.is_empty() {
            if top_reasons.iter().any(|reason| {
                let lower = reason.to_lowercase();
                lower.contains("duplicated decision")
                    || lower.contains("ceremonial logic")
                    || lower.contains("unnecessarily complicated")
                    || lower.contains("hidden intent")
                    || lower.contains("needless indirection")
                    || lower.contains("state transition")
            }) {
                return "simplify the flagged method and remove the unnecessary machinery"
                    .to_string();
            }
            return "simplify the flagged method and keep its intent direct".to_string();
        }

        let has_reason = |kind| {
            top_reasons
                .iter()
                .any(|reason| slop_reason::is(reason, kind))
        };
        if has_reason(ReasonKind::FilenameVague) {
            return "rename the file so its purpose is obvious".to_string();
        }
        if has_reason(ReasonKind::StrongSlop)
            || top_reasons.iter().any(|reason| {
                let lower = reason.to_lowercase();
                lower.contains("broad dependency fan-out")
                    || lower.contains("sprawling helper surface")
            })
        {
            return "split the file into smaller responsibilities".to_string();
        }
        if top_reasons.iter().any(|reason| {
            let lower = reason.to_lowercase();
            lower.contains("too many parameters")
        }) {
            return "bundle the inputs or split the function".to_string();
        }
        if top_reasons.iter().any(|reason| {
            slop_reason::any(reason, &[ReasonKind::ControlFlow, ReasonKind::StrongSlop])
        }) {
            return "split the function and flatten the control flow".to_string();
        }
        if top_reasons.iter().any(|reason| {
            let lower = reason.to_lowercase();
            lower.contains("copy-pasted method body")
                || lower.contains("near-duplicate method body")
        }) {
            return "extract the shared logic into one place".to_string();
        }
        if top_reasons
            .iter()
            .any(|reason| reason.to_lowercase().contains("overbuilt helper"))
        {
            return "inline or simplify the helper".to_string();
        }

        "trim the largest offender and keep the file focused".to_string()
    }

    pub(super) fn finish(self) -> crate::report_types::FileVerdict {
        let mut verdict = self.verdict();
        let mut top_reasons = self
            .signal_lines()
            .into_iter()
            .map(|(_, reason)| reason)
            .collect::<Vec<_>>();
        if top_reasons.len() > 3 {
            top_reasons.truncate(3);
        }
        let flagged_methods = self.flagged_methods();
        if !matches!(verdict, FindingTier::Clean) && top_reasons.is_empty() {
            verdict = FindingTier::Clean;
        }
        let recommended_action = if matches!(verdict, FindingTier::Clean) {
            String::new()
        } else {
            self.recommended_action(&top_reasons, &flagged_methods)
        };

        crate::report_types::FileVerdict {
            file_path: self.file_path,
            role: file_role_label(self.role).to_string(),
            verdict,
            top_reasons: top_reasons.clone(),
            flagged_methods,
            recommended_action,
        }
    }
}

pub(super) fn classify_signal_tier(tier: FindingTier) -> Option<SignalSeverity> {
    match tier {
        FindingTier::Slop => Some(SignalSeverity::Severe),
        FindingTier::KindaSlop => Some(SignalSeverity::Mild),
        FindingTier::Clean => None,
        FindingTier::Unresolved => None,
    }
}

fn method_reasons(reasons: &BTreeSet<String>) -> Vec<&String> {
    reasons
        .iter()
        .filter(|reason| !reason.trim().is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_only_method_is_kept_when_it_is_the_only_signal() {
        let mut builder = FileVerdictBuilder::new("demo.rs".to_string(), FileRole::Library, 1);
        builder.add_method_reason(
            "thin_wrapper",
            SignalSeverity::Severe,
            "thin wrapper that adds no logic",
        );

        let verdict = builder.finish();

        assert_eq!(verdict.flagged_methods, vec!["thin_wrapper".to_string()]);
        assert!(
            verdict
                .top_reasons
                .iter()
                .any(|reason| reason.contains("thin wrapper"))
        );
    }

    #[test]
    fn semantic_method_reason_remains_visible_alongside_file_reason() {
        let mut builder = FileVerdictBuilder::new("demo.rs".to_string(), FileRole::Library, 2);
        builder.add_file_reason(
            SignalSeverity::Severe,
            "file does too much: mixes unrelated responsibilities",
        );
        builder.add_method_reason(
            "thin_wrapper",
            SignalSeverity::Severe,
            "thin wrapper that adds no logic",
        );

        let verdict = builder.finish();

        assert!(
            verdict
                .flagged_methods
                .iter()
                .any(|method| method == "thin_wrapper")
        );
        assert!(
            verdict
                .top_reasons
                .iter()
                .any(|reason| reason.contains("thin wrapper"))
        );
    }

    #[test]
    fn verdict_without_visible_reasons_fails_closed_to_clean() {
        let mut builder = FileVerdictBuilder::new("main.py".to_string(), FileRole::Entrypoint, 41);
        builder.add_file_reason(SignalSeverity::Severe, "trivial delegation wrapper");
        builder.file_signals.reasons.clear();
        builder.method_signals.clear();

        let verdict = builder.finish();

        assert_eq!(verdict.verdict, FindingTier::Clean);
        assert!(verdict.top_reasons.is_empty());
        assert!(verdict.flagged_methods.is_empty());
        assert!(verdict.recommended_action.is_empty());
    }

    #[test]
    fn unresolved_method_cannot_be_hidden_by_clean_file_review() {
        let mut builder = FileVerdictBuilder::new("boundary.py".to_string(), FileRole::Library, 1);
        builder.mark_llm_review(false, Some("boundary"));
        builder.mark_llm_review(false, None);
        builder.add_unresolved_method(
            Some("boundary"),
            "interface implementations and external callers were not available",
        );

        let verdict = builder.finish();

        assert_eq!(verdict.verdict, FindingTier::Unresolved);
        assert_eq!(verdict.flagged_methods, vec!["boundary".to_string()]);
        assert!(verdict.top_reasons[0].contains("unresolved review"));
    }
}
