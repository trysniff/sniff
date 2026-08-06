use serde::{Deserialize, Serialize};
use std::fmt;

pub const SLOP_DEFINITION: &str = "Unnecessary or misleading implementation machinery that superficially satisfies a task while transferring disproportionate comprehension, verification, or change burden to future developers.";

pub const PRODUCT_NON_GOALS: &[&str] = &[
    "AI authorship detection",
    "security scanning",
    "bug finding",
    "linting",
    "generic maintainability scoring",
    "architecture preference enforcement",
    "automatic repository modification",
];

pub const SLOP_PATTERN_PROMPT_LIST: &str = "residual_machinery, duplicated_semantics, parallel_reinvention, ceremonial_logic, needless_indirection, speculative_defense, band_aid_control_flow, contract_fog, test_mirroring, test_subversion, fictional_integration, abandoned_compatibility, responsibility_fragmentation, misleading_completion, unnecessary_state_complexity, and other";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlopPattern {
    None,
    ResidualMachinery,
    DuplicatedSemantics,
    ParallelReinvention,
    CeremonialLogic,
    NeedlessIndirection,
    SpeculativeDefense,
    BandAidControlFlow,
    ContractFog,
    TestMirroring,
    TestSubversion,
    FictionalIntegration,
    AbandonedCompatibility,
    ResponsibilityFragmentation,
    MisleadingCompletion,
    UnnecessaryStateComplexity,
    Other,
}

impl SlopPattern {
    pub const FINDING_PATTERNS: &[Self] = &[
        Self::ResidualMachinery,
        Self::DuplicatedSemantics,
        Self::ParallelReinvention,
        Self::CeremonialLogic,
        Self::NeedlessIndirection,
        Self::SpeculativeDefense,
        Self::BandAidControlFlow,
        Self::ContractFog,
        Self::TestMirroring,
        Self::TestSubversion,
        Self::FictionalIntegration,
        Self::AbandonedCompatibility,
        Self::ResponsibilityFragmentation,
        Self::MisleadingCompletion,
        Self::UnnecessaryStateComplexity,
        Self::Other,
    ];

    pub fn parse(value: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_string())).ok()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ResidualMachinery => "residual_machinery",
            Self::DuplicatedSemantics => "duplicated_semantics",
            Self::ParallelReinvention => "parallel_reinvention",
            Self::CeremonialLogic => "ceremonial_logic",
            Self::NeedlessIndirection => "needless_indirection",
            Self::SpeculativeDefense => "speculative_defense",
            Self::BandAidControlFlow => "band_aid_control_flow",
            Self::ContractFog => "contract_fog",
            Self::TestMirroring => "test_mirroring",
            Self::TestSubversion => "test_subversion",
            Self::FictionalIntegration => "fictional_integration",
            Self::AbandonedCompatibility => "abandoned_compatibility",
            Self::ResponsibilityFragmentation => "responsibility_fragmentation",
            Self::MisleadingCompletion => "misleading_completion",
            Self::UnnecessaryStateComplexity => "unnecessary_state_complexity",
            Self::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ResidualMachinery => "residual machinery",
            Self::DuplicatedSemantics => "duplicated semantics",
            Self::ParallelReinvention => "parallel reinvention",
            Self::CeremonialLogic => "ceremonial logic",
            Self::NeedlessIndirection => "needless indirection",
            Self::SpeculativeDefense => "speculative defensive machinery",
            Self::BandAidControlFlow => "band-aid control flow",
            Self::ContractFog => "contract fog",
            Self::TestMirroring => "test mirrors implementation",
            Self::TestSubversion => "test subversion",
            Self::FictionalIntegration => "fictional integration",
            Self::AbandonedCompatibility => "abandoned compatibility machinery",
            Self::ResponsibilityFragmentation => "responsibility fragmentation",
            Self::MisleadingCompletion => "misleading completion",
            Self::UnnecessaryStateComplexity => "unnecessary state complexity",
            Self::Other => "other evidenced slop mechanism",
        }
    }

    pub fn is_finding(self) -> bool {
        self != Self::None
    }
}

impl fmt::Display for SlopPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{SLOP_DEFINITION, SlopPattern};

    #[test]
    fn ontology_has_one_stable_wire_name_per_pattern() {
        for pattern in SlopPattern::FINDING_PATTERNS {
            assert_eq!(SlopPattern::parse(pattern.as_str()), Some(*pattern));
            assert!(pattern.is_finding());
        }
        assert_eq!(SlopPattern::parse("none"), Some(SlopPattern::None));
        assert!(!SlopPattern::None.is_finding());
        assert!(SlopPattern::parse("sprawling_function").is_none());
    }

    #[test]
    fn canonical_definition_names_burden_and_unnecessary_machinery() {
        assert!(SLOP_DEFINITION.contains("Unnecessary or misleading"));
        assert!(SLOP_DEFINITION.contains("burden"));
    }

    #[test]
    fn prompt_vocabulary_covers_every_typed_finding_pattern_once() {
        let prompt_names = super::SLOP_PATTERN_PROMPT_LIST
            .replace(", and ", ", ")
            .split(", ")
            .map(str::to_string)
            .collect::<Vec<_>>();
        let typed_names = SlopPattern::FINDING_PATTERNS
            .iter()
            .map(|pattern| pattern.as_str().to_string())
            .collect::<Vec<_>>();

        assert_eq!(prompt_names, typed_names);
    }
}
