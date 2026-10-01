use super::super::*;
use serde::{Deserialize, Serialize};

pub(super) const CONTRACT: &str = "project-model-command-receipts-v1-input-closure-unproven";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    pub(super) contract: String,
    pub(super) indexer: SemanticIndexerKind,
    pub(super) version: String,
    pub(super) installation_tree_sha256: String,
    pub(super) repository_sha256: String,
}

impl Scope {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.contract != CONTRACT
            || self.version.is_empty()
            || !matches!(
                self.indexer,
                SemanticIndexerKind::Go | SemanticIndexerKind::TypeScriptJavaScript
            )
            || !is_lower_sha256(&self.installation_tree_sha256)
            || !is_lower_sha256(&self.repository_sha256)
        {
            return Err("compiler census scope is incomplete or unsupported".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum Inputs {
    Go {
        executable_sha256: String,
        sdk_sha256: String,
        dependencies_sha256: String,
    },
    TypeScript {
        runtime_sha256: String,
    },
}

impl Inputs {
    pub(super) fn validate(&self, kind: SemanticIndexerKind) -> Result<(), String> {
        let digests = match (kind, self) {
            (
                SemanticIndexerKind::Go,
                Self::Go {
                    executable_sha256,
                    sdk_sha256,
                    dependencies_sha256,
                },
            ) => vec![executable_sha256, sdk_sha256, dependencies_sha256],
            (SemanticIndexerKind::TypeScriptJavaScript, Self::TypeScript { runtime_sha256 }) => {
                vec![runtime_sha256]
            }
            _ => return Err("compiler census inputs changed provider".to_string()),
        };
        if digests.iter().any(|digest| !is_lower_sha256(digest)) {
            return Err("compiler census input commitment is invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum Role {
    TypeScriptProject,
    GoPlatforms,
    GoModule,
    GoEnvironment,
    GoSourceContexts,
    GoWorld,
}

impl Role {
    pub(in super::super) fn operation(self) -> &'static str {
        match self {
            Self::TypeScriptProject => "TypeScript compiler project model",
            Self::GoPlatforms => "Go compiler platform domain",
            Self::GoModule => "Go compiler module identity",
            Self::GoEnvironment => "Go compiler context environment",
            Self::GoSourceContexts => "Go compiler source constraint facts",
            Self::GoWorld => "Go compiler package selection",
        }
    }

    pub(super) fn indexer(self) -> SemanticIndexerKind {
        if self == Self::TypeScriptProject {
            SemanticIndexerKind::TypeScriptJavaScript
        } else {
            SemanticIndexerKind::Go
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct Request {
    pub(in super::super) role: Role,
    pub(in super::super) arguments: Vec<String>,
    pub(in super::super) environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CommandOutcome {
    Returned {
        process: SemanticIndexerProcessEvidence,
    },
    Failed {
        failure: SemanticIndexerRunFailure,
    },
}

impl CommandOutcome {
    pub(super) fn process(&self) -> Option<&SemanticIndexerProcessEvidence> {
        match self {
            Self::Returned { process } => Some(process),
            Self::Failed { failure } => failure.process.as_deref(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandReceipt {
    pub(super) scope_sha256: String,
    pub(super) inputs_sha256: String,
    pub(super) sequence: usize,
    pub(super) preceding_sha256: Option<String>,
    pub(super) request: Request,
    pub(super) result: CommandOutcome,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(in super::super) enum ModelPart {
    TypeScript(super::super::typescript_model_output::CompilerOutput),
    GoPlatforms(String),
    GoModule(super::super::go_model_output::ModuleIdentity),
    GoEnvironment(BTreeMap<String, String>),
    GoSourceContexts(Vec<crate::compiler_go_model::GoCompilerContext>),
    GoWorld(Box<super::super::go_model_output::CompilerWorld>),
}

impl ModelPart {
    pub(super) fn role(&self) -> Role {
        match self {
            Self::TypeScript(_) => Role::TypeScriptProject,
            Self::GoPlatforms(_) => Role::GoPlatforms,
            Self::GoModule(_) => Role::GoModule,
            Self::GoEnvironment(_) => Role::GoEnvironment,
            Self::GoSourceContexts(_) => Role::GoSourceContexts,
            Self::GoWorld(_) => Role::GoWorld,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelReceipt {
    pub(super) scope_sha256: String,
    pub(super) sequence: usize,
    pub(super) command_sha256: String,
    pub(super) model: ModelPart,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TerminalOutcome {
    Accepted {
        plans: Vec<SemanticIndexerVariantPlan>,
    },
    Failed {
        failure: SemanticIndexerRunFailure,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TerminalReceipt {
    pub(super) scope_sha256: String,
    pub(super) inputs: Option<Inputs>,
    pub(super) commands: Vec<String>,
    pub(super) models: Vec<Option<String>>,
    // This schema preserves observations. It never authorizes skipping compiler work.
    pub(super) input_closure_proven: bool,
    pub(super) result: TerminalOutcome,
}

pub(super) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
