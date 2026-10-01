use super::*;
use std::sync::Mutex;

#[path = "semantic_indexer_census_io.rs"]
mod receipt_io;
#[path = "semantic_indexer_census_schema.rs"]
mod schema;
use schema::{
    CommandOutcome, CommandReceipt, ModelReceipt, Scope, TerminalOutcome, TerminalReceipt,
};
pub(super) use schema::{Inputs, ModelPart, Request, Role};

struct State {
    inputs: Option<Inputs>,
    commands: Vec<String>,
    models: Vec<Option<String>>,
    last_role: Option<Role>,
    last_process: Option<Box<SemanticIndexerProcessEvidence>>,
    last_returned: bool,
    finished: bool,
}

pub(super) struct Journal {
    root: PathBuf,
    spec: PinnedIndexer,
    scope_sha256: String,
    state: Mutex<State>,
}

impl Journal {
    pub(super) fn open(
        context: &RequiredIndexerRunContext<'_>,
        spec: PinnedIndexer,
        installed: &InstalledIndexer,
    ) -> Result<Self, SemanticIndexerRunFailure> {
        let scope = Scope {
            contract: schema::CONTRACT.to_string(),
            indexer: spec.kind,
            version: spec.version.to_string(),
            installation_tree_sha256: installed.tree_sha256.clone(),
            repository_sha256: context.repository_content_sha256.to_string(),
        };
        scope
            .validate()
            .map_err(|detail| persistence_failure(spec, detail))?;
        let family = if spec.kind == SemanticIndexerKind::Go {
            "go"
        } else {
            "typescript"
        };
        let root = receipt_io::open_attempt(context.root, &scope.repository_sha256, family)
            .map_err(|detail| persistence_failure(spec, detail))?;
        let scope_sha256 = receipt_io::write(&root, "scope.json", &scope)
            .map_err(|detail| persistence_failure(spec, detail))?;
        Ok(Self {
            root,
            spec,
            scope_sha256,
            state: Mutex::new(State {
                inputs: None,
                commands: Vec::new(),
                models: Vec::new(),
                last_role: None,
                last_process: None,
                last_returned: false,
                finished: false,
            }),
        })
    }

    pub(super) fn bind_inputs(&self, inputs: Inputs) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        let result = (|| {
            inputs.validate(self.spec.kind)?;
            if state.inputs.is_some() || !state.commands.is_empty() || state.finished {
                return Err("compiler census input scope was already bound or executed".to_string());
            }
            receipt_io::write(&self.root, "inputs.json", &inputs)?;
            Ok(())
        })();
        result.map_err(|detail| self.failure(detail))?;
        state.inputs = Some(inputs);
        Ok(())
    }

    pub(super) fn record_command(
        &self,
        request: Request,
        result: Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure>,
    ) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
        let stored = self.store_command(request, &result);
        match (result, stored) {
            (Ok(output), Err(mut failure)) => {
                failure.process = Some(Box::new(process_evidence(output)));
                Err(failure)
            }
            (result, stored) => combine_typed_run_and_integrity(result, stored),
        }
    }

    fn store_command(
        &self,
        request: Request,
        result: &Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure>,
    ) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        let outcome = match result {
            Ok(output) => CommandOutcome::Returned {
                process: process_evidence(output.clone()),
            },
            Err(failure) => CommandOutcome::Failed {
                failure: failure.clone(),
            },
        };
        // A failed startup must not inherit the preceding command's output.
        state.last_process = outcome.process().cloned().map(Box::new);
        state.last_returned = matches!(&outcome, CommandOutcome::Returned { .. });
        let stored = (|| {
            if state.finished
                || request.role.indexer() != self.spec.kind
                || request.arguments.is_empty()
            {
                return Err(
                    "compiler census command is outside its active provider scope".to_string(),
                );
            }
            let inputs = state
                .inputs
                .as_ref()
                .ok_or("compiler census inputs are not bound")?;
            let sequence = state.commands.len();
            let role = request.role;
            let receipt = CommandReceipt {
                scope_sha256: self.scope_sha256.clone(),
                inputs_sha256: receipt_io::hash(inputs)?,
                sequence,
                preceding_sha256: state.commands.last().cloned(),
                request,
                result: outcome,
            };
            let digest = receipt_io::write(&self.root, &command_name(sequence), &receipt)?;
            state.commands.push(digest);
            state.models.push(None);
            state.last_role = Some(role);
            Ok(())
        })();
        stored.map_err(|detail| self.failure(detail))
    }

    pub(super) fn record_model(&self, model: ModelPart) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        let result = (|| {
            let sequence = state
                .commands
                .len()
                .checked_sub(1)
                .ok_or("compiler model has no command witness")?;
            if state.finished
                || !state.last_returned
                || state.last_role != Some(model.role())
                || state.models[sequence].is_some()
            {
                return Err(
                    "compiler model result changed or repeated its command role".to_string()
                );
            }
            let receipt = ModelReceipt {
                scope_sha256: self.scope_sha256.clone(),
                sequence,
                command_sha256: state.commands[sequence].clone(),
                model,
            };
            state.models[sequence] = Some(receipt_io::write(
                &self.root,
                &model_name(sequence),
                &receipt,
            )?);
            Ok(())
        })();
        result.map_err(|detail| {
            let mut failure = self.failure(detail);
            failure.process = state.last_process.clone();
            failure
        })
    }

    pub(super) fn finish(
        &self,
        result: Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure>,
    ) -> Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        let verification = self
            .verify(&state, result.as_ref().ok().map(Vec::as_slice))
            .map_err(|detail| {
                let mut failure = self.failure(detail);
                failure.process = state.last_process.clone();
                failure
            });
        let result = combine_typed_run_and_integrity(result, verification);
        let terminal_result = match &result {
            Ok(plans) => TerminalOutcome::Accepted {
                plans: plans.clone(),
            },
            Err(failure) => TerminalOutcome::Failed {
                failure: failure.clone(),
            },
        };
        let terminal = TerminalReceipt {
            scope_sha256: self.scope_sha256.clone(),
            inputs: state.inputs.clone(),
            commands: state.commands.clone(),
            models: state.models.clone(),
            input_closure_proven: false,
            result: terminal_result,
        };
        let persisted = if state.finished {
            Err(self.failure("compiler census already has a terminal outcome"))
        } else {
            receipt_io::write(&self.root, "terminal.json", &terminal)
                .map(|_| ())
                .map_err(|detail| self.failure(detail))
        };
        if persisted.is_ok() {
            state.finished = true;
        }
        match (result, persisted) {
            (Ok(_), Err(mut failure)) => {
                failure.process = state.last_process.clone();
                Err(failure)
            }
            (result, persisted) => combine_typed_run_and_integrity(result, persisted),
        }
    }

    fn verify(
        &self,
        state: &State,
        plans: Option<&[SemanticIndexerVariantPlan]>,
    ) -> Result<(), String> {
        let accepted = plans.is_some();
        receipt_io::ensure_plain_directory(&self.root)?;
        let scope: Scope = receipt_io::read(&self.root.join("scope.json"), &self.scope_sha256)?;
        scope.validate()?;
        if let Some(plans) = plans {
            if plans.is_empty() {
                return Err("accepted compiler census has no qualified plans".to_string());
            }
            let mut identities = BTreeSet::new();
            for plan in plans {
                plan.validate()?;
                if plan.dimensions.get("source_snapshot_sha256") != Some(&scope.repository_sha256)
                    || !identities.insert(&plan.identity)
                {
                    return Err(
                        "compiler census plans changed source scope or repeated identity"
                            .to_string(),
                    );
                }
            }
        }
        let inputs_sha256 = state.inputs.as_ref().map(receipt_io::hash).transpose()?;
        if let Some(expected) = &inputs_sha256 {
            let inputs: Inputs = receipt_io::read(&self.root.join("inputs.json"), expected)?;
            inputs.validate(scope.indexer)?;
        }
        if accepted
            && (state.commands.is_empty()
                || state.inputs.is_none()
                || state.models.iter().any(Option::is_none))
        {
            return Err(
                "accepted compiler census has incomplete command/model coverage".to_string(),
            );
        }
        for (sequence, digest) in state.commands.iter().enumerate() {
            let command: CommandReceipt =
                receipt_io::read(&self.root.join(command_name(sequence)), digest)?;
            if command.scope_sha256 != self.scope_sha256
                || command.sequence != sequence
                || Some(&command.inputs_sha256) != inputs_sha256.as_ref()
                || command.preceding_sha256.as_ref()
                    != sequence
                        .checked_sub(1)
                        .map(|previous| &state.commands[previous])
                || command.request.role.indexer() != scope.indexer
            {
                return Err("compiler census command changed ordered scope".to_string());
            }
            if accepted {
                let CommandOutcome::Returned { process } = &command.result else {
                    return Err("accepted compiler census includes a failed command".to_string());
                };
                if process.status_code != Some(0)
                    || process.timed_out
                    || process.memory_limit_exceeded
                    || process.process_limit_exceeded
                    || process.stdout_sha256
                        != format!("{:x}", Sha256::digest(process.stdout.as_bytes()))
                {
                    return Err(
                        "accepted compiler model is not backed by complete successful stdout"
                            .to_string(),
                    );
                }
            }
            if let Some(expected) = &state.models[sequence] {
                let model: ModelReceipt =
                    receipt_io::read(&self.root.join(model_name(sequence)), expected)?;
                if model.scope_sha256 != self.scope_sha256
                    || model.sequence != sequence
                    || model.command_sha256 != *digest
                    || model.model.role() != command.request.role
                {
                    return Err("compiler model changed its exact command witness".to_string());
                }
            }
        }
        Ok(())
    }

    fn failure(&self, detail: impl Into<String>) -> SemanticIndexerRunFailure {
        persistence_failure(
            self.spec,
            format!(
                "{}; compiler census receipts: {}",
                detail.into(),
                self.root.display()
            ),
        )
    }
}

fn persistence_failure(
    spec: PinnedIndexer,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::InfrastructureFailed,
        SemanticIndexerRunPhase::SnapshotAssembly,
        detail,
    )
}

fn command_name(sequence: usize) -> String {
    format!("command-{sequence:08}.json")
}
fn model_name(sequence: usize) -> String {
    format!("model-{sequence:08}.json")
}

#[cfg(test)]
#[path = "tests/semantic_indexer_census.rs"]
mod tests;

#[cfg(test)]
pub(super) use tests::assert_native_terminal;
