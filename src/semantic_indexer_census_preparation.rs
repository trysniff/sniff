use super::schema::{CommandOutcome, Inputs, is_lower_sha256};
use super::{receipt_io, *};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    census_sha256: String,
    root: PathBuf,
    projects: Vec<RepositoryPath>,
    before: Inputs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    scope_sha256: String,
    sequence: usize,
    preceding_sha256: Option<String>,
    project: RepositoryPath,
    attempt: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    intent_sha256: String,
    command: SandboxCommand,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    intent_sha256: String,
    launch_sha256: Option<String>,
    result: CommandOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Summary {
    pub(super) scope_sha256: String,
    pub(super) intents: Vec<String>,
    pub(super) launches: Vec<Option<String>>,
    pub(super) outcomes: Vec<Option<String>>,
    pub(super) completed_inputs: Option<String>,
}

pub(super) struct Ledger {
    scope: Scope,
    summary: Summary,
    intents: Vec<Intent>,
    completed: Option<Inputs>,
    next_project: usize,
    next_attempt: usize,
    halted: bool,
}

impl Ledger {
    pub(super) fn summary(&self) -> Summary {
        self.summary.clone()
    }

    pub(super) fn open(
        root: &Path,
        census_sha256: &str,
        execution_root: &Path,
        projects: Vec<RepositoryPath>,
        before: Inputs,
    ) -> Result<Self, String> {
        before.validate(SemanticIndexerKind::Go)?;
        if !is_lower_sha256(census_sha256)
            || projects.is_empty()
            || projects.windows(2).any(|pair| pair[0] >= pair[1])
            || projects.iter().any(|project| {
                project.0.contains('\\')
                    || project
                        .0
                        .split('/')
                        .any(|part| matches!(part, "" | "." | ".."))
                    || project.0.rsplit('/').next() != Some("go.mod")
            })
        {
            return Err("Go preparation scope omitted or changed its owned projects".into());
        }
        let scope = Scope {
            census_sha256: census_sha256.into(),
            root: strip_windows_verbatim_prefix(
                fs::canonicalize(execution_root).map_err(|error| error.to_string())?,
            ),
            projects,
            before,
        };
        let scope_sha256 = receipt_io::write(root, "prepare-scope.json", &scope)?;
        Ok(Self {
            scope,
            summary: Summary {
                scope_sha256,
                intents: Vec::new(),
                launches: Vec::new(),
                outcomes: Vec::new(),
                completed_inputs: None,
            },
            intents: Vec::new(),
            completed: None,
            next_project: 0,
            next_attempt: 1,
            halted: false,
        })
    }

    pub(super) fn begin(
        &mut self,
        root: &Path,
        module: &str,
        attempt: usize,
    ) -> Result<usize, String> {
        if self.completed.is_some()
            || self.halted
            || self.summary.outcomes.last().is_some_and(Option::is_none)
        {
            return Err("Go preparation has a completed scope or unfinished command".into());
        }
        let project = RepositoryPath(if module == "." {
            "go.mod".into()
        } else {
            format!("{module}/go.mod")
        });
        if self.scope.projects.get(self.next_project) != Some(&project)
            || attempt != self.next_attempt
            || attempt > GO_DEPENDENCY_PREPARATION_ATTEMPTS
        {
            return Err(
                "Go preparation command is outside its declared module/attempt scope".into(),
            );
        }
        let sequence = self.intents.len();
        let intent = Intent {
            scope_sha256: self.summary.scope_sha256.clone(),
            sequence,
            preceding_sha256: self.summary.outcomes.last().cloned().flatten(),
            project,
            attempt,
        };
        let digest = receipt_io::write(root, &name("intent", sequence), &intent)?;
        self.intents.push(intent);
        self.summary.intents.push(digest);
        self.summary.launches.push(None);
        self.summary.outcomes.push(None);
        Ok(sequence)
    }

    pub(super) fn launch(
        &mut self,
        root: &Path,
        sequence: usize,
        command: &SandboxCommand,
    ) -> Result<(), String> {
        let intent = self.active(sequence)?;
        let module = super::super::go_model_commands::module_root(&intent.project);
        let actual_root = strip_windows_verbatim_prefix(
            fs::canonicalize(&command.root).map_err(|error| error.to_string())?,
        );
        if actual_root != self.scope.root
            || command.args != go_dependency_arguments(&module)
            || !command.allow_network
            || command.program.is_empty()
            || self.summary.launches[sequence].is_some()
        {
            return Err("Go preparation launch changed its exact command scope".into());
        }
        self.summary.launches[sequence] = Some(receipt_io::write(
            root,
            &name("launch", sequence),
            &Launch {
                intent_sha256: self.summary.intents[sequence].clone(),
                command: command.clone(),
            },
        )?);
        Ok(())
    }

    pub(super) fn returned(
        &mut self,
        root: &Path,
        sequence: usize,
        result: &Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure>,
    ) -> Result<(), String> {
        self.check_return(sequence, result)?;
        let result = match result {
            Ok(output) => CommandOutcome::Returned {
                process: process_evidence(output.clone()),
            },
            Err(failure) => CommandOutcome::Failed {
                failure: failure.clone(),
            },
        };
        let advance = match &result {
            CommandOutcome::Returned { process } => {
                let output = output(process.clone());
                if successful(&output) {
                    (self.next_project + 1, 1, false)
                } else if go_dependency_preparation_retry_delay(
                    &output,
                    self.intents[sequence].attempt,
                )
                .is_some()
                {
                    (self.next_project, self.next_attempt + 1, false)
                } else {
                    (self.next_project, self.next_attempt, true)
                }
            }
            CommandOutcome::Failed { .. } => (self.next_project, self.next_attempt, true),
        };
        self.summary.outcomes[sequence] = Some(receipt_io::write(
            root,
            &name("outcome", sequence),
            &Outcome {
                intent_sha256: self.summary.intents[sequence].clone(),
                launch_sha256: self.summary.launches[sequence].clone(),
                result,
            },
        )?);
        (self.next_project, self.next_attempt, self.halted) = advance;
        Ok(())
    }

    fn active(&self, sequence: usize) -> Result<&Intent, String> {
        if self.completed.is_some()
            || sequence.checked_add(1) != Some(self.intents.len())
            || self
                .summary
                .outcomes
                .get(sequence)
                .is_none_or(Option::is_some)
        {
            return Err("Go preparation result changed or repeated its active intent".into());
        }
        Ok(&self.intents[sequence])
    }

    pub(super) fn check_return(
        &self,
        sequence: usize,
        result: &Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure>,
    ) -> Result<(), String> {
        self.active(sequence)?;
        if result.is_ok() && self.summary.launches[sequence].is_none() {
            return Err("Go preparation returned output without a launch witness".into());
        }
        Ok(())
    }

    pub(super) fn complete(&mut self, root: &Path, inputs: &Inputs) -> Result<(), String> {
        inputs.validate(SemanticIndexerKind::Go)?;
        if self.completed.is_some() || !same_runtime(&self.scope.before, inputs) {
            return Err("Go preparation changed or repeated its runtime input binding".into());
        }
        self.verify(root, true)?;
        self.summary.completed_inputs =
            Some(receipt_io::write(root, "prepare-inputs.json", inputs)?);
        self.completed = Some(inputs.clone());
        Ok(())
    }

    pub(super) fn verify(&self, root: &Path, accepted: bool) -> Result<Summary, String> {
        let scope: Scope =
            receipt_io::read(&root.join("prepare-scope.json"), &self.summary.scope_sha256)?;
        scope.before.validate(SemanticIndexerKind::Go)?;
        let mut completed = Vec::new();
        for (sequence, digest) in self.summary.intents.iter().enumerate() {
            let intent: Intent = receipt_io::read(&root.join(name("intent", sequence)), digest)?;
            if intent.scope_sha256 != self.summary.scope_sha256
                || intent.sequence != sequence
                || intent.preceding_sha256
                    != sequence
                        .checked_sub(1)
                        .and_then(|previous| self.summary.outcomes[previous].clone())
            {
                return Err("Go preparation intent changed its ordered scope".into());
            }
            if let Some(digest) = &self.summary.launches[sequence] {
                let launch: Launch =
                    receipt_io::read(&root.join(name("launch", sequence)), digest)?;
                if launch.intent_sha256 != self.summary.intents[sequence] {
                    return Err("Go preparation launch changed its intent".into());
                }
            }
            let Some(digest) = &self.summary.outcomes[sequence] else {
                if accepted {
                    return Err("Go preparation has an unfinished command".into());
                }
                continue;
            };
            let outcome: Outcome = receipt_io::read(&root.join(name("outcome", sequence)), digest)?;
            if outcome.intent_sha256 != self.summary.intents[sequence]
                || outcome.launch_sha256 != self.summary.launches[sequence]
            {
                return Err("Go preparation output changed its launch/intent".into());
            }
            if accepted {
                let CommandOutcome::Returned { process } = outcome.result else {
                    return Err(
                        "successful Go preparation includes a startup/integrity failure".into(),
                    );
                };
                let output = output(process);
                if self.summary.launches[sequence].is_none()
                    || output.stdout_sha256
                        != format!("{:x}", Sha256::digest(output.stdout.as_bytes()))
                    || output.stderr_sha256
                        != format!("{:x}", Sha256::digest(output.stderr.as_bytes()))
                {
                    return Err("Go preparation omitted its complete captured streams".into());
                }
                let expected = self.scope.projects.get(completed.len());
                if expected != Some(&intent.project)
                    || intent.attempt
                        != if sequence > 0 && self.intents[sequence - 1].project == intent.project {
                            self.intents[sequence - 1].attempt + 1
                        } else {
                            1
                        }
                {
                    return Err(
                        "Go preparation omitted/repeated/reordered a module or attempt".into(),
                    );
                }
                if successful(&output) {
                    completed.push(intent.project);
                } else if go_dependency_preparation_retry_delay(&output, intent.attempt).is_none() {
                    return Err("Go preparation includes a non-retryable failed command".into());
                }
            }
        }
        if accepted && completed != self.scope.projects {
            return Err("Go preparation has incomplete owned-module coverage".into());
        }
        if let Some(expected) = &self.summary.completed_inputs {
            let inputs: Inputs = receipt_io::read(&root.join("prepare-inputs.json"), expected)?;
            if self.completed.as_ref() != Some(&inputs) || !same_runtime(&scope.before, &inputs) {
                return Err("Go preparation completion changed its compiler inputs".into());
            }
        }
        Ok(self.summary.clone())
    }

    pub(super) fn binds(&self, inputs: &Inputs) -> bool {
        self.completed.as_ref() == Some(inputs)
    }
}

fn successful(output: &crate::sandbox::SandboxOutput) -> bool {
    output.status_code == Some(0)
        && !output.timed_out
        && !output.memory_limit_exceeded
        && !output.process_limit_exceeded
}

fn same_runtime(before: &Inputs, after: &Inputs) -> bool {
    matches!((before, after), (
        Inputs::Go { executable_sha256: left_executable, sdk_sha256: left_sdk, .. },
        Inputs::Go { executable_sha256: right_executable, sdk_sha256: right_sdk, .. }
    ) if left_executable == right_executable && left_sdk == right_sdk)
}

fn output(process: SemanticIndexerProcessEvidence) -> crate::sandbox::SandboxOutput {
    crate::sandbox::SandboxOutput {
        status_code: process.status_code,
        stdout: process.stdout,
        stderr: process.stderr,
        stdout_sha256: process.stdout_sha256,
        stderr_sha256: process.stderr_sha256,
        timed_out: process.timed_out,
        memory_limit_exceeded: process.memory_limit_exceeded,
        process_limit_exceeded: process.process_limit_exceeded,
    }
}

fn name(kind: &str, sequence: usize) -> String {
    format!("prepare-{kind}-{sequence:08}.json")
}

#[cfg(test)]
pub(super) fn assert_native_failure_receipts(root: &Path, summary: &Summary, census_sha256: &str) {
    let scope: Scope =
        receipt_io::read(&root.join("prepare-scope.json"), &summary.scope_sha256).unwrap();
    assert_eq!(scope.census_sha256, census_sha256);
    assert_eq!(
        scope.projects,
        vec![
            RepositoryPath("go.mod".into()),
            RepositoryPath("z/go.mod".into())
        ]
    );
    assert_eq!(summary.intents.len(), 2);
    assert_eq!(summary.launches.len(), 2);
    assert_eq!(summary.outcomes.len(), 2);
    assert!(summary.completed_inputs.is_none());
    for sequence in 0..2 {
        let intent: Intent = receipt_io::read(
            &root.join(name("intent", sequence)),
            &summary.intents[sequence],
        )
        .unwrap();
        assert_eq!(intent.sequence, sequence);
        assert_eq!(intent.attempt, 1);
        assert_eq!(intent.project, scope.projects[sequence]);
        assert_eq!(intent.scope_sha256, summary.scope_sha256);
        assert_eq!(
            intent.preceding_sha256,
            sequence
                .checked_sub(1)
                .and_then(|previous| summary.outcomes[previous].clone())
        );
        let launch: Launch = receipt_io::read(
            &root.join(name("launch", sequence)),
            summary.launches[sequence].as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(launch.intent_sha256, summary.intents[sequence]);
        assert_eq!(
            strip_windows_verbatim_prefix(launch.command.root),
            scope.root
        );
        assert_eq!(
            launch.command.args,
            go_dependency_arguments(if sequence == 0 { "." } else { "z" })
        );
        assert!(launch.command.allow_network);
        assert!(!launch.command.program.contains("synthetic"));
        let outcome: Outcome = receipt_io::read(
            &root.join(name("outcome", sequence)),
            summary.outcomes[sequence].as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.intent_sha256, summary.intents[sequence]);
        assert_eq!(outcome.launch_sha256, summary.launches[sequence]);
        let CommandOutcome::Returned { process } = outcome.result else {
            panic!("expected actual Go output")
        };
        assert!(
            !process.timed_out && !process.memory_limit_exceeded && !process.process_limit_exceeded
        );
        assert_eq!(
            process.stdout_sha256,
            format!("{:x}", Sha256::digest(process.stdout.as_bytes()))
        );
        assert_eq!(
            process.stderr_sha256,
            format!("{:x}", Sha256::digest(process.stderr.as_bytes()))
        );
        if sequence == 0 {
            assert_eq!(process.status_code, Some(0));
        } else {
            assert!(process.status_code.is_some_and(|code| code != 0));
            assert!(process.stderr.contains("invalid go version"));
        }
    }
}
