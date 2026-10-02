use super::*;

impl Journal {
    pub(in super::super) fn begin_go_preparation(
        &self,
        execution_root: &Path,
        projects: Vec<RepositoryPath>,
        inputs: Inputs,
    ) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        if self.spec.kind != SemanticIndexerKind::Go
            || state.finished
            || state.inputs.is_some()
            || state.preparation.is_some()
            || !state.commands.is_empty()
        {
            return Err(self.failure("Go preparation is outside its unbound census scope"));
        }
        state.preparation = Some(
            preparation::Ledger::open(
                &self.root,
                &self.scope_sha256,
                execution_root,
                projects,
                inputs,
            )
            .map_err(|detail| self.failure(detail))?,
        );
        Ok(())
    }

    pub(in super::super) fn begin_go_command(
        &self,
        module: &str,
        attempt: usize,
    ) -> Result<usize, SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        if state.finished || state.inputs.is_some() {
            return Err(self.failure("Go preparation command followed model binding or completion"));
        }
        let sequence = state
            .preparation
            .as_mut()
            .ok_or_else(|| self.failure("Go preparation scope is not bound"))?
            .begin(&self.root, module, attempt)
            .map_err(|detail| self.failure(detail))?;
        // Only an accepted new intent clears the preceding worker's evidence.
        state.last_process = None;
        Ok(sequence)
    }

    pub(in super::super) fn record_go_launch(
        &self,
        sequence: usize,
        command: &SandboxCommand,
    ) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        if state.finished || state.inputs.is_some() {
            return Err(self.failure("Go preparation launch followed model binding or completion"));
        }
        state
            .preparation
            .as_mut()
            .ok_or_else(|| self.failure("Go preparation scope is not bound"))?
            .launch(&self.root, sequence, command)
            .map_err(|detail| self.failure(detail))
    }

    pub(in super::super) fn record_go_outcome(
        &self,
        sequence: usize,
        result: Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure>,
    ) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
        let stored = (|| {
            let mut state = self
                .state
                .lock()
                .map_err(|_| self.failure("compiler census state lock failed"))?;
            if state.finished || state.inputs.is_some() {
                return Err(
                    self.failure("Go preparation output followed model binding or completion")
                );
            }
            state
                .preparation
                .as_ref()
                .ok_or_else(|| self.failure("Go preparation scope is not bound"))?
                .check_return(sequence, &result)
                .map_err(|detail| self.failure(detail))?;
            state.last_process = match &result {
                Ok(output) => Some(Box::new(process_evidence(output.clone()))),
                Err(failure) => failure.process.clone(),
            };
            state
                .preparation
                .as_mut()
                .ok_or_else(|| self.failure("Go preparation scope is not bound"))?
                .returned(&self.root, sequence, &result)
                .map_err(|detail| self.failure(detail))
        })();
        match (result, stored) {
            (Ok(output), Err(mut failure)) => {
                failure.process = Some(Box::new(process_evidence(output)));
                Err(failure)
            }
            (result, stored) => combine_typed_run_and_integrity(result, stored),
        }
    }

    pub(in super::super) fn finish_go_preparation(
        &self,
        inputs: &Inputs,
    ) -> Result<(), SemanticIndexerRunFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| self.failure("compiler census state lock failed"))?;
        if state.finished || state.inputs.is_some() {
            return Err(
                self.failure("Go preparation completion followed model binding or completion")
            );
        }
        state
            .preparation
            .as_mut()
            .ok_or_else(|| self.failure("Go preparation scope is not bound"))?
            .complete(&self.root, inputs)
            .map_err(|detail| {
                let mut failure = self.failure(detail);
                failure.process = state.last_process.clone();
                failure
            })
    }

    pub(in super::super) fn check_go_preparation_integrity<T>(
        &self,
        result: Result<T, String>,
    ) -> Result<T, SemanticIndexerRunFailure> {
        result.map_err(|detail| {
            let mut failure = indexer_failure(
                self.spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            );
            if let Ok(state) = self.state.lock() {
                failure.process = state.last_process.clone();
            }
            failure
        })
    }
}
