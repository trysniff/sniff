use super::go_commands::run_go_tool_with_environment;
use super::go_model_output::{ModuleIdentity, module_identity};
use super::go_model_plans::{explicit_environment, offline_environment};
use super::*;
use crate::compiler_go_model::{GoCompilerContext, GoCompilerQuery, GoListModule};
use crate::compiler_go_variants::go_architecture_environment_variable;

pub(super) struct ModelRuntime<'a> {
    pub(super) spec: PinnedIndexer,
    pub(super) root: &'a Path,
    pub(super) installed: &'a InstalledIndexer,
}

impl ModelRuntime<'_> {
    pub(super) async fn run(
        &self,
        arguments: Vec<String>,
        environment: &BTreeMap<String, String>,
        label: &str,
    ) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
        run_go_tool_with_environment(
            self.spec,
            self.root,
            self.installed,
            arguments,
            label,
            environment,
        )
        .await
    }

    pub(super) async fn module(
        &self,
        project: &RepositoryPath,
    ) -> Result<ModuleIdentity, SemanticIndexerRunFailure> {
        let output = self
            .run(
                vec![
                    "-C".to_string(),
                    module_root(project),
                    "list".to_string(),
                    "-m".to_string(),
                    "-json".to_string(),
                    "-mod=readonly".to_string(),
                ],
                &offline_environment(),
                "Go compiler module identity",
            )
            .await?;
        let module: GoListModule = serde_json::from_str(&output.stdout).map_err(|error| {
            model_failure(
                self.spec,
                SemanticIndexerRunPhase::OutputValidation,
                error.to_string(),
            )
        })?;
        module_identity(self.root, project, &module).map_err(|detail| {
            model_failure(self.spec, SemanticIndexerRunPhase::OutputValidation, detail)
        })
    }

    pub(super) async fn environment(
        &self,
        project: &RepositoryPath,
        context: &GoCompilerContext,
    ) -> Result<BTreeMap<String, String>, SemanticIndexerRunFailure> {
        let explicit = explicit_environment(context);
        let mut names = explicit.keys().cloned().collect::<BTreeSet<_>>();
        if let Some(name) = go_architecture_environment_variable(&context.goarch) {
            names.insert(name.to_string());
        }
        let arguments = [
            "-C".to_string(),
            module_root(project),
            "env".to_string(),
            "-json".to_string(),
        ]
        .into_iter()
        .chain(names.iter().cloned())
        .collect();
        let output = self
            .run(arguments, &explicit, "Go compiler context environment")
            .await?;
        let resolved: BTreeMap<String, String> =
            serde_json::from_str(&output.stdout).map_err(|error| {
                model_failure(
                    self.spec,
                    SemanticIndexerRunPhase::OutputValidation,
                    error.to_string(),
                )
            })?;
        if resolved.keys().cloned().collect::<BTreeSet<_>>() != names
            || explicit
                .iter()
                .any(|(name, value)| resolved.get(name) != Some(value))
        {
            return Err(model_failure(
                self.spec,
                SemanticIndexerRunPhase::OutputValidation,
                "Go compiler changed or omitted its requested context environment",
            ));
        }
        Ok(resolved)
    }
}

pub(super) fn inventory_arguments(
    project: &RepositoryPath,
    context: &GoCompilerContext,
) -> Result<Vec<String>, String> {
    let module = module_root(project);
    let pattern = match &context.query {
        GoCompilerQuery::ModulePackages => "./...".to_string(),
        GoCompilerQuery::StandaloneSource {
            source_repository_path,
        } => super::go_shards::module_relative_source(&module, source_repository_path)?,
    };
    Ok(vec![
        "-C".to_string(),
        module,
        "list".to_string(),
        "-e".to_string(),
        "-json".to_string(),
        "-find".to_string(),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
        pattern,
    ])
}

pub(super) fn module_root(project: &RepositoryPath) -> String {
    project
        .0
        .rsplit_once('/')
        .map_or(".", |(directory, _)| directory)
        .to_string()
}

pub(super) fn model_failure(
    spec: PinnedIndexer,
    phase: SemanticIndexerRunPhase,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        if phase == SemanticIndexerRunPhase::OutputValidation {
            SemanticIndexerRunFailureKind::IncompleteOutput
        } else {
            SemanticIndexerRunFailureKind::InfrastructureFailed
        },
        phase,
        detail,
    )
}
