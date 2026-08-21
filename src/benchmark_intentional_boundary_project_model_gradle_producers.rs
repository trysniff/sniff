use super::*;

pub(super) fn normalize_producer_tasks(
    context: &GradleModelContext<'_>,
    project_directory: &Path,
    target_sources: &[String],
    tasks: Vec<GradleToolingProducerTask>,
) -> Result<Vec<IntentionalBoundaryProjectModelProducerTask>, String> {
    let mut normalized = tasks
        .into_iter()
        .map(|task| normalize_producer_task(context, project_directory, target_sources, task))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Gradle Tooling API repeated a producer task".to_string());
    }
    Ok(normalized)
}

fn normalize_producer_task(
    context: &GradleModelContext<'_>,
    project_directory: &Path,
    target_sources: &[String],
    task: GradleToolingProducerTask,
) -> Result<IntentionalBoundaryProjectModelProducerTask, String> {
    if !valid_gradle_project_path(&task.task_path)
        || task.task_path == ":"
        || task.task_type.trim().is_empty()
        || task.task_type.chars().any(char::is_control)
    {
        return Err("Gradle Tooling API producer task identity is invalid".to_string());
    }
    let mut output_repository_paths = task
        .output_files
        .iter()
        .map(|path| {
            emitted_output_repository_path(
                context.root,
                context.emitted_root,
                path,
                "Gradle producer output",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    output_repository_paths.sort();
    if output_repository_paths.is_empty()
        || output_repository_paths
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err("Gradle Tooling API producer outputs are empty or repeated".to_string());
    }
    let mut source_repository_paths = task
        .production_source_files
        .iter()
        .map(|path| {
            emitted_host_path(
                context.root,
                context.emitted_root,
                path,
                "Gradle producer source",
                false,
            )
            .and_then(|path| repository_path(context.root, &path))
        })
        .collect::<Result<Vec<_>, String>>()?;
    source_repository_paths.sort();
    if source_repository_paths.is_empty()
        || source_repository_paths
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || source_repository_paths
            .iter()
            .any(|source| target_sources.binary_search(source).is_err())
        || source_repository_paths.iter().any(|source| {
            !output_repository_paths
                .iter()
                .any(|output| path_contains(output, source))
        })
    {
        return Err("Gradle Tooling API producer sources changed ownership".to_string());
    }
    let project_repository_path = project_directory
        .strip_prefix(context.root)
        .map_err(|_| "Gradle project directory escaped the repository".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    if output_repository_paths
        .iter()
        .any(|output| output == &project_repository_path)
    {
        return Err("Gradle producer declares its entire project as output".to_string());
    }
    Ok(IntentionalBoundaryProjectModelProducerTask {
        task_path: task.task_path,
        task_type: task.task_type,
        output_repository_paths,
        source_repository_paths,
    })
}

pub(super) fn validate_producer_tasks(target: &IntentionalBoundaryProjectModelTarget) -> bool {
    target
        .producer_tasks
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        && target.producer_tasks.iter().all(|task| {
            valid_gradle_project_path(&task.task_path)
                && task.task_path != ":"
                && !task.task_type.trim().is_empty()
                && !task.task_type.chars().any(char::is_control)
                && sorted_unique(&task.output_repository_paths)
                && sorted_unique(&task.source_repository_paths)
                && task.source_repository_paths.iter().all(|source| {
                    target.source_repository_paths.binary_search(source).is_ok()
                        && task
                            .output_repository_paths
                            .iter()
                            .any(|output| path_contains(output, source))
                })
        })
}

fn sorted_unique(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn path_contains(directory_or_file: &str, source: &str) -> bool {
    source == directory_or_file
        || source
            .strip_prefix(directory_or_file)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
