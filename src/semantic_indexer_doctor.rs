use crate::semantic_indexer_installation::SemanticIndexerStore;
use crate::semantic_indexer_manifest::{
    IndexerRuntime, PinnedIndexer, pinned_indexer, required_indexers,
};
use crate::types::FileRecord;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const VERSION_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) async fn check_required_indexers(files: &[FileRecord]) -> Vec<String> {
    let required = required_indexers(files);
    if required.is_empty() {
        return Vec::new();
    }

    let store = match SemanticIndexerStore::for_user() {
        Ok(store) => store,
        Err(error) => return vec![format!("semantic indexer cache: {error}")],
    };
    let mut failures = Vec::new();
    for kind in required {
        let spec = match pinned_indexer(kind) {
            Ok(spec) => spec,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let installed = match store.verify(spec) {
            Ok(installed) => installed,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        if let Err(error) = check_version(spec, &installed.entrypoint).await {
            failures.push(error);
        }
    }
    failures
}

async fn check_version(spec: PinnedIndexer, entrypoint: &Path) -> Result<(), String> {
    let mut command = match spec.runtime {
        IndexerRuntime::NodeScript => {
            let mut command = Command::new("node");
            command.arg(entrypoint).arg("--version");
            command
        }
        IndexerRuntime::Native => {
            let mut command = Command::new(entrypoint);
            command.arg("--version");
            command
        }
        IndexerRuntime::JavaJar => {
            let mut command = Command::new("java");
            command.args(["-jar"]).arg(entrypoint).arg("--version");
            command
        }
    };
    command.kill_on_drop(true);
    let output = timeout(VERSION_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{} version check timed out after {} seconds",
                spec.display_name,
                VERSION_TIMEOUT.as_secs()
            )
        })
        .and_then(|result| {
            result.map_err(|error| {
                format!(
                    "{} version check could not start: {error}",
                    spec.display_name
                )
            })
        })?;
    let mut version_output = String::from_utf8_lossy(&output.stdout).into_owned();
    version_output.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!(
            "{} version check failed with {}; output: {}",
            spec.display_name,
            output.status,
            compact_output(&version_output)
        ));
    }
    if !spec.accepts_version_output(&version_output) {
        return Err(format!(
            "{} version mismatch; expected {}, received {}",
            spec.display_name,
            spec.version,
            compact_output(&version_output)
        ));
    }
    Ok(())
}

fn compact_output(output: &str) -> String {
    let output = output.split_whitespace().collect::<Vec<_>>().join(" ");
    if output.len() > 240 {
        format!("{}...", &output[..240])
    } else {
        output
    }
}

#[cfg(test)]
#[path = "tests/semantic_indexer_doctor.rs"]
mod tests;
