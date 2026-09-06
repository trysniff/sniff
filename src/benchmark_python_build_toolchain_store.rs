use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const STORE_CONTRACT: &str = "sniff-python-build-toolchain-store-v2";
const WHEELHOUSE_CONTRACT: &str = "sniff-python-wheelhouse-v1";
const RECORD_NAME: &str = "sniff-python-build-toolchain.json";
const LOCK_NAME: &str = "requirements.txt";
const REQUIREMENTS_NAME: &str = "requirements-contract.json";
const PROVENANCE_NAME: &str = "wheelhouse-provenance.json";
const WHEELHOUSE_NAME: &str = "wheelhouse";
const MAX_RECORD_BYTES: u64 = 256 * 1024;
const MAX_LOCK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TREE_FILES: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PythonBuildToolchainRequest {
    pub(super) repository_revision: String,
    pub(super) manifest_repository_path: String,
    pub(super) manifest_source_sha256: String,
    pub(super) build_backend: String,
    pub(super) backend_path: Vec<String>,
    pub(super) build_requirements: Vec<String>,
    pub(super) package_index: String,
    pub(super) python_runtime_identity_sha256: String,
    pub(super) pip_runtime_identity_sha256: String,
    pub(super) target_platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PythonBuildRequirementsContract {
    pub(super) static_requirements: Vec<String>,
    pub(super) dynamic_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PythonWheelArtifact {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) filename: String,
    pub(super) sha256: String,
    pub(super) size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PythonWheelhouseProvenance {
    pub(super) version: u32,
    pub(super) contract: String,
    pub(super) artifacts: Vec<PythonWheelArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonBuildToolchainRecord {
    version: u32,
    contract: String,
    request_sha256: String,
    request: PythonBuildToolchainRequest,
    lock_sha256: String,
    requirements_contract_sha256: String,
    provenance_sha256: String,
    wheelhouse_tree_sha256: String,
    toolchain_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PreparedPythonBuildToolchain {
    pub(super) root: PathBuf,
    pub(super) lock: PathBuf,
    pub(super) requirements_contract: PathBuf,
    pub(super) provenance: PathBuf,
    pub(super) wheelhouse: PathBuf,
    pub(super) identity_sha256: String,
}

#[derive(Debug, Clone)]
pub(super) struct PythonBuildToolchainStore {
    root: PathBuf,
}

impl PythonBuildToolchainStore {
    pub(super) fn for_user() -> Result<Self, String> {
        Ok(Self::at(
            crate::semantic_cache::cache_base_directory()?.join("python-build-toolchains"),
        ))
    }

    pub(super) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) fn entry_root(
        &self,
        request: &PythonBuildToolchainRequest,
    ) -> Result<PathBuf, String> {
        Ok(self
            .root
            .join(STORE_CONTRACT)
            .join(request_sha256(request)?))
    }

    pub(super) fn verify(
        &self,
        request: &PythonBuildToolchainRequest,
    ) -> Result<PreparedPythonBuildToolchain, String> {
        let root = self.entry_root(request)?;
        verify_entry(request, &root)
    }

    pub(super) fn import_prepared(
        &self,
        request: &PythonBuildToolchainRequest,
        prepared_root: &Path,
    ) -> Result<PreparedPythonBuildToolchain, String> {
        validate_prepared_root(prepared_root)?;
        let final_root = self.entry_root(request)?;
        let parent = final_root.parent().ok_or_else(|| {
            format!(
                "Python build-toolchain entry has no parent: {}",
                final_root.display()
            )
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create Python build-toolchain store {}: {error}",
                parent.display()
            )
        })?;
        if final_root.exists() {
            return self.verify(request);
        }

        static NEXT_STAGING: AtomicU64 = AtomicU64::new(0);
        let staging_root = parent.join(format!(
            ".staging-{}-{}",
            std::process::id(),
            NEXT_STAGING.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            copy_tree(prepared_root, &staging_root)?;
            seal_entry(request, &staging_root)?;
            match fs::rename(&staging_root, &final_root) {
                Ok(()) => {}
                Err(_error) if final_root.exists() => {
                    let _ = fs::remove_dir_all(&staging_root);
                    return self.verify(request);
                }
                Err(error) => {
                    return Err(format!(
                        "failed to publish Python build toolchain at {}: {error}",
                        final_root.display()
                    ));
                }
            }
            self.verify(request)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging_root);
        }
        result
    }
}

impl PreparedPythonBuildToolchain {
    pub(super) fn materialize_into(&self, cache: &Path) -> Result<(), String> {
        let lock = cache.join(LOCK_NAME);
        let requirements_contract = cache.join(REQUIREMENTS_NAME);
        let provenance = cache.join(PROVENANCE_NAME);
        let wheelhouse = cache.join(WHEELHOUSE_NAME);
        if lock.exists()
            || requirements_contract.exists()
            || provenance.exists()
            || wheelhouse.exists()
        {
            return Err(format!(
                "private Python build-toolchain destination is not empty: {}",
                cache.display()
            ));
        }
        fs::copy(&self.lock, &lock).map_err(|error| {
            format!(
                "failed to materialize Python requirements lock into {}: {error}",
                lock.display()
            )
        })?;
        fs::copy(&self.requirements_contract, &requirements_contract).map_err(|error| {
            format!(
                "failed to materialize Python requirements contract into {}: {error}",
                requirements_contract.display()
            )
        })?;
        fs::copy(&self.provenance, &provenance).map_err(|error| {
            format!(
                "failed to materialize Python wheelhouse provenance into {}: {error}",
                provenance.display()
            )
        })?;
        if let Err(error) = copy_tree(&self.wheelhouse, &wheelhouse) {
            let _ = fs::remove_file(&lock);
            let _ = fs::remove_file(&requirements_contract);
            let _ = fs::remove_file(&provenance);
            let _ = fs::remove_dir_all(&wheelhouse);
            return Err(error);
        }
        Ok(())
    }

    #[cfg(test)]
    fn requirements(&self) -> Result<PythonBuildRequirementsContract, String> {
        let bytes = read_bounded_regular_file(
            &self.requirements_contract,
            MAX_LOCK_BYTES,
            "requirements contract",
        )?;
        serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "Python build-toolchain requirements contract is corrupt at {}: {error}",
                self.requirements_contract.display()
            )
        })
    }
}
#[path = "benchmark_python_build_toolchain_store_files.rs"]
mod files;
use files::copy_tree;
#[cfg(test)]
use files::read_bounded_regular_file;

#[path = "benchmark_python_build_toolchain_store_validation.rs"]
mod validation;
use validation::{request_sha256, seal_entry, validate_prepared_root, verify_entry};

#[path = "benchmark_python_environment_hash.rs"]
mod environment_hash;
pub(super) use environment_hash::python_environment_tree_sha256;

#[cfg(test)]
#[path = "benchmark_python_build_toolchain_store_tests.rs"]
mod tests;
