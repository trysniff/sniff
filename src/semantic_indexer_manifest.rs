use crate::types::FileRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(crate) const INDEXER_INSTALL_CONTRACT: &str = "semantic-indexers-v1";
#[cfg(windows)]
pub(crate) const WINDOWS_SCIP_GO_PATCH_ID: &str = "x-tools-v0.45.0-and-go-tool-explicit-stdin-v4";
#[cfg(windows)]
pub(crate) const WINDOWS_SCIP_JAVA_PATCH_ID: &str = "isolated-gradle-file-temp-overlay-v19";
#[cfg(windows)]
pub(crate) const WINDOWS_RUST_INDEXER_PATCH_ID: &str = "appcontainer-process-transport-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SemanticIndexerKind {
    TypeScriptJavaScript,
    Python,
    Go,
    Kotlin,
    Rust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexerRuntime {
    NodeScript,
    Native,
    JavaJar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexerInstallSource {
    Npm {
        package: &'static str,
        integrity_sha512: &'static str,
    },
    GoModule {
        module: &'static str,
        package: &'static str,
        commit: &'static str,
    },
    Download(IndexerDownload),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexerDownload {
    pub(crate) url: &'static str,
    pub(crate) sha256: &'static str,
    pub(crate) archive: DownloadArchive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadArchive {
    Raw,
    Gzip,
    Zip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinnedIndexer {
    pub(crate) kind: SemanticIndexerKind,
    pub(crate) display_name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) runtime: IndexerRuntime,
    pub(crate) source: IndexerInstallSource,
    pub(crate) version_output: VersionOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionOutput {
    Exact(&'static str),
    ContainsToken(&'static str),
}

impl PinnedIndexer {
    pub(crate) fn install_directory_name(self) -> &'static str {
        match self.kind {
            SemanticIndexerKind::TypeScriptJavaScript => "typescript-javascript",
            SemanticIndexerKind::Python => "python",
            SemanticIndexerKind::Go => "go",
            SemanticIndexerKind::Kotlin => "kotlin",
            SemanticIndexerKind::Rust => "rust",
        }
    }

    pub(crate) fn entrypoint_relative_path(self) -> PathBuf {
        match self.kind {
            SemanticIndexerKind::TypeScriptJavaScript => {
                PathBuf::from("node_modules/@sourcegraph/scip-typescript/dist/src/main.js")
            }
            SemanticIndexerKind::Python => {
                PathBuf::from("node_modules/@sourcegraph/scip-python/index.js")
            }
            SemanticIndexerKind::Go => PathBuf::from("bin").join(executable("scip-go")),
            SemanticIndexerKind::Kotlin => PathBuf::from("bin").join("scip-java-v0.13.1"),
            SemanticIndexerKind::Rust => PathBuf::from("bin").join(executable("rust-analyzer")),
        }
    }

    pub(crate) fn companion_relative_paths(self) -> Vec<PathBuf> {
        if cfg!(windows) && self.kind == SemanticIndexerKind::Rust {
            vec![PathBuf::from("bin").join(executable("cargo"))]
        } else {
            Vec::new()
        }
    }

    pub(crate) fn accepts_version_output(self, output: &str) -> bool {
        let output = output.trim();
        match self.version_output {
            VersionOutput::Exact(expected) => output == expected,
            VersionOutput::ContainsToken(expected) => output
                .split(|character: char| character.is_ascii_whitespace() || character == ',')
                .any(|token| token == expected),
        }
    }
}

impl SemanticIndexerKind {
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::TypeScriptJavaScript => "scip-typescript",
            Self::Python => "scip-python",
            Self::Go => "scip-go",
            Self::Kotlin => "scip-java",
            Self::Rust => "rust-analyzer",
        }
    }
}

pub(crate) fn pinned_indexer(kind: SemanticIndexerKind) -> Result<PinnedIndexer, String> {
    match kind {
        SemanticIndexerKind::TypeScriptJavaScript => Ok(PinnedIndexer {
            kind,
            display_name: "scip-typescript",
            version: "0.4.0",
            runtime: IndexerRuntime::NodeScript,
            source: IndexerInstallSource::Npm {
                package: "@sourcegraph/scip-typescript",
                integrity_sha512: "k+AtsrqmS41Sd5qjkZlHcmvoSQIvBOonRj4jpgp0KNFM6aqvMGpdSuPUqrUcg8ENTKjUbfaUVszgQwq3bCOvwA==",
            },
            version_output: VersionOutput::Exact("0.4.0"),
        }),
        SemanticIndexerKind::Python => Ok(PinnedIndexer {
            kind,
            display_name: "scip-python",
            version: "0.6.6",
            runtime: IndexerRuntime::NodeScript,
            source: IndexerInstallSource::Npm {
                package: "@sourcegraph/scip-python",
                integrity_sha512: "qoKL1Rggg0o5newAFbCFAKlS0AjWxG5MA+mC28BtgxOv0DhO4zdL8u7151FxEppDpXMVvm7+yXSjXotoVH9cMQ==",
            },
            version_output: VersionOutput::Exact("0.6.6"),
        }),
        SemanticIndexerKind::Go => Ok(PinnedIndexer {
            kind,
            display_name: "scip-go",
            version: "0.2.7",
            runtime: IndexerRuntime::Native,
            source: IndexerInstallSource::GoModule {
                module: "github.com/scip-code/scip-go",
                package: "github.com/scip-code/scip-go/cmd/scip-go",
                commit: "2e9ff3c2603a85daabe125c9f20075ec52df0731",
            },
            version_output: VersionOutput::ContainsToken("0.2.7"),
        }),
        SemanticIndexerKind::Kotlin => Ok(PinnedIndexer {
            kind,
            display_name: "scip-java",
            version: "0.13.1",
            runtime: IndexerRuntime::JavaJar,
            source: IndexerInstallSource::Download(IndexerDownload {
                url: "https://github.com/scip-code/scip-java/releases/download/v0.13.1/scip-java-v0.13.1",
                sha256: "a694cae143c32c5b6226362fb4bd268a8d13d3cd9b482819b3b0029a9a97b8fe",
                archive: DownloadArchive::Raw,
            }),
            version_output: VersionOutput::Exact("0.13.1"),
        }),
        SemanticIndexerKind::Rust => Ok(PinnedIndexer {
            kind,
            display_name: "rust-analyzer",
            version: if cfg!(windows) {
                "2026-08-03-sniff.1"
            } else {
                "2026-08-03"
            },
            runtime: IndexerRuntime::Native,
            source: IndexerInstallSource::Download(rust_analyzer_download()?),
            version_output: VersionOutput::Exact(
                "rust-analyzer 0.3.2997-standalone (b54a82b321 2026-08-02)",
            ),
        }),
    }
}

pub(crate) fn required_indexers(files: &[FileRecord]) -> BTreeSet<SemanticIndexerKind> {
    files
        .iter()
        .filter_map(|file| match file.language.to_ascii_lowercase().as_str() {
            "typescript" | "javascript" => Some(SemanticIndexerKind::TypeScriptJavaScript),
            "python" => Some(SemanticIndexerKind::Python),
            "go" => Some(SemanticIndexerKind::Go),
            "kotlin" => Some(SemanticIndexerKind::Kotlin),
            "rust" => Some(SemanticIndexerKind::Rust),
            _ => None,
        })
        .collect()
}

fn executable(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn rust_analyzer_download() -> Result<IndexerDownload, String> {
    let target = (std::env::consts::OS, std::env::consts::ARCH);
    let download = match target {
        ("windows", "x86_64") => IndexerDownload {
            url: "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.1/sniff-rust-indexer-x86_64-pc-windows-msvc.zip",
            sha256: "a0d49152280dba80ffb6adac59e5d93c231784b09301831e68c49aa78e8566bf",
            archive: DownloadArchive::Zip,
        },
        ("windows", "aarch64") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-aarch64-pc-windows-msvc.zip",
            sha256: "c10cde297644fd79ef1c288d96059bb01e345970dd89ac9d673a4e58512330e9",
            archive: DownloadArchive::Zip,
        },
        ("macos", "x86_64") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-x86_64-apple-darwin.gz",
            sha256: "8966f9429085c243817b9d13afa76e98920668c07a9b432901daaf047397c6cb",
            archive: DownloadArchive::Gzip,
        },
        ("macos", "aarch64") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-aarch64-apple-darwin.gz",
            sha256: "bba6cd8209643cd781f3ee5474fa232d3ee1b77a57f2e77982806e3c80a65207",
            archive: DownloadArchive::Gzip,
        },
        ("linux", "x86_64") if cfg!(target_env = "musl") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-x86_64-unknown-linux-musl.gz",
            sha256: "d63a986d83f1888079549d44d24af89c85ef88f42f520c9c00c01424125e885c",
            archive: DownloadArchive::Gzip,
        },
        ("linux", "x86_64") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-x86_64-unknown-linux-gnu.gz",
            sha256: "769670319df8571dac91b6eab6d3a65b18b69488a6900959f2fb6157181ace9d",
            archive: DownloadArchive::Gzip,
        },
        ("linux", "aarch64") if !cfg!(target_env = "musl") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-aarch64-unknown-linux-gnu.gz",
            sha256: "ea5cb460f1532bf3c6f399b079840e968e3c25857669cd65af36dd707ea097e8",
            archive: DownloadArchive::Gzip,
        },
        _ => {
            return Err(format!(
                "rust-analyzer {} has no pinned asset for {}-{}",
                "2026-08-03", target.0, target.1
            ));
        }
    };
    Ok(download)
}

#[cfg(test)]
#[path = "tests/semantic_indexer_manifest.rs"]
mod tests;
