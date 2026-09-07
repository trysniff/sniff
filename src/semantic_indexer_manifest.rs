use crate::types::FileRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(crate) const INDEXER_INSTALL_CONTRACT: &str = "semantic-indexers-v1";
pub(crate) const SCIP_TYPESCRIPT_SIGNATURE_PATCH_ID: &str = "compiler-api-signatures-v2";
pub(crate) const SCIP_PYTHON_PUBLIC_API_PATCH_ID: &str = "compiler-public-api-v1";
pub(crate) const SCIP_JAVA_KOTLIN_ANNOTATION_PATCH_ID: &str =
    "compiler-resolved-annotation-use-sites-v1";
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
    NpmTarballs {
        packages: &'static [PinnedNpmPackage],
    },
    GoModule {
        module: &'static str,
        package: &'static str,
        commit: &'static str,
    },
    Download(IndexerDownload),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinnedNpmPackage {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) url: &'static str,
    pub(crate) integrity_sha512: &'static str,
}

const SCIP_TYPESCRIPT_NPM_PACKAGES: &[PinnedNpmPackage] = &[
    PinnedNpmPackage {
        name: "@sourcegraph/scip-typescript",
        version: "0.4.0",
        url: "https://registry.npmjs.org/@sourcegraph/scip-typescript/-/scip-typescript-0.4.0.tgz",
        integrity_sha512: "k+AtsrqmS41Sd5qjkZlHcmvoSQIvBOonRj4jpgp0KNFM6aqvMGpdSuPUqrUcg8ENTKjUbfaUVszgQwq3bCOvwA==",
    },
    PinnedNpmPackage {
        name: "commander",
        version: "12.1.0",
        url: "https://registry.npmjs.org/commander/-/commander-12.1.0.tgz",
        integrity_sha512: "Vw8qHK3bZM9y/P10u3Vib8o/DdkvA2OtPtZvD871QKjy74Wj1WSKFILMPRPSdUSx5RFK1arlJzEtA4PkFgnbuA==",
    },
    PinnedNpmPackage {
        name: "google-protobuf",
        version: "3.21.4",
        url: "https://registry.npmjs.org/google-protobuf/-/google-protobuf-3.21.4.tgz",
        integrity_sha512: "MnG7N936zcKTco4Jd2PX2U96Kf9PxygAPKBug+74LHzmHXmceN16MmRcdgZv+DGef/S9YvQAfRsNCn4cjf9yyQ==",
    },
    PinnedNpmPackage {
        name: "progress",
        version: "2.0.3",
        url: "https://registry.npmjs.org/progress/-/progress-2.0.3.tgz",
        integrity_sha512: "7PiHtLll5LdnKIMw100I+8xJXR5gW2QwWYkT6iJva0bXitZKa/XMrSbdmg3r2Xnaidz9Qumd0VPaMrZlF9V9sA==",
    },
    PinnedNpmPackage {
        name: "typescript",
        version: "5.6.2",
        url: "https://registry.npmjs.org/typescript/-/typescript-5.6.2.tgz",
        integrity_sha512: "NW8ByodCSNCwZeghjN3o+JX5OFH0Ojg6sadjEKY4huZ52TqbJTJnDo5+Tw98lSy63NZvi4n+ez5m2u5d4PkZyw==",
    },
];

const SCIP_PYTHON_NPM_PACKAGES: &[PinnedNpmPackage] = &[PinnedNpmPackage {
    name: "@sourcegraph/scip-python",
    version: "0.6.6",
    url: "https://registry.npmjs.org/@sourcegraph/scip-python/-/scip-python-0.6.6.tgz",
    integrity_sha512: "qoKL1Rggg0o5newAFbCFAKlS0AjWxG5MA+mC28BtgxOv0DhO4zdL8u7151FxEppDpXMVvm7+yXSjXotoVH9cMQ==",
}];

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
    GitCommit {
        prefix: &'static str,
        commit: &'static str,
        suffix: &'static str,
        min_abbreviation: usize,
    },
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
            VersionOutput::GitCommit {
                prefix,
                commit,
                suffix,
                min_abbreviation,
            } => output
                .strip_prefix(prefix)
                .and_then(|output| output.strip_suffix(suffix))
                .is_some_and(|abbreviation| {
                    abbreviation.len() >= min_abbreviation
                        && abbreviation.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && commit.starts_with(abbreviation)
                }),
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
            source: IndexerInstallSource::NpmTarballs {
                packages: SCIP_TYPESCRIPT_NPM_PACKAGES,
            },
            version_output: VersionOutput::Exact("0.4.0"),
        }),
        SemanticIndexerKind::Python => Ok(PinnedIndexer {
            kind,
            display_name: "scip-python",
            version: "0.6.6",
            runtime: IndexerRuntime::NodeScript,
            source: IndexerInstallSource::NpmTarballs {
                packages: SCIP_PYTHON_NPM_PACKAGES,
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
            version_output: VersionOutput::GitCommit {
                prefix: "rust-analyzer 0.3.2997-standalone (",
                commit: "b54a82b321c9617c5cf0b07ac0f12c08f7bc5902",
                suffix: " 2026-08-02)",
                min_abbreviation: 9,
            },
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
    rust_analyzer_download_for(
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(target_env = "musl"),
    )
}

fn rust_analyzer_download_for(
    os: &str,
    architecture: &str,
    is_musl: bool,
) -> Result<IndexerDownload, String> {
    let target = (os, architecture);
    let download = match target {
        ("windows", "x86_64") => IndexerDownload {
            url: "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.2/sniff-rust-indexer-x86_64-pc-windows-msvc.zip",
            sha256: "4b57083b09b46634eabf24589f7059001de7f91f0007875ed6133c4a1727a6a5",
            archive: DownloadArchive::Zip,
        },
        ("windows", "aarch64") => IndexerDownload {
            url: "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.2/sniff-rust-indexer-aarch64-pc-windows-msvc.zip",
            sha256: "dc1d0bdf114919290635f4f2d95eb2c76a744ba406a1ebf62dd38d63069f8361",
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
        ("linux", "x86_64") if is_musl => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-x86_64-unknown-linux-musl.gz",
            sha256: "d63a986d83f1888079549d44d24af89c85ef88f42f520c9c00c01424125e885c",
            archive: DownloadArchive::Gzip,
        },
        ("linux", "x86_64") => IndexerDownload {
            url: "https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-03/rust-analyzer-x86_64-unknown-linux-gnu.gz",
            sha256: "769670319df8571dac91b6eab6d3a65b18b69488a6900959f2fb6157181ace9d",
            archive: DownloadArchive::Gzip,
        },
        ("linux", "aarch64") if !is_musl => IndexerDownload {
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
