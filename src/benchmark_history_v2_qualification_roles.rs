use super::intentional_boundary_inventory::read_intentional_boundary_git_blob;
use super::{
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SourceRole, HistoricalV2SourceRoleBasis,
    HistoricalV2SourceRoleDecision, HistoricalV2SourceSnapshotCensus,
    IntentionalBoundarySemanticSurface,
};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn classify_snapshot_roles(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<BTreeMap<String, HistoricalV2SourceRoleDecision>, String> {
    let mut roles = BTreeMap::new();
    for file in &source.source_files {
        let bytes = read_intentional_boundary_git_blob(root, &file.object_id, file.byte_length)?;
        let role = classify_source_role(
            &file.repository_path,
            &bytes,
            has_runtime_surface(&file.repository_path, semantic),
        );
        if roles.insert(file.repository_path.clone(), role).is_some() {
            return Err("historical-v2 source role census repeats a path".to_string());
        }
    }
    Ok(roles)
}

fn classify_source_role(
    repository_path: &str,
    source: &[u8],
    has_runtime_surface: bool,
) -> HistoricalV2SourceRoleDecision {
    let normalized = repository_path.replace('\\', "/").to_ascii_lowercase();
    let segments = normalized.split('/').collect::<Vec<_>>();
    let name = segments.last().copied().unwrap_or_default();

    if has_segment(
        &segments,
        &["vendor", "vendored", "third_party", "node_modules"],
    ) {
        decision(
            HistoricalV2SourceRole::Vendored,
            HistoricalV2SourceRoleBasis::VendoredPath,
        )
    } else if has_generated_marker(source) {
        decision(
            HistoricalV2SourceRole::Generated,
            HistoricalV2SourceRoleBasis::GeneratedHeader,
        )
    } else if has_segment(&segments, &["generated", "gen"])
        || name.contains(".generated.")
        || name.starts_with("generated.")
    {
        decision(
            HistoricalV2SourceRole::Generated,
            HistoricalV2SourceRoleBasis::GeneratedPath,
        )
    } else if has_segment(&segments, &["fixtures", "fixture", "gold_fixtures"]) {
        decision(
            HistoricalV2SourceRole::Fixture,
            HistoricalV2SourceRoleBasis::FixturePath,
        )
    } else if has_segment(&segments, &["examples", "example", "samples", "sample"]) {
        decision(
            HistoricalV2SourceRole::Example,
            HistoricalV2SourceRoleBasis::ExamplePath,
        )
    } else if is_test_path(&segments, name) {
        decision(
            HistoricalV2SourceRole::Test,
            HistoricalV2SourceRoleBasis::TestPath,
        )
    } else if has_segment(&segments, &["docs", "doc"]) {
        decision(
            HistoricalV2SourceRole::Documentation,
            HistoricalV2SourceRoleBasis::DocumentationPath,
        )
    } else if has_segment(&segments, &["scripts", "script"]) && !has_runtime_surface {
        decision(
            HistoricalV2SourceRole::Script,
            HistoricalV2SourceRoleBasis::ScriptPath,
        )
    } else if has_runtime_surface {
        decision(
            HistoricalV2SourceRole::Production,
            HistoricalV2SourceRoleBasis::CompilerRuntimeSurface,
        )
    } else {
        decision(
            HistoricalV2SourceRole::Production,
            HistoricalV2SourceRoleBasis::TrackedSupportedSource,
        )
    }
}

fn decision(
    role: HistoricalV2SourceRole,
    basis: HistoricalV2SourceRoleBasis,
) -> HistoricalV2SourceRoleDecision {
    HistoricalV2SourceRoleDecision { role, basis }
}

fn has_runtime_surface(path: &str, semantic: &HistoricalV2SemanticSnapshotCensus) -> bool {
    semantic.public_symbols.iter().any(|public| {
        public
            .symbol
            .definitions
            .iter()
            .any(|definition| definition.repository_path == path)
            && public
                .symbol
                .surfaces
                .iter()
                .any(|surface| !matches!(surface, IntentionalBoundarySemanticSurface::PublicApi))
    })
}

fn has_segment(segments: &[&str], expected: &[&str]) -> bool {
    segments
        .iter()
        .any(|segment| expected.iter().any(|expected| segment == expected))
}

fn is_test_path(segments: &[&str], name: &str) -> bool {
    has_segment(
        segments,
        &[
            "test",
            "tests",
            "__tests__",
            "commontest",
            "androidtest",
            "iostest",
            "jvmtest",
        ],
    ) || name.starts_with("test_")
        || name.ends_with("_test.py")
        || name.ends_with("_test.go")
        || name.ends_with("_test.rs")
        || name.ends_with("_spec.rs")
        || name.ends_with("test.kt")
        || name.ends_with("tests.kt")
        || name.ends_with("test.java")
        || name.ends_with("tests.java")
        || name.contains(".test.")
        || name.contains(".spec.")
}

fn has_generated_marker(source: &[u8]) -> bool {
    let prefix = &source[..source.len().min(16 * 1024)];
    let text = String::from_utf8_lossy(prefix).to_ascii_lowercase();
    text.lines().take(40).any(|line| {
        let line = line.trim_start();
        let Some(comment) = ["//", "#", "/*", "*", "<!--"]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        else {
            return false;
        };
        let comment = comment.trim_start();
        [
            "code generated by",
            "do not edit this file",
            "do not edit manually",
            "this file is generated",
            "this file was generated",
            "automatically generated",
            "@generated",
        ]
        .iter()
        .any(|marker| comment.contains(marker))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_marker_beats_a_normal_source_path() {
        assert_eq!(
            classify_source_role(
                "src/api.rs",
                b"// Code generated by tool. DO NOT EDIT.\n",
                false
            ),
            decision(
                HistoricalV2SourceRole::Generated,
                HistoricalV2SourceRoleBasis::GeneratedHeader,
            )
        );
    }

    #[test]
    fn generated_words_inside_code_are_not_a_marker() {
        assert_eq!(
            classify_source_role(
                "src/detector.rs",
                b"const MARKER: &str = \"code generated by\";\n",
                false,
            ),
            decision(
                HistoricalV2SourceRole::Production,
                HistoricalV2SourceRoleBasis::TrackedSupportedSource,
            )
        );
    }

    #[test]
    fn test_names_are_case_insensitive() {
        assert_eq!(
            classify_source_role("src/FooTests.kt", b"class FooTests", false),
            decision(
                HistoricalV2SourceRole::Test,
                HistoricalV2SourceRoleBasis::TestPath,
            )
        );
    }

    #[test]
    fn runtime_script_is_production() {
        assert_eq!(
            classify_source_role("scripts/release.py", b"def main(): pass", true),
            decision(
                HistoricalV2SourceRole::Production,
                HistoricalV2SourceRoleBasis::CompilerRuntimeSurface,
            )
        );
        assert_eq!(
            classify_source_role("scripts/release.py", b"def main(): pass", false),
            decision(
                HistoricalV2SourceRole::Script,
                HistoricalV2SourceRoleBasis::ScriptPath,
            )
        );
    }
}
