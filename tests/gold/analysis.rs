use super::*;

#[test]
fn bumpkin_style_analysis_bundle_distinguishes_surfaces_and_hotspots() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_bumpkin_style"));
    let src_dir = temp_root.join("src");
    let analysis_dir = src_dir.join("bumpkin").join("analysis");
    let scripts_dir = temp_root.join("scripts");
    let examples_dir = scripts_dir.join("examples");
    fs::create_dir_all(&analysis_dir).unwrap();
    fs::create_dir_all(&examples_dir).unwrap();

    write_temp_file(
        &analysis_dir,
        "findings.py",
        r#"
from __future__ import annotations

import re

from bumpkin.analysis import finding_aggregation, finding_js_ts, finding_python_detector

aggregate_findings = finding_aggregation.aggregate_findings


def _reindex_findings(findings):
    return [f"{finding.rule}:{index}" for index, finding in enumerate(findings, 1)]


def detect_semver_findings(diff_text):
    findings = []
    findings.extend(finding_js_ts.run_js_ts_export_detection(diff_text))
    findings.extend(finding_python_detector.run_python_api_detection(diff_text))
    return findings
"#,
    );

    write_temp_file(
        &analysis_dir,
        "explanation_facts.py",
        r#"
from __future__ import annotations

import re
from dataclasses import dataclass

LOW_SIGNAL_HINT_SYMBOLS = {"snippet", "value", "text", "path", "data"}


@dataclass(frozen=True)
class ExplanationFacts:
    label: str
    target_summary: str
    scope: str
    operation_hint: str | None


def summarize_path_targets(paths, max_items=2):
    seen = []
    for path in paths:
        if path not in seen:
            seen.append(path)
    return ", ".join(seen[:max_items])


def derive_scope_from_path(path, *, rule):
    parts = str(path or "").replace("\\\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "src":
        return parts[2]
    return str(rule or "core").replace("_", "-")
"#,
    );

    let mut signatures = String::from(
        r#"
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PythonFunctionSignature:
    name: str
    params: str
    return_type: str | None
    is_async: bool
    source: str

"#,
    );
    for index in 0..21 {
        signatures.push_str(&format!(
            "def helper_{index}(value):\n    return value + {index}\n\n"
        ));
    }
    signatures.push_str(
        r#"
def extract_python_signatures(items):
    total = 0
    for item in items:
        if item == 0:
            total += 0
        elif item == 1:
            total += 1
        elif item == 2:
            total += 2
        elif item == 3:
            total += 3
        elif item == 4:
            total += 4
        elif item == 5:
            total += 5
        elif item == 6:
            total += 6
        elif item == 7:
            total += 7
        elif item == 8:
            total += 8
        elif item == 9:
            total += 9
        elif item == 10:
            total += 10
        elif item == 11:
            total += 11
        elif item == 12:
            total += 12
        elif item == 13:
            total += 13
        elif item == 14:
            total += 14
        elif item == 15:
            total += 15
        elif item == 16:
            total += 16
        elif item == 17:
            total += 17
        elif item == 18:
            total += 18
        elif item == 19:
            total += 19
        elif item == 20:
            total += 20
        elif item == 21:
            total += 21
        elif item == 22:
            total += 22
        elif item == 23:
            total += 23
        elif item == 24:
            total += 24
        elif item == 25:
            total += 25
        elif item == 26:
            total += 26
        elif item == 27:
            total += 27
        elif item == 28:
            total += 28
        elif item == 29:
            total += 29
        elif item == 30:
            total += 30
        elif item == 31:
            total += 31
        elif item == 32:
            total += 32
        elif item == 33:
            total += 33
        elif item == 34:
            total += 34
        elif item == 35:
            total += 35
        elif item == 36:
            total += 36
        elif item == 37:
            total += 37
        elif item == 38:
            total += 38
        elif item == 39:
            total += 39
        elif item == 40:
            total += 40
        elif item == 41:
            total += 41
        elif item == 42:
            total += 42
        elif item == 43:
            total += 43
        elif item == 44:
            total += 44
        elif item == 45:
            total += 45
        elif item == 46:
            total += 46
        elif item == 47:
            total += 47
        elif item == 48:
            total += 48
        elif item == 49:
            total += 49
        elif item == 50:
            total += 50
        elif item == 51:
            total += 51
        elif item == 52:
            total += 52
        elif item == 53:
            total += 53
        elif item == 54:
            total += 54
        elif item == 55:
            total += 55
        elif item == 56:
            total += 56
        elif item == 57:
            total += 57
        elif item == 58:
            total += 58
        elif item == 59:
            total += 59
        elif item == 60:
            total += 60
        elif item == 61:
            total += 61
        elif item == 62:
            total += 62
        elif item == 63:
            total += 63
        elif item == 64:
            total += 64
        elif item == 65:
            total += 65
        elif item == 66:
            total += 66
        elif item == 67:
            total += 67
        elif item == 68:
            total += 68
        elif item == 69:
            total += 69
        elif item == 70:
            total += 70
        elif item == 71:
            total += 71
        elif item == 72:
            total += 72
        elif item == 73:
            total += 73
        elif item == 74:
            total += 74
        elif item == 75:
            total += 75
        elif item == 76:
            total += 76
        elif item == 77:
            total += 77
        elif item == 78:
            total += 78
        elif item == 79:
            total += 79
        else:
            total += item
    return total
"#,
    );
    write_temp_file(&analysis_dir, "finding_python_signatures.py", &signatures);

    write_temp_file(
        &analysis_dir,
        "finding_python_all_contract.py",
        r#"
from __future__ import annotations

def extract_python_possible_all_exports(lines):
    exports = set()
    for line in lines:
        if "__all__" not in line:
            continue
        if "[" in line or "(" in line:
            exports.add("dynamic")
        elif "=" in line:
            exports.add("explicit")
        else:
            exports.add("unknown")
    return exports

def extract_python_all_contract(lines):
    exports = set()
    has_explicit_all = False
    has_unsupported_all = False
    for line in lines:
        if "__all__" not in line:
            continue
        has_explicit_all = True
        if "+=" in line:
            exports.add("append")
        elif "=" in line:
            exports.add("replace")
        else:
            has_unsupported_all = True
    return has_explicit_all, has_unsupported_all, exports
"#,
    );

    write_temp_file(
        &analysis_dir,
        "finding_python_detection_context.py",
        r#"
from __future__ import annotations

def build_python_detection_context(file_diff):
    removed_version_lines = [line for line in file_diff["removed"] if line]
    added_version_lines = [line for line in file_diff["added"] if line]
    workspace_lines = file_diff.get("workspace")
    workspace_api_reexport_names = set(file_diff.get("api", []))
    removed_import_public_names = {line for line in removed_version_lines if line.startswith("from ")}
    added_import_public_names = {line for line in added_version_lines if line.startswith("from ")}
    removed_local_public_names = {line for line in removed_version_lines if line.startswith("def ")}
    added_local_public_names = {line for line in added_version_lines if line.startswith("def ")}
    removed_star_reexports = {line for line in removed_version_lines if "import *" in line}
    added_star_reexports = {line for line in added_version_lines if "import *" in line}
    removed_all_exports = {line for line in removed_version_lines if "__all__" in line}
    added_all_exports = {line for line in added_version_lines if "__all__" in line}
    touched_meaningful_code = bool(removed_version_lines or added_version_lines or workspace_lines)
    unresolved_candidate_names = [line for line in removed_version_lines if "candidate" in line]
    workspace_public_names = set(workspace_lines or [])
    removed_signatures = {line: [line] for line in removed_version_lines}
    added_signatures = {line: [line] for line in added_version_lines}
    return {
        "removed": removed_version_lines,
        "added": added_version_lines,
        "workspace_public_names": workspace_public_names,
        "removed_signatures": removed_signatures,
        "added_signatures": added_signatures,
        "touched_meaningful_code": touched_meaningful_code,
        "unresolved_candidate_names": unresolved_candidate_names,
    }
"#,
    );

    write_temp_file(
        &analysis_dir,
        "finding_python_packaging.py",
        r#"
from __future__ import annotations

import ast
import configparser
import re

def extract_python_floor_from_constraint(constraint):
    match = re.search(r"(>=|>|~=|\^|==)\s*(\d+(?:\.\d+)*)", constraint)
    if not match:
        return None
    parts = [int(part) for part in match.group(2).split(".")]
    if match.group(1) == ">":
        parts[-1] += 1
    return tuple(parts)

def extract_setup_py_top_level_strings(module):
    constants = {}
    helpers = {}
    for statement in module.body:
        if isinstance(statement, ast.Assign):
            constants["x"] = "y"
        elif isinstance(statement, ast.AnnAssign):
            constants["a"] = "b"
        elif isinstance(statement, ast.FunctionDef):
            helpers[statement.name] = "value"
    return constants, helpers

def extract_setup_cfg_python_requires_floor(lines):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string("\n".join(lines))
    for line in lines:
        if "python_requires" in line:
            return extract_python_floor_from_constraint(line)
    return None
"#,
    );

    write_temp_file(
        &analysis_dir,
        "finding_python_surface_base.py",
        r#"
from __future__ import annotations
import ast
import re

PYTHON_DEF_START_PATTERN = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
PYTHON_PUBLIC_CLASS_PATTERN = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")
PYTHON_ALL_EXPORT_START_PATTERN = re.compile(r"^\s*__all__(?:\s*:\s*[^=]+)?\s*(\+?=)\s*")

def extract_python_string_names(node):
    if node is None:
        return set()
    if isinstance(node, str):
        return {node}
    if isinstance(node, list):
        out = set()
        for item in node:
            if isinstance(item, str):
                out.add(item)
        return out
    return set()

def extract_python_possible_string_names(node):
    if node is None:
        return set()
    if isinstance(node, tuple):
        out = set()
        for item in node:
            out |= extract_python_string_names(item)
        return out
    if isinstance(node, dict):
        return set(node.keys())
    if isinstance(node, set):
        return {str(item) for item in node if item}
    return set()

def collect_python_signature_source(lines, start_index):
    collected = [lines[start_index]]
    paren_depth = lines[start_index].count("(") - lines[start_index].count(")")
    cursor = start_index + 1
    while cursor < len(lines):
        if paren_depth <= 0 and collected[-1].strip().endswith(":"):
            break
        collected.append(lines[cursor])
        paren_depth += lines[cursor].count("(") - lines[cursor].count(")")
        cursor += 1
    return " ".join(line.strip() for line in collected), cursor

def collect_python_all_assignment(lines, start_index):
    collected = [lines[start_index]]
    bracket_depth = lines[start_index].count("[") - lines[start_index].count("]")
    cursor = start_index + 1
    while cursor < len(lines):
        if bracket_depth <= 0:
            break
        collected.append(lines[cursor])
        bracket_depth += lines[cursor].count("[") - lines[cursor].count("]")
        cursor += 1
    return " ".join(line.strip() for line in collected), cursor

def collect_python_import_statement(lines, start_index):
    collected = [lines[start_index]]
    cursor = start_index + 1
    while cursor < len(lines) and collected[-1].rstrip().endswith("\\"):
        collected.append(lines[cursor])
        cursor += 1
    return " ".join(line.strip() for line in collected), cursor

def python_import_binding_name(alias):
    if getattr(alias, "asname", None):
        return alias.asname
    if not getattr(alias, "name", None):
        return None
    return alias.name.split(".", 1)[0]

def is_obviously_internal_python_path(path):
    normalized = str(path or "").replace("\\", "/").strip("/")
    if not normalized:
        return False
    parts = normalized.split("/")
    if "tests" in parts or "docs" in parts:
        return True
    return normalized.endswith("_test.py")

def split_top_level_params(params):
    if not params:
        return []
    pieces = []
    current = []
    depth = 0
    for char in params:
        if char == "," and depth == 0:
            pieces.append("".join(current).strip())
            current = []
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        current.append(char)
    if current:
        pieces.append("".join(current).strip())
    return [piece for piece in pieces if piece]
"#,
    );

    write_temp_file(
        &scripts_dir,
        "run_app_server.py",
        r#"
from __future__ import annotations

import os
import sys


def _parse_port():
    raw_port = os.getenv("PORT") or "8080"
    try:
        return int(raw_port)
    except ValueError as err:
        raise ValueError("PORT must be an integer.") from err


def main():
    print(_parse_port())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"#,
    );

    write_temp_file(
        &examples_dir,
        "webhook_framework_apps.py",
        r#"
from __future__ import annotations


def create_fastapi_app():
    return object()


def create_flask_app():
    return object()
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    assert_eq!(paths.len(), 9);

    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    let flagged_files: Vec<_> = scorer_flags
        .iter()
        .filter(|flag| flag.tier != FindingTier::Clean)
        .map(|flag| flag.file_path.as_str())
        .collect();

    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("findings.py")),
        "facade files should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("finding_python_surface_base.py")),
        "the surface-base analysis helper should stay out of the hotspot list: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().all(|flag| {
            !flag.file_path.ends_with("finding_python_surface_base.py")
                || flag.tier == FindingTier::Clean
        }),
        "the surface-base analysis helper should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("finding_python_all_contract.py")),
        "the all-contract analysis helper should stay out of the hotspot list: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().all(|flag| {
            !flag.file_path.ends_with("finding_python_all_contract.py")
                || flag.tier == FindingTier::Clean
        }),
        "the all-contract analysis helper should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("run_app_server.py")),
        "CLI entrypoints should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("webhook_framework_apps.py")),
        "example factories should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        flagged_files
            .iter()
            .any(|path| path.ends_with("finding_python_signatures.py")),
        "the large analysis module should still be identified as a hotspot: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().any(|flag| {
            flag.file_path.ends_with("finding_python_signatures.py")
                && flag.tier == FindingTier::Slop
        }),
        "the large analysis module should be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        !flagged_files
            .iter()
            .any(|path| path.ends_with("finding_python_packaging.py")),
        "the packaging analysis helper should stay out of the hotspot list: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().all(|flag| {
            !flag.file_path.ends_with("finding_python_packaging.py")
                || flag.tier == FindingTier::Clean
        }),
        "the packaging analysis helper should stay clean: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn bumpkin_support_analysis_helpers_stay_clean_while_helpers_clones_are_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_bumpkin_support_helpers"));
    let analysis_dir = temp_root.join("src").join("bumpkin").join("analysis");
    let release_dir = temp_root.join("src").join("bumpkin").join("release");
    fs::create_dir_all(&analysis_dir).unwrap();
    fs::create_dir_all(&release_dir).unwrap();

    let diff_text_source = r#"
from __future__ import annotations

def _changed_files(from_ref, to_ref):
    return []

def _normalize_path(path):
    return path.strip()

def _cap_diff_per_file(diff_text, max_chars_per_file):
    if max_chars_per_file <= 0:
        return diff_text, 0
    if len(diff_text) <= max_chars_per_file:
        return diff_text, 0
    if "diff --git " not in diff_text:
        return diff_text, 0
    return diff_text[:max_chars_per_file], 1
"#;
    let candidate_source = r#"
from __future__ import annotations

def _coerce_int(value, *, field_name):
    if isinstance(value, bool):
        raise RuntimeError(field_name)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            try:
                return int(normalized)
            except ValueError:
                raise RuntimeError(field_name)
    raise RuntimeError(field_name)

def _deserialize_release_candidate(payload):
    if not isinstance(payload, dict):
        raise RuntimeError("invalid")
    if "pull_requests" not in payload:
        raise RuntimeError("missing")
    return payload
"#;

    write_temp_file(&analysis_dir, "diff_text.py", diff_text_source);
    write_temp_file(&analysis_dir, "helpers.py", diff_text_source);
    write_temp_file(
        &analysis_dir,
        "finding_python_reexports.py",
        r#"
from __future__ import annotations

def extract_python_imported_names(statement_source, *, path):
    if not statement_source:
        return set()
    if "import" not in statement_source:
        return set()
    return {"name"}

def has_python_explicit_public_import_alias(lines, *, path):
    for line in lines:
        if line.startswith("from "):
            return True
    return False
"#,
    );
    write_temp_file(&release_dir, "candidate.py", candidate_source);
    write_temp_file(&release_dir, "helpers.py", candidate_source);
    write_temp_file(
        &temp_root.join("src").join("bumpkin").join("eval"),
        "fixtures.py",
        r#"
from __future__ import annotations

def ensure_string_list(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("bad")
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]

def validate_expected_payload(expected, *, path):
    if not isinstance(expected, dict):
        raise ValueError(str(path))
    return expected

def filter_cases(cases, *, language_group, include_tuning_targets, default_language_group):
    filtered = []
    for case in cases:
        if case.get("tuning_target") and not include_tuning_targets:
            continue
        if language_group and case.get("language") != language_group:
            continue
        filtered.append(case)
    return filtered
"#,
    );
    write_temp_file(
        &temp_root
            .join("supabase")
            .join("functions")
            .join("create-polar-checkout-session"),
        "index.ts",
        r#"
export default async function handler(req: Request) {
  if (req.method !== "POST") {
    return new Response("method not allowed", { status: 405 });
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" },
  });
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("diff_text.py") && flag.tier != FindingTier::Clean),
        "support diff_text module should stay clean: {:?}",
        flags
    );
    assert!(
        !flags.iter().any(|flag| {
            flag.file_path.ends_with("finding_python_reexports.py")
                && flag.tier != FindingTier::Clean
        }),
        "analysis re-export plumbing should stay clean: {:?}",
        flags
    );
    assert!(
        !flags.iter().any(|flag| {
            flag.file_path.ends_with("fixtures.py")
                && flag.file_path.contains("/eval/")
                && flag.tier != FindingTier::Clean
        }),
        "evaluation fixture harness should stay clean: {:?}",
        flags
    );
    assert!(
        !flags.iter().any(|flag| {
            flag.file_path.ends_with("candidate.py") && flag.tier != FindingTier::Clean
        }),
        "support release candidate module should stay clean: {:?}",
        flags
    );
    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("helpers.py")
                && flag
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("filename is vague"))
        }),
        "generic helper clones should still be scored as noisy: {:?}",
        flags
    );
    assert!(
        !flags.iter().any(|flag| {
            flag.file_path
                .ends_with("supabase/functions/create-polar-checkout-session/index.ts")
                && flag.tier != FindingTier::Clean
        }),
        "serverless function entrypoints should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}
