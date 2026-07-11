use sniff::callgraph::build_ref_count_flags;
use sniff::types::{FileRecord, MethodRecord};

fn file(path: &str, methods: Vec<MethodRecord>) -> FileRecord {
    FileRecord {
        file_path: path.to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods,
    }
}

fn method(
    name: &str,
    path: &str,
    source: &str,
    loc: usize,
    is_exported: bool,
    real_ref_count: usize,
) -> MethodRecord {
    MethodRecord {
        name: name.to_string(),
        file_path: path.to_string(),
        source: source.to_string(),
        loc,
        param_count: 0,
        start_line: 1,
        end_line: loc.max(1),
        is_exported,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count,
    }
}

#[test]
fn thin_wrapper_exports_do_not_trigger_orphaned_export_flags() {
    let path = "src/version.py";
    let methods = vec![
        method(
            "bump_semver",
            path,
            "def bump_semver(version: str, label: str) -> str:\n    from bumpkin.versioning.tags import bump_semver as _bump_semver\n\n    return _bump_semver(version, label)\n",
            5,
            true,
            0,
        ),
        method(
            "detect_next_version",
            path,
            "def detect_next_version(label: str) -> tuple[str | None, str | None, list[str]]:\n    from bumpkin.versioning.tags import detect_next_version as _detect_next_version\n\n    return _detect_next_version(label)\n",
            6,
            true,
            0,
        ),
    ];

    let flags = build_ref_count_flags(&[file(path, methods)]);
    assert!(flags.is_empty());
}

#[test]
fn explicit_public_api_modules_do_not_trigger_orphaned_export_flags() {
    let path = "src/bumpkin/versioning/tags.py";
    const SOURCE: &str = "from __future__ import annotations\n\nimport json\nimport os\nimport re\nimport subprocess\nimport urllib.error\nimport urllib.request\nfrom dataclasses import dataclass\nfrom datetime import datetime, timezone\nfrom typing import cast\n\n__all__ = [\"bump_semver\", \"detect_next_version\", \"list_tags\", \"parse_tag\", \"resolve_current_tag\"]\n";
    let methods = vec![
        method(
            "bump_semver",
            path,
            "def bump_semver(version: str, label: str) -> str:\n    major, minor, patch = [int(x) for x in version.split(\".\")]\n    normalized = label.upper()\n\n    if normalized == \"MAJOR\":\n        return f\"{major + 1}.0.0\"\n    if normalized == \"MINOR\":\n        return f\"{major}.{minor + 1}.0\"\n    if normalized == \"NO_BUMP\":\n        return f\"{major}.{minor}.{patch}\"\n    return f\"{major}.{minor}.{patch + 1}\"\n",
            11,
            true,
            0,
        ),
        method(
            "detect_next_version",
            path,
            "def detect_next_version(label: str, latest_tag: str | None = None, tags: list[str] | None = None) -> tuple[str | None, str | None, list[str]]:\n    return latest_tag, None, []\n",
            3,
            true,
            0,
        ),
    ];

    let mut file_record = file(path, methods);
    file_record.source = SOURCE.to_string();

    let flags = build_ref_count_flags(&[file_record]);
    assert!(flags.is_empty());
}

#[test]
fn test_helpers_named_reset_are_ignored() {
    let path = "src/bumpkin/retry.py";
    let source = "def reset_model_request_interval() -> None:\n    \"\"\"Test helper to reset interval state for deterministic call pacing assertions.\"\"\"\n    global _last_model_request_ns\n    global _rate_limit_cooldown_until_ns\n    with _request_interval_state:\n        _last_model_request_ns = None\n        _rate_limit_cooldown_until_ns = None\n";
    let methods = vec![method(
        "reset_model_request_interval",
        path,
        source,
        7,
        true,
        0,
    )];

    let mut file_record = file(path, methods);
    file_record.source = source.to_string();

    let flags = build_ref_count_flags(&[file_record]);
    assert!(flags.is_empty());
}

#[test]
fn protocol_stub_methods_are_ignored() {
    let path = "src/bumpkin/integrations/github/http_adapter.py";
    let source = "class WebhookHandler(Protocol):\n    def handle_github_webhook(\n        self,\n        *,\n        headers: Mapping[str, object],\n        raw_body: bytes,\n    ) -> WebhookResponse: ...\n";
    let methods = vec![method(
        "handle_github_webhook",
        path,
        "def handle_github_webhook(\n        self,\n        *,\n        headers: Mapping[str, object],\n        raw_body: bytes,\n    ) -> WebhookResponse: ...\n",
        6,
        true,
        0,
    )];

    let mut file_record = file(path, methods);
    file_record.source = source.to_string();

    let flags = build_ref_count_flags(&[file_record]);
    assert!(flags.is_empty());
}

#[test]
fn contract_and_catalog_surfaces_do_not_trigger_orphaned_export_flags() {
    let contract_path = "ui/background/core/session-runtime-contracts.ts";
    let contract_source = "export type LoggerMethod = (...args: unknown[]) => void;\n\
export type SessionPolicy = 'aggressive_clean' | 'preserve_login';\n\
export interface PlatformConfig {\n\
  signupUrl?: string;\n\
  checkUrl?: string;\n\
}\n";
    let contract_file = FileRecord {
        file_path: contract_path.to_string(),
        source: contract_source.to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    };

    let catalog_path = "ui/src/data/platforms.ts";
    let catalog_source = "export type Platform = { id: string };\n\
const RAW_PLATFORMS: Record<string, Platform> = Object.fromEntries([]);\n\
export const PLATFORMS = RAW_PLATFORMS;\n\
export function getPlatformClaimMode(platformId: string) { return 'assisted'; }\n\
export function isPlatformCacheEligible(platformId: string) { return false; }\n\
export function getPlatformSetupObjective(platformId: string) { return 'create_account'; }\n\
export function getPlatformSetupLabel(platformId: string) { return 'Create Account'; }\n\
export function getPlatformSetupTasks(platformId: string) { return []; }\n\
export function isStrictFillPlatform(platformId: string) { return false; }\n\
export function getPlatformDisplayName(platformId: string) { return platformId; }\n";
    let catalog_methods = vec![
        method("getPlatformClaimMode", catalog_path, "", 1, true, 0),
        method("isPlatformCacheEligible", catalog_path, "", 1, true, 0),
        method("getPlatformSetupObjective", catalog_path, "", 1, true, 0),
        method("getPlatformSetupLabel", catalog_path, "", 1, true, 0),
        method("getPlatformSetupTasks", catalog_path, "", 1, true, 0),
        method("isStrictFillPlatform", catalog_path, "", 1, true, 0),
        method("getPlatformDisplayName", catalog_path, "", 1, true, 0),
    ];
    let mut catalog_file = file(catalog_path, catalog_methods);
    catalog_file.source = catalog_source.to_string();

    let flags = build_ref_count_flags(&[contract_file, catalog_file]);
    assert!(flags.is_empty());
}

#[test]
fn analysis_finding_support_modules_do_not_trigger_orphaned_export_flags() {
    let path = "src/bumpkin/analysis/finding_python_surface_base.py";
    let methods = vec![
        method(
            "collect_python_signature_source",
            path,
            "def collect_python_signature_source(lines: list[str], start_index: int) -> tuple[str, int]:\n    return \"\", 0\n",
            26,
            true,
            0,
        ),
        method(
            "split_top_level_params",
            path,
            "def split_top_level_params(params: str) -> list[str]:\n    return []\n",
            31,
            true,
            0,
        ),
    ];

    let file_record = file(path, methods);
    let flags = build_ref_count_flags(&[file_record]);
    assert!(flags.is_empty());
}
