use super::*;

#[test]
fn catch_all_helpers_files_are_flagged_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_helpers_slop"));
    fs::create_dir_all(&temp_root).unwrap();

    let helpers_path = temp_root.join("helpers.ts");
    fs::write(
        &helpers_path,
        r#"
export function stableStringify(value: any): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const entries = keys.map(
      (key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`,
    );
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

export const REGISTRY_CHECKSUM_CANONICALIZATION = "stable_json_v1";

export function buildRegistryChecksumPayload(payload: {
  schemaVersion: unknown;
  minClientVersion: unknown;
  version: unknown;
  updatedAt: unknown;
  rules: unknown;
}) {
  return {
    schemaVersion: payload.schemaVersion,
    minClientVersion: payload.minClientVersion,
    version: payload.version,
    updatedAt: payload.updatedAt,
    rules: payload.rules,
  };
}

export async function sha256Base64(payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const hash = await crypto.subtle.digest("SHA-256", data);
  let binary = "";
  const bytes = new Uint8Array(hash);
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function jsonResponse(
  body: unknown,
  init: ResponseInit = {},
  origin?: string,
) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  }
  return new Response(JSON.stringify(body), { ...init, headers });
}

function splitHeaderTokens(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return String(raw)
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean);
}

function mergeHeaderTokens(...lists: Array<string[] | undefined>): string[] {
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const list of lists) {
    if (!list) continue;
    for (const token of list) {
      const canonical = token.trim();
      const key = canonical.toLowerCase();
      if (!canonical || seen.has(key)) continue;
      seen.add(key);
      merged.push(canonical);
    }
  }
  return merged;
}

const DEFAULT_CORS_ALLOW_HEADERS = [
  "Content-Type",
  "Authorization",
  "X-Operator-Id",
  "X-Idempotency-Key",
  "X-Sentry-Auth",
  "X-Sentry-Envelope",
  "X-Nameset-Tunnel-Token",
];

export function buildCorsPreflightResponse(args: {
  origin: string;
  methods: string[];
  requestHeaders?: string | null;
  allowHeaders?: string[];
  exposeHeaders?: string[];
  maxAgeSeconds?: number;
}): Response {
  const headers = new Headers();
  headers.set("Access-Control-Allow-Origin", args.origin || "null");
  headers.set("Vary", "Origin");

  const allowMethods = mergeHeaderTokens(args.methods, ["OPTIONS"]);
  headers.set("Access-Control-Allow-Methods", allowMethods.join(", "));

  const allowHeaders = mergeHeaderTokens(
    DEFAULT_CORS_ALLOW_HEADERS,
    args.allowHeaders,
    splitHeaderTokens(args.requestHeaders),
  );
  headers.set("Access-Control-Allow-Headers", allowHeaders.join(", "));

  if (Array.isArray(args.exposeHeaders) && args.exposeHeaders.length > 0) {
    headers.set(
      "Access-Control-Expose-Headers",
      mergeHeaderTokens(args.exposeHeaders).join(", "),
    );
  }
  if (Number.isFinite(args.maxAgeSeconds) && (args.maxAgeSeconds || 0) > 0) {
    headers.set("Access-Control-Max-Age", String(Math.floor(args.maxAgeSeconds || 0)));
  }

  return new Response(null, { status: 200, headers });
}

export function parseBooleanFlag(
  raw: string | undefined,
  fallback: boolean,
): boolean {
  if (typeof raw !== "string") return fallback;
  const normalized = raw.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return fallback;
}
"#,
    )
    .unwrap();

    let helpers_path_str = helpers_path.to_string_lossy().to_string();
    let file_records = parse_records(std::slice::from_ref(&helpers_path_str));
    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        scorer_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("helpers.ts")
                && flag.tier == FindingTier::KindaSlop),
        "expected catch-all helpers file to be scored as at least kinda slop: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().any(|flag| {
            flag.file_path.ends_with("helpers.ts")
                && flag.reasons.iter().any(|reason| {
                    reason.contains("file does too much") || reason.contains("filename is vague")
                })
        }),
        "expected slop reasons to mention the catch-all shape: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn fixture_paths_are_treated_as_intentional_surfaces() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_fixture_roles"));
    let fixtures_dir = temp_root.join("fixtures");
    fs::create_dir_all(&fixtures_dir).unwrap();

    let fixture_path = fixtures_dir.join("helpers.py");
    fs::write(&fixture_path, "def process_data():\n    return 1\n").unwrap();

    let fixture_path_str = fixture_path.to_string_lossy().to_string();
    let mut file_records = vec![parse_file(&fixture_path_str)];
    let mut graph = SymbolGraph::new(&temp_root.to_string_lossy());
    graph.add_file(parse_file_symbols(&fixture_path_str));
    graph.resolve_all();
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    assert!(
        ref_flags.is_empty(),
        "fixture surfaces should not be orphaned-export noise: {:?}",
        ref_flags
    );
    assert!(
        scorer_flags.is_empty(),
        "fixture surfaces should not be scored as slop: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn placeholder_shell_modules_are_scored_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_placeholder_shell"));
    fs::create_dir_all(temp_root.join("src")).unwrap();

    let shell_path = write_temp_file(
        &temp_root.join("src"),
        "report_builder.rs",
        r#"
pub fn build_report() {
    // TODO: implement
    let _findings = [];
}
"#,
    );

    let file_records = parse_records(std::slice::from_ref(&shell_path));
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("report_builder.rs")
                && flag.tier == FindingTier::Slop
                && flag
                    .reasons
                    .iter()
                    .any(|reason| reason == "placeholder implementation")
        }),
        "expected placeholder shell modules to be scored as slop: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn small_policy_mapping_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_policy_mapping"));
    let policy_dir = temp_root.join("src").join("bumpkin").join("orchestrator");
    fs::create_dir_all(&policy_dir).unwrap();

    let file_path = write_temp_file(
        &policy_dir,
        "adjudication.py",
        r#"
from __future__ import annotations

from bumpkin.analysis.findings import SEVERITY_ORDER, AggregatedFindingResult

DEFAULT_CHANGELOG_BY_LABEL = {
    "MAJOR": "feat: introduce breaking api changes",
    "MINOR": "feat: add backward-compatible api changes",
    "PATCH": "fix: update internal implementation",
    "NO_BUMP": "chore: no release required",
}

_FAILURE_REASON_PATTERNS: tuple[tuple[str, str], ...] = (
    ("no token available", "missing_token"),
    ("429", "rate_limited"),
    ("too many requests", "rate_limited"),
    ("tokens_limit_reached", "payload_too_large"),
    ("request body too large", "payload_too_large"),
    ("401", "invalid_token"),
    ("403", "invalid_token"),
    ("bad credentials", "invalid_token"),
    ("certificate_verify_failed", "ssl_failure"),
    ("ssl:", "ssl_failure"),
    ("nodename nor servname provided", "dns_failure"),
    ("name or service not known", "dns_failure"),
    ("http 5", "endpoint_failure"),
    ("timed out", "endpoint_failure"),
    ("connection refused", "endpoint_failure"),
    ("schema", "response_schema_error"),
    ("non-json output", "response_schema_error"),
)

_MODE_SOURCE_MAP = {
    "github-models": "model",
    "openrouter": "model",
    "openai-compatible": "model",
    "fallback-heuristic": "semantic-fallback",
    "deterministic-findings": "deterministic-findings",
    "deterministic-heuristic": "deterministic-findings",
    "deterministic-engine": "deterministic-findings",
    "deterministic-no-diff": "deterministic-no-diff",
    "no-bump": "no-diff-heuristic",
    "stub": "stub",
}

_AUTHORITATIVE_SOURCES = {
    "deterministic-findings",
    "deterministic-heuristic",
    "deterministic-no-diff",
    "court",
    "model",
    "hybrid",
}


def categorize_failure_reason(reason: str | None) -> str | None:
    if not reason:
        return None
    normalized = reason.strip().lower()
    return next(
        (category for needle, category in _FAILURE_REASON_PATTERNS if needle in normalized),
        "unknown_failure",
    )


def source_from_mode(mode_used: str) -> str:
    return _MODE_SOURCE_MAP.get(mode_used, "unknown")


def derive_analysis_state(*, status: str, classification_source: str) -> tuple[str, str]:
    if status == "manual_review":
        return "manual_review", classification_source
    if classification_source in _AUTHORITATIVE_SOURCES:
        return "authoritative", classification_source
    return "degraded_fallback", classification_source


def apply_findings_adjudication(
    model_result: dict[str, object],
    *,
    aggregated_findings: AggregatedFindingResult | None,
    mode_used: str,
    notes: list[str],
) -> tuple[dict[str, object], str | None, str]:
    if aggregated_findings is None:
        notes.append("No deterministic JS/TS exported API findings were produced.")
        return model_result, None, source_from_mode(mode_used)

    notes.append(
        f"Deterministic findings engine produced {aggregated_findings.contributing_findings} finding(s)."
    )
    notes.append(f"Aggregation trace: {aggregated_findings.aggregation_trace}")
    deterministic_result = aggregated_findings.to_result_dict()
    deterministic_status = str(deterministic_result.get("status", "manual_review"))
    deterministic_label = (
        str(deterministic_result.get("label", "")).upper()
        if deterministic_status == "classified"
        else ""
    )
    model_status = str(model_result.get("status", "manual_review"))
    model_label = str(model_result.get("label", "")).upper() if model_status == "classified" else ""

    if deterministic_status != "classified":
        return deterministic_result, aggregated_findings.aggregation_trace, "deterministic-findings"

    if deterministic_label == "MAJOR":
        return deterministic_result, aggregated_findings.aggregation_trace, "deterministic-findings"

    if source_from_mode(mode_used) != "model":
        return deterministic_result, aggregated_findings.aggregation_trace, "deterministic-findings"

    if model_status != "classified" or model_label not in SEVERITY_ORDER:
        return deterministic_result, aggregated_findings.aggregation_trace, "deterministic-findings"

    floor_level = SEVERITY_ORDER.get(deterministic_label)
    model_level = SEVERITY_ORDER.get(model_label)
    if floor_level is None or model_level is None:
        return model_result, aggregated_findings.aggregation_trace, "model"

    if model_level >= floor_level:
        return model_result, aggregated_findings.aggregation_trace, "hybrid"

    promoted = dict(model_result)
    promoted["status"] = "classified"
    promoted["label"] = deterministic_label
    promoted["confidence"] = deterministic_result.get("confidence") or model_result.get("confidence")
    promoted["changelog"] = DEFAULT_CHANGELOG_BY_LABEL.get(
        deterministic_label, model_result.get("changelog")
    )
    promoted["reasoning"] = "hybrid adjudication"
    return promoted, aggregated_findings.aggregation_trace, "hybrid"
"#,
    );

    let file = parse_file(&file_path);
    let file_records = vec![file];
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn config_validation_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_config_validation"));
    let config_dir = temp_root.join("src").join("bumpkin");
    fs::create_dir_all(&config_dir).unwrap();

    let file_path = write_temp_file(
        &config_dir,
        "config.py",
        r#"
from dataclasses import dataclass
from pathlib import Path

@dataclass
class BumpkinConfig:
    policy_mode: str
    docs_only_label: str


def _ensure_bool(value, field_name):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    raise ValueError(field_name)


def _ensure_policy_mode(value):
    if value is None:
        return "pragmatic"
    return value.strip().lower()


def _ensure_positive_int(value, field_name, *, default):
    if value is None:
        return default
    return max(1, int(value))


def load_bumpkin_config(path: Path | None = None) -> BumpkinConfig:
    if path is None:
        path = Path("bumpkin.yml")
    return BumpkinConfig(policy_mode="pragmatic", docs_only_label="NO_BUMP")
"#,
    );

    let file = parse_file(&file_path);
    let file_records = vec![file];
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn planner_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_planner"));
    let planner_dir = temp_root.join("src").join("bumpkin");
    fs::create_dir_all(&planner_dir).unwrap();

    let file_path = write_temp_file(
        &planner_dir,
        "planner.py",
        r#"
from __future__ import annotations

from dataclasses import dataclass
import os

DECISION_VERSION = "decision_contract_v3"


@dataclass(frozen=True)
class ProviderProfile:
    provider: str
    max_prompt_tokens: int
    max_output_tokens: int
    request_timeout_s: int

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "max_prompt_tokens": self.max_prompt_tokens,
            "max_output_tokens": self.max_output_tokens,
            "request_timeout_s": self.request_timeout_s,
        }


@dataclass(frozen=True)
class PlannerDecision:
    version: str
    route: str
    reason: str
    allow_model_call: bool
    provider_profile: ProviderProfile
    used_token_budget: int
    chunk_capacity: int

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "route": self.route,
            "reason": self.reason,
            "allow_model_call": self.allow_model_call,
            "provider_profile": self.provider_profile.to_dict(),
            "used_token_budget": self.used_token_budget,
            "chunk_capacity": self.chunk_capacity,
        }


def _parse_int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(1, value)


def _provider_name(mode: str, endpoint: str) -> str:
    normalized_mode = mode.strip().lower()
    if normalized_mode == "openrouter":
        return "openrouter"
    if normalized_mode == "github-models":
        return "github-models"
    return "openai-compatible"


def resolve_provider_profile(*, mode: str, endpoint: str, request_timeout: int) -> ProviderProfile:
    return ProviderProfile(
        provider=_provider_name(mode, endpoint),
        max_prompt_tokens=_parse_int_env("BUMPKIN_OPENAI_COMPAT_MAX_PROMPT_TOKENS", 6000),
        max_output_tokens=_parse_int_env("BUMPKIN_MAX_OUTPUT_TOKENS", 400),
        request_timeout_s=max(1, request_timeout),
    )


def plan_analysis_route(
    *,
    mode: str,
    endpoint: str,
    has_model_token: bool,
    approx_prompt_tokens: int,
    request_timeout: int,
    chunking_enabled: bool,
    chunk_max_tokens: int,
    chunk_max_count: int,
) -> PlannerDecision:
    profile = resolve_provider_profile(
        mode=mode,
        endpoint=endpoint,
        request_timeout=request_timeout,
    )
    if not has_model_token:
        return PlannerDecision(
            version=DECISION_VERSION,
            route="manual_review",
            reason="missing_model_token",
            allow_model_call=False,
            provider_profile=profile,
            used_token_budget=approx_prompt_tokens,
            chunk_capacity=max(0, chunk_max_tokens) * max(0, chunk_max_count),
        )
    return PlannerDecision(
        version=DECISION_VERSION,
        route="full",
        reason="within_provider_budget",
        allow_model_call=True,
        provider_profile=profile,
        used_token_budget=approx_prompt_tokens,
        chunk_capacity=max(0, chunk_max_tokens) * max(0, chunk_max_count),
    )
"#,
    );

    let file = parse_file(&file_path);
    let file_records = vec![file];
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn scope_guard_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_scope_guard"));
    let scope_dir = temp_root.join("src").join("bumpkin").join("orchestrator");
    fs::create_dir_all(&scope_dir).unwrap();

    let file_path = write_temp_file(
        &scope_dir,
        "scope.py",
        r#"
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

OVERRIDE_LABELS = {
    "bump:major": "MAJOR",
    "bump:minor": "MINOR",
    "bump:patch": "PATCH",
}


@dataclass
class PREventContext:
    pr_number: int | None
    base_sha: str | None
    head_sha: str | None
    merge_sha: str | None
    labels: list[str]


def run_git(args: list[str]) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("git command failed")
    return proc.stdout.strip()


def resolve_merge_parent_sha(merge_sha: str) -> str | None:
    candidate = merge_sha.strip()
    if not candidate:
        return None
    try:
        return run_git(["rev-parse", f"{candidate}^1"])
    except RuntimeError:
        return None


def read_event_context(event_path: str | None) -> PREventContext:
    if not event_path:
        return PREventContext(None, None, None, None, [])
    p = Path(event_path)
    if not p.exists():
        return PREventContext(None, None, None, None, [])
    payload = json.loads(p.read_text())
    pr = payload.get("pull_request")
    if not pr:
        return PREventContext(None, None, None, None, [])
    return PREventContext(int(pr["number"]), None, None, None, [])


def select_diff_scope(
    from_ref_arg: str,
    to_ref_arg: str,
    event_context: PREventContext,
    *,
    merge_parent_resolver=resolve_merge_parent_sha,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if event_context.pr_number is not None and not from_ref_arg and not to_ref_arg:
        merge_parent_sha = merge_parent_resolver(event_context.merge_sha or "")
        if merge_parent_sha:
            notes.append("Using merged PR diff scope.")
    return from_ref_arg, to_ref_arg, notes
"#,
    );

    let file = parse_file(&file_path);
    let file_records = vec![file];
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn prompt_and_policy_support_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_prompt_policy_support"));
    let root = temp_root.join("src").join("bumpkin");
    let versioning_dir = root.join("versioning");
    let licensing_dir = root.join("licensing");
    fs::create_dir_all(&versioning_dir).unwrap();
    fs::create_dir_all(&licensing_dir).unwrap();

    let versioning_path = write_temp_file(
        &versioning_dir,
        "tags.py",
        r#"
from __future__ import annotations

import re

VERSION_RE = re.compile(r"^(?P<prefix>.*?)(?P<version>\d+(?:\.\d+){2,3})$")


def parse_tag(tag: str) -> tuple[str, str] | None:
    match = VERSION_RE.match(tag.strip())
    if not match:
        return None
    return match.group("prefix"), match.group("version")
"#,
    );

    let prompt_pack_path = write_temp_file(
        &root,
        "prompt_pack.py",
        r#"
from __future__ import annotations

from dataclasses import dataclass, field

PROMPT_VERSION = "js-ts-v1"
SYSTEM_PROMPT = "You classify git diffs into SemVer impact."


@dataclass(frozen=True)
class PromptPackMetadata:
    prompt_version: str
    language_group: str
    promotion_status: str
    fixture_set: str


@dataclass(frozen=True)
class PromptPack:
    metadata: PromptPackMetadata
    system_prompt: str
    language_rules: str
    few_shot_examples: tuple[str, ...] = field(default_factory=tuple)
"#,
    );

    let licensing_path = write_temp_file(
        &licensing_dir,
        "policy.py",
        r#"
from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_LICENSE_TIERS = ("oss", "commercial")


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    tier: str
    capabilities: frozenset[str]


def resolve_license_policy(tier: str | None = None) -> LicensePolicy:
    normalized = (tier or "oss").strip().lower()
    if normalized not in SUPPORTED_LICENSE_TIERS:
        raise ValueError("Unknown license tier")
    return LicensePolicy(tier=normalized, capabilities=frozenset())
"#,
    );

    let file_records = vec![
        parse_file(&versioning_path),
        parse_file(&prompt_pack_path),
        parse_file(&licensing_path),
    ];
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert!(file_verdicts.is_empty());

    fs::remove_dir_all(&temp_root).ok();
}
