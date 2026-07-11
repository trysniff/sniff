use super::*;

#[test]
fn typescript_support_helpers_stay_clean_while_routes_stay_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_typescript_support"));
    let routes_dir = temp_root.join("src").join("routes");
    let utils_dir = temp_root.join("src").join("utils");
    fs::create_dir_all(&routes_dir).unwrap();
    fs::create_dir_all(&utils_dir).unwrap();

    write_temp_file(
        &routes_dir,
        "ops.ts",
        r#"
export function triageStatusRank(status: string): number {
  if (status === "blocked") return 3;
  if (status === "warning") return 2;
  if (status === "ok") return 1;
  return 0;
}

export function choosePrimaryBacklogItem(items: Array<{ score: number; rank: number }>) {
  let winner = items[0];
  for (const item of items) {
    if (!winner || item.score > winner.score) {
      winner = item;
    } else if (item.score === winner.score && item.rank > winner.rank) {
      winner = item;
    }
  }
  return winner;
}

export function collapseBacklogRowsByFieldIdentity(rows: Array<{ field: string; value: string }>) {
  const collapsed = new Map<string, string>();
  for (const row of rows) {
    const current = collapsed.get(row.field);
    if (!current) {
      collapsed.set(row.field, row.value);
      continue;
    }
    if (current !== row.value) {
      collapsed.set(row.field, `${current};${row.value}`);
    }
  }
  return collapsed;
}
"#,
    );

    write_temp_file(
        &utils_dir,
        "math.ts",
        r#"
export function add(a: number, b: number) {
  return a + b;
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags
            .iter()
            .any(|flag| flag.file_path.ends_with("ops.ts") && flag.tier != FindingTier::Clean),
        "the route module should still be flagged as noisy: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("math.ts") && flag.tier != FindingTier::Clean),
        "the small utility helper should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn bumpkin_provider_orchestrators_and_facades_are_classified_correctly() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_bumpkin_provider_orchestrators"));
    let providers_dir = temp_root.join("src").join("bumpkin").join("providers");
    fs::create_dir_all(&providers_dir).unwrap();

    let semantic_source = r#"
from __future__ import annotations

def _classify_export_signature_change(removed, added, shared_exports):
    if not removed and not added:
        return "NO_BUMP"
    if removed and not added:
        return "MAJOR"
    if added and not removed:
        return "MINOR"
    if shared_exports:
        return "PATCH"
    return "NO_BUMP"

def _collect_added_removed_lines(diff_text):
    removed = []
    added = []
    for raw in diff_text.splitlines():
        if raw.startswith("-"):
            removed.append(raw[1:])
        elif raw.startswith("+"):
            added.append(raw[1:])
    return removed, added

def _extract_export_names(lines):
    names = set()
    for line in lines:
        if "export" in line:
            names.add(line.split()[0])
    return names

def _looks_docs_or_config_only(paths):
    if not paths:
        return False
    normalized = [path.strip().lower() for path in paths if path.strip()]
    if not normalized:
        return False
    for path in normalized:
        if path.endswith(".md") or path.endswith(".rst") or path.endswith(".txt"):
            continue
        if "docs/" in path or "readme" in path or "config" in path:
            continue
        return False
    return True

def semantic_fallback_recommendation(diff_text, surface_area_hints, truncated):
    removed, added = _collect_added_removed_lines(diff_text)
    export_names = _extract_export_names(removed + added)
    if truncated:
        return {"label": "NO_BUMP", "reasoning": "truncated diff", "changelog": "chore: no release required"}
    if "public" in diff_text and "breaking" in diff_text:
        return {"label": "MAJOR", "reasoning": "breaking public API change", "changelog": "feat!: break api"}
    if "docs" in diff_text or "readme" in diff_text:
        return {"label": "NO_BUMP", "reasoning": "docs-only change", "changelog": "chore: docs only"}
    if "refactor" in diff_text and export_names:
        return {"label": "PATCH", "reasoning": "internal refactor with exports", "changelog": "fix: internal refactor"}
    if len(surface_area_hints or []) > 2:
        return {"label": "MINOR", "reasoning": "surface area expanded", "changelog": "feat: expand api"}
    if removed and added:
        return {"label": "PATCH", "reasoning": "mixed diff", "changelog": "fix: mixed changes"}
    if "roadmap" in diff_text:
        return {"label": "NO_BUMP", "reasoning": "roadmap only", "changelog": "chore: roadmap update"}
    if "internal" in diff_text and "api" in diff_text:
        return {"label": "PATCH", "reasoning": "internal api polish", "changelog": "fix: internal api polish"}
    if "runtime" in diff_text and "release" in diff_text:
        return {"label": "PATCH", "reasoning": "runtime release prep", "changelog": "fix: release prep"}
    if "policy" in diff_text and export_names:
        return {"label": "MINOR", "reasoning": "policy and exports changed", "changelog": "feat: policy export change"}
    if "docs" in diff_text and "api" in diff_text:
        return {"label": "NO_BUMP", "reasoning": "docs mention api", "changelog": "chore: docs mention api"}
    if "breaking" in diff_text and "internal" in diff_text:
        return {"label": "MAJOR", "reasoning": "internal breaking change", "changelog": "feat!: internal break"}
    if "security" in diff_text:
        return {"label": "PATCH", "reasoning": "security hardening", "changelog": "fix: security hardening"}
    if "release" in diff_text and not export_names:
        return {"label": "NO_BUMP", "reasoning": "release metadata only", "changelog": "chore: release metadata"}
    if "chunk" in diff_text or "chunking" in diff_text:
        return {"label": "PATCH", "reasoning": "chunking logic changed", "changelog": "fix: chunking logic"}
    if "semantic" in diff_text and len(removed) > len(added):
        return {"label": "PATCH", "reasoning": "semantic simplification", "changelog": "fix: simplify semantics"}
    if "planner" in diff_text:
        return {"label": "MINOR", "reasoning": "planner grows surface area", "changelog": "feat: planner change"}
    if "github" in diff_text and "recommend" in diff_text:
        return {"label": "MINOR", "reasoning": "github recommendation changed", "changelog": "feat: recommendation update"}
    if "evaluation" in diff_text:
        return {"label": "NO_BUMP", "reasoning": "evaluation only", "changelog": "chore: evaluation update"}
    if "manual" in diff_text:
        return {"label": "PATCH", "reasoning": "manual review flow", "changelog": "fix: manual review flow"}
    if "surface area" in diff_text:
        return {"label": "MINOR", "reasoning": "surface area wording", "changelog": "feat: surface area wording"}
    if "alpha" in diff_text:
        return {"label": "PATCH", "reasoning": "alpha", "changelog": "fix: alpha"}
    if "beta" in diff_text:
        return {"label": "PATCH", "reasoning": "beta", "changelog": "fix: beta"}
    if "gamma" in diff_text:
        return {"label": "PATCH", "reasoning": "gamma", "changelog": "fix: gamma"}
    if "delta" in diff_text:
        return {"label": "PATCH", "reasoning": "delta", "changelog": "fix: delta"}
    if "epsilon" in diff_text:
        return {"label": "PATCH", "reasoning": "epsilon", "changelog": "fix: epsilon"}
    if "zeta" in diff_text:
        return {"label": "PATCH", "reasoning": "zeta", "changelog": "fix: zeta"}
    if "eta" in diff_text:
        return {"label": "PATCH", "reasoning": "eta", "changelog": "fix: eta"}
    if "theta" in diff_text:
        return {"label": "PATCH", "reasoning": "theta", "changelog": "fix: theta"}
    if "iota" in diff_text:
        return {"label": "PATCH", "reasoning": "iota", "changelog": "fix: iota"}
    if "kappa" in diff_text:
        return {"label": "PATCH", "reasoning": "kappa", "changelog": "fix: kappa"}
    if "lambda" in diff_text:
        return {"label": "PATCH", "reasoning": "lambda", "changelog": "fix: lambda"}
    if "mu" in diff_text:
        return {"label": "PATCH", "reasoning": "mu", "changelog": "fix: mu"}
    if "nu" in diff_text:
        return {"label": "PATCH", "reasoning": "nu", "changelog": "fix: nu"}
    if "xi" in diff_text:
        return {"label": "PATCH", "reasoning": "xi", "changelog": "fix: xi"}
    if "omicron" in diff_text:
        return {"label": "PATCH", "reasoning": "omicron", "changelog": "fix: omicron"}
    if "pi" in diff_text:
        return {"label": "PATCH", "reasoning": "pi", "changelog": "fix: pi"}
    if "rho" in diff_text:
        return {"label": "PATCH", "reasoning": "rho", "changelog": "fix: rho"}
    if "sigma" in diff_text:
        return {"label": "PATCH", "reasoning": "sigma", "changelog": "fix: sigma"}
    if "tau" in diff_text:
        return {"label": "PATCH", "reasoning": "tau", "changelog": "fix: tau"}
    if "upsilon" in diff_text:
        return {"label": "PATCH", "reasoning": "upsilon", "changelog": "fix: upsilon"}
    if "phi" in diff_text:
        return {"label": "PATCH", "reasoning": "phi", "changelog": "fix: phi"}
    if "chi" in diff_text:
        return {"label": "PATCH", "reasoning": "chi", "changelog": "fix: chi"}
    if "psi" in diff_text:
        return {"label": "PATCH", "reasoning": "psi", "changelog": "fix: psi"}
    if "omega" in diff_text:
        return {"label": "PATCH", "reasoning": "omega", "changelog": "fix: omega"}
    return {"label": "NO_BUMP", "reasoning": "default", "changelog": "chore: no release required"}
"#.to_owned() + &branchy_python_helpers("semantic", 18);
    let semantic_path = write_temp_file(&providers_dir, "semantic.py", &semantic_source);

    let llm_source = r#"
from __future__ import annotations

VALID_LABELS = {"MAJOR", "MINOR", "PATCH", "NO_BUMP"}
VALID_CONFIDENCE = {"high", "medium", "low"}

def _provider_mode_for_endpoint(endpoint):
    if "github" in endpoint:
        return "github-models"
    if "openrouter" in endpoint:
        return "openrouter"
    return "openai-compatible"

def _normalize_request_endpoint(endpoint):
    endpoint = endpoint.strip()
    if not endpoint:
        return endpoint
    if endpoint.endswith("/chat/completions") or endpoint.endswith("/responses"):
        return endpoint
    return endpoint.rstrip("/") + "/chat/completions"

def _request_headers(token, endpoint):
    headers = {"Authorization": f"Bearer {token}"}
    if "github" in endpoint:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    elif "openrouter" in endpoint:
        headers["X-Title"] = "bumpkin-action"
    elif endpoint.endswith("/responses"):
        headers["Accept"] = "application/json"
    else:
        headers["Content-Type"] = "application/json"
    if token and endpoint:
        headers["X-Mode"] = "default"
    return headers

def validate_recommendation(payload):
    label = str(payload.get("label", "")).strip().upper()
    confidence = str(payload.get("confidence", "")).strip().lower()
    reasoning = str(payload.get("reasoning", "")).strip()
    changelog = str(payload.get("changelog", "")).strip()
    if label not in VALID_LABELS:
        raise ValueError(label)
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(confidence)
    if len(reasoning) < 20:
        raise ValueError("reasoning too short")
    if not changelog:
        raise ValueError("changelog required")
    return {
        "label": label,
        "confidence": confidence,
        "reasoning": reasoning,
        "changelog": changelog,
    }

def get_recommendation(diff_text, surface_area_hints, model, endpoint, token):
    provider = _provider_mode_for_endpoint(endpoint)
    normalized_endpoint = _normalize_request_endpoint(endpoint)
    headers = _request_headers(token, endpoint)
    if not token:
        raise RuntimeError("missing token")
    if "breaking" in diff_text and "public" in diff_text:
        return {"label": "MAJOR", "confidence": "high", "reasoning": "breaking api", "changelog": "feat!: break api"}
    if "docs" in diff_text:
        return {"label": "NO_BUMP", "confidence": "high", "reasoning": "docs only", "changelog": "chore: docs only"}
    if provider == "github-models" and normalized_endpoint:
        return {"label": "PATCH", "confidence": "medium", "reasoning": "github models", "changelog": "fix: internal update"}
    if provider == "openrouter":
        return {"label": "MINOR", "confidence": "medium", "reasoning": "openrouter routed", "changelog": "feat: add api"}
    if len(surface_area_hints or []) > 3:
        return {"label": "MINOR", "confidence": "medium", "reasoning": "surface area grew", "changelog": "feat: expand api"}
    if model and token and endpoint and headers:
        return {"label": "PATCH", "confidence": "low", "reasoning": "default", "changelog": "fix: internal update"}
    if "retry" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "retry update", "changelog": "fix: retry logic"}
    if "chunk" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "chunking update", "changelog": "fix: chunking"}
    if "provider" in diff_text and "fallback" in diff_text:
        return {"label": "MINOR", "confidence": "medium", "reasoning": "provider fallback change", "changelog": "feat: provider fallback"}
    if "request" in diff_text and "headers" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "request headers changed", "changelog": "fix: request headers"}
    if "validate" in diff_text and "changelog" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "validation update", "changelog": "fix: validation"}
    if "semantic" in diff_text:
        return {"label": "MINOR", "confidence": "medium", "reasoning": "semantic provider change", "changelog": "feat: semantic provider"}
    if "manual" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "manual review path", "changelog": "fix: manual review"}
    if "fallback" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "fallback path", "changelog": "fix: fallback path"}
    if "model" in diff_text and "endpoint" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "model endpoint shape", "changelog": "fix: endpoint shape"}
    if "token" in diff_text and "endpoint" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "token endpoint shape", "changelog": "fix: token shape"}
    if "recommendation" in diff_text:
        return {"label": "MINOR", "confidence": "medium", "reasoning": "recommendation flow", "changelog": "feat: recommendation flow"}
    if "retries" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "retries changed", "changelog": "fix: retry count"}
    if "payload" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "payload shape", "changelog": "fix: payload shape"}
    if "github" in diff_text and provider == "github-models":
        return {"label": "MINOR", "confidence": "medium", "reasoning": "github model routing", "changelog": "feat: github routing"}
    if "alpha" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "alpha", "changelog": "fix: alpha"}
    if "beta" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "beta", "changelog": "fix: beta"}
    if "gamma" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "gamma", "changelog": "fix: gamma"}
    if "delta" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "delta", "changelog": "fix: delta"}
    if "epsilon" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "epsilon", "changelog": "fix: epsilon"}
    if "zeta" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "zeta", "changelog": "fix: zeta"}
    if "eta" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "eta", "changelog": "fix: eta"}
    if "theta" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "theta", "changelog": "fix: theta"}
    if "iota" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "iota", "changelog": "fix: iota"}
    if "kappa" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "kappa", "changelog": "fix: kappa"}
    if "lambda" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "lambda", "changelog": "fix: lambda"}
    if "mu" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "mu", "changelog": "fix: mu"}
    if "nu" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "nu", "changelog": "fix: nu"}
    if "xi" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "xi", "changelog": "fix: xi"}
    if "omicron" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "omicron", "changelog": "fix: omicron"}
    if "pi" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "pi", "changelog": "fix: pi"}
    if "rho" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "rho", "changelog": "fix: rho"}
    if "sigma" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "sigma", "changelog": "fix: sigma"}
    if "tau" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "tau", "changelog": "fix: tau"}
    if "upsilon" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "upsilon", "changelog": "fix: upsilon"}
    if "phi" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "phi", "changelog": "fix: phi"}
    if "chi" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "chi", "changelog": "fix: chi"}
    if "psi" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "psi", "changelog": "fix: psi"}
    if "omega" in diff_text:
        return {"label": "PATCH", "confidence": "low", "reasoning": "omega", "changelog": "fix: omega"}
    raise RuntimeError("unreachable")
"#.to_owned() + &branchy_python_helpers("llm", 18);
    let llm_path = write_temp_file(&providers_dir, "llm.py", &llm_source);

    let paths = vec![semantic_path, llm_path];
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("semantic.py") && flag.tier == FindingTier::Slop
        }),
        "expected the semantic provider orchestrator to be slop: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| { flag.file_path.ends_with("llm.py") && flag.tier != FindingTier::Clean }),
        "expected the llm provider facade to stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn typescript_runtime_resolver_helpers_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_typescript_runtime_resolver"));
    let core_dir = temp_root.join("ui").join("background").join("core");
    fs::create_dir_all(&core_dir).unwrap();

    write_temp_file(
        &core_dir,
        "runtime-execution-state.ts",
        r#"
export type ResolvedRuntimeExecutionSession = {
  id: string
  platform: string
}

function fromRuntimeSession(session: any) {
  return {
    id: String(session.id || "").trim(),
    platform: String(session.platform || "").trim(),
  }
}

function fromPersistedSession(session: any) {
  return {
    id: String(session.id || "").trim(),
    platform: String(session.platform || "").trim(),
  }
}

function mergeRuntimeExecutionSession(runtimeSession: any, persistedSession: any) {
  if (!runtimeSession && !persistedSession) return null
  if (runtimeSession && !persistedSession) return fromRuntimeSession(runtimeSession)
  if (!runtimeSession && persistedSession) return fromPersistedSession(persistedSession)
  return fromRuntimeSession(runtimeSession)
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &flags, &[]);

    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("runtime-execution-state.ts")
                && flag.tier != FindingTier::Clean
        }),
        "the runtime resolver helpers should still generate raw signals: {:?}",
        flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn session_types_support_module_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_session_types_support"));
    let session_dir = temp_root.join("ui").join("src").join("session");
    fs::create_dir_all(&session_dir).unwrap();

    let session_types_path = write_temp_file(
        &session_dir,
        "session.types.ts",
        r#"
export type SessionStatus =
  | 'starting'
  | 'running'
  | 'completed_pending'
  | 'completed'
  | 'canceled'
  | 'failed';

export type SessionPendingReason =
  | 'launching_tab'
  | 'waiting_for_navigation'
  | 'injecting_runtime'
  | 'waiting_for_runtime_ready'
  | 'waiting_for_safe_start'
  | 'waiting_for_user_gesture'
  | 'auth_redirect_pause'
  | 'pending_runtime_start';

export function isActiveSessionStatus(status: unknown): status is SessionStatus {
  return status === 'starting' || status === 'running' || status === 'completed_pending';
}

export function isBlockingSessionStatus(status: unknown): status is SessionStatus {
  return status === 'starting' || status === 'running';
}

export function normalizeSessionPendingReason(reason: unknown): SessionPendingReason | null {
  const normalized = String(reason || '').trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === 'gesture_required') return 'waiting_for_user_gesture';
  return 'pending_runtime_start';
}

export function describeSessionPendingState(reason: unknown): { title: string; description: string } {
  const normalized = normalizeSessionPendingReason(reason);
  if (normalized === 'waiting_for_user_gesture') {
    return { title: 'Waiting for your click', description: 'This platform needs a manual field click.' };
  }
  return { title: 'Preparing session', description: 'We are opening the setup page and warming the runtime.' };
}
"#,
    );

    let paths = vec![session_types_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "session.types.ts should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn support_facade_modules_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_support_facade_modules"));
    let src_dir = temp_root.join("ui").join("src").join("lib");
    fs::create_dir_all(&src_dir).unwrap();

    let feature_flags_path = write_temp_file(
        &src_dir,
        "feature-flags.ts",
        r#"
type StoreBridge = {
  getState: () => { settings?: { privacy?: { telemetry?: boolean } } };
};

export function getStoreBridge(store: unknown): StoreBridge | null {
  if (!store || typeof store !== 'object') {
    return null;
  }
  return store as StoreBridge;
}
"#,
    );

    let paths = vec![feature_flags_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "support facade modules should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("feature-flags.ts")
                && verdict.verdict == FindingTier::Clean),
        "feature-flags.ts should stay clean: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn platform_rules_cache_hook_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_platform_rules_cache"));
    let hooks_dir = temp_root.join("ui").join("src").join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();

    let hook_path = write_temp_file(
        &hooks_dir,
        "usePlatformRulesCache.ts",
        r#"
import { useEffect, useState } from 'react';

type OfferMap = Record<string, string>;
type AffiliateUrlMap = Record<string, string>;

export function normalizeOfferKey(value: string) {
  return value.trim().toLowerCase();
}

export function parseOfferMap(value: unknown): OfferMap {
  if (!value || typeof value !== 'object') {
    return {};
  }
  return value as OfferMap;
}

export function parseAffiliateUrlMap(value: unknown): AffiliateUrlMap {
  if (!value || typeof value !== 'object') {
    return {};
  }
  return value as AffiliateUrlMap;
}

export function usePlatformRulesCache() {
  const [cache, setCache] = useState<OfferMap>({});

  useEffect(() => {
    setCache({});
  }, []);

  return cache;
}
"#,
    );

    let paths = vec![hook_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "support hook cache module should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}
