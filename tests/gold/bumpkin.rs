use super::*;

#[test]
fn bumpkin_hotspots_and_entrypoints_stay_on_the_right_side_of_static_scoring() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_bumpkin_static_regression"));
    fs::create_dir_all(&temp_root).unwrap();

    let contracts_path = write_temp_file(
        &temp_root,
        "src/bumpkin/contracts.py",
        &format!(
            "from __future__ import annotations\n\n\
def validate_output_contract(payload):\n    errors = []\n{}\n    if payload.get(\"reasoning\") and len(str(payload[\"reasoning\"])) < 10:\n        errors.append(\"short reasoning\")\n    if payload.get(\"analysis_state\") not in {{\"authoritative\", \"manual_review\"}}:\n        errors.append(\"bad state\")\n    if payload.get(\"decision_authority\") not in {{\"deterministic\", \"court\"}}:\n        errors.append(\"bad authority\")\n    if payload.get(\"coverage_contract\") is None:\n        errors.append(\"missing coverage\")\n    if payload.get(\"case_file\") is None:\n        errors.append(\"missing case file\")\n    if payload.get(\"planner\") is None:\n        errors.append(\"missing planner\")\n    if payload.get(\"semantic_facts\") is None:\n        errors.append(\"missing semantic facts\")\n    return errors\n{}\n",
            (0..28)
                .map(|idx| format!(
                    "    if payload.get(\"flag_{idx}\"):\n        errors.append(\"flag_{idx}\")\n",
                    idx = idx
                ))
                .collect::<String>(),
            branchy_python_helpers("contract_hotspot", 20),
        ),
    );

    let pipeline_path = write_temp_file(
        &temp_root,
        "src/bumpkin/orchestrator/pipeline.py",
        &format!(
            "from bumpkin.contracts import validate_output_contract\n\n\
def run(args, *, comment_poster=None):\n    notes = []\n{}\n    if getattr(args, \"from_ref\", None):\n        notes.append(\"from\")\n    if getattr(args, \"to_ref\", None):\n        notes.append(\"to\")\n    if getattr(args, \"use_difftastic\", False):\n        notes.append(\"difftastic\")\n    if getattr(args, \"token_cap\", None):\n        notes.append(\"cap\")\n    if getattr(args, \"request_timeout\", None):\n        notes.append(\"timeout\")\n    if getattr(args, \"mode\", None) == \"pr\":\n        notes.append(\"pr\")\n    if getattr(args, \"mode\", None) == \"local\":\n        notes.append(\"local\")\n    output = {{\"status\": \"classified\", \"analysis_state\": \"authoritative\", \"reasoning\": \"x\" * 20, \"planner\": {{}}, \"coverage_contract\": {{}}}}\n    validate_output_contract(output)\n    return len(notes)\n{}\n",
            (0..36)
                .map(|idx| format!(
                    "    if getattr(args, \"flag_{idx}\", False):\n        notes.append(\"flag_{idx}\")\n",
                    idx = idx
                ))
                .collect::<String>(),
            branchy_python_helpers("pipeline_hotspot", 20),
        ),
    );

    let semantic_path = write_temp_file(
        &temp_root,
        "src/bumpkin/providers/semantic.py",
        &format!(
            "def _extract_export_names(lines):\n    names = set()\n{}\n    return names\n{}\n\n\
def semantic_fallback_recommendation(diff_text, *, surface_area_hints=None):\n    notes = []\n    for line in diff_text.splitlines():\n        if \"docs\" in line:\n            notes.append(line)\n        elif \"config\" in line:\n            notes.append(line)\n        elif \"public\" in line:\n            notes.append(line)\n        elif \"internal\" in line:\n            notes.append(line)\n        elif \"runtime\" in line:\n            notes.append(line)\n        elif \"api\" in line:\n            notes.append(line)\n        elif \"breaking\" in line:\n            notes.append(line)\n{}\n    for hint in surface_area_hints or []:\n        if hint and hint not in notes:\n            notes.append(hint)\n    return {{\"label\": \"NO_BUMP\", \"notes\": notes, \"surface_area_hints\": surface_area_hints or []}}\n",
            (0..16)
                .map(|idx| format!(
                    "    for line_{idx} in lines:\n        if \"export\" in line_{idx}:\n            names.add(line_{idx})\n        if \"class\" in line_{idx}:\n            names.add(line_{idx})\n",
                    idx = idx
                ))
                .collect::<String>(),
            branchy_python_helpers("semantic_hotspot", 19),
            (0..24)
                .map(|idx| format!(
                    "        elif \"needle_{idx}\" in line:\n            notes.append(line)\n",
                    idx = idx
                ))
                .collect::<String>(),
        ),
    );

    let checkout_path = write_temp_file(
        &temp_root,
        "ui/background/core/checkout-rpc.ts",
        &format!(
            "export function createCheckoutRpc(value: number) {{\n  let total = 0;\n{}\n  return total;\n}}\n{}\n",
            (0..36)
                .map(|idx| format!(
                    "  if (value > {idx}) {{\n    total += {idx};\n  }}\n",
                    idx = idx
                ))
                .collect::<String>(),
            branchy_typescript_helpers("checkoutRpc", 20),
        ),
    );

    let main_path = write_temp_file(
        &temp_root,
        "src/main.py",
        "from bumpkin.providers.semantic import semantic_fallback_recommendation\n\n\
def main():\n    return semantic_fallback_recommendation(\"\")\n",
    );

    let app_path = write_temp_file(
        &temp_root,
        "src/App.tsx",
        "export function App() {\n  return <main>Hello</main>;\n}\n",
    );

    let index_path = write_temp_file(
        &temp_root,
        "supabase/functions/create-polar-checkout-session/index.ts",
        "export default async function handler(req: Request) {\n  if (req.method !== \"POST\") {\n    return new Response(\"method not allowed\", { status: 405 });\n  }\n  return new Response(JSON.stringify({ ok: true }), {\n    headers: { \"Content-Type\": \"application/json\" },\n  });\n}\n",
    );

    let paths = vec![
        contracts_path,
        pipeline_path,
        semantic_path,
        checkout_path,
        main_path,
        app_path,
        index_path,
    ];
    let file_records = parse_records(&paths);
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert!(
        static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("contracts.py") && flag.tier == FindingTier::Slop),
        "contracts.py should still be detected as real slop: {:?}",
        static_flags
    );
    assert!(
        static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("pipeline.py") && flag.tier == FindingTier::Slop),
        "pipeline.py should still be detected as real slop: {:?}",
        static_flags
    );
    assert!(
        static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("semantic.py") && flag.tier == FindingTier::Slop),
        "semantic.py should still be detected as real slop: {:?}",
        static_flags
    );
    assert!(
        static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("checkout-rpc.ts")
                && flag.tier == FindingTier::Slop),
        "checkout-rpc.ts should still be detected as real slop: {:?}",
        static_flags
    );
    assert!(
        static_flags.iter().all(|flag| {
            !flag.file_path.ends_with("main.py")
                && !flag.file_path.ends_with("App.tsx")
                && !flag.file_path.ends_with("index.ts")
        }),
        "entrypoints should stay out of static scoring: {:?}",
        static_flags
    );

    assert!(
        file_verdicts
            .iter()
            .all(|verdict| verdict.verdict == FindingTier::Clean),
        "static-only signals must not become final findings: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn contract_type_and_catalog_modules_are_not_flagged_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_contract_catalog"));
    fs::create_dir_all(&temp_root).unwrap();

    let contract_path = temp_root.join("ui/background/core/session-runtime-contracts.ts");
    let catalog_path = temp_root.join("ui/src/data/platforms.ts");
    fs::create_dir_all(contract_path.parent().unwrap()).unwrap();
    fs::create_dir_all(catalog_path.parent().unwrap()).unwrap();

    fs::write(
        &contract_path,
        "export type LoggerMethod = (...args: unknown[]) => void;\n\
         export type SessionPolicy = 'aggressive_clean' | 'preserve_login';\n\
         export interface PlatformConfig {\n\
           signupUrl?: string;\n\
           checkUrl?: string;\n\
         }\n",
    )
    .unwrap();
    fs::write(
        &catalog_path,
        "export type Platform = { id: string };\n\
         const RAW_PLATFORMS: Record<string, Platform> = Object.fromEntries([]);\n\
         export const PLATFORMS = RAW_PLATFORMS;\n\
         export function getPlatformClaimMode(platformId: string) { return 'assisted'; }\n\
         export function isPlatformCacheEligible(platformId: string) { return false; }\n\
         export function getPlatformSetupObjective(platformId: string) { return 'create_account'; }\n\
         export function getPlatformSetupLabel(platformId: string) { return 'Create Account'; }\n\
         export function getPlatformSetupTasks(platformId: string) { return []; }\n\
         export function isStrictFillPlatform(platformId: string) { return false; }\n\
         export function getPlatformDisplayName(platformId: string) { return platformId; }\n",
    )
    .unwrap();

    let contract_path_str = contract_path.to_string_lossy().to_string();
    let catalog_path_str = catalog_path.to_string_lossy().to_string();

    let mut file_records = vec![
        parse_file(&contract_path_str),
        parse_file(&catalog_path_str),
    ];
    let mut graph = SymbolGraph::new(&temp_root.to_string_lossy());
    graph.add_file(parse_file_symbols(&contract_path_str));
    graph.add_file(parse_file_symbols(&catalog_path_str));
    graph.resolve_all();
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        ref_flags.is_empty(),
        "contract/catalog surfaces should not be orphaned-export noise: {:?}",
        ref_flags
    );
    assert!(
        scorer_flags.is_empty(),
        "contract/catalog surfaces should not be scored as slop: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn protocol_surfaces_stay_clean_while_adapter_integration_storage_surfaces_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_protocol_and_storage"));
    fs::create_dir_all(&temp_root).unwrap();

    let sqlite_path = write_temp_file(
        &temp_root,
        "src/bumpkin/integrations/github/persistence_sqlite.py",
        r#"
from __future__ import annotations

class SqliteAppStateStore:
    def __init__(self) -> None:
        self._events = {}
        self._recommendations = {}
        self._backlog = {}
        self._next_id = 1

    def close(self) -> None:
        self._events.clear()

    def record_event(self, *, envelope, event, status="accepted") -> bool:
        key = (envelope.provider, envelope.event_id)
        if key in self._events:
            return False
        self._events[key] = {"event": event, "status": status}
        return True

    def get_event(self, *, provider, provider_event_id):
        return self._events.get((provider, provider_event_id))

    def update_event_status(self, *, provider, provider_event_id, status) -> bool:
        key = (provider, provider_event_id)
        record = self._events.get(key)
        if record is None:
            return False
        record["status"] = status
        return True

    def list_deferred_merge_events(self, *, provider, repository, limit=20):
        return []

    def latest_recommended_label_for_pr(self, *, repository, pull_request_number):
        return None

    def latest_recommendation_for_pr(self, *, repository, pull_request_number):
        return None

    def record_recommendation_snapshot(self, *, repository, pull_request_number, label, current_version, source, source_event_id=None, recorded_at=None) -> None:
        self._recommendations[(repository, pull_request_number)] = label

    def upsert_release_backlog_item(self, *, repository, pull_request_number, merge_commit_sha, recommended_label, recommended_current_version, pull_request_title=None, pull_request_author_login=None, pull_request_url=None, release_summary=None, source_event_id=None, merged_at=None) -> int:
        item_id = self._next_id
        self._next_id += 1
        self._backlog[(repository, pull_request_number)] = item_id
        return item_id

    def list_unreleased_release_backlog_items(self, *, repository, limit=500):
        return []

    def mark_release_backlog_items_included(self, *, repository, backlog_ids, release_tag, included_at=None) -> int:
        return len(backlog_ids)

    def record_approval(self, *, approval, commit_sha, source_event_id=None) -> int:
        return 0

    def latest_approval_for_pr(self, *, repository, pull_request_number):
        return None

    def delete_approvals(self, *, repository, pull_request_number) -> int:
        return 0

    def record_publish_decision(self, *, repository, pull_request_number, commit_sha, decision, policy_snapshot, evaluated_at=None) -> int:
        return 0

    def latest_publish_decision_for_pr(self, *, repository, pull_request_number):
        return None

    def list_audit_entries(self, *, entity_type, entity_id):
        return []
"#,
    );

    let protocols_path = write_temp_file(
        &temp_root,
        "src/bumpkin/integrations/github/persistence_protocols.py",
        r#"
from __future__ import annotations

from typing import Protocol

class EventPersistenceStore(Protocol):
    def record_event(self, *, envelope, event, status="accepted") -> bool: ...
    def get_event(self, *, provider, provider_event_id): ...

class RecommendationPersistenceStore(Protocol):
    def latest_recommended_label_for_pr(self, *, repository, pull_request_number): ...
    def latest_recommendation_for_pr(self, *, repository, pull_request_number): ...
"#,
    );

    let file_records = parse_records(&[sqlite_path.clone(), protocols_path.clone()]);
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert!(
        static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("persistence_sqlite.py")
                && flag.tier == FindingTier::Slop),
        "sqlite persistence store should surface as slop: {:?}",
        static_flags
    );
    assert!(
        static_flags
            .iter()
            .all(|flag| !flag.file_path.ends_with("persistence_protocols.py")),
        "protocol surface should stay out of static scoring: {:?}",
        static_flags
    );
    assert!(
        file_verdicts
            .iter()
            .all(|verdict| verdict.verdict == FindingTier::Clean),
        "static-only signals must not become final findings: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}
