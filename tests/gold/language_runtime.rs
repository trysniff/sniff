use super::*;

#[test]
fn typescript_service_worker_support_factory_stays_clean_end_to_end() {
    let temp_root =
        std::env::temp_dir().join(unique_tag("sniff_typescript_service_worker_support"));
    let core_dir = temp_root.join("ui").join("background").join("core");
    fs::create_dir_all(&core_dir).unwrap();

    write_temp_file(
        &core_dir,
        "service-worker-support.ts",
        r#"
/// <reference types="chrome" />

import {
  readKillSwitchesFromStorage,
  type KillSwitchesState,
} from '../../src/lib/engine-runtime-storage';
import { createNamesetStorePrivacyManager } from './nameset-store';
import {
  deriveFeedbackContextFromSender as deriveFeedbackContextFromSenderImpl,
  encryptWithSessionKey as encryptWithSessionKeyImpl,
} from './crypto-feedback';

type LoggerLike = {
  warn: (message: string, error?: unknown) => void;
};

type PrivacyManagerLike = ReturnType<typeof createNamesetStorePrivacyManager>;

type ServiceWorkerSupportDeps = {
  chromeApi: typeof chrome;
  cryptoObj: Crypto;
  encoder: TextEncoder;
  logger: LoggerLike;
  storeKey: string;
  originId: string;
  privacyManager?: PrivacyManagerLike;
  readKillSwitchesFromStorageImpl?: typeof readKillSwitchesFromStorage;
};

export function createServiceWorkerSupportServices(deps: ServiceWorkerSupportDeps) {
  const {
    chromeApi,
    cryptoObj,
    encoder,
    logger,
    storeKey,
    originId,
    readKillSwitchesFromStorageImpl = readKillSwitchesFromStorage,
  } = deps;
  const privacyManager = deps.privacyManager ?? createNamesetStorePrivacyManager({
    chromeApi,
    storeKey,
    originId,
  });

  async function getImprovementTelemetryConsent(): Promise<boolean> {
    return privacyManager.getImprovementTelemetryConsent();
  }

  async function setImprovementTelemetryConsent(enabled: boolean): Promise<void> {
    try {
      await privacyManager.setImprovementTelemetryConsent(enabled);
    } catch (error) {
      logger.warn('[ServiceWorker] Failed to persist telemetry consent:', error);
    }
  }

  async function migrateNamesetStoreToCanonicalObject(): Promise<void> {
    try {
      await privacyManager.migrateNamesetStoreToCanonicalObject();
    } catch (error) {
      logger.warn('[ServiceWorker] nameset-store canonical migration skipped:', error);
    }
  }

  async function readKillSwitches(): Promise<KillSwitchesState> {
    try {
      return await readKillSwitchesFromStorageImpl(chromeApi.storage.local);
    } catch {
      return {};
    }
  }

  function deriveFeedbackContextFromSender(sender: chrome.runtime.MessageSender): {
    domain: string | null;
    uriHash: string | null;
  } {
    return deriveFeedbackContextFromSenderImpl(sender);
  }

  async function encryptWithSessionKey(plaintext: string) {
    return encryptWithSessionKeyImpl(plaintext, {
      chromeApi,
      cryptoObj,
      encoder,
    });
  }

  return {
    getImprovementTelemetryConsent,
    setImprovementTelemetryConsent,
    migrateNamesetStoreToCanonicalObject,
    readKillSwitches,
    deriveFeedbackContextFromSender,
    encryptWithSessionKey,
  };
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn durable_object_state_gateway_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_state_gateway"));
    let gateway_dir = temp_root.join("worker").join("src").join("durable");
    fs::create_dir_all(&gateway_dir).unwrap();

    write_temp_file(
        &gateway_dir,
        "state-gateway.ts",
        r#"
import {
  applyRegistryRollbackMutation,
  applyRegistryUpdateMutation,
} from "../core/registry-mutations";
import { applyPlatformOverridesMutation } from "../core/platform-overrides-mutations";
import { ROUTE_DEPS } from "../core/route-deps";
import type { Env } from "../types";

type CounterIncrementOperation = {
  key: string;
  delta: number;
  expirationTtl?: number;
};

type KvPutOperation = {
  key: string;
  value: string;
  expirationTtl?: number;
};

type KvDeleteOperation = {
  key: string;
};

const MAX_BATCH_OPERATIONS = 100;
const MAX_KV_KEY_LENGTH = 512;
const MAX_KV_VALUE_BYTES = 64 * 1024;

function getUtf8ByteLength(value: string): number {
  return new Blob([value]).size;
}

function parseCounter(raw: string | null): number {
  if (!raw) return 0;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return 0;
  return parsed;
}

function isValidCounterOperation(op: CounterIncrementOperation): boolean {
  return Boolean(
    op &&
      typeof op.key === "string" &&
      op.key.length > 0 &&
      op.key.length <= MAX_KV_KEY_LENGTH &&
      Number.isFinite(op.delta),
  );
}

function isValidKvPutOperation(op: KvPutOperation): boolean {
  return Boolean(
    op &&
      typeof op.key === "string" &&
      op.key.length > 0 &&
      op.key.length <= MAX_KV_KEY_LENGTH &&
      typeof op.value === "string" &&
      getUtf8ByteLength(op.value) <= MAX_KV_VALUE_BYTES,
  );
}

function isValidKvDeleteOperation(op: KvDeleteOperation): boolean {
  return Boolean(
    op &&
      typeof op.key === "string" &&
      op.key.length > 0 &&
      op.key.length <= MAX_KV_KEY_LENGTH,
  );
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export class StateGateway implements DurableObject {
  private readonly state: DurableObjectState;
  private readonly env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }

    if (url.pathname === "/counter/increment-batch") {
      let payload: { operations?: CounterIncrementOperation[] } | null = null;
      try {
        payload = (await request.json()) as { operations?: CounterIncrementOperation[] };
      } catch {
        return json({ ok: false, error: "invalid_json" }, 400);
      }
      const operations = Array.isArray(payload?.operations) ? payload.operations : [];
      if (operations.length > MAX_BATCH_OPERATIONS) {
        return json({ ok: false, error: "batch_too_large" }, 413);
      }
      if (operations.some((op) => !isValidCounterOperation(op))) {
        return json({ ok: false, error: "invalid_operation" }, 400);
      }
      return this.state.blockConcurrencyWhile(async () => {
        const results: Array<{ key: string; previous: number; next: number }> = [];
        for (const op of operations) {
          const previous = parseCounter(await this.env.RULES.get(op.key));
          const next = previous + Math.trunc(op.delta);
          await this.env.RULES.put(op.key, String(next), {
            expirationTtl:
              Number.isFinite(op.expirationTtl) && (op.expirationTtl || 0) > 0
                ? Math.trunc(op.expirationTtl as number)
                : undefined,
          });
          results.push({ key: op.key, previous, next });
        }
        return json({ ok: true, results }, 200);
      });
    }

    if (url.pathname === "/kv/put-batch") {
      let payload: { operations?: KvPutOperation[] } | null = null;
      try {
        payload = (await request.json()) as { operations?: KvPutOperation[] };
      } catch {
        return json({ ok: false, error: "invalid_json" }, 400);
      }
      const operations = Array.isArray(payload?.operations) ? payload.operations : [];
      if (operations.length > MAX_BATCH_OPERATIONS) {
        return json({ ok: false, error: "batch_too_large" }, 413);
      }
      if (operations.some((op) => !isValidKvPutOperation(op))) {
        return json({ ok: false, error: "invalid_operation" }, 400);
      }
      return this.state.blockConcurrencyWhile(async () => {
        for (const op of operations) {
          await this.env.RULES.put(op.key, op.value, {
            expirationTtl:
              Number.isFinite(op.expirationTtl) && (op.expirationTtl || 0) > 0
                ? Math.trunc(op.expirationTtl as number)
                : undefined,
          });
        }
        return json({ ok: true }, 200);
      });
    }

    if (url.pathname === "/kv/delete-batch") {
      let payload: { operations?: KvDeleteOperation[] } | null = null;
      try {
        payload = (await request.json()) as { operations?: KvDeleteOperation[] };
      } catch {
        return json({ ok: false, error: "invalid_json" }, 400);
      }
      const operations = Array.isArray(payload?.operations) ? payload.operations : [];
      if (operations.length > MAX_BATCH_OPERATIONS) {
        return json({ ok: false, error: "batch_too_large" }, 413);
      }
      if (operations.some((op) => !isValidKvDeleteOperation(op))) {
        return json({ ok: false, error: "invalid_operation" }, 400);
      }
      return this.state.blockConcurrencyWhile(async () => {
        for (const op of operations) {
          await this.env.RULES.delete(op.key);
        }
        return json({ ok: true }, 200);
      });
    }

    if (url.pathname === "/registry/update") {
      let payload: { payload?: any } | null = null;
      try {
        payload = (await request.json()) as { payload?: any };
      } catch {
        return json({ ok: false, error: "invalid_json" }, 400);
      }
      return this.state.blockConcurrencyWhile(async () => {
        const mutation = await applyRegistryUpdateMutation({
          env: this.env,
          deps: ROUTE_DEPS,
          payload: payload?.payload,
          waitUntil: (promise) => this.state.waitUntil(promise),
        });
        return json(mutation.body, mutation.status);
      });
    }

    if (url.pathname === "/registry/rollback") {
      return this.state.blockConcurrencyWhile(async () => {
        const mutation = await applyRegistryRollbackMutation({
          env: this.env,
          deps: ROUTE_DEPS,
          waitUntil: (promise) => this.state.waitUntil(promise),
        });
        return json(mutation.body, mutation.status);
      });
    }

    if (url.pathname === "/platform-links/update") {
      let payload: { payload?: any } | null = null;
      try {
        payload = (await request.json()) as { payload?: any };
      } catch {
        return json({ ok: false, error: "invalid_json" }, 400);
      }
      return this.state.blockConcurrencyWhile(async () => {
        const mutation = await applyPlatformOverridesMutation({
          env: this.env,
          deps: ROUTE_DEPS,
          payload: payload?.payload,
        });
        return json(mutation.body, mutation.status);
      });
    }

    return json({ ok: false, error: "not_found" }, 404);
  }
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &flags, &[]);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn go_support_helpers_stay_clean_while_routes_stay_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_go_support"));
    let routes_dir = temp_root.join("src").join("routes");
    let utils_dir = temp_root.join("src").join("utils");
    fs::create_dir_all(&routes_dir).unwrap();
    fs::create_dir_all(&utils_dir).unwrap();

    write_temp_file(
        &routes_dir,
        "ops.go",
        r#"
package routes

func TriageStatusRank(status string) int {
    if status == "blocked" {
        return 3
    }
    if status == "warning" {
        return 2
    }
    if status == "ok" {
        return 1
    }
    return 0
}

func ChoosePrimaryBacklogItem(items []struct{ score int; rank int }) struct{ score int; rank int } {
    winner := items[0]
    for _, item := range items {
        if item.score > winner.score {
            winner = item
        } else if item.score == winner.score && item.rank > winner.rank {
            winner = item
        }
    }
    return winner
}
"#,
    );

    write_temp_file(
        &utils_dir,
        "math.go",
        r#"
package utils

func Add(a int, b int) int {
    return a + b
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags
            .iter()
            .any(|flag| flag.file_path.ends_with("ops.go") && flag.tier != FindingTier::Clean),
        "the Go route module should still be flagged as noisy: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("math.go") && flag.tier != FindingTier::Clean),
        "the small Go helper should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn rust_support_helpers_stay_clean_while_routes_stay_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_rust_support"));
    let routes_dir = temp_root.join("src").join("routes");
    let utils_dir = temp_root.join("src").join("utils");
    fs::create_dir_all(&routes_dir).unwrap();
    fs::create_dir_all(&utils_dir).unwrap();

    write_temp_file(
        &routes_dir,
        "ops.rs",
        r#"
pub fn triage_status_rank(status: &str) -> i32 {
    if status == "blocked" {
        return 3;
    }
    if status == "warning" {
        return 2;
    }
    if status == "ok" {
        return 1;
    }
    0
}
"#,
    );

    write_temp_file(
        &utils_dir,
        "math.rs",
        r#"
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags
            .iter()
            .any(|flag| flag.file_path.ends_with("ops.rs") && flag.tier != FindingTier::Clean),
        "the Rust route module should still be flagged as noisy: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("math.rs") && flag.tier != FindingTier::Clean),
        "the small Rust helper should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn kotlin_support_helpers_stay_clean_while_routes_stay_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_kotlin_support"));
    let routes_dir = temp_root.join("src").join("routes");
    let utils_dir = temp_root.join("src").join("utils");
    fs::create_dir_all(&routes_dir).unwrap();
    fs::create_dir_all(&utils_dir).unwrap();

    write_temp_file(
        &routes_dir,
        "ops.kt",
        r#"
package routes

fun triageStatusRank(status: String): Int {
    if (status == "blocked") return 3
    if (status == "warning") return 2
    if (status == "ok") return 1
    return 0
}

fun choosePrimaryBacklogItem(items: List<Pair<Int, Int>>): Pair<Int, Int> {
    var winner = items.first()
    for (item in items) {
        if (item.first > winner.first) {
            winner = item
        } else if (item.first == winner.first && item.second > winner.second) {
            winner = item
        }
    }
    return winner
}
"#,
    );

    write_temp_file(
        &utils_dir,
        "math.kt",
        r#"
package utils

fun add(a: Int, b: Int): Int {
    return a + b
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags
            .iter()
            .any(|flag| flag.file_path.ends_with("ops.kt") && flag.tier != FindingTier::Clean),
        "the Kotlin route module should still be flagged as noisy: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("math.kt") && flag.tier != FindingTier::Clean),
        "the small Kotlin helper should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}
