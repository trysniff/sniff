use super::*;

#[test]
fn medication_numeric_rules_still_surface_as_real_slop_end_to_end() {
    let _kotlin_dogfood = lock_kotlin_dogfood();
    let root = unique_root("sniff-dogfood-medication-numeric-rules");
    fs::create_dir_all(&root).unwrap();
    let slop_hits = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
    let slop_hits_clone = Arc::clone(&slop_hits);
    let prompts_clone = Arc::clone(&prompts);

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let (stream_back, request) = read_http_request(stream);
            if let Ok(mut locked) = prompts_clone.lock() {
                locked.push(request.clone());
            }
            let body = if let Some(proof_body) = proof_mock_response(&request) {
                proof_body
            } else {
                let body = if request.contains("CASE FIELDS:") {
                    r#"{"choices":[{"message":{"content":"{\"cases\":[]}"}}]}"#
                } else if request.contains("Return exactly one JSON object with this shape") {
                    r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#
                } else if request.contains("MedicationNumericRules.kt") {
                    slop_hits_clone.fetch_add(1, Ordering::SeqCst);
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"character == '/' && !slashSeen && currentPartHasDigits && !endsWith(\\\".\\\") -> {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
                };
                let body = body.to_string();
                semanticize_method_response(&request, &body)
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut stream = stream_back;
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    let endpoint = format!("http://{}", addr);
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt",
        r#"
package com.onpill.shared.uicontract

public fun sanitizeMedicationWholeNumberInput(value: String): String {
  var digitSeen = false
  return buildString {
    for (character in value) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        digitSeen -> break
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationDecimalInput(value: String): String {
  var decimalSeen = false
  var digitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        character == '.' && !decimalSeen -> {
          if (isEmpty()) {
            append('0')
          }
          append(character)
          decimalSeen = true
        }
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationStrengthInput(value: String): String {
  var slashSeen = false
  var currentPartHasDigits = false
  var currentPartHasDecimal = false
  var anyDigitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          currentPartHasDigits = true
          anyDigitSeen = true
        }
        character == '.' && !currentPartHasDecimal -> {
          if (!currentPartHasDigits) {
            append('0')
            currentPartHasDigits = true
            anyDigitSeen = true
          }
          append(character)
          currentPartHasDecimal = true
        }
        character == '/' && !slashSeen && currentPartHasDigits && !endsWith(".") -> {
          append(character)
          slashSeen = true
          currentPartHasDigits = false
          currentPartHasDecimal = false
        }
        character == '/' && slashSeen -> break
      }
    }
  }.takeIf { anyDigitSeen }.orEmpty()
}
"#,
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .env("SNIFF_DEBUG_REPORT", "1")
        .arg(root.join("shared"))
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    let prompt_text = prompts.lock().unwrap().join("\n---\n");
    assert!(
        report.contains("MedicationNumericRules.kt"),
        "expected the numeric rules file to remain visible as real slop:\n{}\n\nstdout:\n{}\n\nstderr:\n{}\n\nPrompts:\n{}\n\nslop_hits={}",
        report,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        prompt_text,
        slop_hits.load(Ordering::SeqCst)
    );
    assert!(
        report.contains("Slop"),
        "expected the numeric rules hotspot to still be reported as slop:\n{}\n\nPrompts:\n{}",
        report,
        prompt_text
    );
    assert!(
        report.contains("sanitizeMedicationStrengthInput"),
        "expected the real hotspot method to be named in the report:\n{}\n\nPrompts:\n{}",
        report,
        prompt_text
    );
    assert!(
        prompt_text.contains("MedicationNumericRules.kt"),
        "expected the file-review prompt to mention the filename:\n{}",
        prompt_text
    );
    assert!(
        slop_hits.load(Ordering::SeqCst) > 0,
        "expected the mock server to emit a slop response for the numeric rules file"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn service_worker_support_boundaries_are_reviewed_end_to_end() {
    let root = unique_root("sniff-dogfood-support-boundary");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    populate_support_boundary_repo(&root);

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("sloppy.py"),
        "expected the real slop file to appear in the report:\n{}",
        report
    );
    assert!(
        !report.contains("service-worker-support.ts"),
        "support boundary glue should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("feature-flags.ts"),
        "feature-flag glue should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("password-session-cache.ts"),
        "session cache glue should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("File path: ") && prompt_text.contains("service-worker-support.ts"),
        "support boundary methods should be sent for AI review:\n{}",
        prompt_text
    );
    assert!(
        prompt_text.contains("File path: ") && prompt_text.contains("feature-flags.ts"),
        "feature-flag methods should be sent for AI review:\n{}",
        prompt_text
    );
    assert!(
        prompt_text.contains("File path: ") && prompt_text.contains("password-session-cache.ts"),
        "session cache methods should be sent for AI review:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn polar_webhook_small_helper_surface_stays_out_of_the_report_end_to_end() {
    let root = unique_root("sniff-dogfood-polar-webhook");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "supabase/functions/polar-webhook/index.ts",
        r#"
function readEnvBool(name: string, defaultValue = true): boolean {
  const raw = String((globalThis as any).Deno.env.get(name) ?? "").trim().toLowerCase();
  if (!raw) return defaultValue;
  if (["0", "false", "off", "no"].includes(raw)) return false;
  if (["1", "true", "on", "yes"].includes(raw)) return true;
  return defaultValue;
}

function readAmountCents(order: Record<string, unknown>): number {
  const totals = (order?.totals as Record<string, unknown> | undefined) ?? {};
  const value =
    order?.total_amount ??
    order?.totalAmount ??
    order?.amount ??
    order?.amount_in_cents ??
    order?.amountInCents ??
    totals?.total ??
    totals?.gross ??
    0;
  const num = Number(value);
  return Number.isFinite(num) ? Math.trunc(num) : 0;
}

function readCustomerEmail(order: Record<string, unknown>): string | null {
  const customer = (order?.customer as Record<string, unknown> | undefined) ?? {};
  const candidate =
    customer.email ??
    order?.customer_email ??
    order?.email ??
    (order?.billing_address as Record<string, unknown> | undefined)?.email ??
    null;
  if (typeof candidate !== "string") return null;
  const normalized = candidate.trim();
  if (!normalized || !normalized.includes("@")) return null;
  return normalized;
}

export async function handler(req: Request) {
  const order = { totals: {}, customer: {} };
  const amount = readAmountCents(order);
  const email = readCustomerEmail(order);
  const enabled = readEnvBool("POLAR_WEBHOOK_ENABLED", true);
  return new Response(JSON.stringify({ amount, email, enabled }));
}
"#,
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        !report.contains("polar-webhook/index.ts"),
        "small webhook helper surface should stay out of the report:\n{}",
        report
    );
    assert!(
        report.contains("0 slop | 0 kinda slop"),
        "webhook helper surface should normalize away from slop:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("File path:")
            && prompt_text.contains("readAmountCents")
            && prompt_text.contains("readCustomerEmail"),
        "polar webhook should still be reviewed by the AI:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cleanup_surface_stays_clean_while_payload_staging_surfaces_end_to_end() {
    let root = unique_root("sniff-dogfood-cleanup-boundary");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/runtime-session-cleanup.ts",
        r#"
export function createRuntimeSessionCleanup() {
  return {
    clearStaleRuntimeSessionState() {},
    closeCompletedRuntimeSession() {},
    closeCanceledRuntimeSession() {},
    detachRuntimeSessionOwnership() {},
  };
}
"#,
    );
    write_file(
        &root,
        "ui/background/core/drop-payload-staging.ts",
        r#"
export function createDropPayloadStaging() {
  const tokens = new Map<string, string>();
  function normalizeDropFilename(filename: string): string {
    return filename.trim().replace(/[^a-z0-9._-]+/gi, "_");
  }
  function sanitizeDropPayload(payload: unknown): string | null {
    if (!payload || typeof payload !== "object") return null;
    return "ok";
  }
  return { normalizeDropFilename, sanitizeDropPayload, tokens };
  }
"#,
    );
    write_file(
        &root,
        "ui/background/core/service-worker-runtime-handlers.ts",
        r#"
export function createServiceWorkerRuntimeHandlers() {
  return {
    handleBrandGetAccessState() {},
    handleBrandGetClaimMatrix() {},
    handleBrandAttachToken() {},
    handleBrandDeleteOrArchive() {},
    handleBrandRestoreArchived() {},
    handleBrandHardDeleteFree() {},
    handleProfileUpsert() {},
    handleProfileDelete() {},
  };
}
"#,
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        !report.contains("runtime-session-cleanup.ts"),
        "cleanup support surface should stay out of the report:\n{}",
        report
    );
    assert!(
        report.contains("drop-payload-staging.ts"),
        "payload staging slop should stay in the report:\n{}",
        report
    );
    assert!(
        report.contains("service-worker-runtime-handlers.ts"),
        "runtime handlers slop should stay in the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("createDropPayloadStaging")
            && prompt_text.contains("createRuntimeSessionCleanup")
            && prompt_text.contains("createServiceWorkerRuntimeHandlers"),
        "both surfaces should be reviewed by the AI:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_feedback_and_crypto_survive_while_auth_flow_stays_clean_end_to_end() {
    let root = unique_root("sniff-dogfood-brandset-feedback-crypto");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/auth-flow.ts",
        "export function authFlowIsReady() {\n  return true;\n}\n",
    );
    write_file(
        &root,
        "ui/background/core/feedback-handlers.ts",
        &format!(
            "{}{}",
            js_slop_bundle("feedbackHandlers"),
            js_branchy_helpers("feedbackHandlers", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/crypto-feedback.ts",
        &format!(
            "{}{}",
            js_slop_bundle("cryptoFeedback"),
            js_branchy_helpers("cryptoFeedback", 18)
        ),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("feedback-handlers.ts"),
        "feedback handlers should stay in the report:\n{}",
        report
    );
    assert!(
        report.contains("crypto-feedback.ts"),
        "crypto feedback should stay in the report:\n{}",
        report
    );
    assert!(
        !report.contains("auth-flow.ts"),
        "auth flow should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("feedbackHandlersEntry")
            && prompt_text.contains("cryptoFeedbackEntry")
            && prompt_text.contains("auth-flow.ts"),
        "all three surfaces should be reviewed by the AI:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_serverless_entrypoints_stay_clean_while_release_job_surfaces_end_to_end() {
    let root = unique_root("sniff-dogfood-bumpkin-shape");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_bumpkin_shape_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "supabase/functions/create-polar-checkout-session/index.ts",
        "export default async function handler(req: Request) {\n  if (req.method !== \"POST\") {\n    return new Response(\"method not allowed\", { status: 405 });\n  }\n  return new Response(JSON.stringify({ ok: true }), {\n    headers: { \"Content-Type\": \"application/json\" },\n  });\n}\n",
    );
    write_file(
        &root,
        "ui/background/core/checkout-rpc.ts",
        "export function createCheckoutRpc() {\n  const steps = [1, 2, 3, 4, 5, 6];\n  if (steps.length > 3) {\n    return steps.map((step) => step * 2).join(',');\n  }\n  return 'ok';\n}\n",
    );
    write_file(
        &root,
        "ui/background/core/domain-gateway.ts",
        "export function createDomainGateway() {\n  let total = 0;\n  for (const item of [1, 2, 3, 4, 5]) {\n    if (item % 2 === 0) {\n      total += item;\n    } else {\n      total += item * 2;\n    }\n  }\n  return total;\n}\n",
    );
    write_file(
        &root,
        "src/bumpkin/analysis/explanation_facts.py",
        &python_clean_module("summarize_path_targets"),
    );
    write_file(
        &root,
        "src/bumpkin/release_job.py",
        &python_slop_bundle("releaseJob", "run_release_job"),
    );
    write_file(&root, "src/main.py", "def main():\n    return 0\n");
    write_file(&root, "src/App.tsx", &ts_clean_module("App"));

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("checkout-rpc.ts"),
        "expected the real slop integration file to appear in the report:\n{}",
        report
    );
    assert!(
        !report.contains("supabase/functions/create-polar-checkout-session/index.ts"),
        "serverless function entrypoints should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("src/main.py"),
        "main.py should stay out of the report:\n{}",
        report
    );
    assert!(
        report.contains("release_job.py"),
        "release_job.py should be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("src/App.tsx"),
        "small root app shells should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("explanation_facts.py"),
        "support facades should stay out of the report:\n{}",
        report
    );
    assert!(
        report.contains("Slop"),
        "expected the slop files to be surfaced as slop:\n{}",
        report
    );

    let prompts = prompts.lock().unwrap();
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("File path: ") && prompt.contains("checkout-rpc.ts")),
        "expected checkout-rpc.ts to be reviewed by the mock provider"
    );
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("File path: ") && prompt.contains("index.ts")),
        "serverless entrypoint methods should be reviewed as slop candidates"
    );
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("File path: ") && prompt.contains("release_job.py")),
        "release_job.py should be reviewed as slop candidates"
    );
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("File path: ") && prompt.contains("App.tsx")),
        "small root app shell methods should be reviewed as slop candidates"
    );

    let _ = fs::remove_dir_all(&root);
}
