use super::*;

#[test]
fn brandset_signup_wrapper_survives_end_to_end() {
    let root = unique_root("sniff-dogfood-brandset-signup-wrapper");
    fs::create_dir_all(&root).unwrap();
    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "supabase/functions/signup-wrapper/index.ts",
        "export function normalizeIpToken(raw: unknown): string | null {\n  if (typeof raw !== 'string') {\n    return null;\n  }\n  return raw.trim() || null;\n}\n\nexport function parseAllowedRedirectHosts(raw: string): string[] {\n  const hosts = raw.split(',');\n  return hosts.map((host) => host.trim()).filter(Boolean);\n}\n",
    );
    write_file(
        &root,
        "supabase/functions/create-polar-checkout-session/index.ts",
        "export default async function handler(req: Request) {\n  if (req.method !== \"POST\") {\n    return new Response(\"method not allowed\", { status: 405 });\n  }\n  return new Response(JSON.stringify({ ok: true }), {\n    headers: { \"Content-Type\": \"application/json\" },\n  });\n}\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("supabase").join("functions"))
        .arg("--only-files")
        .arg("--skip-dotenv")
        .env("SNIFF_API_KEY", "test-key")
        .env("SNIFF_ENDPOINT", &endpoint)
        .env("SNIFF_MODEL", "test-model")
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
    assert!(report.contains("AI coverage:**"));
    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("signup-wrapper")
            && prompt_text.contains("normalizeIpToken")
            && prompt_text.contains("parseAllowedRedirectHosts"),
        "expected signup-wrapper to be reviewed by the mock provider:\n{}",
        prompt_text
    );
    assert!(
        prompt_text.contains("create-polar-checkout-session"),
        "expected the checkout entrypoint to be reviewed too:\n{}",
        prompt_text
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn default_scan_reviews_every_method_and_every_file_end_to_end() {
    let root = unique_root("sniff-dogfood-exhaustive-method-review");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{endpoint}/chat/completions");
    write_file(
        &root,
        ".env",
        &format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    );
    write_file(
        &root,
        "src/math.py",
        "def add(left, right):\n    return left + right\n\ndef normalize(value):\n    return value.strip()\n",
    );
    write_file(
        &root,
        "src/format.ts",
        "export function formatValue(value: string): string {\n  return value.trim();\n}\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "exhaustive scan should complete:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("AI coverage:** 5 of 5 expected reviews completed, 0 missed"),
        "expected two file reviews plus three method reviews:\n{report}"
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    for method in ["add", "normalize", "formatValue"] {
        assert!(
            prompt_text.contains(&format!("Method: {method}")),
            "expected method {method} to be reviewed:\n{prompt_text}"
        );
    }
    assert!(
        prompt_text.contains("Filename: math.py") && prompt_text.contains("Filename: format.ts"),
        "expected both files to be reviewed:\n{prompt_text}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn default_scan_reviews_every_supported_language_end_to_end() {
    let root = unique_root("sniff-dogfood-exhaustive-language-review");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{endpoint}/chat/completions");
    write_file(
        &root,
        ".env",
        &format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    );
    write_file(
        &root,
        "src/math.py",
        "def add(left, right):\n    return left + right\n",
    );
    write_file(
        &root,
        "src/format.ts",
        "export function formatValue(value: string): string {\n  return value.trim();\n}\n",
    );
    write_file(
        &root,
        "src/legacy.js",
        "export function normalizeValue(value) {\n  return String(value).trim();\n}\n",
    );
    write_file(
        &root,
        "src/lib.rs",
        "pub fn normalize_value(value: &str) -> String {\n    value.trim().to_string()\n}\n",
    );
    write_file(
        &root,
        "src/main.go",
        "package main\n\nfunc normalizeValue(value string) string {\n    return value\n}\n",
    );
    write_file(
        &root,
        "src/Main.kt",
        "fun normalizeValue(value: String): String {\n    return value.trim()\n}\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cross-language scan should complete:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("AI coverage:** 12 of 12 expected reviews completed, 0 missed"),
        "expected every language method and file to be reviewed:\n{report}"
    );
    assert!(
        !report.contains("## `"),
        "clean cross-language corpus should not produce findings:\n{report}"
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    for method in ["add", "formatValue", "normalizeValue", "normalize_value"] {
        assert!(
            prompt_text.contains(&format!("Method: {method}")),
            "expected method {method} to be reviewed:\n{prompt_text}"
        );
    }
    for filename in [
        "math.py",
        "format.ts",
        "legacy.js",
        "lib.rs",
        "main.go",
        "Main.kt",
    ] {
        assert!(
            prompt_text.contains(&format!("Filename: {filename}")),
            "expected file {filename} to be reviewed:\n{prompt_text}"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn default_scan_surfaces_method_slop_through_the_final_report() {
    let root = unique_root("sniff-dogfood-method-slop");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{endpoint}/chat/completions");
    write_file(
        &root,
        ".env",
        &format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    );
    write_file(&root, "src/sloppy.py", &python_slop_module("sloppy"));
    write_file(&root, "src/clean.py", &python_clean_module("clean"));

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected status:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(report.contains("AI coverage:** 4 of 4 expected reviews completed, 0 missed"));
    assert!(
        report.contains("sloppy.py"),
        "method slop should reach the report:\n{report}"
    );
    assert!(
        report.contains("function is too big"),
        "the method reason should survive aggregation:\n{report}"
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(prompt_text.contains("Method: sloppy"));
    assert!(prompt_text.contains("Method: clean"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_supabase_clean_neighbors_stay_clean_while_signup_wrapper_surfaces() {
    let root = unique_root("sniff-dogfood-brandset-supabase");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "supabase/functions/signup-wrapper/index.ts",
        "export function normalizeIpToken(raw: unknown): string | null {\n  if (typeof raw !== 'string') {\n    return null;\n  }\n  const token = raw.trim();\n  if (!token) {\n    return null;\n  }\n  if (token.length > 48) {\n    return token.slice(0, 48);\n  }\n  return token;\n}\n\nexport function parseAllowedRedirectHosts(input: string | string[] | undefined): string[] {\n  const values = Array.isArray(input) ? input : input ? [input] : [];\n  const hosts: string[] = [];\n  for (const value of values) {\n    const normalized = value.trim();\n    if (normalized) {\n      hosts.push(normalized.replace(/^https?:\\/\\//, ''));\n    }\n  }\n  return hosts;\n}\n\nexport function signupWrapper() {\n  const redirectHosts = parseAllowedRedirectHosts(['https://example.com', 'https://app.example.com']);\n  const tokens = ['alpha', 'beta', 'gamma', 'delta'];\n  let total = 0;\n  for (const token of tokens) {\n    const normalized = normalizeIpToken(token);\n    if (normalized) {\n      total += normalized.length;\n    } else {\n      total += 1;\n    }\n  }\n  if (redirectHosts.length > 1) {\n    total += redirectHosts.length;\n  }\n  return { total, redirectHosts };\n}\n",
    );
    write_file(
        &root,
        "supabase/functions/notify-payment-health/index.ts",
        &ts_clean_module("notifyPaymentHealth"),
    );
    write_file(
        &root,
        "supabase/functions/create-polar-checkout-session/index.ts",
        &ts_clean_module("createPolarCheckoutSession"),
    );
    write_file(
        &root,
        "supabase/functions/_shared/fetch-with-timeout.ts",
        &ts_clean_module("fetchWithTimeout"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("supabase").join("functions"))
        .arg("--only-files")
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
        report.contains("signup-wrapper") && report.contains("index.ts"),
        "expected signup-wrapper to remain in the report:\n{}",
        report
    );
    assert!(
        !report.contains("notify-payment-health"),
        "notify-payment-health should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("create-polar-checkout-session"),
        "create-polar-checkout-session should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("signup-wrapper")
            && prompt_text.contains("notify-payment-health")
            && prompt_text.contains("create-polar-checkout-session"),
        "expected the Supabase surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_session_layer_boundary_survives_end_to_end() {
    let root = unique_root("sniff-dogfood-brandset-session-layer");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/session-launch-policy.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionLaunchPolicy"),
            js_branchy_helpers("sessionLaunchPolicy", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-actions.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionActions"),
            js_branchy_helpers("sessionActions", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-url-helpers.ts",
        "export function normalizeSessionUrl(value: string): string {\n  return value.trim();\n}\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
        .arg("--only-files")
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
        report.contains("session-launch-policy.ts"),
        "expected session-launch-policy to remain in the report:\n{}",
        report
    );
    assert!(
        report.contains("session-actions.ts"),
        "expected session-actions to remain in the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-url-helpers.ts"),
        "session-url-helpers should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("session-launch-policy")
            && prompt_text.contains("session-actions")
            && prompt_text.contains("session-url-helpers"),
        "expected the session layer surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_session_state_survives_while_contract_files_stay_clean() {
    let root = unique_root("sniff-dogfood-brandset-session-state");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/session-state.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionState"),
            js_branchy_helpers("sessionState", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-runtime-contracts.ts",
        "export type SessionRuntimeContract = {\n  id: string;\n  state: string;\n};\n",
    );
    write_file(
        &root,
        "ui/background/core/session-init-payload.ts",
        "export interface SessionInitPayload {\n  sessionId: string;\n  status: string;\n}\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
        .arg("--only-files")
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
        report.contains("session-state.ts"),
        "expected session-state to remain in the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-runtime-contracts.ts"),
        "session-runtime-contracts should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-init-payload.ts"),
        "session-init-payload should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("session-state")
            && prompt_text.contains("session-runtime-contracts")
            && prompt_text.contains("session-init-payload"),
        "expected the session state surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_session_safe_start_boundary_survives_end_to_end() {
    let root = unique_root("sniff-dogfood-brandset-safe-start");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/session-safe-start.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionSafeStart"),
            js_branchy_helpers("sessionSafeStart", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-tab-guard.ts",
        "export function guardSessionTab(tabId: number): boolean {\n  return tabId > 0;\n}\n",
    );
    write_file(
        &root,
        "ui/background/core/session-completion-lifecycle.ts",
        "export function completeSessionLifecycle(status: string): string {\n  return status.trim();\n}\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
        .arg("--only-files")
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
        report.contains("session-safe-start.ts"),
        "expected session-safe-start to remain in the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-tab-guard.ts"),
        "session-tab-guard should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-completion-lifecycle.ts"),
        "session-completion-lifecycle should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("session-safe-start")
            && prompt_text.contains("session-tab-guard")
            && prompt_text.contains("session-completion-lifecycle"),
        "expected the safe-start surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_session_orchestration_boundary_surfaces_real_slop_and_keeps_neighbors_clean() {
    let root = unique_root("sniff-dogfood-brandset-session-orchestration");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/session-actions.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionActions"),
            js_branchy_helpers("sessionActions", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-launch-orchestration.ts",
        &format!(
            "{}{}",
            js_slop_bundle("sessionLaunchOrchestration"),
            js_branchy_helpers("sessionLaunchOrchestration", 18)
        ),
    );
    write_file(
        &root,
        "ui/background/core/runtime-message-validation.ts",
        &format!(
            "export function validateRuntimeMessage(message) {{\n  if (message.type === \"START_SESSION\") {{\n    return true;\n  }}\n  if (message.type === \"STOP_SESSION\") {{\n    return true;\n  }}\n  if (message.type === \"CHECK_SESSION\") {{\n    return true;\n  }}\n  return false;\n}}\n{}",
            js_branchy_helpers("runtimeMessageValidation", 6)
        ),
    );
    write_file(
        &root,
        "ui/background/core/session-challenge-orchestration.ts",
        "export function createSessionChallengeOrchestration() {\n  return { state: 'ready' };\n}\n",
    );
    write_file(
        &root,
        "ui/background/core/session-url-helpers.ts",
        "export function normalizeSessionUrl(value: string): string {\n  return value.trim();\n}\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
        .arg("--only-files")
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
        report.contains("session-actions.ts"),
        "expected session-actions to remain in the report:\n{}",
        report
    );
    assert!(
        report.contains("session-launch-orchestration.ts"),
        "expected session-launch-orchestration to remain in the report:\n{}",
        report
    );
    assert!(
        report.contains("runtime-message-validation.ts"),
        "expected runtime-message-validation to remain in the report:\n{}",
        report
    );
    for clean_name in [
        "session-challenge-orchestration.ts",
        "session-url-helpers.ts",
    ] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("session-actions")
            && prompt_text.contains("session-launch-orchestration")
            && prompt_text.contains("runtime-message-validation")
            && prompt_text.contains("session-challenge-orchestration"),
        "expected the session orchestration surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}
