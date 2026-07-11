use super::*;

#[test]
fn bumpkin_github_recommendations_surfaces_real_slop_while_publishers_stay_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-github-recommendations");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/integrations/github/recommendations.py",
        &python_slop_bundle("recommendations", "build_api_diff_result"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/releases.py",
        &python_clean_module("list_releases"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/tags.py",
        &python_clean_module("list_tags"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("recommendations.py"),
        "recommendations.py should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["releases.py", "tags.py"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("recommendations.py")
            && prompt_text.contains("releases.py")
            && prompt_text.contains("tags.py"),
        "expected the GitHub recommendation surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_github_webhook_plumbing_surfaces_real_slop_while_http_client_stays_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-github-webhook-plumbing");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/integrations/github/contracts.py",
        &python_slop_bundle("contracts", "validate_app_event_envelope_payload"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/ingress.py",
        &python_slop_bundle("ingress", "ingest_webhook_event"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/reactions.py",
        &python_slop_bundle("reactions", "publish_issue_comment"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/webhook.py",
        &python_slop_bundle("webhook", "handle_github_webhook"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/webhook_commands.py",
        &python_slop_bundle("webhookCommands", "build_command_reaction"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/webhook_service.py",
        &python_slop_bundle("webhookService", "process_merge_recommendation"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/http_client.py",
        &python_clean_module("request_json"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
    for slop_name in [
        "contracts.py",
        "ingress.py",
        "reactions.py",
        "webhook.py",
        "webhook_commands.py",
        "webhook_service.py",
    ] {
        assert!(
            report.contains(slop_name),
            "{slop_name} should be surfaced as slop:\n{}",
            report
        );
    }
    assert!(
        !report.contains("http_client.py"),
        "http_client.py should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    for name in [
        "contracts.py",
        "ingress.py",
        "reactions.py",
        "webhook.py",
        "webhook_commands.py",
        "webhook_service.py",
        "http_client.py",
    ] {
        assert!(
            prompt_text.contains(name),
            "expected {name} to be reviewed by the mock provider:\n{}",
            prompt_text
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_release_rendering_surfaces_real_slop_while_publish_and_analysis_stay_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-release-rendering");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/release/rendering.py",
        &python_slop_bundle("releaseRendering", "build_release_evidence_lines"),
    );
    write_file(
        &root,
        "src/bumpkin/release/publish.py",
        &python_clean_module("publish_release"),
    );
    write_file(
        &root,
        "src/bumpkin/release/analysis.py",
        &python_clean_module("review_release_analysis"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("rendering.py"),
        "rendering.py should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["publish.py", "analysis.py"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("rendering.py")
            && prompt_text.contains("publish.py")
            && prompt_text.contains("analysis.py"),
        "expected the release rendering surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_webhook_release_flow_surfaces_real_slop_while_notes_and_commands_stay_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-webhook-release-flow");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/integrations/github/webhook_release_flow.py",
        &python_slop_bundle("webhookReleaseFlow", "process_release_command"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/release_notes.py",
        &python_clean_module("build_release_notes"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/commands.py",
        &python_clean_module("list_commands"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("webhook_release_flow.py"),
        "webhook_release_flow.py should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["release_notes.py", "commands.py"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("webhook_release_flow.py")
            && prompt_text.contains("release_notes.py")
            && prompt_text.contains("commands.py"),
        "expected the webhook release flow surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_persistence_surfaces_real_slop_while_protocols_stay_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-persistence");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/integrations/github/persistence_ephemeral.py",
        &python_clean_module("create_ephemeral_store"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/persistence_sqlite.py",
        &python_slop_bundle("persistenceSqlite", "load_sqlite_state"),
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/persistence_protocols.py",
        &python_clean_module("describe_persistence_protocols"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
    {
        let slop_name = "persistence_sqlite.py";
        assert!(
            report.contains(slop_name),
            "{slop_name} should be surfaced as slop:\n{}",
            report
        );
    }
    assert!(
        !report.contains("persistence_protocols.py"),
        "persistence_protocols.py should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    for name in ["persistence_sqlite.py", "persistence_protocols.py"] {
        assert!(
            prompt_text.contains(name),
            "expected {name} to be reviewed by the mock provider:\n{}",
            prompt_text
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn multiline_llm_evidence_survives_recovery_and_still_flags_slop() {
    let root = unique_root("sniff-dogfood-multiline-evidence");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/multiline-evidence.ts",
        r#"
export function buildOutputPayload(status: string, payload: string) {
  const lines: string[] = [];
  lines.push(status.trim());
  lines.push(payload.trim());
  if (status.includes("error")) {
    lines.push("retry");
  } else if (payload.length > 120) {
    lines.push("chunk");
  } else {
    lines.push("ok");
  }
  return lines.join(":");
}

export function normalizePayload(payload: string) {
  const parts = payload.split("\n");
  return parts
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

export function renderPayloadSummary(payload: string) {
  const normalized = normalizePayload(payload);
  if (normalized.length === 0) {
    return "empty";
  }
  if (normalized.length > 4) {
    return normalized.slice(0, 4).join(",");
  }
  return normalized.join("|");
}

export function auditPayloadLine(line: string) {
  let total = 0;
  for (const ch of line) {
    if (ch === "{") {
      total += 2;
    } else if (ch === "}") {
      total += 2;
    } else if (ch === ":") {
      total += 1;
    } else {
      total += 1;
    }
  }
  return total;
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
        .arg(".")
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
        report.contains("multiline-evidence.ts"),
        "expected multiline evidence file to survive JSON recovery and stay in the report:\n{}",
        report
    );
    assert!(
        report.contains("Slop"),
        "expected the recovered malformed response to still count as slop:\n{}",
        report
    );

    let prompts = prompts.lock().unwrap();
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("Filename: multiline-evidence.ts")),
        "expected multiline-evidence.ts to be reviewed by the mock provider"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_analysis_hotspots_survive_end_to_end() {
    let root = unique_root("sniff-dogfood-bumpkin-analysis");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    for name in [
        "case_file.py",
        "finding_js_ts.py",
        "finding_python_signature_findings.py",
        "finding_python_signatures.py",
        "finding_python_surface_findings.py",
        "semantic_review.py",
    ] {
        write_file(
            &root,
            &format!("src/bumpkin/analysis/{name}"),
            &format!(
                "def {stem}_orchestrate(items):\n    total = 0\n    for item in items:\n        if item:\n            total += 1\n        else:\n            total += 0\n    if total > 3:\n        return total\n    return total\n{}\n",
                branchy_python_helpers(name.trim_end_matches(".py"), 18),
                stem = name.trim_end_matches(".py")
            ),
        );
    }
    write_file(
        &root,
        "src/bumpkin/analysis/findings.py",
        "def summarize_findings():\n    return []\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
    for name in [
        "case_file.py",
        "finding_js_ts.py",
        "finding_python_signatures.py",
        "semantic_review.py",
    ] {
        assert!(
            report.contains(name),
            "expected {name} to survive end-to-end and remain in the report:\n{}",
            report
        );
    }
    assert!(
        !report.contains("src\\bumpkin\\analysis\\findings.py"),
        "the small findings helper should stay out of the report:\n{}",
        report
    );

    let prompts = prompts.lock().unwrap();
    for name in [
        "Filename: case_file.py",
        "Filename: finding_js_ts.py",
        "Filename: finding_python_signatures.py",
        "Filename: semantic_review.py",
    ] {
        assert!(
            prompts.iter().any(|prompt| prompt.contains(name)),
            "expected {name} to be reviewed by the mock provider"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_provider_hotspots_survive_end_to_end() {
    let root = unique_root("sniff-dogfood-bumpkin-providers");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/providers/chunking.py",
        &format!(
            "def split_diff_units_into_chunks(units):\n    chunks = []\n    for unit in units:\n        if unit is None:\n            continue\n        if isinstance(unit, str) and len(unit) > 80:\n            chunks.append(unit[:80])\n        elif isinstance(unit, str):\n            chunks.append(unit)\n        else:\n            chunks.append(str(unit))\n    return chunks\n\n{}",
            branchy_python_helpers("chunking", 18)
        ),
    );
    write_file(
        &root,
        "src/bumpkin/providers/semantic.py",
        &format!(
            "def semantic_fallback_recommendation(items):\n    score = 0\n    for item in items:\n        if item:\n            score += 1\n        else:\n            score -= 1\n    if score > 4:\n        return \"high\"\n    if score > 0:\n        return \"medium\"\n    return \"low\"\n\n{}",
            branchy_python_helpers("semantic", 18)
        ),
    );
    write_file(
        &root,
        "src/bumpkin/providers/llm.py",
        "def get_recommendation(prompt):\n    return prompt.strip()\n",
    );
    write_file(
        &root,
        "src/bumpkin/providers/llm_transport.py",
        "def post_prompt(prompt):\n    return {\"prompt\": prompt}\n",
    );
    write_file(
        &root,
        "src/bumpkin/providers/llm_recommend.py",
        "from .llm import get_recommendation\n",
    );
    write_file(
        &root,
        "src/bumpkin/providers/__init__.py",
        "from .llm import get_recommendation\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("chunking.py"),
        "expected chunking.py to remain in the report:\n{}",
        report
    );
    assert!(
        report.contains("semantic.py"),
        "expected semantic.py to remain in the report:\n{}",
        report
    );
    assert!(
        !report.contains("llm.py"),
        "the provider facade should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("llm_transport.py"),
        "the transport layer should stay out of the report:\n{}",
        report
    );

    let prompts = prompts.lock().unwrap();
    for name in [
        "Filename: chunking.py",
        "Filename: semantic.py",
        "Filename: llm.py",
        "Filename: llm_transport.py",
        "Filename: llm_recommend.py",
    ] {
        assert!(
            prompts.iter().any(|prompt| prompt.contains(name)),
            "expected {name} to be reviewed by the mock provider"
        );
    }

    let _ = fs::remove_dir_all(&root);
}
