use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Command(ProcessCommand);

impl Command {
    fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let mut command = ProcessCommand::new(program);
        // Local mocks should expose contract failures immediately, not inherit
        // the production retry window and make CI appear to hang.
        command
            .arg("--yes")
            .env("SNIFF_LLM_MAX_ATTEMPTS", "2")
            .env("SNIFF_LLM_RETRY_BUDGET_SECS", "5")
            .env("SNIFF_LLM_MAX_FORMAT_REPAIRS", "1")
            .env("SNIFF_LLM_MAX_CONCURRENCY", "1");
        Self(command)
    }
}

impl Deref for Command {
    type Target = ProcessCommand;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Command {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct ManagedChild {
    child: Option<Child>,
}

impl ManagedChild {
    fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }

    fn wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill();
        self.wait();
    }
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("{label}-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let git = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&root)
        .output()
        .expect("git must be available for isolated compiler-index fixtures");
    assert!(
        git.status.success(),
        "failed to initialize isolated compiler-index fixture repository: {}",
        String::from_utf8_lossy(&git.stderr)
    );
    let commit = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Sniff Tests",
            "-c",
            "user.email=sniff-tests@example.invalid",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "fixture",
        ])
        .current_dir(&root)
        .output()
        .expect("git commit must be available for isolated compiler-index fixtures");
    assert!(
        commit.status.success(),
        "failed to create isolated compiler-index fixture HEAD: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    root
}

fn write_file(root: &Path, relative: &str, contents: &str) {
    if relative.ends_with(".go") && !root.join("go.mod").is_file() {
        fs::write(root.join("go.mod"), "module sniff-dogfood\n\ngo 1.25\n").unwrap();
    }
    if relative.ends_with(".kt") && !root.join("build.gradle.kts").is_file() {
        fs::write(
            root.join("settings.gradle.kts"),
            "rootProject.name = \"sniff-dogfood-kotlin\"\n",
        )
        .unwrap();
        fs::write(
            root.join("build.gradle.kts"),
            "plugins { kotlin(\"jvm\") version \"2.2.0\" }\n\nrepositories { mavenCentral() }\n\nkotlin { jvmToolchain(17) }\n",
        )
        .unwrap();
    }
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn ts_slop_module(function_name: &str) -> String {
    let function_name = function_name.replace('-', "_");
    format!(
        "export function {function_name}() {{\n  const values = [1, 2, 3, 4, 5, 6];\n  let total = 0;\n  for (const value of values) {{\n    if (value % 2 === 0) {{\n      total += value;\n    }} else {{\n      total += value * 2;\n    }}\n  }}\n  if (total > 10) {{\n    return total.toString();\n  }}\n  return \"0\";\n}}\n"
    )
}

fn js_slop_bundle(prefix: &str) -> String {
    format!(
        "export function {prefix}Entry(value) {{\n  let total = 0;\n  for (const item of [1, 2, 3, 4, 5, 6]) {{\n    if (item % 2 === 0) {{\n      total += item;\n    }} else {{\n      total += item * 2;\n    }}\n  }}\n  if (value) {{\n    total += value;\n  }}\n  return total;\n}}\n\nexport function {prefix}Fallback(value) {{\n  if (!value) {{\n    return null;\n  }}\n  if (value.length > 3) {{\n    return value.trim();\n  }}\n  return value;\n}}\n\nexport function {prefix}Summarize(items) {{\n  const output = [];\n  for (const item of items) {{\n    if (item) {{\n      output.push(item);\n    }}\n  }}\n  return output.join(\",\");\n}}\n"
    )
}

fn js_branchy_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\nexport function {prefix}Helper{idx:02}(value) {{\n  if (value === 0) {{\n    return 0;\n  }}\n  if (value === 1) {{\n    return 1;\n  }}\n  if (value === 2) {{\n    return 2;\n  }}\n  return value;\n}}\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn python_slop_module(function_name: &str) -> String {
    format!(
        "def {function_name}(items):\n    total = 0\n    for item in items:\n        if item:\n            total += item\n        else:\n            total += 0\n    if total > 10:\n        return total\n    return total\n"
    )
}

fn python_clean_module(function_name: &str) -> String {
    format!("def {function_name}(items):\n    return list(items)\n")
}

fn branchy_python_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\ndef {prefix}_helper_{idx:02}(value):\n    if value == 0:\n        return 0\n    if value == 1:\n        return 1\n    if value == 2:\n        return 2\n    return value\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn ts_clean_module(function_name: &str) -> String {
    format!("export function {function_name}() {{\n  return \"ok\";\n}}\n")
}

fn python_slop_bundle(prefix: &str, function_name: &str) -> String {
    format!(
        "{}{}",
        python_slop_module(function_name),
        branchy_python_helpers(prefix, 18)
    )
}

fn ts_slop_bundle(prefix: &str, function_name: &str) -> String {
    format!(
        "{}{}",
        ts_slop_module(function_name),
        js_branchy_helpers(prefix, 18)
    )
}

fn read_http_request(stream: TcpStream) -> (TcpStream, String) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 {
            break;
        }
        headers.push_str(&line);
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body);
    }

    let request = format!("{}{}", headers, String::from_utf8_lossy(&body));
    (reader.into_inner(), request)
}

fn repair_mock_file_evidence(request: &str, body: &str) -> String {
    if !request.contains("Filename:") || !body.contains("\\\"smelly\\\":true") {
        return body.to_string();
    }

    let source = request
        .split_once("Source:\\n---\\n")
        .and_then(|(_, rest)| rest.split_once("\\n---"))
        .map(|(source, _)| source.replace("\\n", "\n").replace("\\\"", "\""))
        .unwrap_or_default();

    let Ok(mut envelope) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    let Some(content) = envelope
        .pointer("/choices/0/message/content")
        .and_then(serde_json::Value::as_str)
    else {
        return body.to_string();
    };
    let Ok(mut verdict) = serde_json::from_str::<serde_json::Value>(content) else {
        return body.to_string();
    };
    let evidence_is_valid = verdict
        .get("evidence")
        .and_then(serde_json::Value::as_str)
        .map(|evidence| source.contains(evidence))
        .unwrap_or(false);
    if !evidence_is_valid {
        let replacement = source
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if request.contains(".py") {
                    "def ".to_string()
                } else if request.contains(".rs") {
                    "fn ".to_string()
                } else if request.contains(".go") {
                    "func ".to_string()
                } else if request.contains(".kt") {
                    "fun ".to_string()
                } else {
                    "export".to_string()
                }
            });
        verdict["evidence"] = serde_json::Value::String(replacement);
        let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
            return body.to_string();
        };
        *content_slot = serde_json::Value::String(verdict.to_string());
    }

    envelope.to_string()
}

fn remove_method_line_number_prefixes(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            let Some((prefix, remainder)) = line.split_once('|') else {
                return line;
            };
            if prefix.trim().parse::<usize>().is_ok() {
                remainder.strip_prefix(' ').unwrap_or(remainder)
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn request_prompt(request: &str) -> String {
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(request);
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return request.to_string();
    };
    let Some(content) = payload
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
    else {
        return request.to_string();
    };
    if let Some(content) = content.as_str() {
        return content.to_string();
    }
    content
        .as_array()
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(request)
        .to_string()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MockMethodPass {
    Intent,
    Semantic,
}

fn mock_method_pass(prompt: &str) -> Option<MockMethodPass> {
    if prompt.contains("INTENT INVESTIGATION PASS") || prompt.contains("semantic intent pass") {
        return Some(MockMethodPass::Intent);
    }
    if prompt.contains("ADVERSARIAL SEMANTIC PASS")
        || prompt.contains("FINAL ADJUDICATION PASS")
        || prompt.contains("adversarial semantic pass")
        || prompt.contains("final adjudicator")
        || prompt.contains("focused dead-method adjudicator")
        || prompt
            .contains("final severity judge for a deterministically proven private-unused method")
        || prompt.contains("claim-scoped adjudicator")
    {
        return Some(MockMethodPass::Semantic);
    }
    None
}

fn batch_method_block(prompt: &str, index: usize) -> Option<&str> {
    let marker = format!("METHOD KEY: m{index}\n");
    let block = prompt.split_once(&marker)?.1;
    Some(
        block
            .split_once("\n\n================ METHOD ================\n\n")
            .map(|(block, _)| block)
            .unwrap_or(block),
    )
}

fn batch_method_path(prompt: &str, index: usize) -> Option<&str> {
    batch_method_block(prompt, index)?
        .lines()
        .find_map(|line| line.strip_prefix("File path: "))
}

fn batch_method_name(prompt: &str, index: usize) -> Option<&str> {
    batch_method_block(prompt, index)?
        .lines()
        .find_map(|line| line.strip_prefix("Method: "))?
        .split_once(" (")
        .map(|(name, _)| name)
}

fn authoritative_file_source<'a>(prompt: &'a str, path: &str) -> Option<&'a str> {
    let file_marker = format!("Authoritative full containing file: {path}\n---\n");
    let rest = prompt.split_once(&file_marker)?.1;
    for delimiter in [
        "\n---\n\n================ FILE ================\n\n",
        "\n---\n\nMETHOD KEY:",
    ] {
        if let Some((source, _)) = rest.split_once(delimiter) {
            return Some(source);
        }
    }
    None
}

fn batch_method_source(prompt: &str, index: usize) -> Option<(String, usize)> {
    let block = batch_method_block(prompt, index)?;
    let path = batch_method_path(prompt, index)?;
    let range = block
        .lines()
        .find_map(|line| line.strip_prefix("Evidence line range: "))?;
    let (start, end) = range.split_once(" through ")?;
    let start = start.trim().parse::<usize>().ok()?;
    let end = end.trim().parse::<usize>().ok()?;
    let file_source = remove_method_line_number_prefixes(authoritative_file_source(prompt, path)?);
    let method_source = file_source
        .lines()
        .skip(start.saturating_sub(1))
        .take(end.saturating_sub(start).saturating_add(1))
        .collect::<Vec<_>>()
        .join("\n");
    Some((method_source, start))
}

fn mock_hotspot_path(path: &str) -> bool {
    let path = path.replace('\\', "/").to_lowercase();
    [
        "sloppy.py",
        "signup-wrapper/index.ts",
        "session-launch-policy.ts",
        "session-actions.ts",
        "session-state.ts",
        "session-safe-start.ts",
        "session-launch-orchestration.ts",
        "runtime-message-validation.ts",
        "drop-payload-staging.ts",
        "service-worker-runtime-handlers.ts",
        "registry-sync.ts",
        "runtime-wireup.ts",
        "feedback-handlers.ts",
        "crypto-feedback.ts",
        "frame-sync.ts",
        "pipeline.py",
        "planning.py",
        "repository_client.py",
        "rationale.py",
        "comments.py",
        "engine.py",
        "recommendations.py",
        "contracts.py",
        "ingress.py",
        "reactions.py",
        "webhook.py",
        "webhook_commands.py",
        "webhook_service.py",
        "rendering.py",
        "webhook_release_flow.py",
        "persistence_ephemeral.py",
        "persistence_sqlite.py",
        "release_job.py",
        "finding_python_signatures.py",
        "finding_js_ts.py",
        "finding_python_signature_findings.py",
        "finding_python_surface_findings.py",
        "semantic_review.py",
        "case_file.py",
        "chunking.py",
        "semantic.py",
        "checkout-rpc.ts",
        "domain-gateway.ts",
        "multiline-evidence.ts",
        "applicationcontroller.js",
        "jobcontroller.js",
        "postscontroller.js",
        "usercontroller.js",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn apply_mock_semantic_tier(review: &mut serde_json::Value, tier: &str) {
    let unresolved = tier == "unresolved";
    let clean = tier == "clean";
    review["tier"] = serde_json::Value::String(tier.to_string());
    review["contract_status"] = serde_json::Value::String(
        if clean {
            "required"
        } else if unresolved {
            "unknown"
        } else {
            "unnecessary"
        }
        .to_string(),
    );
    review["behavior_status"] =
        serde_json::Value::String(if unresolved { "unknown" } else { "preserved" }.to_string());
    review["pattern"] = serde_json::Value::String(if clean || unresolved {
        "none".to_string()
    } else {
        "residual_machinery".to_string()
    });
    review["simplification"] = serde_json::Value::String(
        if clean || unresolved {
            "none"
        } else {
            "replace the unnecessary machinery with the direct operation"
        }
        .to_string(),
    );
    review["change_scope"] =
        serde_json::Value::String(if clean || unresolved { "none" } else { "local" }.to_string());
    if clean {
        review["reason"] = serde_json::Value::String("clean".to_string());
        review["missing_evidence"] = serde_json::json!([]);
        review["evidence"] = serde_json::json!([]);
    }
}

fn single_method_source(prompt: &str) -> (String, usize) {
    let source = prompt
        .split_once("Method source:\n---\n")
        .and_then(|(_, rest)| rest.split_once("\n---"))
        .map(|(source, _)| remove_method_line_number_prefixes(source))
        .unwrap_or_default();
    let start = prompt
        .split_once("absolute file line numbers from ")
        .and_then(|(_, rest)| rest.split_once(" through "))
        .and_then(|(start, _)| start.trim().parse::<usize>().ok())
        .unwrap_or(1);
    (source, start)
}

fn exact_mock_evidence(source: &str, method_start: usize, preferred: &str) -> serde_json::Value {
    let quote = if !preferred.trim().is_empty() && source.contains(preferred) {
        preferred.to_string()
    } else {
        source
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("return value")
            .to_string()
    };
    let quote_start = source
        .lines()
        .position(|line| line.contains(&quote))
        .map(|offset| method_start + offset)
        .unwrap_or(method_start);
    let quote_end = quote_start + quote.lines().count().saturating_sub(1);
    serde_json::json!([{
        "start_line": quote_start,
        "end_line": quote_end,
        "quote": quote
    }])
}

fn semanticize_method_response(request: &str, body: &str) -> String {
    let decoded_prompt = request_prompt(request);
    let Some(pass) = mock_method_pass(&decoded_prompt) else {
        return body.to_string();
    };

    let Ok(mut envelope) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    if decoded_prompt
        .contains("final severity judge for a deterministically proven private-unused method")
    {
        let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
            return body.to_string();
        };
        *content_slot = serde_json::Value::String(
            serde_json::json!({
                "tier": "slop",
                "reason": "The unused private method adds misleading conceptual machinery."
            })
            .to_string(),
        );
        return envelope.to_string();
    }
    let Some(content) = envelope
        .pointer("/choices/0/message/content")
        .and_then(serde_json::Value::as_str)
    else {
        return body.to_string();
    };
    let Ok(mut verdict) = serde_json::from_str::<serde_json::Value>(content) else {
        return body.to_string();
    };
    let tier = verdict
        .get("tier")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("clean")
        .to_string();
    let reason = verdict
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let batch_count = decoded_prompt.matches("METHOD KEY:").count();

    if pass == MockMethodPass::Intent {
        let missing_evidence = verdict
            .get("missing_evidence")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let content = if batch_count > 0 {
            let has_path_oracle = (0..batch_count).any(|index| {
                batch_method_path(&decoded_prompt, index).is_some_and(mock_hotspot_path)
            });
            let reviews = (0..batch_count)
                .map(|index| {
                    let method_tier = if has_path_oracle {
                        if batch_method_path(&decoded_prompt, index)
                            .is_some_and(mock_hotspot_path)
                        {
                            "slop"
                        } else {
                            "clean"
                        }
                    } else {
                        tier.as_str()
                    };
                    serde_json::json!({
                        "method_key": format!("m{index}"),
                        "intent": "The method performs the behavior represented by this dogfood fixture.",
                        "contract_status": if method_tier == "clean" { "required" } else if method_tier == "unresolved" { "unknown" } else { "unnecessary" },
                        "necessity_check": "The fixture dossier establishes the method contract used by this test.",
                        "missing_evidence": if method_tier == "unresolved" { missing_evidence.clone() } else { serde_json::json!([]) }
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({"reviews": reviews})
        } else {
            serde_json::json!({
                "intent": "The method performs the behavior represented by this dogfood fixture.",
                "contract_status": if tier == "clean" { "required" } else if tier == "unresolved" { "unknown" } else { "unnecessary" },
                "necessity_check": "The fixture dossier establishes the method contract used by this test.",
                "missing_evidence": missing_evidence
            })
        };
        let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
            return body.to_string();
        };
        *content_slot = serde_json::Value::String(content.to_string());
        return envelope.to_string();
    }

    let unresolved = tier == "unresolved";
    verdict["contract_status"] = serde_json::Value::String(
        if tier == "clean" {
            "required"
        } else if unresolved {
            "unknown"
        } else {
            "unnecessary"
        }
        .to_string(),
    );
    verdict["contract_impact"] = serde_json::Value::String(
        if tier == "clean" {
            "The fixture contract requires the current method shape."
        } else if unresolved {
            "The contract impact cannot be established from the fixture evidence."
        } else {
            "The simplification preserves the fixture method signature and contract."
        }
        .to_string(),
    );
    verdict["dependency_impact"] = serde_json::Value::String(if tier == "clean" {
        "The fixture callers depend on the current behavior."
    } else if unresolved {
        "External dependency impact cannot be established."
    } else {
        "No fixture caller, test, adapter, callback, re-export, or compatibility path depends on the redundant machinery."
    }
    .to_string());
    verdict["simplification"] = serde_json::Value::String(
        if unresolved || tier == "clean" {
            "none"
        } else {
            "replace the unnecessary machinery with the direct operation"
        }
        .to_string(),
    );
    verdict["change_scope"] = serde_json::Value::String(
        if unresolved || tier == "clean" {
            "none"
        } else {
            "local"
        }
        .to_string(),
    );
    verdict["behavior_status"] =
        serde_json::Value::String(if unresolved { "unknown" } else { "preserved" }.to_string());
    if !unresolved {
        verdict["missing_evidence"] = serde_json::json!([]);
    }

    verdict["pattern"] = serde_json::Value::String(if tier == "clean" || unresolved {
        "none".to_string()
    } else {
        "residual_machinery".to_string()
    });
    verdict["intent"] = serde_json::Value::String(
        "The method performs the behavior represented by this dogfood fixture.".to_string(),
    );
    verdict["necessity_check"] = serde_json::Value::String(
        "The fixture response includes a semantic necessity check.".to_string(),
    );
    if tier == "clean" || unresolved {
        verdict["smelly"] = serde_json::Value::Bool(false);
        verdict["evidence"] = serde_json::json!([]);
    } else {
        verdict["smelly"] = serde_json::Value::Bool(true);
        let original_evidence = verdict
            .get("evidence")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let (source, method_start) = single_method_source(&decoded_prompt);
        verdict["evidence"] = exact_mock_evidence(&source, method_start, original_evidence);
    }
    verdict["reason"] = serde_json::Value::String(reason);

    let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
        return body.to_string();
    };
    if batch_count > 0 {
        let has_path_oracle = (0..batch_count)
            .any(|index| batch_method_path(&decoded_prompt, index).is_some_and(mock_hotspot_path));
        let reviews = (0..batch_count)
            .map(|index| {
                let mut review = verdict.clone();
                review["method_key"] = serde_json::Value::String(format!("m{index}"));
                let method_tier = if has_path_oracle {
                    if batch_method_path(&decoded_prompt, index).is_some_and(mock_hotspot_path) {
                        "slop"
                    } else {
                        "clean"
                    }
                } else {
                    tier.as_str()
                };
                apply_mock_semantic_tier(&mut review, method_tier);
                if method_tier != "clean" && method_tier != "unresolved" {
                    let preferred = review
                        .get("evidence")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|entries| entries.first())
                        .and_then(|entry| entry.get("quote"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if let Some((source, start)) = batch_method_source(&decoded_prompt, index) {
                        let preferred = if source.contains(preferred) {
                            preferred
                        } else {
                            batch_method_name(&decoded_prompt, index).unwrap_or(preferred)
                        };
                        review["evidence"] = exact_mock_evidence(&source, start, preferred);
                    }
                }
                review
            })
            .collect::<Vec<_>>();
        *content_slot =
            serde_json::Value::String(serde_json::json!({"reviews": reviews}).to_string());
    } else {
        *content_slot = serde_json::Value::String(verdict.to_string());
    }
    envelope.to_string()
}

fn proof_mock_response(request: &str) -> Option<String> {
    let prompt = request_prompt(request);
    if !prompt.contains("counterfactual proof stage")
        && !prompt.contains("RESPONSE RULES")
        && !request.contains("\\nEVIDENCE ")
    {
        return None;
    }

    let mut proofs = Vec::new();
    let mut case_id = None;
    let mut evidence = None;
    let mut evidence_source = Vec::new();
    let mut in_fence = false;

    let mut flush = |case_id: &mut Option<&str>,
                     evidence: &mut Option<(String, usize, usize)>,
                     evidence_source: &mut Vec<String>| {
        let Some(case_id) = case_id.take() else {
            evidence_source.clear();
            return;
        };
        let Some((file_path, start_line, end_line)) = evidence.take() else {
            evidence_source.clear();
            return;
        };
        if evidence_source.is_empty() {
            return;
        }
        let mut replacement = evidence_source.join("\n");
        replacement.push_str("  \n");
        proofs.push(serde_json::json!({
            "case_id": case_id,
            "decision": "validated",
            "reason": "The mock proof changes only trailing whitespace in the cited source.",
            "edits": [{
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "replacement": replacement
            }]
        }));
        evidence_source.clear();
    };

    for line in prompt.lines() {
        if let Some(next_case_id) = line.strip_prefix("CASE ") {
            flush(&mut case_id, &mut evidence, &mut evidence_source);
            case_id = Some(next_case_id.trim());
            in_fence = false;
            continue;
        }
        if let Some(header) = line.strip_prefix("EVIDENCE ") {
            let Some((file_path, range)) = header.rsplit_once(':') else {
                continue;
            };
            let Some((start_line, end_line)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start_line), Ok(end_line)) =
                (start_line.parse::<usize>(), end_line.parse::<usize>())
            else {
                continue;
            };
            evidence = Some((file_path.to_string(), start_line, end_line));
            evidence_source.clear();
            in_fence = false;
            continue;
        }
        if line.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            evidence_source.push(line.to_string());
        }
    }
    flush(&mut case_id, &mut evidence, &mut evidence_source);

    Some(
        serde_json::json!({
            "choices": [{"message": {"content": serde_json::json!({"proofs": proofs}).to_string()}}]
        })
        .to_string(),
    )
}

fn spawn_openai_style_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let (stream_back, request) = read_http_request(stream);
            let body = if let Some(proof_body) = proof_mock_response(&request) {
                proof_body
            } else if request.contains("CASE FIELDS:") {
                r#"{"choices":[{"message":{"content":"{\"cases\":[]}"}}]}"#.to_string()
            } else if request.contains("You classify codebase file roles for Sniff.")
                || (request.contains("probe")
                    && request.contains("Return exactly one JSON object with this shape"))
            {
                r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"mock\"}"}}]}"#.to_string()
            } else if request.contains("Filename:") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#.to_string()
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#.to_string()
            };
            let body = if proof_mock_response(&request).is_some() {
                body
            } else {
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

    (format!("http://{}", addr), hits)
}

fn spawn_unresolved_method_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let (mut stream, request) = read_http_request(stream);
            let body = if let Some(proof_body) = proof_mock_response(&request) {
                proof_body
            } else {
                let prompt = request_prompt(&request);
                let content = if prompt.contains("CASE FIELDS:") {
                    r#"{"cases":[]}"#
                } else if prompt.contains("You classify codebase file roles for Sniff.")
                    || (request.contains("probe")
                        && request.contains("Return exactly one JSON object with this shape"))
                {
                    r#"{"role":"core_library","reason":"production module"}"#
                } else if prompt.contains("Filename:") {
                    r#"{"smelly":false,"tier":"clean","evidence":"","cohesive":true,"name_accurate":true,"reason":"clean"}"#
                } else {
                    r#"{"smelly":false,"tier":"unresolved","pattern":"none","intent":"Forward to an external package boundary.","reason":"The boundary contract cannot be established from repository evidence.","necessity_check":"The external implementation is unavailable.","contract_status":"unknown","contract_impact":"The effect of simplifying the boundary cannot be established.","dependency_impact":"External consumers cannot be inspected.","simplification":"none","change_scope":"none","behavior_status":"unknown","missing_evidence":["external package implementation and consumers"],"evidence":[]}"#
                };
                let body = serde_json::json!({
                    "choices": [{"message": {"content": content}}]
                })
                .to_string();
                semanticize_method_response(&request, &body)
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    format!("http://{}", addr)
}

fn spawn_prompt_logging_server() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
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
                } else if request.contains("Return exactly one JSON object with this shape")
                    || request.contains("You classify codebase file roles for Sniff.")
                {
                    r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"mock\"}"}}]}"#
                } else if request.contains("Method: sloppy") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return total\",\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: sloppy.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return total\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: polar-webhook/index.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"const totals = (order?.totals as Record<string, unknown> | undefined) ?? {};\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"readAmountCents: overbuilt fallback chain with unused totals variable; readCustomerEmail: unnecessary fallback to empty object for customer; readEnvBool: copy-pasted method body\"}"}}]}"#
                } else if request.contains("Filename: drop-payload-staging.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createDropPayloadStaging\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: service-worker-runtime-handlers.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createServiceWorkerRuntimeHandlers\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: registry-sync.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createRegistrySync\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: session-launch-policy.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function mapEntitlementReasonToResponse(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: session-actions.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function createSessionActions(deps: SessionActionsDeps) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: session-state.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function createSessionStateManager(deps: {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: session-safe-start.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function randomIntInclusive(min: number, max: number): number {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: runtime-message-validation.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"if (message.type === \\\"START_SESSION\\\") {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"single function handles validation for many unrelated message types\"}"}}]}"#
                } else if request.contains("Filename: session-launch-orchestration.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"async function prepareSessionLaunch(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: pipeline.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run(args: Namespace, *, comment_poster: CommentPoster | None = None) -> int:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: planning.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def prepare_release_plan(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: runtime-wireup.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"registerRuntimeWireup: function is too big (374 LOC > 100)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: feedback-handlers.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function createFeedbackHandlers(deps: FeedbackHandlersDeps) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: crypto-feedback.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export async function encryptWithSessionKey(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: repository_client.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def get_pull_request(self, number: int) -> ReleaseScopedPullRequest:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: rationale.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_release_why_lines(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: comments.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_recommendation_comment_metadata(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: engine.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def apply_impact_evidence_threshold(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: recommendations.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_api_diff_result(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: frame-sync.ts") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function createFrameSyncCoordinator(chromeApi: typeof chrome) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: contracts.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def validate_app_event_envelope_payload(payload: dict[str, Any]) -> list[str]:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface\"}"}}]}"#
                } else if request.contains("Filename: ingress.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def ingest_webhook_event(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: reactions.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class GitHubIssueCommentPublisher:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: webhook.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def handle_github_webhook(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: webhook_commands.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_command_reaction(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: webhook_service.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def process_merge_recommendation(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: rendering.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_release_evidence_lines(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: webhook_release_flow.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def process_release_command(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: persistence_ephemeral.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class EphemeralAppStateStore:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: persistence_sqlite.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class SqliteAppStateStore:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("signup-wrapper") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function normalizeIpToken(raw: unknown): string | null {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("buildOutputPayload")
                    || request.contains("normalizePayload")
                    || request.contains("renderPayloadSummary")
                    || request.contains("auditPayloadLine")
                    || request.contains("multiline-evidence.ts")
                {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function buildOutputPayload(status: string, payload: string) {\n  const lines: string[] = [];\n  lines.push(status.trim());\n  lines.push(payload.trim());\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("main.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"from bumpkin.release.analysis import (\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: release_job.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_release_job(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: finding_python_signatures.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def extract_python_signatures\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: case_file.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def case_file_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: finding_js_ts.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_js_ts_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: finding_python_signature_findings.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_python_signature_findings_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: finding_python_surface_findings.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_python_surface_findings_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: semantic_review.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_review_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: chunking.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def split_diff_units_into_chunks(units):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: semantic.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_fallback_recommendation(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("applicationController.js")
                    || request.contains("jobController.js")
                    || request.contains("postsController.js")
                    || request.contains("userController.js")
                {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
                };
                let body = repair_mock_file_evidence(&request, body);
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

    (format!("http://{}", addr), hits, prompts)
}

fn spawn_bumpkin_shape_server() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
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
            let proof_body = if request.contains("\\nEVIDENCE ") {
                Some(proof_mock_response(&request).unwrap_or_else(|| {
                    serde_json::json!({
                        "choices": [{"message": {"content": "{\"proofs\":[]}"}}]
                    })
                    .to_string()
                }))
            } else {
                proof_mock_response(&request)
            };
            let body = if let Some(proof_body) = proof_body {
                proof_body
            } else {
                let body = if request.contains("CASE FIELDS:") {
                    r#"{"choices":[{"message":{"content":"{\"cases\":[]}"}}]}"#
                } else if request.contains("Return exactly one JSON object with this shape") {
                    r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#
                } else if request.contains("Filename: checkout-rpc.ts")
                    || request.contains("Filename: domain-gateway.ts")
                {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createCheckoutRpc\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: chunking.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def split_diff_units_into_chunks(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: semantic.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_fallback_recommendation(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: case_file.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def build_case_file(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: finding_js_ts.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_js_ts_export_detection(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: finding_python_signature_findings.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def append_python_signature_findings(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: finding_python_signatures.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def extract_python_signatures(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
                } else if request.contains("Filename: finding_python_surface_findings.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def append_python_surface_findings(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: semantic_review.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def detect_contradictions(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else if request.contains("Filename: release_job.py") {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_release_job(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
                } else {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
                };
                let body = body.to_string();
                let body = repair_mock_file_evidence(&request, &body);
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

    (format!("http://{}", addr), hits, prompts)
}

fn spawn_bumpkin_github_integration_server() -> (String, ManagedChild) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let (mut stream, request) = read_http_request(stream);
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let proof_body = proof_mock_response(&request);
            let body = if let Some(proof_body) = proof_body {
                proof_body
            } else {
                let body = if request.contains("CASE FIELDS:") {
                    r#"{"choices":[{"message":{"content":"{\"cases\":[]}"}}]}"#
                } else if request.contains("Return exactly one JSON object with this shape") {
                    r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#
                } else if request.contains("Filename: contracts.py")
                    || request.contains("Filename: ingress.py")
                    || request.contains("Filename: reactions.py")
                    || request.contains("Filename: recommendations.py")
                    || request.contains("Filename: webhook.py")
                    || request.contains("Filename: webhook_commands.py")
                    || request.contains("Filename: webhook_service.py")
                    || request.contains("Filename: persistence_sqlite.py")
                    || request.contains("Filename: github_auth.py")
                {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function is too big\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
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
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    let _ = ready_rx.recv();
    (format!("http://{}", addr), ManagedChild { child: None })
}

fn populate_bumpkin_like_repo(root: &Path) {
    let packages = ["analysis", "providers", "release", "orchestrator", "github"];

    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );

    for package in packages {
        let package_dir = root.join("src").join("bumpkin").join(package);
        fs::create_dir_all(&package_dir).unwrap();

        write_file(
            root,
            &format!("src/bumpkin/{package}/__init__.py"),
            &format!("from .core import {package}_entry\nfrom .helpers import {package}_helper\n"),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/core.py"),
            &format!(
                "from .helpers import {package}_helper\n\n\
def {package}_entry():\n    return {package}_helper()\n\n\
def {package}_dispatch(flag: bool):\n    if flag:\n        return {package}_helper()\n    return 0\n"
            ),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/helpers.py"),
            &format!(
                "def {package}_helper():\n    return 1\n\n\
def {package}_fallback(value):\n    if value:\n        return value\n    return {package}_helper()\n"
            ),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/bridge.py"),
            &format!(
                "from .core import {package}_entry\n\n\
def bridge_{package}():\n    return {package}_entry()\n"
            ),
        );
    }

    write_file(
        root,
        "src/bumpkin/__init__.py",
        "from .analysis import analysis_entry\nfrom .providers import providers_entry\nfrom .release import release_entry\n",
    );

    write_file(
        root,
        "src/main.py",
        "from bumpkin import analysis_entry\n\ndef main():\n    return analysis_entry()\n",
    );
}

fn populate_react_entrypoint_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "src/main.tsx",
        "import { createRoot } from 'react-dom/client';\n\
         import { App } from './App';\n\
         createRoot(document.getElementById('root')!).render(<App />);\n",
    );
    write_file(
        root,
        "src/App.tsx",
        "export function App() {\n  return <main>Hello</main>;\n}\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_support_boundary_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/background/core/service-worker-support.ts",
        "export async function getImprovementTelemetryConsent() { return true; }\n\
         export async function setImprovementTelemetryConsent(enabled: boolean) { return enabled; }\n\
         export async function migrateNamesetStoreToCanonicalObject() { return; }\n\
         export async function readKillSwitches() { return {}; }\n\
         export function deriveFeedbackContextFromSender(sender: chrome.runtime.MessageSender) { return { domain: null, uriHash: null }; }\n\
         export async function encryptWithSessionKey(plaintext: string) { return plaintext; }\n",
    );
    write_file(
        root,
        "ui/src/lib/feature-flags.ts",
        "export class FeatureFlags {\n\
             static isEnabled(flag: string) { return true; }\n\
             static async setOverride(flag: string, value: boolean) { return value; }\n\
         }\n",
    );
    write_file(
        root,
        "ui/src/lib/password-session-cache.ts",
        "export const getSessionPassword = async (brandId: string) => null;\n\
         export const setSessionPassword = async (brandId: string, password: string) => {};\n\
         export const clearSessionPassword = async (brandId: string) => {};\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_data_catalog_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/src/data/platforms.ts",
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
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_contract_type_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/background/core/session-runtime-contracts.ts",
        "export type LoggerMethod = (...args: unknown[]) => void;\n\
         export type SessionPolicy = 'aggressive_clean' | 'preserve_login';\n\
         export interface PlatformConfig {\n\
           signupUrl?: string;\n\
           checkUrl?: string;\n\
         }\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

#[path = "dogfood/brandset.rs"]
mod brandset;
#[path = "dogfood/bumpkin_github.rs"]
mod bumpkin_github;
#[path = "dogfood/bumpkin_release.rs"]
mod bumpkin_release;
#[path = "dogfood/contracts.rs"]
mod contracts;
#[path = "dogfood/core.rs"]
mod core;
#[path = "dogfood/surfaces.rs"]
mod surfaces;
