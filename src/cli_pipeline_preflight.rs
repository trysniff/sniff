use crate::config::ResolvedConfig;
use crate::pricing::PricingRates;
use crate::types::FileRecord;
use std::collections::BTreeMap;
use std::io::{Error as IoError, ErrorKind, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{env, io, llm, pipeline_roles, run};

const CHARS_PER_TOKEN: usize = 3;
const LOWER_OUTPUT_TOKENS_PER_METHOD: usize = 250;
const UPPER_OUTPUT_TOKENS_PER_METHOD: usize = 900;
const LOWER_SECONDS_PER_REQUEST: usize = 5;
// Provider-side reasoning made a measured 135-method Ky run exceed the former
// 60-second ceiling. Keep the public estimate conservative across providers.
const UPPER_SECONDS_PER_REQUEST: usize = 120;

#[derive(Debug, Clone)]
pub(super) struct ScanEstimate {
    pub files: usize,
    pub methods: usize,
    pub languages: BTreeMap<String, usize>,
    pub source_chars: usize,
    pub input_tokens_low: usize,
    pub input_tokens_high: usize,
    pub output_tokens_low: usize,
    pub output_tokens_high: usize,
    pub requests_low: usize,
    pub requests_high: usize,
    pub runtime_seconds_low: usize,
    pub runtime_seconds_high: usize,
    pub cost_low: f64,
    pub cost_high: f64,
    pub confirmation_reasons: Vec<String>,
    pub rates: PricingRates,
}

impl ScanEstimate {
    pub(super) fn from_files(files: &[FileRecord]) -> Self {
        let files_count = files.len();
        let methods = files.iter().map(|file| file.methods.len()).sum::<usize>();
        let source_chars = files
            .iter()
            .map(|file| file.source.chars().count())
            .sum::<usize>();
        let method_chars = files
            .iter()
            .flat_map(|file| &file.methods)
            .map(|method| method.source.chars().count())
            .sum::<usize>();
        let batch_size = configured_usize("SNIFF_LLM_METHOD_BATCH_SIZE", 8, 1, 8);
        let concurrency = configured_usize("SNIFF_LLM_MAX_CONCURRENCY", 4, 1, 8);
        let batches = files
            .iter()
            .map(|file| ceil_div(file.methods.len(), batch_size))
            .sum::<usize>();
        let repeated_file_chars = files
            .iter()
            .map(|file| file.source.chars().count() * ceil_div(file.methods.len(), batch_size))
            .sum::<usize>();
        let review_chars = repeated_file_chars.saturating_add(method_chars);
        let input_chars_low = review_chars
            .saturating_mul(2)
            .saturating_add(methods.saturating_mul(1_800));
        let input_chars_high = review_chars
            .saturating_mul(3)
            .saturating_add(source_chars)
            .saturating_add(methods.saturating_mul(6_000));
        let input_tokens_low = ceil_div(input_chars_low, CHARS_PER_TOKEN);
        let input_tokens_high = ceil_div(input_chars_high, CHARS_PER_TOKEN);
        let output_tokens_low = methods.saturating_mul(LOWER_OUTPUT_TOKENS_PER_METHOD);
        let output_tokens_high = methods.saturating_mul(UPPER_OUTPUT_TOKENS_PER_METHOD);
        let requests_low = batches.saturating_mul(2);
        let requests_high = batches.saturating_mul(3);
        let runtime_seconds_low =
            ceil_div(requests_low, concurrency).saturating_mul(LOWER_SECONDS_PER_REQUEST);
        let runtime_seconds_high =
            ceil_div(requests_high, concurrency).saturating_mul(UPPER_SECONDS_PER_REQUEST);
        let rates = PricingRates::from_env();
        let cost_low = rates.cost(input_tokens_low, 0, output_tokens_low);
        let cost_high = rates.cost(input_tokens_high, 0, output_tokens_high);
        let confirmation_cost = configured_f64("SNIFF_CONFIRM_COST_USD", 1.0);
        let mut confirmation_reasons = Vec::new();
        if cost_high >= confirmation_cost {
            confirmation_reasons.push(format!(
                "upper cost estimate ${cost_high:.2} reaches the ${confirmation_cost:.2} confirmation threshold"
            ));
        }
        if runtime_seconds_high >= 2 * 60 * 60 {
            confirmation_reasons.push("upper runtime estimate reaches two hours".to_string());
        }
        if methods >= 2_000 {
            confirmation_reasons.push("repository contains at least 2,000 methods".to_string());
        }

        let mut languages = BTreeMap::new();
        for file in files {
            *languages.entry(file.language.clone()).or_insert(0) += 1;
        }

        Self {
            files: files_count,
            methods,
            languages,
            source_chars,
            input_tokens_low,
            input_tokens_high,
            output_tokens_low,
            output_tokens_high,
            requests_low,
            requests_high,
            runtime_seconds_low,
            runtime_seconds_high,
            cost_low,
            cost_high,
            confirmation_reasons,
            rates,
        }
    }

    fn is_expensive(&self) -> bool {
        !self.confirmation_reasons.is_empty()
    }
}

fn configured_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn configured_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(default)
}

fn ceil_div(value: usize, divisor: usize) -> usize {
    value.saturating_add(divisor - 1) / divisor
}

fn format_duration(seconds: usize) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let hours = minutes / 60;
    let remaining_minutes = minutes % 60;
    format!("{hours}h {remaining_minutes}m")
}

fn load_scan_inputs(
    path: &str,
    skip_dotenv: bool,
) -> Result<(ResolvedConfig, PathBuf), Box<dyn std::error::Error>> {
    let target = PathBuf::from(path);
    env::load_working_dir_env(skip_dotenv).map_err(IoError::other)?;
    env::load_target_env(&target, skip_dotenv).map_err(IoError::other)?;
    if !target.exists() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("target does not exist: {}", target.display()),
        )
        .into());
    }
    let config = crate::config_loader::resolve_config(&target)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    Ok((config, target))
}

pub async fn estimate(path: &str, skip_dotenv: bool) -> Result<i32, Box<dyn std::error::Error>> {
    let (config, _) = load_scan_inputs(path, skip_dotenv)?;
    let files = io::scan_files(path, &config)
        .await
        .map_err(|err| IoError::other(format!("file scan failed: {err}")))?;
    if files.is_empty() {
        return Err(
            IoError::new(ErrorKind::InvalidInput, "No supported source files found.").into(),
        );
    }
    let estimate = ScanEstimate::from_files(&files);
    print_estimate(&estimate);
    Ok(0)
}

fn print_estimate(estimate: &ScanEstimate) {
    println!("Sniff estimate (no LLM requests were made)");
    println!("  files: {}", estimate.files);
    println!("  methods: {}", estimate.methods);
    println!("  source characters: {}", estimate.source_chars);
    let languages = estimate
        .languages
        .iter()
        .map(|(language, count)| format!("{language} {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  languages: {languages}");
    println!(
        "  estimated input: {}-{} tokens",
        estimate.input_tokens_low, estimate.input_tokens_high
    );
    println!(
        "  estimated output: {}-{} tokens",
        estimate.output_tokens_low, estimate.output_tokens_high
    );
    println!(
        "  estimated requests: {}-{} before retries",
        estimate.requests_low, estimate.requests_high
    );
    println!(
        "  estimated runtime: {}-{}",
        format_duration(estimate.runtime_seconds_low),
        format_duration(estimate.runtime_seconds_high)
    );
    println!(
        "  estimated cost: ${:.2}-${:.2}",
        estimate.cost_low, estimate.cost_high
    );
    println!(
        "  rates: ${:.4}/M input, ${:.4}/M cached input, ${:.4}/M output",
        estimate.rates.input_per_million,
        estimate.rates.cached_input_per_million,
        estimate.rates.output_per_million
    );
    println!(
        "  note: this is a conservative range; provider latency, repairs, caching, and output length vary"
    );
    if estimate.is_expensive() {
        println!("  confirmation required for a real scan:");
        for reason in &estimate.confirmation_reasons {
            println!("    - {reason}");
        }
    }
}

pub(super) fn print_scan_cost_summary(estimate: &ScanEstimate) {
    eprintln!(
        "Estimated LLM cost: ${:.2}-${:.2}; runtime: {}-{} (provider-dependent).",
        estimate.cost_low,
        estimate.cost_high,
        format_duration(estimate.runtime_seconds_low),
        format_duration(estimate.runtime_seconds_high)
    );
}

pub(super) fn confirm_expensive_scan(
    estimate: &ScanEstimate,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !estimate.is_expensive() || assume_yes {
        return Ok(());
    }
    let reason = estimate.confirmation_reasons.join("; ");
    if !std::io::stdin().is_terminal() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("expensive scan requires confirmation ({reason}); rerun with --yes"),
        )
        .into());
    }

    eprint!("This scan may be expensive ({reason}). Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(IoError::new(
            ErrorKind::Interrupted,
            "scan cancelled before any LLM review",
        )
        .into())
    }
}

pub async fn doctor(
    path: &str,
    skip_dotenv: bool,
    probe: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    println!("Sniff doctor");
    let mut failures = Vec::new();
    let target = PathBuf::from(path);

    if target.exists() {
        print_ok("target", &target.display().to_string());
    } else {
        print_fail("target", "path does not exist", &mut failures);
    }

    if let Err(err) = env::load_working_dir_env(skip_dotenv)
        .and_then(|_| env::load_target_env(&target, skip_dotenv))
    {
        print_fail("environment", &err, &mut failures);
    } else {
        print_ok(
            "environment",
            if skip_dotenv {
                ".env loading disabled"
            } else {
                "shell and repository .env loaded"
            },
        );
    }

    let config = match crate::config_loader::resolve_config(&target) {
        Ok(config) => {
            print_ok(
                "configuration",
                "sniff.config.toml and environment resolved",
            );
            Some(config)
        }
        Err(err) => {
            print_fail("configuration", &err, &mut failures);
            None
        }
    };

    let api_key_present = crate::env_value::read("SNIFF_API_KEY").is_some();
    if api_key_present {
        print_ok("API key", "SNIFF_API_KEY is set (value hidden)");
    } else {
        print_fail("API key", "SNIFF_API_KEY is missing", &mut failures);
    }

    if let Some(config) = config.as_ref() {
        validate_endpoint(&config.llm.endpoint, &mut failures);
        if config.model.trim().is_empty() {
            print_fail(
                "model",
                "SNIFF_MODEL and config model are both empty",
                &mut failures,
            );
        } else {
            print_ok("model", config.model.trim());
        }

        if target.exists() {
            match io::scan_files(path, config).await {
                Ok(files) if files.is_empty() => print_fail(
                    "source scan",
                    "no supported Rust, Python, JavaScript/TypeScript, Go, or Kotlin files found",
                    &mut failures,
                ),
                Ok(files) => {
                    print_ok("source scan", &run::source_inventory_summary(&files));
                    let indexer_failures =
                        crate::semantic_indexer_doctor::check_required_indexers(&files).await;
                    if indexer_failures.is_empty() {
                        print_ok(
                            "semantic indexers",
                            "all required pinned indexers are installed and verified",
                        );
                    } else {
                        for failure in indexer_failures {
                            print_fail("semantic indexers", &failure, &mut failures);
                        }
                    }
                }
                Err(err) => print_fail("source scan", &err, &mut failures),
            }
            match check_report_writable(&target) {
                Ok(path) => print_ok("report output", &format!("writable: {}", path.display())),
                Err(err) => print_fail("report output", &err, &mut failures),
            }
        }

        if probe {
            println!("  [paid] provider probe: sending one small model request");
            if failures.is_empty() {
                let client = pipeline_roles::build_llm_client(config).map_err(IoError::other)?;
                llm::preflight_llm_endpoint(path, 1, client.as_ref()).await?;
                print_ok("provider probe", "valid JSON response received");
            } else {
                print_fail(
                    "provider probe",
                    "not sent because required checks failed",
                    &mut failures,
                );
            }
        } else {
            println!(
                "  [skip] provider probe: use `sniff doctor --probe` to make one paid request"
            );
        }
    }

    if failures.is_empty() {
        println!(
            "Doctor passed. No LLM request was made{}.",
            if probe {
                " beyond the explicit probe"
            } else {
                ""
            }
        );
        Ok(0)
    } else {
        Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("doctor found {} failed check(s)", failures.len()),
        )
        .into())
    }
}

fn validate_endpoint(endpoint: &str, failures: &mut Vec<String>) {
    if endpoint.trim().is_empty() {
        print_fail(
            "endpoint",
            "SNIFF_ENDPOINT and config endpoint are both empty",
            failures,
        );
        return;
    }
    match reqwest::Url::parse(endpoint.trim()) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => {
            print_ok("endpoint", endpoint.trim())
        }
        Ok(_) => print_fail("endpoint", "URL must use http or https", failures),
        Err(err) => print_fail("endpoint", &format!("invalid URL: {err}"), failures),
    }
}

fn check_report_writable(target: &Path) -> Result<PathBuf, String> {
    let report_path = run::report_path_for_target(target);
    if report_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&report_path)
            .map_err(|err| format!("cannot write {}: {err}", report_path.display()))?;
        return Ok(report_path);
    }

    let parent = report_path.parent().unwrap_or_else(|| Path::new("."));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let probe = parent.join(format!(".sniff-write-probe-{nonce}"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|err| format!("cannot create report in {}: {err}", parent.display()))?;
    std::fs::remove_file(&probe)
        .map_err(|err| format!("cannot remove write probe {}: {err}", probe.display()))?;
    Ok(report_path)
}

fn print_ok(label: &str, detail: &str) {
    println!("  [ok] {label}: {detail}");
}

fn print_fail(label: &str, detail: &str, failures: &mut Vec<String>) {
    println!("  [fail] {label}: {detail}");
    failures.push(format!("{label}: {detail}"));
}

#[cfg(test)]
mod tests {
    use super::{ScanEstimate, check_report_writable, format_duration};
    use crate::types::{FileRecord, MethodRecord};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn method(path: &str, language: &str, source: &str) -> MethodRecord {
        MethodRecord {
            name: "review".to_string(),
            file_path: path.to_string(),
            source: source.to_string(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: false,
            language: language.to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }
    }

    #[test]
    fn estimate_counts_files_methods_languages_and_nonzero_ranges() {
        let files = vec![FileRecord {
            file_path: "src/main.py".to_string(),
            source: "def review():\n    return 1\n".to_string(),
            language: "python".to_string(),
            methods: vec![method(
                "src/main.py",
                "python",
                "def review():\n    return 1",
            )],
        }];

        let estimate = ScanEstimate::from_files(&files);

        assert_eq!(estimate.files, 1);
        assert_eq!(estimate.methods, 1);
        assert_eq!(estimate.languages.get("python"), Some(&1));
        assert!(estimate.input_tokens_high >= estimate.input_tokens_low);
        assert!(estimate.output_tokens_high >= estimate.output_tokens_low);
        assert!(estimate.runtime_seconds_high >= estimate.runtime_seconds_low);
        assert!(estimate.cost_high >= estimate.cost_low);
    }

    #[test]
    fn duration_is_human_readable() {
        assert_eq!(format_duration(5), "5s");
        assert_eq!(format_duration(120), "2m");
        assert_eq!(format_duration(7_500), "2h 5m");
    }

    #[test]
    fn report_probe_does_not_leave_a_file_behind() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-doctor-write-{nonce}"));
        fs::create_dir_all(&root).unwrap();

        let report = check_report_writable(&root).unwrap();

        assert_eq!(
            report.file_name().and_then(|name| name.to_str()),
            Some("sniff-report.md")
        );
        assert_eq!(
            fs::canonicalize(report.parent().unwrap()).unwrap(),
            fs::canonicalize(&root).unwrap()
        );
        assert!(!report.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
