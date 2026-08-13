use clap::{Parser, Subcommand};

#[path = "cli_pipeline.rs"]
mod pipeline;

fn parse_budget_usd(value: &str) -> Result<f64, String> {
    let budget = value
        .trim()
        .parse::<f64>()
        .map_err(|_| "budget must be a number in USD".to_string())?;
    if !budget.is_finite() || budget < 0.0 {
        return Err("budget must be a finite, non-negative number in USD".to_string());
    }
    Ok(budget)
}

#[derive(Parser, Debug)]
#[command(name = "sniff")]
#[command(version)]
#[command(
    about = "Find unnecessary or misleading implementation machinery in codebases.",
    long_about = None
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    #[arg(default_value = ".")]
    pub path: String,

    #[arg(long, global = true)]
    pub skip_dotenv: bool,

    #[arg(long)]
    pub estimate: bool,

    #[arg(
        long,
        global = true,
        help = "approve an unusually expensive scan without prompting"
    )]
    pub yes: bool,

    #[arg(
        long,
        global = true,
        allow_hyphen_values = true,
        value_parser = parse_budget_usd,
        help = "pause before admitting more paid reviews at this cumulative estimated scan cost"
    )]
    pub budget_usd: Option<f64>,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Validate configuration, source discovery, and report access without reviewing code.
    Doctor {
        #[arg(default_value = ".")]
        path: String,

        /// Send one small paid request through the configured provider.
        #[arg(long)]
        probe: bool,
    },
    /// Install and verify the pinned compiler semantic indexers required by a repository.
    Indexers {
        #[command(subcommand)]
        command: IndexerCommand,
    },
    /// Show persisted scan progress without loading configuration or contacting a provider.
    Status {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Continue an interrupted scan from its durable journal.
    Resume {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Evaluate a complete held-out SniffBench prediction ledger without contacting a provider.
    Benchmark {
        #[command(subcommand)]
        command: BenchmarkCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum BenchmarkCommand {
    /// Create a deterministic ranked worksheet from a pinned OSS sampling frame.
    PrepareSelection {
        /// Precommitted frame identity, seed, quotas, prefix, and size limits.
        policy: String,
        /// Exact pinned OpenSSF project-list CSV declared by the policy.
        frame: String,
        /// New label-free assessment worksheet; existing files are never overwritten.
        output: String,
    },
    /// Bind a larger selection endpoint to a completed, underfilled prior round.
    PrepareExtension {
        /// Schema-v2 draft policy with the larger endpoint and no prefilled continuation hashes.
        policy_draft: String,
        /// Exact pinned sampling-frame CSV shared with the prior round.
        frame: String,
        /// Completed prior assessment worksheet to commit into the extension policy.
        prior_worksheet: String,
        /// New finalized extension policy; existing files are never overwritten.
        output: String,
    },
    /// Extend a completed, underfilled frozen selection without changing prior ranks.
    ExtendSelection {
        /// Precommitted schema-v2 policy with the larger endpoint and prior commitments.
        policy: String,
        /// Exact pinned sampling-frame CSV shared with the prior round.
        frame: String,
        /// Completed prior assessment worksheet committed by the extension policy.
        prior_worksheet: String,
        /// New worksheet containing the immutable prior prefix and unassessed continuation.
        output: String,
    },
    /// Assess every ranked OSS candidate with GitHub metadata and an exact local method census.
    AssessSelection {
        /// Same precommitted policy used to prepare the worksheet.
        policy: String,
        /// Exact pinned sampling-frame CSV declared by the policy.
        frame: String,
        /// Immutable ranked worksheet created by `prepare-selection`.
        worksheet: String,
        /// Durable per-rank checkpoints and temporary source worktrees.
        state_directory: String,
        /// Selected clean checkouts retained at OWNER/REPOSITORY for source sealing.
        checkout_root: String,
        /// New completed assessment worksheet; existing files are never overwritten.
        output: String,
    },
    /// Validate every ranked assessment and emit a committed source-selection audit.
    AuditSelection {
        /// Same precommitted policy used to prepare the worksheet.
        policy: String,
        /// Exact pinned sampling-frame CSV declared by the policy.
        frame: String,
        /// Completed ranked-prefix assessment worksheet.
        worksheet: String,
        /// New immutable selection audit; existing files are never overwritten.
        output: String,
    },
    /// Validate a complete ranked assessment even when its precommitted quotas are underfilled.
    AuditSelectionComponent {
        /// Same precommitted policy used to prepare the worksheet.
        policy: String,
        /// Exact pinned sampling-frame CSV declared by the policy.
        frame: String,
        /// Completed ranked-prefix assessment worksheet.
        worksheet: String,
        /// New immutable component audit; existing files are never overwritten.
        output: String,
    },
    /// Combine precommitted source-selection components and enforce aggregate language quotas.
    CombineSelection {
        /// Precommitted aggregate quotas and ordered component policy/frame hashes.
        policy: String,
        /// New immutable composite audit; existing files are never overwritten.
        output: String,
        /// Verified component audit; repeat in the exact order committed by the policy.
        #[arg(long = "component", required = true)]
        components: Vec<String>,
    },
    /// Freeze a label-free OSS source and eligible-method census before any Sniff run.
    SealSources {
        /// Verified source-selection audit with immutable local checkout identities.
        audit: String,
        /// Exact pinned sampling-frame CSV used by the selection audit.
        frame: String,
        /// Root containing every selected checkout at OWNER/REPOSITORY.
        checkout_root: String,
        /// New source-seal manifest; a create-new sibling source bundle is also written.
        output: String,
    },
    /// Create a source-only worksheet for independent blind method labeling.
    PrepareLabels {
        /// Label-free source seal created before Sniff output or labels.
        seal: String,
        /// New reviewer worksheet; existing files are never overwritten.
        output: String,
    },
    /// Validate independent completed label worksheets and preserve every dispute.
    AuditLabels {
        /// Label-free source seal used to create every worksheet.
        seal: String,
        /// New label-audit ledger; existing files are never overwritten.
        output: String,
        /// Independently completed worksheet; repeat for every reviewer.
        #[arg(long = "review", required = true)]
        reviews: Vec<String>,
    },
    /// Create a human-resolution draft from a verified independent label audit.
    PrepareResolution {
        /// Label-free source seal used for the independent reviews.
        seal: String,
        /// Verified output from `audit-labels`.
        audit: String,
        /// New resolution draft; existing files are never overwritten.
        output: String,
    },
    /// Validate completed human resolutions and emit corpus-ready blind cases.
    ResolveLabels {
        /// Label-free source seal used for the independent reviews.
        seal: String,
        /// Verified output from `audit-labels`.
        audit: String,
        /// Completed draft from `prepare-resolution`.
        resolution: String,
        /// New immutable blind-case bundle; existing files are never overwritten.
        output: String,
    },
    /// Verify snapshot and blind-label bundle hashes and create a SniffBench v5 corpus.
    Freeze {
        /// Draft corpus manifest; snapshot paths are relative to its directory.
        draft: String,
        /// New frozen manifest path; existing files are never overwritten.
        output: String,
    },
    /// Create a label-blind review worksheet from immutable completed scans.
    PrepareRun {
        /// Frozen SniffBench corpus manifest.
        corpus: String,
        /// New review worksheet path; existing files are never overwritten.
        output: String,
        /// Completed `.sniff/runs/*.json` artifact; repeat once per repository revision.
        #[arg(long = "artifact", required = true)]
        artifacts: Vec<String>,
    },
    /// Verify a completed blind-review worksheet and emit one BenchmarkRun ledger.
    ImportRun {
        /// Frozen SniffBench corpus manifest.
        corpus: String,
        /// Independently completed review worksheet from `prepare-run`.
        review: String,
        /// New BenchmarkRun JSON path; existing files are never overwritten.
        output: String,
    },
    /// Evaluate complete runs and competitor ledgers against a frozen corpus.
    Evaluate {
        /// Frozen SniffBench v5 corpus manifest and source-snapshot directory.
        corpus: String,
        /// Complete SniffBench v5 runs, adjudications, usage, and baseline ledgers.
        submission: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum IndexerCommand {
    /// Download, verify, and atomically install required indexers.
    Install {
        #[arg(default_value = ".")]
        path: String,

        /// Replace an existing invalid installation after verifying its exact cache path.
        #[arg(long)]
        force: bool,
    },
    /// Execute required pinned indexers and strictly ingest their SCIP output.
    Index {
        #[arg(default_value = ".")]
        path: String,
    },
}

pub async fn run(args: CliArgs) -> Result<i32, Box<dyn std::error::Error>> {
    if args.command.is_some() && args.estimate {
        return Err("--estimate cannot be combined with a subcommand".into());
    }
    if args.budget_usd.is_some()
        && (args.estimate
            || matches!(
                &args.command,
                Some(CliCommand::Doctor { .. } | CliCommand::Status { .. })
            ))
    {
        return Err("--budget-usd is only valid for a normal scan or `sniff resume`".into());
    }

    match args.command {
        Some(CliCommand::Doctor { path, probe }) => {
            pipeline::doctor(&path, args.skip_dotenv, probe).await
        }
        Some(CliCommand::Indexers { command }) => match command {
            IndexerCommand::Install { path, force } => {
                pipeline::install_indexers(&path, force).await
            }
            IndexerCommand::Index { path } => pipeline::index_semantic_sources(&path).await,
        },
        Some(CliCommand::Status { path }) => pipeline::status(&path).await,
        Some(CliCommand::Resume { path }) => {
            pipeline::resume(&path, args.skip_dotenv, args.yes, args.budget_usd).await
        }
        Some(CliCommand::Benchmark { command }) => match command {
            BenchmarkCommand::PrepareSelection {
                policy,
                frame,
                output,
            } => pipeline::prepare_benchmark_source_selection(&policy, &frame, &output),
            BenchmarkCommand::PrepareExtension {
                policy_draft,
                frame,
                prior_worksheet,
                output,
            } => pipeline::prepare_benchmark_source_selection_extension(
                &policy_draft,
                &frame,
                &prior_worksheet,
                &output,
            ),
            BenchmarkCommand::ExtendSelection {
                policy,
                frame,
                prior_worksheet,
                output,
            } => pipeline::extend_benchmark_source_selection(
                &policy,
                &frame,
                &prior_worksheet,
                &output,
            ),
            BenchmarkCommand::AssessSelection {
                policy,
                frame,
                worksheet,
                state_directory,
                checkout_root,
                output,
            } => {
                pipeline::assess_benchmark_source_selection(
                    &policy,
                    &frame,
                    &worksheet,
                    &state_directory,
                    &checkout_root,
                    &output,
                )
                .await
            }
            BenchmarkCommand::AuditSelection {
                policy,
                frame,
                worksheet,
                output,
            } => pipeline::audit_benchmark_source_selection(&policy, &frame, &worksheet, &output),
            BenchmarkCommand::AuditSelectionComponent {
                policy,
                frame,
                worksheet,
                output,
            } => pipeline::audit_benchmark_source_selection_component(
                &policy, &frame, &worksheet, &output,
            ),
            BenchmarkCommand::CombineSelection {
                policy,
                output,
                components,
            } => pipeline::combine_benchmark_source_selections(&policy, &output, &components),
            BenchmarkCommand::SealSources {
                audit,
                frame,
                checkout_root,
                output,
            } => pipeline::seal_benchmark_sources(&audit, &frame, &checkout_root, &output),
            BenchmarkCommand::PrepareLabels { seal, output } => {
                pipeline::prepare_benchmark_labels(&seal, &output)
            }
            BenchmarkCommand::AuditLabels {
                seal,
                output,
                reviews,
            } => pipeline::audit_benchmark_labels(&seal, &output, &reviews),
            BenchmarkCommand::PrepareResolution {
                seal,
                audit,
                output,
            } => pipeline::prepare_benchmark_label_resolution(&seal, &audit, &output),
            BenchmarkCommand::ResolveLabels {
                seal,
                audit,
                resolution,
                output,
            } => pipeline::resolve_benchmark_labels(&seal, &audit, &resolution, &output),
            BenchmarkCommand::Freeze { draft, output } => {
                pipeline::freeze_benchmark(&draft, &output)
            }
            BenchmarkCommand::PrepareRun {
                corpus,
                output,
                artifacts,
            } => pipeline::prepare_benchmark_run(&corpus, &output, &artifacts),
            BenchmarkCommand::ImportRun {
                corpus,
                review,
                output,
            } => pipeline::import_benchmark_run(&corpus, &review, &output),
            BenchmarkCommand::Evaluate { corpus, submission } => {
                pipeline::benchmark(&corpus, &submission)
            }
        },
        None if args.estimate => pipeline::estimate(&args.path, args.skip_dotenv).await,
        None => pipeline::run(&args.path, args.skip_dotenv, args.yes, args.budget_usd).await,
    }
}

#[cfg(test)]
mod tests {
    use super::{BenchmarkCommand, CliArgs, CliCommand, IndexerCommand};
    use clap::Parser;

    #[test]
    fn parses_doctor_with_an_explicit_paid_probe() {
        let args = CliArgs::try_parse_from(["sniff", "doctor", "repo", "--probe"])
            .expect("doctor arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Doctor { path, probe }) if path == "repo" && probe
        ));

        let assess = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "assess-selection",
            "policy.json",
            "projects.csv",
            "selection-review.json",
            "selection-state",
            "checkouts",
            "selection-complete.json",
        ])
        .expect("benchmark source-selection assessment arguments");
        assert!(matches!(
            assess.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::AssessSelection {
                    policy,
                    frame,
                    worksheet,
                    state_directory,
                    checkout_root,
                    output
                }
            }) if policy == "policy.json"
                && frame == "projects.csv"
                && worksheet == "selection-review.json"
                && state_directory == "selection-state"
                && checkout_root == "checkouts"
                && output == "selection-complete.json"
        ));
    }

    #[test]
    fn parses_explicit_indexer_installation() {
        let args = CliArgs::try_parse_from(["sniff", "indexers", "install", "repo", "--force"])
            .expect("indexer installation arguments");
        assert!(matches!(
            args.command,
            Some(CliCommand::Indexers {
                command: IndexerCommand::Install { path, force }
            }) if path == "repo" && force
        ));
    }

    #[test]
    fn parses_explicit_indexer_execution() {
        let args = CliArgs::try_parse_from(["sniff", "indexers", "index", "repo"])
            .expect("indexer execution arguments");
        assert!(matches!(
            args.command,
            Some(CliCommand::Indexers {
                command: IndexerCommand::Index { path }
            }) if path == "repo"
        ));
    }

    #[test]
    fn parses_non_llm_estimate_mode() {
        let args =
            CliArgs::try_parse_from(["sniff", "--estimate", "repo"]).expect("estimate arguments");

        assert!(args.estimate);
        assert_eq!(args.path, "repo");
    }

    #[test]
    fn parses_offline_status() {
        let args = CliArgs::try_parse_from(["sniff", "status", "repo"]).expect("status arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Status { path }) if path == "repo"
        ));
    }

    #[test]
    fn parses_offline_benchmark_ledgers() {
        let args = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "evaluate",
            "cases.json",
            "predictions.json",
        ])
        .expect("benchmark arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::Evaluate { corpus, submission }
            })
                if corpus == "cases.json" && submission == "predictions.json"
        ));
    }

    #[test]
    fn parses_offline_benchmark_freeze() {
        let args =
            CliArgs::try_parse_from(["sniff", "benchmark", "freeze", "draft.json", "frozen.json"])
                .expect("benchmark freeze arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::Freeze { draft, output }
            }) if draft == "draft.json" && output == "frozen.json"
        ));
    }

    #[test]
    fn parses_offline_benchmark_source_seal() {
        let prepare = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "prepare-selection",
            "policy.json",
            "projects.csv",
            "selection-review.json",
        ])
        .expect("benchmark source-selection preparation arguments");
        assert!(matches!(
            prepare.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::PrepareSelection { policy, frame, output }
            }) if policy == "policy.json"
                && frame == "projects.csv"
                && output == "selection-review.json"
        ));

        let audit = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "audit-selection",
            "policy.json",
            "projects.csv",
            "selection-review.json",
            "selection-audit.json",
        ])
        .expect("benchmark source-selection audit arguments");
        assert!(matches!(
            audit.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::AuditSelection {
                    policy,
                    frame,
                    worksheet,
                    output
                }
            }) if policy == "policy.json"
                && frame == "projects.csv"
                && worksheet == "selection-review.json"
                && output == "selection-audit.json"
        ));

        let component = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "audit-selection-component",
            "policy.json",
            "projects.csv",
            "selection-review.json",
            "selection-component.json",
        ])
        .expect("benchmark source-selection component arguments");
        assert!(matches!(
            component.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::AuditSelectionComponent {
                    policy,
                    frame,
                    worksheet,
                    output
                }
            }) if policy == "policy.json"
                && frame == "projects.csv"
                && worksheet == "selection-review.json"
                && output == "selection-component.json"
        ));

        let composite = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "combine-selection",
            "composite-policy.json",
            "selection-composite.json",
            "--component",
            "base.json",
            "--component",
            "kotlin.json",
        ])
        .expect("benchmark composite source-selection arguments");
        assert!(matches!(
            composite.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::CombineSelection {
                    policy,
                    output,
                    components
                }
            }) if policy == "composite-policy.json"
                && output == "selection-composite.json"
                && components == ["base.json", "kotlin.json"]
        ));

        let args = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "seal-sources",
            "selection-audit.json",
            "projects.csv",
            "checkouts",
            "blind-source-seal.json",
        ])
        .expect("benchmark source-seal arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::SealSources { audit, frame, checkout_root, output }
            }) if audit == "selection-audit.json"
                && frame == "projects.csv"
                && checkout_root == "checkouts"
                && output == "blind-source-seal.json"
        ));
    }

    #[test]
    fn parses_offline_benchmark_label_workflow() {
        let prepare = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "prepare-labels",
            "blind-source-seal.json",
            "review-a.json",
        ])
        .expect("prepare label arguments");
        assert!(matches!(
            prepare.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::PrepareLabels { seal, output }
            }) if seal == "blind-source-seal.json" && output == "review-a.json"
        ));

        let audit = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "audit-labels",
            "blind-source-seal.json",
            "label-audit.json",
            "--review",
            "review-a.json",
            "--review",
            "review-b.json",
        ])
        .expect("audit label arguments");
        assert!(matches!(
            audit.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::AuditLabels { seal, output, reviews }
            }) if seal == "blind-source-seal.json"
                && output == "label-audit.json"
                && reviews == ["review-a.json", "review-b.json"]
        ));

        let prepare_resolution = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "prepare-resolution",
            "blind-source-seal.json",
            "label-audit.json",
            "resolution.json",
        ])
        .expect("prepare resolution arguments");
        assert!(matches!(
            prepare_resolution.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::PrepareResolution { seal, audit, output }
            }) if seal == "blind-source-seal.json"
                && audit == "label-audit.json"
                && output == "resolution.json"
        ));

        let resolve = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "resolve-labels",
            "blind-source-seal.json",
            "label-audit.json",
            "resolution.json",
            "blind-cases.json",
        ])
        .expect("resolve label arguments");
        assert!(matches!(
            resolve.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::ResolveLabels {
                    seal,
                    audit,
                    resolution,
                    output
                }
            }) if seal == "blind-source-seal.json"
                && audit == "label-audit.json"
                && resolution == "resolution.json"
                && output == "blind-cases.json"
        ));
    }

    #[test]
    fn parses_offline_benchmark_run_preparation() {
        let args = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "prepare-run",
            "corpus.json",
            "review.json",
            "--artifact",
            "python.json",
            "--artifact",
            "typescript.json",
        ])
        .expect("benchmark prepare-run arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::PrepareRun { corpus, output, artifacts }
            }) if corpus == "corpus.json"
                && output == "review.json"
                && artifacts == ["python.json", "typescript.json"]
        ));
    }

    #[test]
    fn parses_offline_benchmark_run_import() {
        let args = CliArgs::try_parse_from([
            "sniff",
            "benchmark",
            "import-run",
            "corpus.json",
            "review.json",
            "run.json",
        ])
        .expect("benchmark import-run arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Benchmark {
                command: BenchmarkCommand::ImportRun { corpus, review, output }
            }) if corpus == "corpus.json" && review == "review.json" && output == "run.json"
        ));
    }

    #[test]
    fn parses_explicit_resume_approval() {
        let args = CliArgs::try_parse_from(["sniff", "resume", "repo", "--yes"])
            .expect("resume arguments");

        assert!(matches!(
            args.command,
            Some(CliCommand::Resume { path }) if path == "repo"
        ));
        assert!(args.yes);
    }

    #[test]
    fn parses_expensive_scan_approval() {
        let args = CliArgs::try_parse_from(["sniff", "repo", "--yes"]).expect("scan arguments");

        assert!(args.yes);
    }

    #[test]
    fn parses_a_non_negative_scan_budget() {
        let args = CliArgs::try_parse_from(["sniff", "repo", "--budget-usd", "0.75"])
            .expect("budget arguments");

        assert_eq!(args.budget_usd, Some(0.75));
    }

    #[test]
    fn rejects_negative_and_non_finite_scan_budgets() {
        for value in ["-0.01", "NaN", "inf", "-inf"] {
            let error = CliArgs::try_parse_from(["sniff", "--budget-usd", value])
                .expect_err("invalid budget must not parse");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn rejects_removed_optional_file_review_modes() {
        for flag in ["--with-file-reviews", "--only-files"] {
            let error = CliArgs::try_parse_from(["sniff", flag])
                .expect_err("legacy optional review mode must not parse");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[tokio::test]
    async fn rejects_estimate_with_a_subcommand() {
        let args = CliArgs::try_parse_from(["sniff", "--estimate", "doctor"])
            .expect("arguments should parse before mode validation");

        let error = super::run(args).await.expect_err("conflicting modes");

        assert_eq!(
            error.to_string(),
            "--estimate cannot be combined with a subcommand"
        );
    }
}
