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
    /// Verify snapshot hashes and create an immutable SniffBench v2 corpus manifest.
    Freeze {
        /// Draft corpus manifest; snapshot paths are relative to its directory.
        draft: String,
        /// New frozen manifest path; existing files are never overwritten.
        output: String,
    },
    /// Evaluate complete runs and competitor ledgers against a frozen corpus.
    Evaluate {
        /// Frozen SniffBench v2 corpus manifest and source-snapshot directory.
        corpus: String,
        /// Complete SniffBench v2 runs, adjudications, usage, and baseline ledgers.
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
            BenchmarkCommand::Freeze { draft, output } => {
                pipeline::freeze_benchmark(&draft, &output)
            }
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
