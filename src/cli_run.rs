use clap::{Parser, Subcommand};

#[path = "cli_pipeline.rs"]
mod pipeline;

#[derive(Parser, Debug)]
#[command(name = "sniff")]
#[command(version)]
#[command(about = "Sniff - a slop finder for codebases.", long_about = None)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    #[arg(default_value = ".")]
    pub path: String,

    #[arg(long = "with-file-reviews", alias = "only-files")]
    pub with_file_reviews: bool,

    #[arg(long, global = true)]
    pub skip_dotenv: bool,

    #[arg(long)]
    pub estimate: bool,

    #[arg(long, help = "approve an unusually expensive scan without prompting")]
    pub yes: bool,
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
}

pub async fn run(args: CliArgs) -> Result<i32, Box<dyn std::error::Error>> {
    if args.command.is_some() && args.estimate {
        return Err("--estimate cannot be combined with a subcommand".into());
    }

    match args.command {
        Some(CliCommand::Doctor { path, probe }) => {
            pipeline::doctor(&path, args.skip_dotenv, probe).await
        }
        None if args.estimate => {
            pipeline::estimate(&args.path, args.with_file_reviews, args.skip_dotenv).await
        }
        None => {
            pipeline::run(
                &args.path,
                args.with_file_reviews,
                args.skip_dotenv,
                args.yes,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CliArgs, CliCommand};
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
    fn parses_non_llm_estimate_mode() {
        let args =
            CliArgs::try_parse_from(["sniff", "--estimate", "repo"]).expect("estimate arguments");

        assert!(args.estimate);
        assert_eq!(args.path, "repo");
    }

    #[test]
    fn parses_expensive_scan_approval() {
        let args = CliArgs::try_parse_from(["sniff", "repo", "--yes"]).expect("scan arguments");

        assert!(args.yes);
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
