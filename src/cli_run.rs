use clap::Parser;

#[path = "cli_pipeline.rs"]
mod pipeline;

#[derive(Parser, Debug)]
#[command(name = "sniff")]
#[command(version = "0.1.0")]
#[command(about = "Sniff - a slop finder for codebases.", long_about = None)]
pub struct CliArgs {
    #[arg(default_value = ".")]
    pub path: String,

    #[arg(long)]
    pub verbose: bool,

    #[arg(long)]
    pub only_files: bool,

    #[arg(long)]
    pub skip_dotenv: bool,
}

pub async fn run(
    path: &str,
    verbose: bool,
    only_files: bool,
    skip_dotenv: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    pipeline::run(path, verbose, only_files, skip_dotenv).await
}
