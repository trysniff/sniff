use clap::Parser;

#[path = "cli_pipeline.rs"]
mod pipeline;

#[derive(Parser, Debug)]
#[command(name = "sniff")]
#[command(version)]
#[command(about = "Sniff - a slop finder for codebases.", long_about = None)]
pub struct CliArgs {
    #[arg(default_value = ".")]
    pub path: String,

    #[arg(long = "with-file-reviews", alias = "only-files")]
    pub with_file_reviews: bool,

    #[arg(long)]
    pub skip_dotenv: bool,
}

pub async fn run(
    path: &str,
    with_file_reviews: bool,
    skip_dotenv: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    pipeline::run(path, with_file_reviews, skip_dotenv).await
}
