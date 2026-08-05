pub mod analyzer;
pub mod callgraph;
pub mod cli;
pub mod config;
pub mod config_loader;
pub mod env_value;
pub mod file_verdicts;
pub mod language_adapter;
pub mod languages;
pub mod llm;
pub mod parser;
pub mod pricing;
pub mod report_types;
pub mod reporter;
pub mod roles;
pub mod scorer;
pub mod signal_layers;
pub(crate) mod slop_reason;
pub mod symbol_graph;
pub mod types;
pub mod walker;

mod cli_banner;

use clap::Parser;
use std::thread;

fn main() {
    let args = cli::CliArgs::parse();
    cli_banner::print();
    let handle = match thread::Builder::new()
        .name("sniff-runner".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => return Err(format!("failed to build tokio runtime: {}", err)),
            };
            rt.block_on(async move { cli::run(args).await.map_err(|e| e.to_string()) })
        }) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("Fatal error: failed to spawn sniff runner: {}", err);
            std::process::exit(2);
        }
    };

    match handle.join() {
        Ok(Ok(code)) => std::process::exit(code),
        Ok(Err(e)) => {
            eprintln!("Fatal error: {}", e);
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("Fatal error: sniff runner thread panicked");
            std::process::exit(2);
        }
    }
}
