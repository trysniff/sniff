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
pub mod product_contract;
pub mod report_types;
pub mod reporter;
#[path = "analyzer_journal.rs"]
pub(crate) mod review_journal;
pub mod roles;
pub mod scorer;
pub(crate) mod semantic_cache;
pub mod semantic_index;
pub mod semantic_index_scip;
pub(crate) mod semantic_indexer_doctor;
pub(crate) mod semantic_indexer_installation;
pub(crate) mod semantic_indexer_installer;
pub(crate) mod semantic_indexer_manifest;
pub(crate) mod semantic_indexer_runner;
pub(crate) mod semantic_method_join;
pub mod signal_layers;
pub mod slop_cases;
pub(crate) mod slop_reason;
pub mod symbol_graph;
pub mod types;
pub mod walker;

mod cli_banner;

use clap::Parser;
use std::thread;

fn main() {
    if let Some(code) = run_internal_windows_gradle_launcher() {
        std::process::exit(code);
    }
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

fn run_internal_windows_gradle_launcher() -> Option<i32> {
    #[cfg(windows)]
    {
        if std::env::var_os("SNIFF_INTERNAL_GRADLE_LAUNCHER").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return None;
        }
        let wrapper = match std::env::var_os("SNIFF_GRADLE_WRAPPER") {
            Some(wrapper) => wrapper,
            None => {
                eprintln!("internal Gradle launcher missing SNIFF_GRADLE_WRAPPER");
                return Some(2);
            }
        };
        let project = match std::env::var_os("SNIFF_GRADLE_PROJECT") {
            Some(project) => project,
            None => {
                eprintln!("internal Gradle launcher missing SNIFF_GRADLE_PROJECT");
                return Some(2);
            }
        };
        let status = std::process::Command::new("cmd.exe")
            .arg("/d")
            .arg("/c")
            .arg("call")
            .arg(wrapper)
            .arg("-p")
            .arg(project)
            .args(std::env::args_os().skip(1))
            .status();
        Some(match status {
            Ok(status) => status.code().unwrap_or(1),
            Err(error) => {
                eprintln!("internal Gradle launcher failed: {error}");
                2
            }
        })
    }

    #[cfg(not(windows))]
    {
        None
    }
}
