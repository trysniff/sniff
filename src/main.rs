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
mod repository_proof;
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
pub mod synthesis;
pub mod types;
pub mod walker;

mod cli_banner;
mod counterfactual;
mod sandbox;
mod source_privacy;

use clap::Parser;
use std::thread;

pub mod benchmark;

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
        let launcher_jar = match std::env::var_os("SNIFF_GRADLE_LAUNCHER_JAR") {
            Some(launcher_jar) => launcher_jar,
            None => {
                eprintln!("internal Gradle launcher missing SNIFF_GRADLE_LAUNCHER_JAR");
                return Some(2);
            }
        };
        let main_class = match std::env::var("SNIFF_GRADLE_MAIN_CLASS") {
            Ok(main_class)
                if matches!(
                    main_class.as_str(),
                    "org.gradle.wrapper.GradleWrapperMain" | "org.gradle.launcher.GradleMain"
                ) =>
            {
                main_class
            }
            _ => {
                eprintln!("internal Gradle launcher has an unsupported main class");
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
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if let Err(error) = normalize_gradle_init_script_paths(&arguments) {
            eprintln!(
                "internal Gradle launcher could not normalize scip-java init script: {error}"
            );
            return Some(2);
        }
        let java_home = match std::env::var_os("JAVA_HOME") {
            Some(java_home) => java_home,
            None => {
                eprintln!("internal Gradle launcher missing JAVA_HOME");
                return Some(2);
            }
        };
        let java = std::path::PathBuf::from(java_home).join("bin/java.exe");
        let mut command = std::process::Command::new(java);
        let java_options = match std::env::var("JAVA_OPTS") {
            Ok(options) => options,
            Err(_) => {
                eprintln!("internal Gradle launcher missing JAVA_OPTS");
                return Some(2);
            }
        };
        let Some((base_options, agent)) = java_options.rsplit_once(" -javaagent:") else {
            eprintln!("internal Gradle launcher has malformed JAVA_OPTS");
            return Some(2);
        };
        if base_options != semantic_indexer_runner::GRADLE_INDEXER_BASE_JVM_ARGS || agent.is_empty()
        {
            eprintln!("internal Gradle launcher rejected unexpected JAVA_OPTS");
            return Some(2);
        }
        command.args(base_options.split_ascii_whitespace());
        command.arg(format!("-javaagent:{agent}"));
        let status = command
            .arg("-Dorg.gradle.appname=gradle")
            .arg("-classpath")
            .arg(launcher_jar)
            .arg(main_class)
            .arg("-p")
            .arg(&project)
            .args(arguments)
            .current_dir(project)
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

#[cfg(windows)]
fn normalize_gradle_init_script_paths(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    let Some(index) = arguments.iter().position(|argument| {
        argument == std::ffi::OsStr::new("--init-script") || argument == std::ffi::OsStr::new("-I")
    }) else {
        return Ok(());
    };
    let script = arguments
        .get(index + 1)
        .ok_or_else(|| "Gradle init-script flag has no path".to_string())?;
    let script = std::path::Path::new(script);
    let contents = std::fs::read_to_string(script).map_err(|error| {
        format!(
            "failed to read Gradle init script {}: {error}",
            script.display()
        )
    })?;
    let normalized = contents.replace('\\', "/");
    std::fs::write(script, normalized).map_err(|error| {
        format!(
            "failed to rewrite Gradle init script {}: {error}",
            script.display()
        )
    })?;
    Ok(())
}
