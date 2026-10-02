mod cli_banner;

use clap::Parser;
use sniff::cli;
use std::thread;

fn main() {
    let handle = match thread::Builder::new()
        .name("sniff-runner".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            // Clap builds the complete command graph while parsing, so parsing belongs on the
            // same deliberately sized stack as the rest of the CLI pipeline.
            let args = cli::CliArgs::parse();
            cli_banner::print();
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
