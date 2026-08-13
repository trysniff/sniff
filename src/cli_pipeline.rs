#[path = "cli_pipeline_benchmark.rs"]
mod benchmark_run;
#[path = "cli_pipeline_env.rs"]
mod env;
#[path = "cli_pipeline_graph.rs"]
mod graph;
#[path = "cli_pipeline_io.rs"]
mod io;
#[path = "cli_pipeline_llm.rs"]
mod llm;
#[path = "cli_pipeline_roles.rs"]
mod pipeline_roles;
#[path = "cli_pipeline_preflight.rs"]
mod preflight;
#[path = "cli_pipeline_run.rs"]
mod run;
#[path = "cli_pipeline_stats.rs"]
mod stats;

pub(crate) use benchmark_run::{
    benchmark, freeze_benchmark, import_benchmark_run, prepare_benchmark_run,
    seal_benchmark_sources,
};
pub use preflight::{doctor, estimate, index_semantic_sources, install_indexers};
pub use run::{resume, run, status};
