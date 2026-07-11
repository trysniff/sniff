#[path = "reporter_console.rs"]
pub mod console;
#[path = "reporter_cost.rs"]
pub mod cost;
#[path = "reporter_markdown.rs"]
pub mod markdown;
#[path = "reporter_render.rs"]
pub mod render;
#[path = "reporter_summary.rs"]
pub mod summary;

pub use render::render_report;
