use super::*;
use crate::parser::parse_file_symbols;
use crate::types::ResolvedSymbol;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_tag(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}_{}_{}", label, std::process::id(), nanos)
}

fn write_temp_file(root: &str, relative: &str, contents: &str) -> String {
    let path = Path::new(root).join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path.to_string_lossy().to_string()
}

#[path = "tests/python_layout.rs"]
mod python_layout;
#[path = "tests/reexports.rs"]
mod reexports;
#[path = "tests/resolution_basics.rs"]
mod resolution_basics;
#[path = "tests/typescript_namespace.rs"]
mod typescript_namespace;
