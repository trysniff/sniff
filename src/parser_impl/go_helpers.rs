use super::*;

#[path = "go_refs.rs"]
pub(crate) mod refs;
#[path = "go_scan.rs"]
mod scan;

pub(crate) use scan::{SymbolExtractor, extract_methods, get_parser, parse_source};
