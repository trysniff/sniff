use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdsConfig {
    #[serde(default = "default_max_loc")]
    pub max_loc: usize,
    #[serde(default = "default_max_nesting")]
    pub max_nesting: usize,
    #[serde(default = "default_max_params")]
    pub max_params: usize,
    #[serde(default = "default_max_methods_per_file")]
    pub max_methods_per_file: usize,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        ThresholdsConfig {
            max_loc: default_max_loc(),
            max_nesting: default_max_nesting(),
            max_params: default_max_params(),
            max_methods_per_file: default_max_methods_per_file(),
        }
    }
}

fn default_max_loc() -> usize {
    100
}
fn default_max_nesting() -> usize {
    6
}
fn default_max_params() -> usize {
    6
}
fn default_max_methods_per_file() -> usize {
    20
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LLMConfig {
    #[serde(default)]
    pub system_context: String,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedConfig {
    #[serde(default)]
    pub thresholds: ThresholdsConfig,
    #[serde(default = "default_ignore")]
    pub ignore: Vec<String>,
    #[serde(default = "default_generic_names")]
    pub generic_names: Vec<String>,
    #[serde(default = "default_generic_file_names")]
    pub generic_file_names: Vec<String>,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub llm: LLMConfig,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        ResolvedConfig {
            thresholds: ThresholdsConfig::default(),
            ignore: default_ignore(),
            generic_names: default_generic_names(),
            generic_file_names: default_generic_file_names(),
            model: default_model(),
            llm: LLMConfig::default(),
        }
    }
}

fn default_ignore() -> Vec<String> {
    vec![
        "node_modules".into(),
        ".next".into(),
        ".turbo".into(),
        ".cache".into(),
        "dist".into(),
        "build".into(),
        "out".into(),
        "output".into(),
        "screenshots".into(),
        ".git".into(),
        "coverage".into(),
        "__pycache__".into(),
        ".venv".into(),
        "vendor".into(),
        "target".into(),
    ]
}

fn default_generic_names() -> Vec<String> {
    vec![
        "handle*".into(),
        "process*".into(),
        "do*".into(),
        "manage*".into(),
        "get*".into(),
        "set*".into(),
        "update*".into(),
        "data".into(),
        "temp".into(),
        "result".into(),
        "info".into(),
        "stuff".into(),
        "misc".into(),
    ]
}

fn default_generic_file_names() -> Vec<String> {
    vec![
        "utils".into(),
        "helpers".into(),
        "misc".into(),
        "common".into(),
        "shared".into(),
        "tools".into(),
    ]
}

fn default_model() -> String {
    String::new()
}
