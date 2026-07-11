#[derive(Debug, Clone)]
pub struct LanguageAdapter {
    pub name: String,
    pub grammar_package: String,
    pub extensions: Vec<String>,
    pub function_node_types: Vec<String>,
    pub excluded_parent_types: Vec<String>,
    pub name_field: String,
    pub params_field: String,
    pub param_node_types: Vec<String>,
    pub nesting_node_types: Vec<String>,
    pub export_detection: ExportDetection,
    pub generic_names: Vec<String>,
    pub allowed_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExportDetection {
    Keyword,
    Convention,
    None,
}
