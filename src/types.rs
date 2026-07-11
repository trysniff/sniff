use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTier {
    Slop,
    KindaSlop,
    Clean,
}

impl FindingTier {
    pub fn label(self) -> &'static str {
        match self {
            FindingTier::Slop => "Slop",
            FindingTier::KindaSlop => "Kinda Slop",
            FindingTier::Clean => "Clean",
        }
    }

    pub fn json_label(self) -> &'static str {
        match self {
            FindingTier::Slop => "slop",
            FindingTier::KindaSlop => "kinda_slop",
            FindingTier::Clean => "clean",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub file_path: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodRecord {
    pub name: String,
    pub file_path: String,
    pub source: String,
    pub loc: usize,
    pub param_count: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub is_exported: bool,
    pub language: String,
    pub nesting_depth: usize,
    pub references: Vec<Reference>,
    pub real_ref_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub file_path: String,
    pub source: String,
    pub language: String,
    pub methods: Vec<MethodRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Variable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolDefinition {
    pub id: usize,
    pub name: String,
    pub kind: SymbolKind,
    pub start_line: usize,
    pub end_line: usize,
    pub is_exported: bool,
    pub owner_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub local_name: String,
    pub source_module: String,
    pub imported_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub exported_name: String,
    pub local_symbol_name: String,
    pub source_module: Option<String>,
    pub source_symbol_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolReference {
    pub name: String,
    pub line: usize,
    pub snippet: String,
    pub resolved_symbol: Option<ResolvedSymbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolvedSymbol {
    Local(usize),
    External {
        file_path: String,
        symbol_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalFileSymbols {
    pub file_path: String,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub references: Vec<SymbolReference>,
}
