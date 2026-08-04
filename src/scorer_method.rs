use crate::config::ResolvedConfig;
use crate::languages;
use crate::report_types::StaticFlag;
use crate::roles::is_protocol_surface_module;
use crate::roles::{is_analysis_finding_support_module, is_intentional_surface_record};
use crate::types::FileRecord;
use std::collections::HashSet;
use std::path::Path;

use super::rules;
use super::tiers;

pub(super) struct MethodFlagInput<'a> {
    pub file: &'a FileRecord,
    pub config: &'a ResolvedConfig,
    pub flags: &'a mut Vec<StaticFlag>,
}

fn is_placeholder_stub_method(method: &crate::types::MethodRecord) -> bool {
    let source = method.source.trim().to_lowercase();
    if source.is_empty() || method.loc > 8 {
        return false;
    }

    let body_line_count = source
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count();
    if body_line_count > 4 {
        return false;
    }

    let discards_args = source.contains("del ");
    let returns_constant = source.contains("return 0")
        || source.contains("return none")
        || source.contains("return false")
        || source.contains("return {}")
        || source.contains("return []");

    discards_args && returns_constant
}

pub(crate) fn is_cfg_test_module_method(
    file: &FileRecord,
    method: &crate::types::MethodRecord,
) -> bool {
    cfg_test_method_lines(file).contains(&method.start_line)
}

pub(crate) fn cfg_test_method_lines(file: &FileRecord) -> HashSet<usize> {
    if !file.file_path.ends_with(".rs") {
        return HashSet::new();
    }
    let Ok(parsed) = syn::parse_file(&file.source) else {
        return HashSet::new();
    };
    let mut spans = Vec::new();
    collect_rust_test_method_spans(
        &parsed.items,
        rust_attrs_select_tests(&parsed.attrs),
        &mut spans,
    );
    file.methods
        .iter()
        .filter(|method| {
            spans
                .iter()
                .any(|(start, end)| *start <= method.start_line && method.start_line <= *end)
        })
        .map(|method| method.start_line)
        .collect()
}

fn rust_attrs_select_tests(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        matches!(&attribute.meta, syn::Meta::List(list)
            if (attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
                && list.tokens.to_string().split(|character: char| !character.is_alphanumeric() && character != '_').any(|token| token == "test"))
    })
}

fn rust_span_lines(span: proc_macro2::Span) -> (usize, usize) {
    (span.start().line, span.end().line)
}

fn collect_rust_test_method_spans(
    items: &[syn::Item],
    inherited_test_context: bool,
    spans: &mut Vec<(usize, usize)>,
) {
    use syn::spanned::Spanned;

    for item in items {
        match item {
            syn::Item::Fn(function)
                if inherited_test_context || rust_attrs_select_tests(&function.attrs) =>
            {
                spans.push(rust_span_lines(function.span()));
            }
            syn::Item::Impl(implementation) => {
                let test_context =
                    inherited_test_context || rust_attrs_select_tests(&implementation.attrs);
                for item in &implementation.items {
                    if let syn::ImplItem::Fn(function) = item
                        && (test_context || rust_attrs_select_tests(&function.attrs))
                    {
                        spans.push(rust_span_lines(function.span()));
                    }
                }
            }
            syn::Item::Trait(trait_item) => {
                let test_context =
                    inherited_test_context || rust_attrs_select_tests(&trait_item.attrs);
                for item in &trait_item.items {
                    if let syn::TraitItem::Fn(function) = item
                        && (test_context || rust_attrs_select_tests(&function.attrs))
                    {
                        spans.push(rust_span_lines(function.span()));
                    }
                }
            }
            syn::Item::Mod(module) => {
                let test_context = inherited_test_context || rust_attrs_select_tests(&module.attrs);
                if let Some((_, nested)) = &module.content {
                    collect_rust_test_method_spans(nested, test_context, spans);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn collect_method_flags(input: MethodFlagInput<'_>) {
    if is_intentional_surface_record(input.file)
        || is_analysis_finding_support_module(&input.file.file_path)
    {
        return;
    }

    let path_obj = Path::new(&input.file.file_path);
    let ext = match path_obj.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return,
    };
    let adapter = match languages::get_adapter(ext) {
        Some(a) => a,
        None => return,
    };

    let cfg_test_methods = cfg_test_method_lines(input.file);
    for method in &input.file.methods {
        if cfg_test_methods.contains(&method.start_line) {
            continue;
        }

        let mut reasons = rules::score_method_reasons(method, input.config, &adapter);

        if !is_protocol_surface_module(input.file) && is_placeholder_stub_method(method) {
            reasons.push("placeholder implementation".to_string());
        }

        if reasons.len() == 1 && reasons[0] == "name is vague" {
            continue;
        }

        if !reasons.is_empty() {
            let tier = tiers::tier_for_reasons(&reasons);
            input.flags.push(StaticFlag {
                flag_type: "method".to_string(),
                file_path: method.file_path.clone(),
                method_name: Some(method.name.clone()),
                reasons,
                tier,
                gate: "scorer".to_string(),
                loc: method.loc,
                start_line: method.start_line,
                end_line: method.end_line,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConfig;
    use crate::types::{FileRecord, MethodRecord};

    #[test]
    fn placeholder_methods_are_flagged() {
        let file = FileRecord {
            file_path: "src/demo.rs".to_string(),
            source: String::new(),
            language: "rust".to_string(),
            methods: vec![MethodRecord {
                name: "record_approval".to_string(),
                file_path: "src/demo.rs".to_string(),
                source: "def record_approval(...):\n    del approval, commit_sha\n    return 0"
                    .to_string(),
                loc: 4,
                param_count: 0,
                start_line: 1,
                end_line: 4,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: Vec::new(),
                real_ref_count: 0,
            }],
        };
        let mut flags = Vec::new();
        collect_method_flags(MethodFlagInput {
            file: &file,
            config: &ResolvedConfig::default(),
            flags: &mut flags,
        });

        assert!(
            flags.iter().any(|flag| flag
                .reasons
                .iter()
                .any(|reason| reason == "placeholder implementation")),
            "expected placeholder implementation to be flagged: {flags:?}"
        );
    }

    #[test]
    fn cfg_test_module_methods_are_ignored() {
        let file = FileRecord {
            file_path: "src/demo.rs".to_string(),
            source: r#"
pub fn build() {}

#[cfg(test)]
mod tests {
    fn spawn_http_status_server() {}
}
"#
            .to_string(),
            language: "rust".to_string(),
            methods: vec![
                MethodRecord {
                    name: "build".to_string(),
                    file_path: "src/demo.rs".to_string(),
                    source: "pub fn build() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 2,
                    end_line: 2,
                    is_exported: true,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: Vec::new(),
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "spawn_http_status_server".to_string(),
                    file_path: "src/demo.rs".to_string(),
                    source: "fn spawn_http_status_server() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 6,
                    end_line: 6,
                    is_exported: false,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: Vec::new(),
                    real_ref_count: 0,
                },
            ],
        };

        assert!(is_cfg_test_module_method(&file, &file.methods[1]));
        assert!(!is_cfg_test_module_method(&file, &file.methods[0]));
    }

    #[test]
    fn isolated_cfg_test_item_does_not_reclassify_later_production_methods() {
        let source = r#"
#[cfg(test)]
fn test_helper() {}

fn production_helper() {}
"#;
        let methods = [
            ("test_helper", "fn test_helper() {}", 3),
            ("production_helper", "fn production_helper() {}", 5),
        ]
        .into_iter()
        .map(|(name, source, line)| MethodRecord {
            name: name.to_string(),
            file_path: "src/demo.rs".to_string(),
            source: source.to_string(),
            loc: 1,
            param_count: 0,
            start_line: line,
            end_line: line,
            is_exported: false,
            language: "rust".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        })
        .collect::<Vec<_>>();
        let file = FileRecord {
            file_path: "src/demo.rs".to_string(),
            source: source.to_string(),
            language: "rust".to_string(),
            methods,
        };

        assert!(is_cfg_test_module_method(&file, &file.methods[0]));
        assert!(!is_cfg_test_module_method(&file, &file.methods[1]));
    }
}
