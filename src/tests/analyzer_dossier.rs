use super::*;

fn method(source: &str) -> MethodRecord {
    MethodRecord {
        name: "public_api".to_string(),
        file_path: "src/api.py".to_string(),
        source: source.to_string(),
        loc: source.lines().count(),
        param_count: 0,
        start_line: 1,
        end_line: source.lines().count(),
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    }
}

fn file(method: MethodRecord) -> FileRecord {
    FileRecord {
        file_path: method.file_path.clone(),
        source: method.source.clone(),
        language: method.language.clone(),
        methods: vec![method],
    }
}

#[test]
fn lexical_provenance_bounds_large_caller_bodies_to_the_call_site() {
    let source = (1..=200)
        .map(|line| {
            if line == 100 {
                "    target()".to_string()
            } else {
                format!("    sentinel_{line} = {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let method = MethodRecord {
        name: "large_caller".to_string(),
        file_path: "src/large.py".to_string(),
        source: source.clone(),
        loc: 200,
        param_count: 0,
        start_line: 1,
        end_line: 200,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: method.file_path.clone(),
        source,
        language: method.language.clone(),
        methods: vec![method],
    };

    let rendered = render_lexical_call_chains(&[file], &[("src/large.py".to_string(), 100)]);

    assert!(rendered.contains("call site line 100 (bounded context)"));
    assert!(rendered.contains("100 |     target()"));
    assert!(!rendered.contains("1 |     sentinel_1 = 1"));
    assert!(!rendered.contains("200 |     sentinel_200 = 200"));
    assert!(
        rendered.len() < 1_500,
        "bounded context was {} bytes",
        rendered.len()
    );
}

fn empty_facts() -> RepositoryFacts {
    RepositoryFacts {
        rendered: String::new(),
        has_protocol_contract: false,
        has_callback_contract: false,
        has_compatibility_contract: false,
        has_external_contract_evidence: false,
        has_repository_external_visibility: false,
        repository_private_unused_candidate: false,
        stale_discard_signature_proof: None,
    }
}

#[path = "analyzer_dossier_history.rs"]
mod history;
#[path = "analyzer_dossier_proofs.rs"]
mod proofs;
#[path = "analyzer_dossier_resolution.rs"]
mod resolution;
#[path = "analyzer_dossier_surfaces.rs"]
mod surfaces;
