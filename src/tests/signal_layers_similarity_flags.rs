    use super::*;
    use crate::types::MethodRecord;

    fn file(path: &str, methods: Vec<MethodRecord>, source: &str) -> FileRecord {
        FileRecord {
            file_path: path.to_string(),
            source: source.to_string(),
            language: "python".to_string(),
            methods,
        }
    }

    fn protocol_method(path: &str, name: &str) -> MethodRecord {
        MethodRecord {
            name: name.to_string(),
            file_path: path.to_string(),
            source: format!(
                "def {}(\n        self,\n        *,\n        headers: Mapping[str, object],\n        raw_body: bytes,\n    ) -> WebhookResponse: ...\n",
                name
            ),
            loc: 6,
            param_count: 2,
            start_line: 1,
            end_line: 6,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }
    }

    #[test]
    fn protocol_stub_methods_do_not_trigger_similarity_flags() {
        let first = file(
            "src/a.py",
            vec![protocol_method("src/a.py", "handle_github_webhook")],
            "class WebhookHandler(Protocol):\n    def handle_github_webhook(...): ...\n",
        );
        let second = file(
            "src/b.py",
            vec![protocol_method("src/b.py", "handle_github_webhook")],
            "class WebhookHandler(Protocol):\n    def handle_github_webhook(...): ...\n",
        );

        let flags = supporting_similarity_flags(&[first, second]);
        assert!(flags.is_empty());
    }

    #[test]
    fn duplicate_python_helpers_are_detected() {
        let duplicate_body = "def compute(data):\n    cleaned = data.strip()\n    normalized = cleaned.lower()\n    return normalized\n";
        let first = file(
            "src/dup_a.py",
            vec![MethodRecord {
                name: "compute".to_string(),
                file_path: "src/dup_a.py".to_string(),
                source: duplicate_body.to_string(),
                loc: 4,
                param_count: 1,
                start_line: 1,
                end_line: 4,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
            duplicate_body,
        );
        let second = file(
            "src/dup_b.py",
            vec![MethodRecord {
                name: "compute".to_string(),
                file_path: "src/dup_b.py".to_string(),
                source: duplicate_body.to_string(),
                loc: 4,
                param_count: 1,
                start_line: 1,
                end_line: 4,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
            duplicate_body,
        );

        let files = [first.clone(), second.clone()];
        let prepared = build_prepared_methods(&files);
        assert_eq!(prepared.len(), 2);
        let flags = supporting_similarity_flags(&[first, second]);
        assert!(
            flags.iter().any(|flag| flag.gate == "duplication"),
            "expected duplication flag"
        );
    }

    #[test]
    fn pure_delegation_wrappers_do_not_trigger_similarity_flags() {
        let wrapper_body = "def _categorize_failure_reason(reason: str | None) -> str | None:\n    return orchestrator_adjudication.categorize_failure_reason(reason)\n";
        let first = file(
            "src/main.py",
            vec![MethodRecord {
                name: "_categorize_failure_reason".to_string(),
                file_path: "src/main.py".to_string(),
                source: wrapper_body.to_string(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
            wrapper_body,
        );
        let second = file(
            "src/diff.py",
            vec![MethodRecord {
                name: "_estimate_tokens".to_string(),
                file_path: "src/diff.py".to_string(),
                source: "def _estimate_tokens(text: str) -> int:\n    return diff_core.estimate_tokens(text)\n".to_string(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
            "def _estimate_tokens(text: str) -> int:\n    return diff_core.estimate_tokens(text)\n",
        );

        let flags = supporting_similarity_flags(&[first, second]);
        assert!(flags.is_empty(), "delegation wrappers should not look like duplication");
    }
