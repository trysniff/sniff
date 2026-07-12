use super::*;

#[test]
fn wrapper_only_modules_are_detected() {
    let path = "src/version.py";
    let file = FileRecord {
            file_path: path.to_string(),
            source: String::new(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "detect_next_version".to_string(),
                    file_path: path.to_string(),
                    source: "def detect_next_version(label):\n    from bumpkin.versioning.tags import detect_next_version as _detect_next_version\n\n    return _detect_next_version(label)\n".to_string(),
                    loc: 5,
                    param_count: 1,
                    start_line: 1,
                    end_line: 5,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };

    assert!(is_wrapper_only_module(&file));
}

#[test]
fn real_version_py_is_wrapper_only() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\version.py",
        "from bumpkin.versioning import tags\n\n\
def bump_semver(version, label):\n    return tags.bump_semver(version, label)\n\n\
def parse_tag(tag):\n    return tags.parse_tag(tag)\n\n\
def detect_next_version(label):\n    return tags.detect_next_version(label)\n",
    );
    assert!(is_wrapper_only_module(&file));
    assert_eq!(file.methods.len(), 3);
}

#[test]
fn local_computation_is_not_treated_as_wrapper_export() {
    let line = "cleaned = data.strip()";
    assert!(!is_wrapper_assignment(line));
    assert!(!is_python_alias_export_assignment(line));
}

#[test]
fn pure_delegation_methods_are_detected() {
    let method = MethodRecord {
            name: "_categorize_failure_reason".to_string(),
            file_path: "src/main.py".to_string(),
            source: "def _categorize_failure_reason(reason: str | None) -> str | None:\n    return orchestrator_adjudication.categorize_failure_reason(reason)\n".to_string(),
            loc: 2,
            param_count: 1,
            start_line: 1,
            end_line: 2,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };

    assert!(is_thin_delegation_method(&method));
}

#[test]
fn ordinary_python_assignment_methods_are_not_treated_as_delegation() {
    let method = MethodRecord {
        name: "compute".to_string(),
        file_path: "src/demo.py".to_string(),
        source:
            "def compute(data):\n    cleaned = data.strip()\n    normalized = cleaned.lower()\n    return normalized\n"
                .to_string(),
        loc: 4,
        param_count: 1,
        start_line: 1,
        end_line: 4,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    assert!(!is_thin_delegation_method(&method));
}

#[test]
fn expression_bodied_delegation_methods_are_detected() {
    let method = MethodRecord {
        name: "reduce".to_string(),
        file_path:
            "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitRemindersCabinetReducer.kt"
                .to_string(),
        source:
            "internal fun reduce(\n  state: RemindersCabinetState,\n  intent: RemindersCabinetIntent,\n): RemindersCabinetTransition = RemindersCabinetReducer.reduce(state, intent)"
                .to_string(),
        loc: 4,
        param_count: 2,
        start_line: 1,
        end_line: 4,
        is_exported: false,
        language: "kotlin".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    assert!(is_thin_delegation_method(&method));
}

#[test]
fn pure_delegation_modules_are_detected() {
    let file = FileRecord {
            file_path: "src/diff.py".to_string(),
            source: "from bumpkin.analysis import diff_core\n\ndef _run_git(args: list[str]) -> str:\n    return diff_core.run_git(args)\n\ndef _repository_root() -> str:\n    return diff_core.repository_root(run_git_fn=_run_git)\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "_run_git".to_string(),
                    file_path: "src/diff.py".to_string(),
                    source: "def _run_git(args: list[str]) -> str:\n    return diff_core.run_git(args)\n".to_string(),
                    loc: 2,
                    param_count: 1,
                    start_line: 3,
                    end_line: 4,
                    is_exported: false,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "_repository_root".to_string(),
                    file_path: "src/diff.py".to_string(),
                    source: "def _repository_root() -> str:\n    return diff_core.repository_root(run_git_fn=_run_git)\n".to_string(),
                    loc: 2,
                    param_count: 0,
                    start_line: 6,
                    end_line: 7,
                    is_exported: false,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };

    assert!(is_wrapper_only_module(&file));
}

#[test]
fn multiline_forwarding_facades_are_detected() {
    let method = MethodRecord {
            name: "build_diff".to_string(),
            file_path: "src/diff.py".to_string(),
            source: "def build_diff(\n    from_ref: str,\n    to_ref: str,\n    ignore_patterns: Iterable[str] | None = None,\n    allowed_files: Iterable[str] | None = None,\n) -> DiffResult:\n    return diff_core.build_diff(\n        from_ref,\n        to_ref,\n        ignore_patterns=ignore_patterns,\n        allowed_files=allowed_files,\n    )\n".to_string(),
            loc: 12,
            param_count: 4,
            start_line: 1,
            end_line: 12,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };

    assert!(is_thin_delegation_method(&method));
}

#[test]
fn builder_style_utility_methods_are_not_treated_as_thin_delegation() {
    let method = MethodRecord {
        name: "sanitizeMedicationStrengthInput".to_string(),
        file_path:
            "C:\\Users\\User\\AppData\\Local\\Temp\\sniff-dogfood-medication-numeric-rules\\shared\\contract\\src\\commonMain\\kotlin\\com\\pillit\\shared\\uicontract\\MedicationNumericRules.kt"
                .to_string(),
        source: r#"
public fun sanitizeMedicationStrengthInput(value: String): String {
  var slashSeen = false
  var currentPartHasDigits = false
  var currentPartHasDecimal = false
  var anyDigitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          currentPartHasDigits = true
          anyDigitSeen = true
        }
        character == '.' && !currentPartHasDecimal -> {
          if (!currentPartHasDigits) {
            append('0')
            currentPartHasDigits = true
            anyDigitSeen = true
          }
          append(character)
          currentPartHasDecimal = true
        }
        character == '/' && !slashSeen && currentPartHasDigits && !endsWith(".") -> {
          append(character)
          slashSeen = true
          currentPartHasDigits = false
          currentPartHasDecimal = false
        }
        character == '/' && slashSeen -> break
      }
    }
  }.takeIf { anyDigitSeen }.orEmpty()
}
"#
        .to_string(),
        loc: 33,
        param_count: 1,
        start_line: 1,
        end_line: 33,
        is_exported: true,
        language: "kotlin".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let file = FileRecord {
        file_path:
            "C:\\Users\\User\\AppData\\Local\\Temp\\sniff-dogfood-medication-numeric-rules\\shared\\contract\\src\\commonMain\\kotlin\\com\\pillit\\shared\\uicontract\\MedicationNumericRules.kt"
                .to_string(),
        source: method.source.clone(),
        language: "kotlin".to_string(),
        methods: vec![method.clone()],
    };

    assert!(!is_thin_delegation_method(&method));
    assert!(!is_wrapper_only_module(&file));
}

#[test]
fn real_diff_py_is_a_facade_module() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\diff.py",
        "from bumpkin.analysis import diff_core\n\n\
def _run_git(args):\n    return diff_core._run_git(args)\n\n\
def _repository_root():\n    return diff_core._repository_root(run_git_fn=_run_git)\n",
    );
    assert!(is_wrapper_only_module(&file));
    assert!(file.methods.iter().any(is_thin_delegation_method));
}

#[test]
fn real_court_py_is_a_wrapper_only_module() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\orchestrator\\court.py",
        "from bumpkin.orchestrator import court_core\n\n\
def extract_content(payload):\n    return court_core.extract_content(payload)\n",
    );
    assert!(is_wrapper_only_module(&file));
    assert!(file.methods.iter().any(is_thin_delegation_method));
}

#[test]
fn real_webhook_service_py_is_not_treated_as_intentional_surface() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\integrations\\github\\webhook_service.py",
        "def handle_webhook(event):\n    return event\n",
    );
    assert_eq!(
        classify_file_role(
            "C:\\Users\\User\\bumpkin\\src\\bumpkin\\integrations\\github\\webhook_service.py"
        ),
        FileRole::AdapterIntegration
    );
    assert!(!is_intentional_surface_record(&file));
    assert!(!is_wrapper_only_module(&file));
}

#[test]
fn real_persistence_protocols_py_is_intentional_surface() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\integrations\\github\\persistence_protocols.py",
        "from typing import Protocol\n\n\
class EventPersistenceStore(Protocol):\n    def record_event(self, event): ...\n",
    );
    assert!(is_protocol_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn real_llm_transport_py_is_intentional_surface() {
    let file = super::parse_virtual_file(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm_transport.py",
        "def request_json(endpoint, payload):\n    return payload\n",
    );
    assert!(is_support_plumbing_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm_transport.py"
    ));
    assert!(is_intentional_surface_record(&file));
}
