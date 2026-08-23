use super::super::{
    IntentionalBoundaryBehaviorSelector, IntentionalBoundaryBehaviorUnresolvedReason,
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts,
};
use std::path::{Component, Path};

pub(super) fn selector_for(
    test_method: &IntentionalBoundarySemanticMethod,
) -> Result<
    IntentionalBoundaryBehaviorSelector,
    (IntentionalBoundaryBehaviorUnresolvedReason, String),
> {
    if test_method.symbol_name.trim().is_empty()
        || !is_safe_repository_path(&test_method.repository_path)
    {
        return Err((
            IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
            "test method has no safe exact selector".to_string(),
        ));
    }
    Ok(match test_method.indexer {
        IntentionalBoundaryIndexerKind::Rust => IntentionalBoundaryBehaviorSelector::CargoTest {
            test_name: exact_rust_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::Python => IntentionalBoundaryBehaviorSelector::Pytest {
            repository_path: test_method.repository_path.clone(),
            test_name: exact_python_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::Go => IntentionalBoundaryBehaviorSelector::GoTest {
            package_repository_path: parent_repository_path(&test_method.repository_path),
            test_name: exact_go_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::TypeScriptJavaScript => {
            IntentionalBoundaryBehaviorSelector::JavaScriptTest {
                repository_path: test_method.repository_path.clone(),
                test_name: test_method.symbol_name.clone(),
            }
        }
        IntentionalBoundaryIndexerKind::Kotlin => IntentionalBoundaryBehaviorSelector::GradleTest {
            repository_path: test_method.repository_path.clone(),
            test_name: test_method.symbol_name.clone(),
        },
    })
}

fn exact_rust_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    let symbol_id = resolved_symbol_id(method).ok_or_else(unsupported_selector)?;
    rust_harness_name(symbol_id, &method.symbol_name).ok_or_else(unsupported_selector)
}

pub(super) fn rust_harness_name(symbol_id: &str, leaf_name: &str) -> Option<String> {
    let mut fields = symbol_id.splitn(5, ' ');
    if fields.next()? != "rust-analyzer"
        || fields.next()? != "cargo"
        || fields.next()?.is_empty()
        || fields.next()?.is_empty()
    {
        return None;
    }
    let mut descriptors = fields.next()?;
    let mut components = Vec::new();
    while let Some((component, remaining)) = descriptors.split_once('/') {
        if !is_ascii_identifier(component) {
            return None;
        }
        components.push(component);
        descriptors = remaining;
    }
    let function = descriptors.strip_suffix("().")?;
    if function != leaf_name || !is_ascii_identifier(function) {
        return None;
    }
    components.push(function);
    Some(components.join("::"))
}

fn exact_python_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    let symbol = resolved_symbol(method).ok_or_else(unsupported_selector)?;
    if symbol.category != IntentionalBoundarySemanticSymbolCategory::Callable
        || !is_ascii_identifier(&method.symbol_name)
    {
        return Err(unsupported_selector());
    }
    Ok(method.symbol_name.clone())
}

fn exact_go_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    if !is_ascii_identifier(&method.symbol_name) {
        return Err(unsupported_selector());
    }
    Ok(method.symbol_name.clone())
}

fn unsupported_selector() -> (IntentionalBoundaryBehaviorUnresolvedReason, String) {
    (
        IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
        "compiler identity cannot be converted to an exact test selector".to_string(),
    )
}

fn is_ascii_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

pub(super) fn parent_repository_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(|| ".".to_string(), |(parent, _)| parent.to_string())
}

pub(super) fn resolved_symbol_id(method: &IntentionalBoundarySemanticMethod) -> Option<&str> {
    resolved_symbol(method).map(|symbol| symbol.symbol_id.as_str())
}

fn resolved_symbol(
    method: &IntentionalBoundarySemanticMethod,
) -> Option<&IntentionalBoundarySemanticSymbolFacts> {
    match &method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => Some(symbol),
        _ => None,
    }
}

pub(super) fn is_safe_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}
