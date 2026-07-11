pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn starts_with_segment(normalized: &str, segment: &str) -> bool {
    normalized.split('/').next() == Some(segment)
}

pub fn contains_any(path: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path.contains(needle))
}

pub fn is_example_path(normalized: &str) -> bool {
    contains_any(normalized, &["/examples/", "/example/"])
        || starts_with_segment(normalized, "examples")
}

pub fn is_fixture_path(normalized: &str) -> bool {
    contains_any(normalized, &["/fixtures/", "/gold_fixtures/", "/fixture/"])
        || starts_with_segment(normalized, "fixtures")
        || starts_with_segment(normalized, "gold_fixtures")
}

pub fn is_script_path(normalized: &str) -> bool {
    contains_any(normalized, &["/scripts/", "/script/"])
        || starts_with_segment(normalized, "scripts")
}

pub fn is_test_path(normalized: &str, name: &str) -> bool {
    contains_any(
        normalized,
        &[
            "/tests/",
            "/commontest/",
            "/androidtest/",
            "/iostest/",
            "/jvmtest/",
        ],
    ) || starts_with_segment(normalized, "tests")
        || name.ends_with("_test.rs")
        || name.ends_with("Test.kt")
        || name.ends_with("Tests.kt")
        || name.ends_with("Test.java")
        || name.ends_with("Tests.java")
        || name.ends_with(".test.ts")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.js")
        || name.ends_with("_spec.rs")
}

pub fn is_docs_path(normalized: &str) -> bool {
    contains_any(normalized, &["/docs/", "/doc/"]) || starts_with_segment(normalized, "docs")
}

pub fn is_generated_path(normalized: &str, name: &str) -> bool {
    contains_any(normalized, &["/generated/", "/gen/"])
        || starts_with_segment(normalized, "generated")
        || name.contains(".generated.")
        || name.starts_with("generated.")
        || name == "generated"
        || name.ends_with(".pyi")
}

pub fn is_entrypoint_path(normalized: &str, name: &str) -> bool {
    matches!(
        name,
        "main.rs" | "main.py" | "main.ts" | "main.tsx" | "main.jsx" | "main.js" | "main.go"
    ) || normalized.ends_with("/bin/main.rs")
        || normalized.ends_with("/bin/main.py")
        || normalized.ends_with("/bin/main.ts")
        || normalized.ends_with("/bin/main.tsx")
        || normalized.ends_with("/bin/main.jsx")
        || normalized.ends_with("/bin/main.js")
        || normalized.ends_with("/bin/main.go")
        || normalized.ends_with("/__main__.py")
        || normalized.ends_with("/__main__.rs")
        || normalized.ends_with("/__main__.ts")
        || normalized.ends_with("/__main__.tsx")
        || normalized.ends_with("/__main__.jsx")
        || normalized.ends_with("/__main__.js")
        || is_serverless_function_entrypoint(normalized, name)
}

pub fn is_serverless_function_entrypoint(normalized: &str, name: &str) -> bool {
    matches!(
        name,
        "index.ts"
            | "index.tsx"
            | "index.js"
            | "index.jsx"
            | "index.py"
            | "index.rs"
            | "index.go"
            | "index.kt"
    ) && contains_any(
        normalized,
        &[
            "supabase/functions/",
            "netlify/functions/",
            "vercel/functions/",
        ],
    )
}

pub fn is_cli_path(name: &str) -> bool {
    matches!(name, "cli.rs" | "cli.py" | "cli.ts" | "cli.js" | "cli.go")
        || name.ends_with("_cli.rs")
        || name.ends_with("_cli.py")
        || name.ends_with("_cli.ts")
        || name.ends_with("_cli.js")
        || name.ends_with("_cli.go")
}

pub fn is_adapter_integration_path(normalized: &str, name: &str) -> bool {
    contains_any(
        normalized,
        &[
            "/adapter/",
            "/adapters/",
            "/integration/",
            "/integrations/",
            "/bridge/",
            "/bridges/",
            "/gateway/",
            "/gateways/",
            "/client/",
            "/clients/",
            "/transport/",
            "/http/",
            "/api/",
            "/grpc/",
            "/rpc/",
            "/connector/",
            "/connectors/",
        ],
    ) || contains_any(
        name,
        &[
            "adapter",
            "bridge",
            "gateway",
            "client",
            "transport",
            "integration",
            "http",
            "api",
            "grpc",
            "rpc",
            "connector",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::{is_entrypoint_path, is_generated_path};

    #[test]
    fn reacts_main_entrypoints_are_treated_as_entrypoints() {
        assert!(is_entrypoint_path("ui/src/main.tsx", "main.tsx"));
        assert!(is_entrypoint_path("ui/src/main.jsx", "main.jsx"));
        assert!(!is_entrypoint_path("ui/src/index.tsx", "index.tsx"));
    }

    #[test]
    fn python_stub_files_are_treated_as_generated() {
        assert!(is_generated_path(
            "src/typedpkg/__init__.pyi",
            "__init__.pyi"
        ));
        assert!(is_generated_path("src/typedpkg/api.pyi", "api.pyi"));
    }
}
