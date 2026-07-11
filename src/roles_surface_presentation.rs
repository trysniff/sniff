use crate::roles::{contains_any, file_name, normalize_path};
use crate::types::FileRecord;

fn is_route_surface_path(normalized: &str, name: &str) -> bool {
    if !normalized.contains("/app/") {
        return false;
    }

    matches!(
        name,
        "page.tsx"
            | "layout.tsx"
            | "template.tsx"
            | "loading.tsx"
            | "error.tsx"
            | "not-found.tsx"
            | "default.tsx"
            | "route.tsx"
            | "page.jsx"
            | "layout.jsx"
            | "template.jsx"
            | "loading.jsx"
            | "error.jsx"
            | "not-found.jsx"
            | "default.jsx"
            | "route.jsx"
    ) || (normalized.contains("/pages/")
        && matches!(name, "index.tsx" | "index.jsx" | "page.tsx" | "page.jsx"))
}

fn is_component_surface_path(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "/components/",
            "/ui/",
            "/views/",
            "/screens/",
            "/sections/",
            "/modals/",
            "/templates/",
            "/layouts/",
        ],
    )
}

fn is_root_app_shell_path(normalized: &str, name: &str) -> bool {
    matches!(name, "app.tsx" | "app.jsx")
        && (normalized.starts_with("src/") || normalized.contains("/src/"))
}

fn source_looks_like_jsx_surface(source: &str) -> bool {
    let lowered = source.to_lowercase();
    (lowered.contains("return (") || lowered.contains("return <") || lowered.contains("return\n<"))
        && source.contains('<')
}

fn is_small_kotlin_compose_surface(file: &FileRecord, normalized: &str) -> bool {
    if !(normalized.ends_with(".kt") || normalized.ends_with(".kts")) {
        return false;
    }
    if !normalized.contains("/screens/")
        && !normalized.contains("/components/")
        && !normalized.contains("/ui-compose/")
    {
        return false;
    }
    if !file.source.contains("@Composable") {
        return false;
    }
    if file.methods.len() == 1 {
        let max_method_loc = file
            .methods
            .iter()
            .map(|method| method.loc)
            .max()
            .unwrap_or(0);
        return max_method_loc <= 60;
    }

    if file.methods.len() < 4 || file.methods.len() > 20 {
        return false;
    }

    let max_method_loc = file
        .methods
        .iter()
        .map(|method| method.loc)
        .max()
        .unwrap_or(0);
    max_method_loc <= 120
}

pub fn is_presentation_surface_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    let name = file_name(&normalized);

    if is_small_kotlin_compose_surface(file, &normalized) {
        return true;
    }

    if !(normalized.ends_with(".tsx") || normalized.ends_with(".jsx")) {
        return false;
    }

    if is_route_surface_path(&normalized, name) {
        return true;
    }

    if is_root_app_shell_path(&normalized, name)
        && file.methods.len() <= 4
        && source_looks_like_jsx_surface(&file.source)
    {
        return true;
    }

    if file.methods.len() > 4 {
        return false;
    }

    is_component_surface_path(&normalized) && source_looks_like_jsx_surface(&file.source)
}
