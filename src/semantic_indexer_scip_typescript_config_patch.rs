use super::scip_typescript_patch::{replace_exact_once, require_sha256};
use crate::semantic_indexer_manifest::{PinnedIndexer, SemanticIndexerKind};
use std::{fs, path::Path};

const ENTRYPOINT: &str = "node_modules/@sourcegraph/scip-typescript/dist/src/main.js";
const UPSTREAM_SHA256: &str = "22104bf4323e7667ff0d6f38606937c467af2d6e1fda171203c2065d9b757979";
const PATCHED_SHA256: &str = "157ecccdcf130655129378a8c9743420bdbea0875775f2e8aa8272c675ea001a";

const BEFORE: &str = r#"    const readResult = ts.readConfigFile(absolute, path => ts.sys.readFile(path));
    if (readResult.error) {
        throw new Error(ts.formatDiagnostics([readResult.error], ts.createCompilerHost({})));
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const config = readResult.config;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    if (config.compilerOptions !== undefined) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        config.compilerOptions = {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            ...config.compilerOptions,
            ...defaultCompilerOptions(file),
        };
    }
    const basePath = path.dirname(absolute);
    const result = ts.parseJsonConfigFileContent(config, ts.sys, basePath);"#;

const AFTER: &str = r#"    const diagnostics = [];
    const result = ts.getParsedCommandLineOfConfigFile(absolute, {}, {
        ...ts.sys,
        onUnRecoverableConfigFileDiagnostic(diagnostic) {
            diagnostics.push(diagnostic);
        },
    });
    if (!result || diagnostics.length > 0) {
        throw new Error(ts.formatDiagnostics(diagnostics, ts.createCompilerHost({})));
    }"#;

pub(super) fn patch_project_config(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript || spec.version != "0.4.0" {
        return Err(
            "TypeScript configuration patch requires pinned scip-typescript 0.4.0".to_string(),
        );
    }
    let path = root.join(ENTRYPOINT);
    let bytes = fs::read(&path).map_err(|error| {
        format!("failed to read pinned TypeScript configuration parser: {error}")
    })?;
    require_sha256(
        &bytes,
        UPSTREAM_SHA256,
        "upstream scip-typescript configuration parser",
    )?;
    let source = String::from_utf8(bytes)
        .map_err(|_| "TypeScript configuration parser is not UTF-8".to_string())?;
    let patched = replace_exact_once(&source, BEFORE, AFTER, "compiler API project configuration")?;
    require_sha256(
        patched.as_bytes(),
        PATCHED_SHA256,
        "patched scip-typescript configuration parser",
    )?;
    fs::write(&path, patched)
        .map_err(|error| format!("failed to install compiler API configuration parser: {error}"))?;
    require_sha256(
        &fs::read(&path).map_err(|error| error.to_string())?,
        PATCHED_SHA256,
        "installed scip-typescript configuration parser",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_upstream_project_parser_can_be_patched() {
        let patched = replace_exact_once(BEFORE, BEFORE, AFTER, "config parser").unwrap();
        assert!(patched.contains("getParsedCommandLineOfConfigFile(absolute, {}"));
        assert!(!patched.contains("defaultCompilerOptions"));
        assert!(replace_exact_once(&patched, BEFORE, AFTER, "config parser").is_err());
        assert!(
            replace_exact_once(
                &format!("{BEFORE}\n{BEFORE}"),
                BEFORE,
                AFTER,
                "config parser"
            )
            .is_err()
        );
    }
}
