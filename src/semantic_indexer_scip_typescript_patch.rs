use crate::semantic_indexer_manifest::{PinnedIndexer, SemanticIndexerKind};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const SCIP_TYPESCRIPT_VERSION: &str = "0.4.0";
const FILE_INDEXER: &str = "node_modules/@sourcegraph/scip-typescript/dist/src/FileIndexer.js";
const UPSTREAM_SHA256: &str = "95c37b41a5c4725a70f66b39ff60bd2d47459a28bf735b93659077f2f99c967f";
const PATCHED_SHA256: &str = "25d8c590841621f261ffb2ab18e69ab1415320f213ba31807f18baeafd1dc7a4";

const ADD_INFORMATION_BEFORE: &str = r#"    addSymbolInformation(node, sym, declaration, symbol) {
        const documentation = [
            '```ts\n' +
                this.hideWorkingDirectory(this.signatureForDocumentation(node, sym)) +
                '\n```',
        ];"#;

const ADD_INFORMATION_AFTER: &str = r#"    addSymbolInformation(node, sym, declaration, symbol) {
        const compilerSignature = this.signatureForDocumentation(node, sym, declaration);
        const publicCompilerSignature = this.compilerSignatureForDocumentation(node, sym, declaration);
        const documentation = [
            '```ts\n' +
                this.hideWorkingDirectory(compilerSignature) +
                '\n```',
        ];"#;

const SYMBOL_INFORMATION_BEFORE: &str = r#"            symbol: symbol.value,
            documentation,
            relationships: this.relationships(declaration, symbol),
        }));"#;

const SYMBOL_INFORMATION_AFTER: &str = r#"            symbol: symbol.value,
            documentation,
            relationships: this.relationships(declaration, symbol),
            signature_documentation: publicCompilerSignature === undefined
                ? undefined
                : new scip.scip.Document({
                    language: this.document.language,
                    text: this.hideWorkingDirectory(publicCompilerSignature),
                    occurrences: [],
                }),
        }));"#;

const SIGNATURE_HEADER_BEFORE: &str = r#"    signatureForDocumentation(node, sym) {
        var _a;
        const kind = scriptElementKind(node, sym);
        const type = () => this.checker.typeToString(this.checker.getTypeAtLocation(node));
        const asSignatureDeclaration = (node, sym) => {
            var _a;
            const declaration = (_a = sym.declarations) === null || _a === void 0 ? void 0 : _a[0];"#;

const SIGNATURE_HEADER_AFTER: &str = r#"    compilerSignatureForDocumentation(node, sym, declaration) {
        const declarations = sym.declarations || [];
        if (ts.isFunctionLike(declaration) &&
            declaration.body &&
            declarations.some(candidate => candidate !== declaration &&
                ts.isFunctionLike(candidate) &&
                !candidate.body)) {
            return undefined;
        }
        return this.signatureForDocumentation(node, sym, declaration);
    }
    signatureForDocumentation(node, sym, declaration) {
        var _a;
        const formatFlags = ts.TypeFormatFlags.NoTruncation |
            ts.TypeFormatFlags.UseFullyQualifiedType |
            ts.TypeFormatFlags.WriteArrowStyleSignature |
            ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope;
        const kind = scriptElementKind(node, sym);
        const type = () => this.checker.typeToString(this.checker.getTypeAtLocation(node), declaration, formatFlags);
        const asSignatureDeclaration = (node, declaration) => {"#;

const SIGNATURE_BODY_BEFORE: &str = r#"            const signatureDeclaration = asSignatureDeclaration(node, sym);
            if (!signatureDeclaration) {
                return undefined;
            }
            const signature = this.checker.getSignatureFromDeclaration(signatureDeclaration);
            return signature ? this.checker.signatureToString(signature) : undefined;"#;

const SIGNATURE_BODY_AFTER: &str = r#"            const signatureDeclaration = asSignatureDeclaration(node, declaration);
            if (!signatureDeclaration) {
                return undefined;
            }
            const signature = this.checker.getSignatureFromDeclaration(signatureDeclaration);
            return signature
                ? this.checker.signatureToString(signature, signatureDeclaration, formatFlags)
                : undefined;"#;

const ALIAS_BEFORE: &str = r#"            case ts.ScriptElementKind.alias: {
                return 'type ' + node.getText();
            }"#;

const ALIAS_AFTER: &str = r#"            case ts.ScriptElementKind.alias: {
                if (ts.isTypeAliasDeclaration(declaration)) {
                    const alias = this.checker.getTypeFromTypeNode(declaration.type);
                    return ('type ' +
                        node.getText() +
                        ' = ' +
                        this.checker.typeToString(alias, declaration, formatFlags | ts.TypeFormatFlags.InTypeAlias));
                }
                return 'type ' + node.getText();
            }"#;

pub(super) fn patch_compiler_signatures(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript
        || spec.version != SCIP_TYPESCRIPT_VERSION
    {
        return Err(format!(
            "TypeScript signature patch only supports scip-typescript {SCIP_TYPESCRIPT_VERSION}"
        ));
    }
    let path = root.join(FILE_INDEXER);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "failed to read pinned scip-typescript runtime {}: {error}",
            path.display()
        )
    })?;
    require_sha256(
        &bytes,
        UPSTREAM_SHA256,
        "upstream scip-typescript FileIndexer",
    )?;
    let source = String::from_utf8(bytes)
        .map_err(|_| "pinned scip-typescript FileIndexer is not UTF-8".to_string())?;
    let patched = patch_source(&source.replace("\r\n", "\n"))?;
    require_sha256(
        patched.as_bytes(),
        PATCHED_SHA256,
        "patched scip-typescript FileIndexer",
    )?;
    fs::write(&path, patched.as_bytes()).map_err(|error| {
        format!(
            "failed to install scip-typescript signature patch {}: {error}",
            path.display()
        )
    })?;
    let installed = fs::read(&path).map_err(|error| {
        format!(
            "failed to verify scip-typescript signature patch {}: {error}",
            path.display()
        )
    })?;
    require_sha256(
        &installed,
        PATCHED_SHA256,
        "installed scip-typescript FileIndexer",
    )
}

fn patch_source(source: &str) -> Result<String, String> {
    let replacements = [
        (
            ADD_INFORMATION_BEFORE,
            ADD_INFORMATION_AFTER,
            "symbol documentation",
        ),
        (
            SYMBOL_INFORMATION_BEFORE,
            SYMBOL_INFORMATION_AFTER,
            "SCIP signature field",
        ),
        (
            SIGNATURE_HEADER_BEFORE,
            SIGNATURE_HEADER_AFTER,
            "exact compiler declaration",
        ),
        (
            SIGNATURE_BODY_BEFORE,
            SIGNATURE_BODY_AFTER,
            "compiler signature formatting",
        ),
        (ALIAS_BEFORE, ALIAS_AFTER, "compiler-expanded type alias"),
    ];
    replacements
        .into_iter()
        .try_fold(source.to_string(), |current, (before, after, label)| {
            replace_exact_once(&current, before, after, label)
        })
}

fn replace_exact_once(
    source: &str,
    before: &str,
    after: &str,
    label: &str,
) -> Result<String, String> {
    let matches = source.match_indices(before).count();
    if matches != 1 {
        return Err(format!(
            "pinned scip-typescript runtime has {matches} {label} patch sites; expected exactly one"
        ));
    }
    Ok(source.replacen(before, after, 1))
}

fn require_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "{label} checksum mismatch; expected {expected}, received {actual}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_patch_sites_are_required() {
        let source = [
            ADD_INFORMATION_BEFORE,
            SYMBOL_INFORMATION_BEFORE,
            SIGNATURE_HEADER_BEFORE,
            SIGNATURE_BODY_BEFORE,
            ALIAS_BEFORE,
        ]
        .join("\n");

        let patched = patch_source(&source).unwrap();

        assert!(patched.contains("signature_documentation: publicCompilerSignature"));
        assert!(patched.contains("ts.isFunctionLike(candidate)"));
        assert!(patched.contains("ts.TypeFormatFlags.InTypeAlias"));
        assert!(patch_source(&patched).is_err());
        assert!(patch_source("").is_err());
    }

    #[test]
    #[ignore = "requires the exact upstream scip-typescript 0.4.0 FileIndexer.js"]
    fn patches_the_verified_upstream_file() {
        let source = std::path::PathBuf::from(
            std::env::var_os("SNIFF_TEST_SCIP_TYPESCRIPT_FILE_INDEXER")
                .expect("set SNIFF_TEST_SCIP_TYPESCRIPT_FILE_INDEXER"),
        );
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join(FILE_INDEXER);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(source, &target).unwrap();
        let spec = crate::semantic_indexer_manifest::pinned_indexer(
            SemanticIndexerKind::TypeScriptJavaScript,
        )
        .unwrap();

        patch_compiler_signatures(root.path(), spec).unwrap();

        require_sha256(
            &fs::read(target).unwrap(),
            PATCHED_SHA256,
            "test patched scip-typescript FileIndexer",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the installed checksum-pinned scip-typescript runtime and Node.js"]
    fn patched_provider_emits_exact_public_overload_signatures() {
        let spec = crate::semantic_indexer_manifest::pinned_indexer(
            SemanticIndexerKind::TypeScriptJavaScript,
        )
        .unwrap();
        let installed = crate::semantic_indexer_installation::SemanticIndexerStore::for_user()
            .unwrap()
            .verify(spec)
            .unwrap();
        let project = tempfile::tempdir().unwrap();
        let source = project.path().join("src");
        fs::create_dir(&source).unwrap();
        fs::write(
            project.path().join("package.json"),
            r#"{"name":"sniff-signature-probe","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            project.path().join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true,"noEmit":true},"include":["src/**/*.ts"]}"#,
        )
        .unwrap();
        fs::write(
            source.join("index.ts"),
            r#"export function parse(value: string): string;
export function parse(value: number): number;
export function parse(value: string | number): string | number { return value; }
"#,
        )
        .unwrap();
        let output = project.path().join("index.scip");
        let status = std::process::Command::new(if cfg!(windows) { "node.exe" } else { "node" })
            .arg(&installed.entrypoint)
            .arg("index")
            .arg("--cwd")
            .arg(project.path())
            .arg("--output")
            .arg(&output)
            .arg("--no-progress-bar")
            .status()
            .unwrap();
        assert!(status.success());

        let index = crate::semantic_index_scip::ingest_scip_file(project.path(), &output).unwrap();
        let parse = index
            .symbols
            .values()
            .find(|symbol| symbol.provider_identity.ends_with("/parse()."))
            .unwrap();
        let signatures = parse
            .signatures
            .iter()
            .map(|signature| signature.text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            signatures,
            [
                "function parse(value: number) => number",
                "function parse(value: string) => string",
            ]
        );
    }
}
