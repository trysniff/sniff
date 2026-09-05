use crate::semantic_indexer_manifest::{PinnedIndexer, SemanticIndexerKind};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const SCIP_PYTHON_VERSION: &str = "0.6.6";
const SCIP_PYTHON_BUNDLE: &str = "node_modules/@sourcegraph/scip-python/dist/scip-python.js";
const UPSTREAM_SHA256: &str = "55c645ed91e34ea4a2a7b47b1c482162cf173882e335a64c48ea6e8cbdb0ec05";
const PATCHED_SHA256: &str = "428bfa87504028d20a047df3b156b0d1e9cb1749795831a54e316dff0e018c82";

const WRITER_ASSIGNMENT_BEFORE: &str = r#"visitAssignment(e){let t=!1,i="";if(38===e.leftExpression.nodeType){const s=this.evaluator.getType(e.leftExpression);if(e.typeAnnotationComment?i+=this._printExpression(e.typeAnnotationComment,!0):s&&(i+=l.getFullNameOfType(s)),null==s?void 0:s.typeAliasInfo)t=!0;else if(9===e.rightExpression.nodeType){const i=this.evaluator.getType(e.rightExpression.leftExpression);i&&(0,o.isInstantiableClass)(i)&&o.ClassType.isBuiltIn(i,["TypeVar","TypeVarTuple","ParamSpec","NewType"])&&(t=!0)}}return i&&(t&&(i+=" = ",i+=this._printExpression(e.rightExpression)),this.docstrings.set(e.id,[i])),!0}"#;
const WRITER_ASSIGNMENT_AFTER: &str = r#"visitAssignment(e){let t=!1,i="";const s=38===e.leftExpression.nodeType?e.leftExpression:54===e.leftExpression.nodeType&&38===e.leftExpression.valueExpression.nodeType?e.leftExpression.valueExpression:void 0;if(s){const n=this.evaluator.getType(s);if(54===e.leftExpression.nodeType?i+=this._printExpression(e.leftExpression.typeAnnotation,!0):e.typeAnnotationComment?i+=this._printExpression(e.typeAnnotationComment,!0):n&&(i+=l.getFullNameOfType(n)),null==n?void 0:n.typeAliasInfo)t=!0;else if(9===e.rightExpression.nodeType){const i=this.evaluator.getType(e.rightExpression.leftExpression);i&&(0,o.isInstantiableClass)(i)&&o.ClassType.isBuiltIn(i,["TypeVar","TypeVarTuple","ParamSpec","NewType"])&&(t=!0)}}return i&&(t&&(i+=" = ",i+=this._printExpression(e.rightExpression)),this.docstrings.set(e.id,[i])),!0}"#;

const ASSIGNMENT_BEFORE: &str = r#"visitAssignment(e){if(38==e.leftExpression.nodeType){const t=this.evaluator.getDeclarationsForNameNode(e.leftExpression)||[];if(t.length>0){let i=t[0];if(i.node.parent&&i.node.parent.id==e.id){this._docstringWriter.visitAssignment(e);let t=[],s=this._docstringWriter.docstrings.get(e.id);s&&t.push("```python\n"+s.join("\n")+"\n```"),this.document.symbols.push(new h.scip.SymbolInformation({symbol:this.getScipSymbol(i.node).value,documentation:t}))}}}return!0}"#;
const ASSIGNMENT_AFTER: &str = r#"visitAssignment(e){const t=38==e.leftExpression.nodeType?e.leftExpression:54==e.leftExpression.nodeType&&38==e.leftExpression.valueExpression.nodeType?e.leftExpression.valueExpression:void 0;if(t){const i=this.evaluator.getDeclarationsForNameNode(t)||[],s=i.find((t=>y.isNodeContainedWithin(t.node,e)));if(s){this._docstringWriter.visitAssignment(e);let t=[],i=this._docstringWriter.docstrings.get(e.id);i&&t.push("```python\n"+i.join("\n")+"\n```"),this.document.symbols.push(new h.scip.SymbolInformation({symbol:this.getScipSymbol(s.node).value,documentation:t,signature_documentation:i?new h.scip.Document({language:"python",text:i.join("\n"),occurrences:[]}):void 0}))}}return!0}"#;

const FUNCTION_BEFORE: &str = r#"let n=this.getFunctionRelationships(e);return this.document.symbols.push(new h.scip.SymbolInformation({symbol:this.getScipSymbol(e).value,documentation:t,relationships:n})),"#;
const FUNCTION_AFTER: &str = r#"let n=this.getFunctionRelationships(e),r=this.evaluator.getTypeOfFunction(e),o=r&&_.isOverloadedFunction(r.decoratedType)&&!_.FunctionType.isOverloaded(r.functionType)?void 0:new h.scip.Document({language:"python",text:i.join("\n"),occurrences:[]});return this.document.symbols.push(new h.scip.SymbolInformation({symbol:this.getScipSymbol(e).value,documentation:t,relationships:n,signature_documentation:o})),"#;

const CLASS_BEFORE: &str = r#"this.document.symbols.push(new h.scip.SymbolInformation({symbol:n.value,documentation:r,relationships:l})),this.pushNewOccurrence"#;
const CLASS_AFTER: &str = r#"this.document.symbols.push(new h.scip.SymbolInformation({symbol:n.value,documentation:r,relationships:l,signature_documentation:o?new h.scip.Document({language:"python",text:o.join("\n"),occurrences:[]}):void 0})),this.pushNewOccurrence"#;

const IMPORT_MODULE_BEFORE: &str =
    r#"visitImportFrom(e){const t=this.getScipSymbol(e);return this.document.occurrences.push"#;
const IMPORT_MODULE_AFTER: &str = r#"visitImportFrom(e){const t=(i=(0,l.getImportInfo)(e.module),s=i&&[...i.resolvedPaths].reverse().find((e=>e)),n=s&&this.program.getSourceFile(s),r=n&&n.getModuleName(),o=r&&(a.resolve(s).startsWith(this.cwd)?this.projectPackage:this.moduleNameNodeToPythonPackage(e.module)),r&&o?p.makeModuleInit(o,r):this.getScipSymbol(e));var i,s,n,r,o;return this.document.occurrences.push"#;

const IMPORTED_MODULE_BRANCH_BEFORE: &str = r#"if(t&&8===t.category){const e=i.parent;if((0,j.assert)(e),22===e.nodeType){const t=this.moduleNameNodeToPythonPackage(e.module)||this.projectPackage;return p.makeModuleInit(t,[...e.module.nameParts,i.name].map((e=>e.value)).join("."))}}"#;
const IMPORTED_MODULE_BRANCH_AFTER: &str = r#"if(t&&8===t.category){const e=i.parent;if((0,j.assert)(e),22===e.nodeType){const s=this.moduleNameNodeToPythonPackage(e.module)||this.getPackageInfo(i,t.moduleName);return s?p.makeModuleInit(s,t.moduleName):m.ScipSymbol.local(this.counter.next())}}"#;

const NAMESPACE_IMPORT_BEFORE: &str =
    r#"visitImportFromAs(e){return this.pushNewOccurrence(e,this.getScipSymbol(e)),!1}"#;
const NAMESPACE_IMPORT_AFTER: &str = r#"visitImportFromAs(e){const t=this.evaluator.getDeclarationsForNameNode(e.name)||[],i=t[0]&&this.evaluator.resolveAliasDeclaration(t[0],!0),s=i&&i.path&&i.node&&[21,22,36].includes(i.node.nodeType)&&this.program.getSourceFile(i.path),n=s&&s.getModuleName(),r=n&&(a.resolve(i.path).startsWith(this.cwd)?this.projectPackage:this.moduleNameNodeToPythonPackage(e.parent.module));return this.pushNewOccurrence(e,n&&r?p.makeModuleInit(r,n):this.getScipSymbol(e)),!1}"#;

pub(super) fn patch_compiler_public_api(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
    if spec.kind != SemanticIndexerKind::Python || spec.version != SCIP_PYTHON_VERSION {
        return Err(format!(
            "Python public API patch only supports scip-python {SCIP_PYTHON_VERSION}"
        ));
    }
    let path = root.join(SCIP_PYTHON_BUNDLE);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "failed to read pinned scip-python runtime {}: {error}",
            path.display()
        )
    })?;
    require_sha256(&bytes, UPSTREAM_SHA256, "upstream scip-python bundle")?;
    let source = String::from_utf8(bytes)
        .map_err(|_| "pinned scip-python bundle is not UTF-8".to_string())?;
    let patched = patch_source(&source.replace("\r\n", "\n"))?;
    require_sha256(
        patched.as_bytes(),
        PATCHED_SHA256,
        "patched scip-python bundle",
    )?;
    fs::write(&path, patched.as_bytes()).map_err(|error| {
        format!(
            "failed to install scip-python public API patch {}: {error}",
            path.display()
        )
    })?;
    let installed = fs::read(&path).map_err(|error| {
        format!(
            "failed to verify scip-python public API patch {}: {error}",
            path.display()
        )
    })?;
    require_sha256(&installed, PATCHED_SHA256, "installed scip-python bundle")
}

fn patch_source(source: &str) -> Result<String, String> {
    [
        (
            WRITER_ASSIGNMENT_BEFORE,
            WRITER_ASSIGNMENT_AFTER,
            "annotated assignment writer",
        ),
        (ASSIGNMENT_BEFORE, ASSIGNMENT_AFTER, "assignment signatures"),
        (FUNCTION_BEFORE, FUNCTION_AFTER, "function signatures"),
        (CLASS_BEFORE, CLASS_AFTER, "class signatures"),
        (
            IMPORT_MODULE_BEFORE,
            IMPORT_MODULE_AFTER,
            "compiler-resolved import modules",
        ),
        (
            IMPORTED_MODULE_BRANCH_BEFORE,
            IMPORTED_MODULE_BRANCH_AFTER,
            "qualified imported modules",
        ),
        (
            NAMESPACE_IMPORT_BEFORE,
            NAMESPACE_IMPORT_AFTER,
            "qualified namespace imports",
        ),
    ]
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
            "pinned scip-python runtime has {matches} {label} patch sites; expected exactly one"
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
            WRITER_ASSIGNMENT_BEFORE,
            ASSIGNMENT_BEFORE,
            FUNCTION_BEFORE,
            CLASS_BEFORE,
            IMPORT_MODULE_BEFORE,
            IMPORTED_MODULE_BRANCH_BEFORE,
            NAMESPACE_IMPORT_BEFORE,
        ]
        .join("\n");

        let patched = patch_source(&source).unwrap();

        assert!(patched.contains("signature_documentation:i?new h.scip.Document"));
        assert!(patched.contains("_.isOverloadedFunction(r.decoratedType)"));
        assert!(patched.contains("this.program.getSourceFile(s)"));
        assert!(patched.contains("this.program.getSourceFile(i.path)"));
        assert!(patch_source(&patched).is_err());
        assert!(patch_source("").is_err());
    }

    #[test]
    #[ignore = "requires the exact upstream scip-python 0.6.6 bundle"]
    fn patches_the_verified_upstream_bundle() {
        let source = std::path::PathBuf::from(
            std::env::var_os("SNIFF_TEST_SCIP_PYTHON_BUNDLE")
                .expect("set SNIFF_TEST_SCIP_PYTHON_BUNDLE"),
        );
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join(SCIP_PYTHON_BUNDLE);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(source, &target).unwrap();
        let spec =
            crate::semantic_indexer_manifest::pinned_indexer(SemanticIndexerKind::Python).unwrap();

        patch_compiler_public_api(root.path(), spec).unwrap();

        require_sha256(
            &fs::read(target).unwrap(),
            PATCHED_SHA256,
            "test patched scip-python bundle",
        )
        .unwrap();
    }
}
