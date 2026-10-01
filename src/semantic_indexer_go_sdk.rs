use super::*;

pub(super) fn identity_sha256(
    spec: PinnedIndexer,
    execution_root: &Path,
    installed: &InstalledIndexer,
) -> Result<String, String> {
    let prepared =
        build_indexer_sandbox_command(spec, execution_root, installed, Vec::new(), None)?;
    let roots = prepared
        .command
        .env
        .iter()
        .filter(|(name, _)| name == "GOROOT")
        .map(|(_, value)| PathBuf::from(value))
        .collect::<Vec<_>>();
    let [root] = roots.as_slice() else {
        return Err("Go sandbox omitted or repeated its SDK input root".to_string());
    };
    super::go_input_tree::sha256(root, b"sniff-go-sdk-input-tree-v1")
        .map_err(|detail| format!("Go SDK input binding: {detail}"))
}
