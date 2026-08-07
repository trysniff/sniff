use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn fixture(label: &str) -> (PathBuf, FileRecord, SemanticIndexCache) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sniff-semantic-cache-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    let source_path = root.join("src/main.rs");
    fs::write(&source_path, "pub fn answer() -> i32 { 42 }\n").unwrap();
    let record = crate::parser::parse_file_checked(source_path.to_str().unwrap()).unwrap();
    let cache = SemanticIndexCache::at(root.join("cache"));
    (root, record, cache)
}

fn artifacts(root: &Path) -> Vec<PathBuf> {
    let mut artifacts = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                artifacts.push(path);
            }
        }
    }
    artifacts
}

#[test]
fn unchanged_source_reuses_content_addressed_semantic_artifact() {
    let (root, record, cache) = fixture("reuse");
    let (built, first) = cache.load_or_build(&record).unwrap();
    let (reused, second) = cache.load_or_build(&record).unwrap();

    assert_eq!(first, CacheDisposition::Built);
    assert_eq!(second, CacheDisposition::Hit);
    assert_eq!(built.definitions.len(), reused.definitions.len());
    assert_eq!(artifacts(&root.join("cache")).len(), 1);
    fs::remove_dir_all(root).ok();
}

#[test]
fn initial_file_inventory_is_persisted_with_the_semantic_artifact() {
    let (root, record, cache) = fixture("inventory");
    let path = Path::new(&record.file_path);
    let (built, first) = cache.load_or_build_file(path).unwrap();
    let (reused, second) = cache.load_or_build_file(path).unwrap();

    assert_eq!(first, CacheDisposition::Built);
    assert_eq!(second, CacheDisposition::Hit);
    assert_eq!(built.methods.len(), 1);
    assert_eq!(reused.methods.len(), 1);
    assert_eq!(artifacts(&root.join("cache")).len(), 1);
    fs::remove_dir_all(root).ok();
}

#[test]
fn changed_source_gets_a_distinct_semantic_artifact() {
    let (root, record, cache) = fixture("changed");
    cache.load_or_build(&record).unwrap();
    fs::write(
        &record.file_path,
        "pub fn answer() -> i32 { 42 }\npub fn next() -> i32 { 43 }\n",
    )
    .unwrap();
    let changed = crate::parser::parse_file_checked(&record.file_path).unwrap();
    let (_, disposition) = cache.load_or_build(&changed).unwrap();

    assert_eq!(disposition, CacheDisposition::Built);
    assert_eq!(artifacts(&root.join("cache")).len(), 2);
    fs::remove_dir_all(root).ok();
}

#[test]
fn corrupt_exact_artifact_fails_instead_of_falling_back() {
    let (root, record, cache) = fixture("corrupt");
    cache.load_or_build(&record).unwrap();
    let artifact = artifacts(&root.join("cache")).pop().unwrap();
    fs::write(&artifact, "not json").unwrap();

    let error = cache.load_or_build(&record).unwrap_err();
    assert!(error.contains("artifact is corrupt"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn altered_valid_json_payload_fails_checksum_validation() {
    let (root, record, cache) = fixture("checksum");
    cache.load_or_build(&record).unwrap();
    let artifact = artifacts(&root.join("cache")).pop().unwrap();
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&artifact).unwrap()).unwrap();
    value["symbols"]["definitions"][0]["name"] = "tampered".into();
    fs::write(&artifact, serde_json::to_vec(&value).unwrap()).unwrap();

    let error = cache.load_or_build(&record).unwrap_err();
    assert!(error.contains("identity mismatch"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn source_change_during_indexing_fails_closed() {
    let (root, mut record, cache) = fixture("snapshot");
    record.source.push_str("// stale snapshot\n");

    let error = cache.load_or_build(&record).unwrap_err();
    assert!(
        error.contains("source changed while semantic indexing"),
        "{error}"
    );
    assert!(artifacts(&root.join("cache")).is_empty());
    fs::remove_dir_all(root).ok();
}

#[test]
fn semantic_cache_child_process() {
    let Some(root) = std::env::var_os("SNIFF_TEST_SEMANTIC_CACHE_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let source_path = root.join("src/main.rs");
    let cache = SemanticIndexCache::at(root.join("cache"));
    cache.load_or_build_file(&source_path).unwrap();
    fs::write(root.join("ready"), "ready").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn forced_termination_keeps_completed_semantic_artifact_reusable() {
    let (root, record, cache) = fixture("termination");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "semantic_cache::tests::semantic_cache_child_process",
            "--nocapture",
        ])
        .env("SNIFF_TEST_SEMANTIC_CACHE_CHILD", &root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.join("ready").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        root.join("ready").exists(),
        "child did not finish the artifact"
    );
    child.kill().unwrap();
    child.wait().unwrap();

    let (_, disposition) = cache
        .load_or_build_file(Path::new(&record.file_path))
        .unwrap();
    assert_eq!(disposition, CacheDisposition::Hit);
    fs::remove_dir_all(root).ok();
}
