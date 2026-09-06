use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zip::write::SimpleFileOptions;

const EXTERNAL_BACKEND: &str = r#"import base64
import csv
import hashlib
import io
import os
import zipfile


def get_requires_for_build_wheel(config_settings=None):
    return ["fixture-dynamic==1.0.0"]


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    import fixture_dynamic
    if fixture_dynamic.VALUE != "installed-dynamically":
        raise RuntimeError("dynamic build requirement is unavailable")
    filename = "fixture_package-1.0.0-py3-none-any.whl"
    dist_info = "fixture_package-1.0.0.dist-info"
    files = {
        "fixture_package/__init__.py": b"VALUE = 1\n",
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: fixture-package\n"
            b"Version: 1.0.0\n\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: sniff-hermetic-fixture\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
    }
    record_path = f"{dist_info}/RECORD"
    record = io.StringIO(newline="")
    rows = csv.writer(record, lineterminator="\n")
    for path, contents in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
        rows.writerow((path, f"sha256={digest}", len(contents)))
    rows.writerow((record_path, "", ""))
    files[record_path] = record.getvalue().encode()
    output = os.path.join(wheel_directory, filename)
    with zipfile.ZipFile(output, "w") as archive:
        for path, contents in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, contents)
    return filename
"#;

struct LocalPackageIndex {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalPackageIndex {
    fn start() -> Self {
        let backend = wheel(
            "fixture-backend",
            "1.0.0",
            &[("fixture_backend.py", EXTERNAL_BACKEND)],
        );
        let dynamic = wheel(
            "fixture-dynamic",
            "1.0.0",
            &[(
                "fixture_dynamic/__init__.py",
                "VALUE = 'installed-dynamically'\n",
            )],
        );
        let backend_name = "fixture_backend-1.0.0-py3-none-any.whl";
        let dynamic_name = "fixture_dynamic-1.0.0-py3-none-any.whl";
        let mut routes = BTreeMap::new();
        routes.insert(
            "/simple/fixture-backend/".to_string(),
            html_link(backend_name, &backend),
        );
        routes.insert(
            "/simple/fixture-dynamic/".to_string(),
            html_link(dynamic_name, &dynamic),
        );
        routes.insert(format!("/packages/{backend_name}"), backend);
        routes.insert(format!("/packages/{dynamic_name}"), dynamic);
        let routes = Arc::new(routes);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &routes),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("local Python package index failed: {error}"),
                }
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/simple/", self.address)
    }

    fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Drop for LocalPackageIndex {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn html_link(filename: &str, bytes: &[u8]) -> Vec<u8> {
    format!(
        "<!doctype html><a href=\"/packages/{filename}#sha256={:x}\">{filename}</a>",
        Sha256::digest(bytes)
    )
    .into_bytes()
}

fn serve(mut stream: TcpStream, routes: &BTreeMap<String, Vec<u8>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = [0_u8; 8192];
    let size = stream.read(&mut request).unwrap();
    let request = String::from_utf8_lossy(&request[..size]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| path.split('?').next())
        .unwrap_or("/");
    let (status, content_type, body) = routes.get(path).map_or_else(
        || ("404 Not Found", "text/plain", b"not found".as_slice()),
        |body| {
            let content_type = if path.starts_with("/simple/") {
                "text/html"
            } else {
                "application/octet-stream"
            };
            ("200 OK", content_type, body.as_slice())
        },
    );
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
}

fn wheel(distribution: &str, version: &str, modules: &[(&str, &str)]) -> Vec<u8> {
    let normalized = distribution.replace('-', "_");
    let dist_info = format!("{normalized}-{version}.dist-info");
    let mut files = BTreeMap::new();
    for (path, source) in modules {
        files.insert((*path).to_string(), source.as_bytes().to_vec());
    }
    files.insert(
        format!("{dist_info}/METADATA"),
        format!("Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n\n")
            .into_bytes(),
    );
    files.insert(
        format!("{dist_info}/WHEEL"),
        b"Wheel-Version: 1.0\nGenerator: sniff-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            .to_vec(),
    );
    let record_path = format!("{dist_info}/RECORD");
    let mut record = String::new();
    for path in files.keys() {
        record.push_str(&format!("{path},,\n"));
    }
    record.push_str(&format!("{record_path},,\n"));
    files.insert(record_path, record.into_bytes());

    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default();
    for (path, bytes) in files {
        archive.start_file(path, options).unwrap();
        archive.write_all(&bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn only_directory(root: &Path) -> PathBuf {
    let entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    let [entry] = entries.as_slice() else {
        panic!("expected one directory below {}", root.display());
    };
    assert!(entry.is_dir());
    entry.clone()
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Windows AppContainer intentionally denies loopback package indexes"
)]
fn dynamic_requirements_are_resolved_once_then_reused_offline_and_corruption_fails() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[build-system]\nrequires = ['fixture-backend==1.0.0']\nbuild-backend = 'fixture_backend'\n",
    )
    .unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(root.path(), &["config", "user.email", "bench@example.invalid"]);
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
        root.path(),
        &revision,
        "sniff-python-hermetic-index-test",
    )
    .unwrap();
    let store_root = root.path().join("toolchain-store");
    let store = PythonBuildToolchainStore::at(store_root.clone());
    let server = LocalPackageIndex::start();
    let package_index = server.url();

    let first = run_python_wheel_build_with_store_and_index(
        &snapshot,
        &revision,
        "pyproject.toml",
        &store,
        &package_index,
    )
    .unwrap();
    server.stop();

    let cached = run_python_wheel_build_with_store_and_index(
        &snapshot,
        &revision,
        "pyproject.toml",
        &store,
        &package_index,
    )
    .unwrap();
    assert_eq!(cached.toolchain_identity_sha256, first.toolchain_identity_sha256);
    assert_eq!(cached.wheel_filename, first.wheel_filename);
    assert_eq!(cached.wheel_bytes, first.wheel_bytes);

    let contract_root = only_directory(&store_root);
    let entry_root = only_directory(&contract_root);
    let wheelhouse = entry_root.join("wheelhouse");
    let wheel = fs::read_dir(&wheelhouse).unwrap().next().unwrap().unwrap().path();
    fs::write(wheel, b"corrupt").unwrap();
    let error = run_python_wheel_build_with_store_and_index(
        &snapshot,
        &revision,
        "pyproject.toml",
        &store,
        &package_index,
    )
    .unwrap_err();
    assert!(
        error.contains("checksum changed") || error.contains("size or file type changed"),
        "{error}"
    );
}
