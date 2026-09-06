import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys


MAX_FILES = 100_000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def fail(message):
    raise SystemExit(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def pip_tree():
    distribution = importlib.metadata.distribution("pip")
    files = distribution.files
    if files is None or len(files) > MAX_FILES:
        fail("pip distribution has no bounded file inventory")
    records = []
    for entry in files:
        if (
            entry.suffix == ".pyc"
            or "__pycache__" in entry.parts
            or ".." in entry.parts
        ):
            continue
        unresolved = Path(distribution.locate_file(entry))
        if unresolved.is_symlink() or not unresolved.is_file():
            fail("pip distribution contains a non-regular file")
        path = unresolved
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            fail("pip distribution file exceeds its size limit")
        records.append(
            {
                "path": str(entry).replace("\\", "/"),
                "sha256": sha256(path),
                "size": size,
            }
        )
    records.sort(key=lambda record: record["path"])
    if not records or len({record["path"] for record in records}) != len(records):
        fail("pip distribution file inventory is empty or ambiguous")
    digest = hashlib.sha256()
    total_bytes = 0
    for record in records:
        encoded_path = record["path"].encode("utf-8")
        total_bytes += record["size"]
        if total_bytes > MAX_TOTAL_BYTES:
            fail("pip distribution exceeds its total size limit")
        digest.update(len(encoded_path).to_bytes(8, "little"))
        digest.update(encoded_path)
        digest.update(record["size"].to_bytes(8, "little"))
        digest.update(bytes.fromhex(record["sha256"]))
    return str(distribution.version), len(records), total_bytes, digest.hexdigest()


def main():
    if sys.version_info < (3, 11):
        fail("Python 3.11 or newer is required for build-toolchain preparation")
    pip_version, file_count, total_bytes, files_sha256 = pip_tree()
    contract = {
        "version": 2,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
        "platform": sys.platform,
        "pip_version": pip_version,
        "pip_file_count": file_count,
        "pip_total_bytes": total_bytes,
        "pip_files_sha256": files_sha256,
    }
    print(json.dumps(contract, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
