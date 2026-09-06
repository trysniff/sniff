import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import pip
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
    package_file = Path(pip.__file__)
    if package_file.is_symlink() or not package_file.is_file():
        fail("pip runtime module is not a regular file")
    package_root = package_file.parent
    records = []
    for entry in package_root.rglob("*"):
        if (
            entry.suffix == ".pyc"
            or "__pycache__" in entry.parts
            or ".." in entry.parts
        ):
            continue
        if entry.is_symlink():
            fail("pip runtime tree contains a symbolic link")
        if entry.is_dir():
            continue
        if not entry.is_file():
            fail("pip runtime tree contains a non-regular file")
        size = entry.stat().st_size
        if size > MAX_FILE_BYTES:
            fail("pip runtime file exceeds its size limit")
        relative = entry.relative_to(package_root)
        records.append(
            {
                "path": "pip/" + str(relative).replace("\\", "/"),
                "sha256": sha256(entry),
                "size": size,
            }
        )
        if len(records) > MAX_FILES:
            fail("pip runtime tree exceeds its file-count limit")
    records.sort(key=lambda record: record["path"])
    if not records or len({record["path"] for record in records}) != len(records):
        fail("pip runtime file inventory is empty or ambiguous")
    digest = hashlib.sha256()
    total_bytes = 0
    for record in records:
        encoded_path = record["path"].encode("utf-8")
        total_bytes += record["size"]
        if total_bytes > MAX_TOTAL_BYTES:
            fail("pip runtime exceeds its total size limit")
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
