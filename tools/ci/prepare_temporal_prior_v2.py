"""Prepare exact frozen v2 replay inputs; no selection, execution or admission."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import sys
import zipfile

from temporal_prior_replay import decode, read_capture, verify_sha256


FRAME_RUN = 32804623556
FRAME_ID = 9547888605
FRAME_SHA = "8681f9c379c4e4817c7ed49f06f47f4c47d1f91b"
ARCHIVE_SHA = "542174315793a4a46c5c897ef549273f3202a36afdf464ed9ddaa65cc9ffbe7b"
ARCHIVE_BYTES = 25669281
PROTOCOL_SHA = "deb98a285867fc5ea52761c252839d74268f239824bfc1a82027a352695cfc6f"
FRAME_FILES = {
    "environment.txt", "exclusions.json", "frame.json", "provenance.json",
    "selected-payloads.json", "selection.json", "SHA256SUMS",
}
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_SHARD_BYTES = 1024 * 1024 * 1024
SOURCE_ROOTS = ("sniffbench", "gold_fixtures/repo")
SOURCE_FILES = (
    "sniffbench/historical-v2-protocol.json", "sniffbench/blind-oss-v1-source-seal.json",
    "sniffbench/non-blind-v1-history-worksheet.json", "sniffbench/non-blind-v1-selection-policy.json",
    "sniffbench/non-blind-v1-intentional-boundary-protocol.json",
    "sniffbench/non-blind-v1-intentional-boundary-frame-task.json",
    "gold_fixtures/repo/go/main.go", "gold_fixtures/repo/go/math.go",
    "gold_fixtures/repo/helpers.py", "gold_fixtures/repo/helpers.ts",
    "gold_fixtures/repo/javascript/helpers.js", "gold_fixtures/repo/javascript/main.js",
    "gold_fixtures/repo/kotlin/main.kt", "gold_fixtures/repo/kotlin/math.kt",
    "gold_fixtures/repo/python_main.py", "gold_fixtures/repo/rust/main.rs",
    "gold_fixtures/repo/rust/math.rs", "gold_fixtures/repo/ts_main.ts",
)
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
    f"{prefix}{index}" for prefix in ("com", "lpt") for index in range(1, 10)
}


def require_fields(observed, expected):
    if not isinstance(observed, dict):
        raise ValueError("frozen frame metadata is not an object")
    for key, value in expected.items():
        actual = observed.get(key)
        if isinstance(value, dict):
            require_fields(actual, value)
        elif type(actual) is not type(value) or actual != value:
            raise ValueError(f"frozen frame metadata changed: {key}")


def validate_metadata(artifact_path, run_path):
    artifact = decode(read_capture(artifact_path))
    run = decode(read_capture(run_path))
    require_fields(artifact, {
        "id": FRAME_ID, "name": f"historical-v2-frame-{FRAME_RUN}",
        "digest": "sha256:" + ARCHIVE_SHA, "size_in_bytes": ARCHIVE_BYTES,
        "expired": False,
        "workflow_run": {"id": FRAME_RUN, "head_sha": FRAME_SHA, "head_branch": "main"},
    })
    require_fields(run, {
        "id": FRAME_RUN, "run_attempt": 1, "event": "workflow_dispatch",
        "status": "completed", "conclusion": "success", "head_sha": FRAME_SHA,
        "path": ".github/workflows/sniffbench-historical-v2-frame.yml",
        "repository": {"full_name": "trysniff/sniff"},
    })


def extract_frame(archive_path, destination):
    archive_path = Path(archive_path)
    if archive_path.stat().st_size != ARCHIVE_BYTES:
        raise ValueError("frozen frame archive size changed")
    verify_sha256(archive_path, ARCHIVE_SHA)
    destination = Path(destination)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(FRAME_FILES) or set(names) != FRAME_FILES:
            raise ValueError("frozen frame archive layout changed")
        for entry in entries:
            mode = entry.external_attr >> 16
            if ("\x00" in entry.orig_filename or entry.flag_bits & 1
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or entry.file_size > MAX_MEMBER_BYTES):
                raise ValueError("frozen frame archive member changed")
        if sum(entry.file_size for entry in entries) > MAX_EXPANDED_BYTES:
            raise ValueError("frozen frame archive exceeds expanded bound")
        destination.mkdir()
        for entry in entries:
            copied = 0
            with archive.open(entry) as source, (destination / entry.filename).open("xb") as target:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > entry.file_size:
                        raise ValueError("frozen frame archive member exceeds declared size")
                    target.write(chunk)
            if copied != entry.file_size:
                raise ValueError("frozen frame archive member is truncated")


def capture_archive(destination):
    total = 0
    hasher = hashlib.sha256()
    with Path(destination).open("xb") as target:
        while chunk := sys.stdin.buffer.read(min(1024 * 1024, ARCHIVE_BYTES - total + 1)):
            total += len(chunk)
            if total > ARCHIVE_BYTES:
                raise ValueError("frozen frame download exceeds byte bound")
            hasher.update(chunk)
            target.write(chunk)
    if total != ARCHIVE_BYTES or hasher.hexdigest() != ARCHIVE_SHA:
        raise ValueError("frozen frame download commitment changed")


def source_entries(repository):
    output = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-z", "HEAD", "--", *SOURCE_FILES],
        check=True, capture_output=True,
    ).stdout
    entries = []
    names = set()
    for record in output.split(b"\x00"):
        if not record:
            continue
        header, raw_name = record.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        path = PurePosixPath(name)
        if (mode not in {"100644", "100755"} or kind != "blob"
                or path.is_absolute() or PureWindowsPath(name).drive
                or path.as_posix() != name or any(p in {".", ".."} for p in path.parts)
                or any(c in name for c in "\\:\x00")
                or any(p.endswith((".", " ")) or p.split(".", 1)[0].casefold() in WINDOWS_DEVICES
                       or any(ord(c) < 32 or c in '<>"|?*' for c in p) for p in path.parts)
                or not any(name.startswith(root + "/") for root in SOURCE_ROOTS)
                or name.casefold() in names):
            raise ValueError("frozen prior source tree has unsafe or repeated entries")
        names.add(name.casefold())
        entries.append((name, oid))
    if len(entries) != len(SOURCE_FILES) or {n for n, _ in entries} != set(SOURCE_FILES):
        raise ValueError("frozen prior source allowlist differs")
    return entries


def export_source(repository, destination):
    entries = source_entries(repository)
    destination = Path(destination)
    destination.mkdir()
    total = 0
    for name, oid in entries:
        size = int(subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-s", oid],
            check=True, capture_output=True,
        ).stdout)
        if not 0 <= size <= MAX_MEMBER_BYTES or total + size > MAX_EXPANDED_BYTES:
            raise ValueError("frozen prior source bytes exceed bound")
        data = subprocess.run(
            ["git", "-C", str(repository), "cat-file", "blob", oid],
            check=True, capture_output=True,
        ).stdout
        total += len(data)
        if len(data) != size:
            raise ValueError("frozen prior Git blob size changed")
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)


def verify_dataset(protocol_path, dataset_root):
    verify_sha256(protocol_path, PROTOCOL_SHA)
    protocol = decode(read_capture(protocol_path))
    shards = protocol["dataset"]["shards"]
    root = Path(dataset_root)
    if {p.name for p in (root / "data").iterdir()} != {Path(s["path"]).name for s in shards}:
        raise ValueError("frozen dataset shard inventory changed")
    for shard in shards:
        expected_size = shard["size_bytes"]
        if not 0 < expected_size <= MAX_SHARD_BYTES:
            raise ValueError("frozen dataset shard exceeds bound")
        path = root / shard["path"]
        if not path.is_file() or path.is_symlink():
            raise ValueError("frozen dataset shard is not a plain file")
        hasher = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(min(1024 * 1024, expected_size - total + 1)):
                total += len(chunk)
                if total > expected_size:
                    raise ValueError("frozen dataset shard size changed")
                hasher.update(chunk)
        if total != expected_size or hasher.hexdigest() != shard["lfs_sha256"]:
            raise ValueError("frozen dataset shard commitment changed")


def download_dataset(protocol_path, dataset_root, curl="curl"):
    verify_sha256(protocol_path, PROTOCOL_SHA)
    protocol = decode(read_capture(protocol_path))
    version = subprocess.run([curl, "--version"], check=True, capture_output=True, text=True).stdout
    match = re.match(r"curl ([0-9]+)\.([0-9]+)\.([0-9]+)\b", version)
    if match is None or tuple(int(n) for n in match.groups()) < (8, 4, 0):
        raise ValueError("bounded temporal downloads require curl 8.4.0 or newer")
    root = Path(dataset_root)
    root.mkdir()
    (root / "data").mkdir()
    base = "https://huggingface.co/datasets/nebius/SWE-rebench-V2-PRs/resolve/"
    base += protocol["dataset"]["revision"]
    for shard in protocol["dataset"]["shards"]:
        # One probe byte permits an exact-sized payload at EOF; verification requires N.
        subprocess.run([
            curl, "--fail", "--location", "--silent", "--show-error", "--retry", "3",
            "--max-filesize", str(shard["size_bytes"] + 1),
            "--output", str(root / shard["path"]), base + "/" + shard["path"] + "?download=true",
        ], check=True)
    verify_dataset(protocol_path, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    metadata = commands.add_parser("metadata")
    metadata.add_argument("artifact")
    metadata.add_argument("run")
    extract = commands.add_parser("extract")
    extract.add_argument("archive")
    extract.add_argument("destination")
    capture = commands.add_parser("capture")
    capture.add_argument("destination")
    export = commands.add_parser("export")
    export.add_argument("repository")
    export.add_argument("destination")
    dataset = commands.add_parser("dataset")
    dataset.add_argument("protocol")
    dataset.add_argument("root")
    download = commands.add_parser("download")
    download.add_argument("protocol")
    download.add_argument("root")
    args = parser.parse_args()
    if args.command == "metadata":
        validate_metadata(args.artifact, args.run)
    elif args.command == "extract":
        extract_frame(args.archive, args.destination)
    elif args.command == "export":
        export_source(args.repository, args.destination)
    elif args.command == "capture":
        capture_archive(args.destination)
    elif args.command == "download":
        download_dataset(args.protocol, args.root)
    else:
        verify_dataset(args.protocol, args.root)


if __name__ == "__main__":
    main()
