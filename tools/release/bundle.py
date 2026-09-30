"""Create and verify source-bound development candidate archives."""

import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from sbom import source_sbom


TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
}
SCHEMA = "sniff-development-candidate-v1"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 64


def bounded_archive_bytes(archive):
    with archive.open("rb") as handle:
        data = handle.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive exceeds its size limit")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def create(root, binary, metadata_path, rustc_path, output, target, commit, epoch):
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or target not in TARGETS:
        raise ValueError("Invalid source commit or target")
    metadata = json.loads(metadata_path.read_bytes())
    package = next(
        item
        for item in metadata["packages"]
        if item["id"] == metadata["resolve"]["root"]
    )
    version = package["version"]
    if not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("Invalid package version")
    name = "bin/sniff.exe" if "windows" in target else "bin/sniff"
    files = {name: binary.read_bytes()}
    notices = [
        root / "LICENSE",
        root / "THIRD_PARTY_NOTICES.md",
        *sorted((root / "LICENSES").glob("*.txt")),
    ]
    for path in notices:
        files[path.relative_to(root).as_posix()] = path.read_bytes()
    files["INSTALL.md"] = (Path(__file__).parent / "INSTALL.md").read_bytes()
    lock = (root / "Cargo.lock").read_bytes()
    files["sbom.spdx.json"] = encode(
        source_sbom(
            metadata,
            lock,
            commit,
            target,
            epoch,
            name,
            digest(files[name]),
        )
    )
    manifest = {
        "schema": SCHEMA,
        "distribution": "development-candidate",
        "source_repository": "https://github.com/trysniff/sniff",
        "source_commit": commit,
        "package": "sniff-cli",
        "version": version,
        "target": target,
        "rustc": rustc_path.read_text(encoding="utf-8").strip(),
        "cargo_lock_sha256": digest(lock),
        "files": {
            path: {"sha256": digest(data), "size_bytes": len(data)}
            for path, data in sorted(files.items())
        },
    }
    files["manifest.json"] = encode(manifest)
    output.mkdir(parents=True, exist_ok=False)
    archive = output / f"sniff-{version}-{commit[:12]}-{target}.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path, data in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (
                stat.S_IFREG | (0o755 if path == name else 0o644)
            ) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, data)
    (output / "SHA256SUMS").write_text(
        f"{digest(bounded_archive_bytes(archive))}  {archive.name}\n",
        encoding="ascii",
    )
    (output / "manifest.json").write_bytes(files["manifest.json"])
    (output / "sbom.spdx.json").write_bytes(files["sbom.spdx.json"])
    return archive


def verify(archive, target, commit, extract):
    expected = f"{digest(bounded_archive_bytes(archive))}  {archive.name}\n"
    if (archive.parent / "SHA256SUMS").read_text(encoding="ascii") != expected:
        raise ValueError("Archive checksum mismatch")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if (
            len(entries) > MAX_ENTRIES
            or sum(entry.file_size for entry in entries) > MAX_ARCHIVE_BYTES
        ):
            raise ValueError("Archive exceeds its extraction limit")
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive entry")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in entry.filename
                or ":" in entry.filename
                or entry.filename != path.as_posix()
                or path.as_posix() == "."
            ):
                raise ValueError("Unsafe archive entry")
            if stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFREG:
                raise ValueError("Archive contains a non-file entry")
            executable = "bin/sniff.exe" if "windows" in target else "bin/sniff"
            expected_mode = 0o755 if entry.filename == executable else 0o644
            if stat.S_IMODE(entry.external_attr >> 16) != expected_mode:
                raise ValueError("Archive contains unexpected file permissions")
            if entry.file_size > MAX_FILE_BYTES:
                raise ValueError("Archive entry exceeds its size limit")
        manifest_bytes = bundle.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        identity = {
            "schema": SCHEMA,
            "distribution": "development-candidate",
            "source_repository": "https://github.com/trysniff/sniff",
            "source_commit": commit,
            "target": target,
        }
        if any(manifest.get(key) != value for key, value in identity.items()):
            raise ValueError("Candidate identity mismatch")
        if manifest_bytes != (archive.parent / "manifest.json").read_bytes():
            raise ValueError("Manifest sidecar mismatch")
        expected_name = f"sniff-{manifest['version']}-{commit[:12]}-{target}.zip"
        if manifest["package"] != "sniff-cli" or archive.name != expected_name:
            raise ValueError("Candidate package or archive name mismatch")
        if set(names) != set(manifest["files"]) | {"manifest.json"}:
            raise ValueError("Archive file census mismatch")
        for name, commitment in manifest["files"].items():
            data = bundle.read(name)
            if {"sha256": digest(data), "size_bytes": len(data)} != commitment:
                raise ValueError("Candidate file commitment mismatch")
        sbom_bytes = (archive.parent / "sbom.spdx.json").read_bytes()
        if bundle.read("sbom.spdx.json") != sbom_bytes:
            raise ValueError("SBOM sidecar mismatch")
        if executable not in manifest["files"]:
            raise ValueError("Candidate executable missing")
        extract.mkdir(parents=True, exist_ok=False)
        for entry in entries:
            destination = extract / entry.filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(bundle.read(entry.filename))
            destination.chmod(stat.S_IMODE(entry.external_attr >> 16))
    return extract / executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser("create")
    for name in ("root", "binary", "metadata", "rustc", "output"):
        build.add_argument("--" + name, type=Path, required=True)
    build.add_argument("--epoch", type=int, required=True)
    validate = subcommands.add_parser("verify")
    validate.add_argument("--archive", type=Path, required=True)
    validate.add_argument("--extract", type=Path, required=True)
    for command in (build, validate):
        command.add_argument("--target", choices=sorted(TARGETS), required=True)
        command.add_argument("--commit", required=True)
    args = parser.parse_args()
    if args.command == "create":
        print(
            create(
                args.root,
                args.binary,
                args.metadata,
                args.rustc,
                args.output,
                args.target,
                args.commit,
                args.epoch,
            )
        )
    else:
        print(verify(args.archive, args.target, args.commit, args.extract))


if __name__ == "__main__":
    main()
