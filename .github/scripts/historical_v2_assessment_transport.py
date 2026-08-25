#!/usr/bin/env python3
"""Validate and transport the frozen historical-v2 assessment state."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tarfile
from collections.abc import Mapping, Sequence
from typing import Any

ALLOWED_ARCHIVE_ROOTS = frozenset(
    {
        "historical-v2-assessment-state",
        "historical-v2-assessment-work",
        "historical-v2-assessment-frame",
        "historical-v2-assessment-transport",
    }
)
MAX_ARCHIVE_MEMBERS = 2_000_000
MAX_EXTRACTED_BYTES = 20 * 1024 * 1024 * 1024
MAX_MEMBER_PATH_BYTES = 4096

FRAME_RUN_ID = 32_804_623_556
FRAME_RUN_ATTEMPT = 1
FRAME_COLLECTOR_SHA = "8681f9c379c4e4817c7ed49f06f47f4c47d1f91b"
FRAME_ARTIFACT_ID = 9_547_888_605
FRAME_ARTIFACT_NAME = "historical-v2-frame-32804623556"
FRAME_ARTIFACT_DIGEST = (
    "sha256:542174315793a4a46c5c897ef549273f3202a36afdf464ed9ddaa65cc9ffbe7b"
)
FRAME_ARTIFACT_SIZE = 25_669_281
FRAME_CHECKSUMS_SHA256 = (
    "d7c0bb8d0c47d58ad9d30017ca30201c317445eac9f865e3d7dd1cfcb7f228c2"
)
DATASET_REVISION = "40faf2c1bb160de625f3c3270ac9d62ea45f3f9c"
PROTOCOL_SHA256 = "deb98a285867fc5ea52761c252839d74268f239824bfc1a82027a352695cfc6f"
FRAME_SHA256 = "f0df01a6d8e1de08cec21c10bc232f65c375bca28092c53ffb78b8e6954dbf32"
EXCLUSION_MANIFEST_SHA256 = (
    "1a6d6c9c4e58bcb2b30161c13d3711a8bf028ccbb666c7e6d965df4fb933f08c"
)
SELECTION_SHA256 = "d37f4bef7616e5da5dd08b161e497432aa42c5eba32d633da9a9b431d65e98e3"
PAYLOADS_SHA256 = "16b1da8b149a1ecc9d101eef05435b9d1ac504044ebbd644922d39ecc3999bd5"

FRAME_FILE_SHA256 = {
    "environment.txt": "2e87f3c3e1b2005f6b6d09b1bf1b82d30a9433636c3c67f0806cc68e80ab6800",
    "exclusions.json": "74bccb100eb48ab87952bd7eec137b2285edbc68d2547715bc0e06a80e029f76",
    "frame.json": "de8dca6b0248229171a3e82f61b3e59e324ebca47c902e315628d4335120719f",
    "provenance.json": "f6f237a948ffb9de8a4dfefda285f2cf8a9d90777f3700bf69ca53f2f19a45be",
    "selection.json": "e6f06b0b887168205dcaa1d903ffcf54efe6199ea730ee118b28ad8e24925853",
    "selected-payloads.json": "cc27d9274e9d969015055945a9c93df178732835ac3a4312af93acb1b1d66124",
}


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plain_file(path: pathlib.Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} is not a plain file: {path}")


def _plain_directory(path: pathlib.Path, label: str) -> None:
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"{label} is not a plain directory: {path}")


def _read_json(path: pathlib.Path, label: str) -> Any:
    _plain_file(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label}: {error}") from error


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: Mapping[str, Any], label: str
) -> None:
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ValueError(f"{label} field drifted: {key}")


def _normalized_link(path: pathlib.PurePosixPath, target_text: str) -> list[str]:
    target = pathlib.PurePosixPath(target_text)
    if target.is_absolute():
        raise ValueError(f"absolute archive link: {path}")
    normalized: list[str] = []
    for part in path.parent.joinpath(target).parts:
        if part == "..":
            if not normalized:
                raise ValueError(f"escaping archive link: {path}")
            normalized.pop()
        elif part not in ("", "."):
            normalized.append(part)
    return normalized


def _validate_archive_members(payload: tarfile.TarFile) -> None:
    members = payload.getmembers()
    if not members:
        raise ValueError("assessment archive is empty")
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("assessment archive exceeds the member-count limit")

    seen_roots: set[str] = set()
    seen_paths: set[pathlib.PurePosixPath] = set()
    root_directories: set[str] = set()
    symlink_paths: set[pathlib.PurePosixPath] = set()
    extracted_bytes = 0
    for member in members:
        if len(member.name.encode("utf-8")) > MAX_MEMBER_PATH_BYTES:
            raise ValueError(f"archive member path is too long: {member.name}")
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError(f"unsafe archive member: {member.name}")
        if path.parts[0] not in ALLOWED_ARCHIVE_ROOTS:
            raise ValueError(f"unexpected archive member: {member.name}")
        if path in seen_paths:
            raise ValueError(f"duplicate archive member: {member.name}")
        if not (member.isfile() or member.isdir() or member.issym()):
            raise ValueError(f"unsupported archive member: {member.name}")

        seen_paths.add(path)
        seen_roots.add(path.parts[0])
        if len(path.parts) == 1 and member.isdir():
            root_directories.add(path.parts[0])
        if member.isfile():
            if member.size < 0:
                raise ValueError(f"archive member has a negative size: {member.name}")
            extracted_bytes += member.size
            if extracted_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("assessment archive exceeds the extracted-byte limit")
        elif member.issym():
            symlink_paths.add(path)
            normalized = _normalized_link(path, member.linkname)
            if not normalized or normalized[0] != path.parts[0]:
                raise ValueError(f"cross-root archive link: {member.name}")

    if seen_roots != ALLOWED_ARCHIVE_ROOTS:
        raise ValueError(f"assessment archive roots differ: {sorted(seen_roots)}")
    if root_directories != ALLOWED_ARCHIVE_ROOTS:
        raise ValueError(
            f"assessment archive root directories differ: {sorted(root_directories)}"
        )
    for path in seen_paths:
        for parent in path.parents:
            if parent in symlink_paths:
                raise ValueError(f"archive member descends through a link: {path}")


def validate_archive(archive: pathlib.Path) -> None:
    _plain_file(archive, "assessment archive")
    try:
        with tarfile.open(archive, "r:gz") as payload:
            _validate_archive_members(payload)
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"invalid assessment archive: {error}") from error


def extract_resume(archive: pathlib.Path, destination: pathlib.Path) -> None:
    _plain_file(archive, "resume archive")
    _plain_directory(destination, "resume destination")
    for root in ALLOWED_ARCHIVE_ROOTS:
        if destination.joinpath(root).exists():
            raise ValueError(
                f"resume destination already contains archive root: {root}"
            )
    try:
        with tarfile.open(archive, "r:gz") as payload:
            _validate_archive_members(payload)
            payload.extractall(path=destination, filter="data")
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"failed to extract assessment archive: {error}") from error
    for root in ALLOWED_ARCHIVE_ROOTS:
        _plain_directory(destination.joinpath(root), "restored assessment root")


def validate_frame(frame_root: pathlib.Path) -> None:
    _plain_directory(frame_root, "frame root")
    expected_files = set(FRAME_FILE_SHA256) | {"SHA256SUMS"}
    observed_files = set()
    for path in frame_root.iterdir():
        _plain_file(path, "frame artifact")
        observed_files.add(path.name)
    if observed_files != expected_files:
        raise ValueError(f"frame files differ: {sorted(observed_files)}")

    checksums = frame_root.joinpath("SHA256SUMS")
    if _sha256(checksums) != FRAME_CHECKSUMS_SHA256:
        raise ValueError("frame SHA256SUMS commitment drifted")
    expected_checksum_text = "".join(
        f"{digest}  {name}\n" for name, digest in FRAME_FILE_SHA256.items()
    )
    if checksums.read_text(encoding="utf-8") != expected_checksum_text:
        raise ValueError("frame SHA256SUMS contents drifted")
    for name, expected_digest in FRAME_FILE_SHA256.items():
        if _sha256(frame_root.joinpath(name)) != expected_digest:
            raise ValueError(f"frame file commitment drifted: {name}")

    provenance = _require_mapping(
        _read_json(frame_root.joinpath("provenance.json"), "frame provenance"),
        "frame provenance",
    )
    expected_provenance = {
        "schema_version": 1,
        "repository": "trysniff/sniff",
        "collector_revision": FRAME_COLLECTOR_SHA,
        "workflow_run_id": str(FRAME_RUN_ID),
        "workflow_run_attempt": str(FRAME_RUN_ATTEMPT),
        "model_provider_access": False,
    }
    if provenance != expected_provenance:
        raise ValueError("frame provenance drifted")

    frame = _require_mapping(
        _read_json(frame_root.joinpath("frame.json"), "frame"), "frame"
    )
    _require_exact_fields(
        frame,
        {
            "dataset_revision": DATASET_REVISION,
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "row_count": 126_300,
            "eligible_count": 13_774,
            "excluded_count": 112_526,
        },
        "frame",
    )
    exclusions = _require_mapping(
        _read_json(frame_root.joinpath("exclusions.json"), "exclusions"),
        "exclusions",
    )
    _require_exact_fields(
        exclusions,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "manifest_sha256": EXCLUSION_MANIFEST_SHA256,
            "repository_count": 615,
        },
        "exclusions",
    )
    selection = _require_mapping(
        _read_json(frame_root.joinpath("selection.json"), "selection"), "selection"
    )
    _require_exact_fields(
        selection,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "selection_sha256": SELECTION_SHA256,
            "selected_count": 664,
            "unfilled_slot_count": 104,
        },
        "selection",
    )
    payloads = _require_mapping(
        _read_json(frame_root.joinpath("selected-payloads.json"), "payloads"),
        "payloads",
    )
    _require_exact_fields(
        payloads,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "selection_sha256": SELECTION_SHA256,
            "payloads_sha256": PAYLOADS_SHA256,
            "selected_count": 664,
        },
        "payloads",
    )


def _manifest(frame_run_id: int, collector_sha: str) -> dict[str, Any]:
    if frame_run_id != FRAME_RUN_ID:
        raise ValueError(f"frame run ID must be {FRAME_RUN_ID}")
    if re.fullmatch(r"[0-9a-f]{40}", collector_sha) is None:
        raise ValueError("assessment collector SHA is invalid")
    return {
        "collector_sha": collector_sha,
        "exclusion_manifest_sha256": EXCLUSION_MANIFEST_SHA256,
        "frame_artifact_digest": FRAME_ARTIFACT_DIGEST,
        "frame_artifact_id": FRAME_ARTIFACT_ID,
        "frame_artifact_name": FRAME_ARTIFACT_NAME,
        "frame_artifact_size": FRAME_ARTIFACT_SIZE,
        "frame_checksums_sha256": FRAME_CHECKSUMS_SHA256,
        "frame_collector_sha": FRAME_COLLECTOR_SHA,
        "frame_repository": "trysniff/sniff",
        "frame_run_attempt": FRAME_RUN_ATTEMPT,
        "frame_run_id": FRAME_RUN_ID,
        "frame_sha256": FRAME_SHA256,
        "frame_workflow": ".github/workflows/sniffbench-historical-v2-frame.yml",
        "model_provider_access": False,
        "payloads_sha256": PAYLOADS_SHA256,
        "protocol_sha256": PROTOCOL_SHA256,
        "schema_version": 1,
        "selection_sha256": SELECTION_SHA256,
    }


def initialize_manifest(
    path: pathlib.Path, collector_sha: str, frame_run_id: int
) -> None:
    value = _manifest(frame_run_id, collector_sha)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except OSError as error:
        raise ValueError(f"failed to create transport manifest: {error}") from error


def validate_manifest(path: pathlib.Path, frame_run_id: int) -> str:
    value = _require_mapping(
        _read_json(path, "transport manifest"), "transport manifest"
    )
    collector_sha = value.get("collector_sha")
    if not isinstance(collector_sha, str):
        raise ValueError("transport manifest collector SHA is missing")
    expected = _manifest(frame_run_id, collector_sha)
    if value != expected:
        differing = sorted(
            key
            for key in set(value) | set(expected)
            if value.get(key) != expected.get(key)
        )
        raise ValueError(f"transport manifest drifted: {differing}")
    return collector_sha


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract-resume")
    extract.add_argument("archive", type=pathlib.Path)
    extract.add_argument("destination", type=pathlib.Path)

    archive = commands.add_parser("validate-archive")
    archive.add_argument("archive", type=pathlib.Path)

    frame = commands.add_parser("validate-frame")
    frame.add_argument("frame_root", type=pathlib.Path)

    initialize = commands.add_parser("initialize-manifest")
    initialize.add_argument("path", type=pathlib.Path)
    initialize.add_argument("collector_sha")
    initialize.add_argument("frame_run_id", type=_positive_integer)

    manifest = commands.add_parser("validate-manifest")
    manifest.add_argument("path", type=pathlib.Path)
    manifest.add_argument("frame_run_id", type=_positive_integer)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "extract-resume":
            extract_resume(args.archive, args.destination)
        elif args.command == "validate-archive":
            validate_archive(args.archive)
        elif args.command == "validate-frame":
            validate_frame(args.frame_root)
        elif args.command == "initialize-manifest":
            initialize_manifest(args.path, args.collector_sha, args.frame_run_id)
        elif args.command == "validate-manifest":
            print(validate_manifest(args.path, args.frame_run_id))
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
