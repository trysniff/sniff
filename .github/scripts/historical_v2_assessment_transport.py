#!/usr/bin/env python3
"""Validate and transport the frozen historical-v2 assessment state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
TOOLS_WORKFLOW = ".github/workflows/sniffbench-historical-v2-tools.yml"
TOOLS_ARTIFACT_PREFIX = "historical-v2-assessment-tools-"
TOOLS_ARTIFACT_MAX_BYTES = 128 * 1024 * 1024
TOOLS_PROVENANCE_SCHEMA = "sniffbench-historical-v2-tools-provenance-v1"

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
STORAGE_MIGRATION_NAME = "compact-stage-artifact-json-v1"
STORAGE_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-collector-storage-migration-v1"
)
STORAGE_MIGRATION_FROM_COLLECTOR_SHA = (
    "655093e6d55bdcb6e85560136f07c20c35f1f4ba"
)
STORAGE_MIGRATION_TO_COLLECTOR_SHA = (
    "bb658f593e144a659624c294c0db133facb29003"
)
STORAGE_MIGRATION_SOURCE_RUN_ID = 33_085_745_961
STORAGE_MIGRATION_SOURCE_ARTIFACT_ID = 9_662_095_012
STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:94585d826d841663b295bcc04519d1b568ecdd98714e7ecc7dc0e03074d2c4a0"
)
STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE = 348_102_634

GO_PREPARATION_MIGRATION_NAME = "package-scoped-go-dependency-preparation-v1"
GO_PREPARATION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-preparation-migration-v1"
)
GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA = STORAGE_MIGRATION_TO_COLLECTOR_SHA
GO_PREPARATION_MIGRATION_SOURCE_RUN_ID = 33_138_117_044
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID = 9_674_042_205
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:f01e1a276cef8a9204ccfd047a51bb80c30bc351beac30ff764e55c4285a8cad"
)
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE = 126_829_676

GO_MODULE_DOWNLOAD_MIGRATION_NAME = "declared-go-module-dependency-preparation-v1"
GO_MODULE_DOWNLOAD_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-module-download-migration-v1"
)
GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA = (
    "103d417c1fd90b2021c20f711e738d2c987b4fe0"
)
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID = 33_172_568_078
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID = 9_687_113_771
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:e369c48d6c9df58f294edc48a4d9ede079dbd16ab008df75b404d8331f591e68"
)
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE = 139_547_601

GO_PROJECT_ROOT_MIGRATION_NAME = "strict-go-project-root-validation-v1"
GO_PROJECT_ROOT_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-project-root-validation-migration-v1"
)
GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA = (
    "8c66843fa6a889b2d61136bc97775ae70c28b459"
)
GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID = 33_206_916_893
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID = 9_700_530_746
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:d3b2ab951c6693d2e71863570bdca7df981311126265d434d37e1dbb29a91c0f"
)
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE = 214_017_406

GO_EOF_PARSER_MIGRATION_NAME = "valid-go-eof-parser-v1"
GO_EOF_PARSER_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-eof-parser-migration-v1"
)
GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA = (
    "eac13353d39aa3f6b0dd0a27f6236d39637e6ce5"
)
GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID = 33_222_053_747
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID = 9_707_546_228
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c84330141739d038d247b9ab732b25474d9e6f14eddd0e66dfa6ef1307b588f2"
)
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE = 154_813_306

RESUME_SYMLINK_MIGRATION_NAME = "validated-resume-symlink-extraction-v1"
RESUME_SYMLINK_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-resume-symlink-extraction-migration-v1"
)
RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA = (
    "e044b4cdd238b13429f9c364eb3370e3939ffef7"
)
RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID = 33_277_931_633
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID = 9_725_671_517
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:1be3107f6857e785e6d5ca5316009f354464065bb8de6adeb4737d6c0c769936"
)
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE = 390_116_536

GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME = "committed-git-blob-source-census-v1"
GIT_BLOB_SOURCE_CENSUS_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-committed-git-blob-source-census-migration-v1"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA = (
    "94cd25a2689da1fae589d35074663a741554ad4f"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID = 33_294_497_203
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID = 9_730_689_446
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:f12fc0d45e1bc226a58c82731123ed5d6bbd1b51f0851758ec21cc35fe28228d"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE = 435_876_651

BOUNDED_GO_SEMANTIC_MIGRATION_NAME = "bounded-go-semantic-indexing-v1"
BOUNDED_GO_SEMANTIC_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-go-semantic-indexing-migration-v1"
)
BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA = (
    "ce0854638539d3862176abfd74b0d7e854eeaf0e"
)
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID = 33_367_134_527
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID = 9_755_742_430
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:fc4d21bf9780f2489e562bf3fa598d7e09530736f4b4e628b71a95f3251de17e"
)
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE = 328_326_113

HOSTED_SEAL_MARGIN_MIGRATION_NAME = "hosted-semantic-seal-margin-v1"
HOSTED_SEAL_MARGIN_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-hosted-semantic-seal-margin-migration-v1"
)
HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA = (
    "a697637ab5a0b68aeccc796df410d164fadf6abd"
)
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID = 33_655_327_837
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID = 9_856_923_702
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:41354adaea64b1c3ef1e82116ca995ca19ec7e92c7c7a48a13619dc9dab8dbdd"
)
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE = 369_624_965

GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME = "resumable-go-semantic-assembly-v1"
GO_SEMANTIC_ASSEMBLY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-resumable-go-semantic-assembly-migration-v1"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA = (
    "14cb74ec87663377463bbbe272ec48e3d478464b"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID = 33_693_790_826
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID = 9_871_249_545
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c4df6dc3298ead628449f6049e9aeada3c08c4185f0db091cf106fce428d4e86"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE = 373_052_082

FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME = (
    "finalized-go-semantic-compaction-v1"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-finalized-go-semantic-compaction-migration-v1"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA = (
    "04b9eb6a30bb997aa23c046af5ed99719a4fdb53"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID = 33_719_054_949
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID = 9_879_759_973
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c5ea8869939496f173a6dfcf8d4190e5ca26418b1c9daf47469b73e5279e6cec"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE = 382_505_430

INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME = (
    "indexed-semantic-snapshot-projection-v1"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-indexed-semantic-snapshot-projection-migration-v1"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA = (
    "311c6f087c4145ba3c6d1841c4dd58ff92cf21e4"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID = 33_730_932_228
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID = 9_884_076_774
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:9c34131a7d2ca09b647795aede94c909350bdaf455cb413db5ebca7783910587"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE = 337_799_271

NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME = (
    "batched-source-normalized-semantic-snapshot-v1"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-batched-source-normalized-semantic-snapshot-migration-v1"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA = (
    "379c2719695fc059351c9e4ad74a42d2e6500fd2"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID = 33_746_871_459
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID = 9_890_267_578
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:dee513c46e6ee8195a1ba37241afd913a03a950241ea7d8dbbefc2304e5cfa18"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE = 337_800_342

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


def _positive_json_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def validate_tools_provenance(
    run_path: pathlib.Path,
    artifacts_path: pathlib.Path,
    repository: str,
    head_sha: str,
    tools_run_id: int,
    assessment_run_id: int,
    assessment_run_attempt: int,
    output_path: pathlib.Path,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ValueError("assessment tools head SHA is invalid")
    if not repository or "\n" in repository or "\r" in repository:
        raise ValueError("assessment tools repository is invalid")

    run = _require_mapping(_read_json(run_path, "tools workflow run"), "tools workflow run")
    _require_exact_fields(
        run,
        {
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": TOOLS_WORKFLOW,
            "status": "completed",
            "conclusion": "success",
            "head_sha": head_sha,
        },
        "tools workflow run",
    )
    if _positive_json_integer(run.get("id"), "tools workflow run ID") != tools_run_id:
        raise ValueError("tools workflow run ID drifted")
    run_attempt = _positive_json_integer(
        run.get("run_attempt"), "tools workflow run attempt"
    )
    if run_attempt != 1:
        raise ValueError("tools workflow run attempt drifted")
    head_repository = _require_mapping(
        run.get("head_repository"), "tools workflow head repository"
    )
    if head_repository.get("full_name") != repository:
        raise ValueError("tools workflow repository drifted")

    listing = _require_mapping(
        _read_json(artifacts_path, "tools artifact listing"),
        "tools artifact listing",
    )
    if _positive_json_integer(
        listing.get("total_count"), "tools artifact total count"
    ) != 1:
        raise ValueError("tools workflow must publish exactly one artifact")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("tools artifact listing must contain exactly one artifact")
    artifact = _require_mapping(artifacts[0], "tools artifact")
    expected_name = f"{TOOLS_ARTIFACT_PREFIX}{head_sha}"
    _require_exact_fields(
        artifact,
        {"name": expected_name},
        "tools artifact",
    )
    if artifact.get("expired") is not False:
        raise ValueError("tools artifact is expired or has invalid expiry state")
    artifact_id = _positive_json_integer(artifact.get("id"), "tools artifact ID")
    artifact_size = _positive_json_integer(
        artifact.get("size_in_bytes"), "tools artifact size"
    )
    if artifact_size > TOOLS_ARTIFACT_MAX_BYTES:
        raise ValueError("tools artifact exceeds the size limit")
    artifact_digest = artifact.get("digest")
    if not isinstance(artifact_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", artifact_digest
    ) is None:
        raise ValueError("tools artifact digest is invalid")

    provenance = {
        "artifact_digest": artifact_digest,
        "artifact_id": artifact_id,
        "artifact_name": expected_name,
        "artifact_size": artifact_size,
        "assessment_run_attempt": assessment_run_attempt,
        "assessment_run_id": assessment_run_id,
        "schema": TOOLS_PROVENANCE_SCHEMA,
        "tools_head_sha": head_sha,
        "tools_run_attempt": run_attempt,
        "tools_run_id": tools_run_id,
        "tools_workflow": TOOLS_WORKFLOW,
    }
    _positive_json_integer(assessment_run_id, "assessment workflow run ID")
    _positive_json_integer(assessment_run_attempt, "assessment workflow run attempt")
    _plain_directory(output_path.parent, "tools provenance parent")
    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(provenance, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise ValueError(f"failed to create tools provenance: {error}") from error
    return provenance


def _normalized_link(path: pathlib.PurePosixPath, target_text: str) -> list[str]:
    if "\\" in target_text:
        raise ValueError(f"non-portable archive link: {path}")
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
        if "\\" in member.name:
            raise ValueError(f"non-portable archive member: {member.name}")
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


def _validated_archive_filter(
    member: tarfile.TarInfo, destination: str
) -> tarfile.TarInfo | None:
    if member.issym():
        # Archive-wide validation already proves that links are relative,
        # same-root, and never parents of another member. Avoid data_filter's
        # filesystem realpath check, which rejects valid Git worktree links
        # whose target passes through a regular .git indirection file.
        return member
    return tarfile.data_filter(member, destination)


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
            payload.extractall(path=destination, filter=_validated_archive_filter)
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


def _manifest_base(frame_run_id: int, collector_sha: str) -> dict[str, Any]:
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
        "selection_sha256": SELECTION_SHA256,
    }


def _manifest(frame_run_id: int, collector_sha: str) -> dict[str, Any]:
    value = _manifest_base(frame_run_id, collector_sha)
    value["schema_version"] = 1
    return value


def _migrated_manifest(
    frame_run_id: int,
    collector_sha: str,
    migrations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    value = _manifest_base(frame_run_id, collector_sha)
    value["collector_migrations"] = [dict(migration) for migration in migrations]
    value["schema_version"] = len(migrations) + 1
    return value


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
    schema_version = value.get("schema_version")
    if schema_version == 1:
        expected = _manifest(frame_run_id, collector_sha)
    elif schema_version in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14):
        migrations = value.get("collector_migrations")
        expected_count = schema_version - 1
        if not isinstance(migrations, list) or len(migrations) != expected_count:
            raise ValueError("transport manifest collector migration is invalid")
        migration_values = [
            _require_mapping(item, "transport manifest collector migration")
            for item in migrations
        ]
        _validate_collector_migrations(migration_values, collector_sha)
        expected = _migrated_manifest(
            frame_run_id, collector_sha, migration_values
        )
    else:
        raise ValueError("transport manifest schema version is unsupported")
    if value != expected:
        differing = sorted(
            key
            for key in set(value) | set(expected)
            if value.get(key) != expected.get(key)
        )
        raise ValueError(f"transport manifest drifted: {differing}")
    return collector_sha


def _migration_record(
    migration_name: str,
    target_collector_sha: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> dict[str, Any]:
    if migration_name == STORAGE_MIGRATION_NAME:
        contract = STORAGE_MIGRATION_CONTRACT
        source_collector_sha = STORAGE_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PREPARATION_MIGRATION_NAME:
        contract = GO_PREPARATION_MIGRATION_CONTRACT
        source_collector_sha = GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_MODULE_DOWNLOAD_MIGRATION_NAME:
        contract = GO_MODULE_DOWNLOAD_MIGRATION_CONTRACT
        source_collector_sha = GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PROJECT_ROOT_MIGRATION_NAME:
        contract = GO_PROJECT_ROOT_MIGRATION_CONTRACT
        source_collector_sha = GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_EOF_PARSER_MIGRATION_NAME:
        contract = GO_EOF_PARSER_MIGRATION_CONTRACT
        source_collector_sha = GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == RESUME_SYMLINK_MIGRATION_NAME:
        contract = RESUME_SYMLINK_MIGRATION_CONTRACT
        source_collector_sha = RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME:
        contract = GIT_BLOB_SOURCE_CENSUS_MIGRATION_CONTRACT
        source_collector_sha = GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == BOUNDED_GO_SEMANTIC_MIGRATION_NAME:
        contract = BOUNDED_GO_SEMANTIC_MIGRATION_CONTRACT
        source_collector_sha = BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == HOSTED_SEAL_MARGIN_MIGRATION_NAME:
        contract = HOSTED_SEAL_MARGIN_MIGRATION_CONTRACT
        source_collector_sha = HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME:
        contract = GO_SEMANTIC_ASSEMBLY_MIGRATION_CONTRACT
        source_collector_sha = GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME:
        contract = FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_CONTRACT
        source_collector_sha = (
            FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME:
        contract = INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_CONTRACT
        source_collector_sha = (
            INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME:
        contract = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_CONTRACT
        source_collector_sha = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
    else:
        raise ValueError("transport manifest collector migration is not allowlisted")
    return {
        "from_collector_sha": source_collector_sha,
        "migration_contract": contract,
        "migration_name": migration_name,
        "source_artifact_digest": source_artifact_digest,
        "source_artifact_id": source_artifact_id,
        "source_artifact_size": source_artifact_size,
        "source_head_sha": source_head_sha,
        "source_run_id": source_run_id,
        "to_collector_sha": target_collector_sha,
    }


def _expected_storage_migration() -> dict[str, Any]:
    return _migration_record(
        STORAGE_MIGRATION_NAME,
        STORAGE_MIGRATION_TO_COLLECTOR_SHA,
        STORAGE_MIGRATION_SOURCE_RUN_ID,
        STORAGE_MIGRATION_FROM_COLLECTOR_SHA,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_preparation_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PREPARATION_MIGRATION_NAME,
        target_collector_sha,
        GO_PREPARATION_MIGRATION_SOURCE_RUN_ID,
        GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_module_download_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_MODULE_DOWNLOAD_MIGRATION_NAME,
        target_collector_sha,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID,
        GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_project_root_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PROJECT_ROOT_MIGRATION_NAME,
        target_collector_sha,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
        GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_eof_parser_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_EOF_PARSER_MIGRATION_NAME,
        target_collector_sha,
        GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
        GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_resume_symlink_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        RESUME_SYMLINK_MIGRATION_NAME,
        target_collector_sha,
        RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
        RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_git_blob_source_census_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
        target_collector_sha,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_bounded_go_semantic_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
        target_collector_sha,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID,
        BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_hosted_seal_margin_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        HOSTED_SEAL_MARGIN_MIGRATION_NAME,
        target_collector_sha,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
        HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_semantic_assembly_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
        target_collector_sha,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_finalized_go_semantic_compaction_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME,
        target_collector_sha,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_indexed_semantic_snapshot_projection_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME,
        target_collector_sha,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_normalized_semantic_snapshot_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME,
        target_collector_sha,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _validate_collector_migrations(
    migrations: Sequence[Mapping[str, Any]], collector_sha: str
) -> None:
    if len(migrations) not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
        raise ValueError("transport manifest collector migration chain is invalid")
    expected = [_expected_storage_migration()]
    if len(migrations) == 2:
        expected.append(_expected_go_preparation_migration(collector_sha))
    elif len(migrations) in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
        expected.append(
            _expected_go_preparation_migration(
                GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
            )
        )
        module_download_target = (
            GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
            if len(migrations) >= 4
            else collector_sha
        )
        expected.append(
            _expected_go_module_download_migration(module_download_target)
        )
        if len(migrations) >= 4:
            project_root_target = (
                GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 5
                else collector_sha
            )
            expected.append(_expected_go_project_root_migration(project_root_target))
        if len(migrations) >= 5:
            eof_target = (
                RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 6
                else collector_sha
            )
            expected.append(_expected_go_eof_parser_migration(eof_target))
        if len(migrations) >= 6:
            resume_target = (
                GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 7
                else collector_sha
            )
            expected.append(_expected_resume_symlink_migration(resume_target))
        if len(migrations) >= 7:
            git_blob_target = (
                BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 8
                else collector_sha
            )
            expected.append(_expected_git_blob_source_census_migration(git_blob_target))
        if len(migrations) >= 8:
            bounded_semantic_target = (
                HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 9
                else collector_sha
            )
            expected.append(
                _expected_bounded_go_semantic_migration(bounded_semantic_target)
            )
        if len(migrations) >= 9:
            hosted_target = (
                GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 10
                else collector_sha
            )
            expected.append(_expected_hosted_seal_margin_migration(hosted_target))
        if len(migrations) >= 10:
            semantic_assembly_target = (
                FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 11
                else collector_sha
            )
            expected.append(
                _expected_go_semantic_assembly_migration(semantic_assembly_target)
            )
        if len(migrations) >= 11:
            finalized_compaction_target = (
                INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 12
                else collector_sha
            )
            expected.append(
                _expected_finalized_go_semantic_compaction_migration(
                    finalized_compaction_target
                )
            )
        if len(migrations) >= 12:
            indexed_projection_target = (
                NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) == 13
                else collector_sha
            )
            expected.append(
                _expected_indexed_semantic_snapshot_projection_migration(
                    indexed_projection_target
                )
            )
        if len(migrations) == 13:
            expected.append(
                _expected_normalized_semantic_snapshot_migration(
                    collector_sha
                )
            )
    elif collector_sha != STORAGE_MIGRATION_TO_COLLECTOR_SHA:
        raise ValueError("transport manifest collector migration target drifted")
    if [dict(migration) for migration in migrations] != expected:
        raise ValueError("transport manifest collector migration chain drifted")
    if any(
        left["to_collector_sha"] != right["from_collector_sha"]
        for left, right in zip(expected, expected[1:])
    ):
        raise ValueError("transport manifest collector migration chain is disconnected")


def migrate_manifest(
    path: pathlib.Path,
    frame_run_id: int,
    target_collector_sha: str,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> str:
    value = _require_mapping(
        _read_json(path, "transport manifest"), "transport manifest"
    )
    source_collector_sha = validate_manifest(path, frame_run_id)
    schema_version = value.get("schema_version")
    if schema_version == 1:
        expected_name = STORAGE_MIGRATION_NAME
        migrations: list[Mapping[str, Any]] = []
    elif schema_version == 2:
        expected_name = GO_PREPARATION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 3:
        expected_name = GO_MODULE_DOWNLOAD_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 4:
        expected_name = GO_PROJECT_ROOT_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 5:
        expected_name = GO_EOF_PARSER_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 6:
        expected_name = RESUME_SYMLINK_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 7:
        expected_name = GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 8:
        expected_name = BOUNDED_GO_SEMANTIC_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 9:
        expected_name = HOSTED_SEAL_MARGIN_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 10:
        expected_name = GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 11:
        expected_name = FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 12:
        expected_name = INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 13:
        expected_name = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    else:
        raise ValueError("transport manifest collector migration chain is closed")
    if migration_name != expected_name:
        raise ValueError("transport manifest collector migration is out of order")
    migration = _migration_record(
        migration_name,
        target_collector_sha,
        source_run_id,
        source_head_sha,
        source_artifact_id,
        source_artifact_digest,
        source_artifact_size,
    )
    if migration["from_collector_sha"] != source_collector_sha:
        raise ValueError("transport manifest collector migration source drifted")
    migrations.append(migration)
    _validate_collector_migrations(migrations, target_collector_sha)
    migrated = _migrated_manifest(frame_run_id, target_collector_sha, migrations)
    temporary = path.with_name(f".{path.name}.migrating")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(migrated, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        raise ValueError(f"failed to migrate transport manifest: {error}") from error
    validate_manifest(path, frame_run_id)
    return target_collector_sha


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

    migrate = commands.add_parser("migrate-manifest")
    migrate.add_argument("path", type=pathlib.Path)
    migrate.add_argument("frame_run_id", type=_positive_integer)
    migrate.add_argument("target_collector_sha")
    migrate.add_argument("migration_name")
    migrate.add_argument("source_run_id", type=_positive_integer)
    migrate.add_argument("source_head_sha")
    migrate.add_argument("source_artifact_id", type=_positive_integer)
    migrate.add_argument("source_artifact_digest")
    migrate.add_argument("source_artifact_size", type=_positive_integer)

    tools = commands.add_parser("validate-tools-provenance")
    tools.add_argument("run", type=pathlib.Path)
    tools.add_argument("artifacts", type=pathlib.Path)
    tools.add_argument("repository")
    tools.add_argument("head_sha")
    tools.add_argument("tools_run_id", type=_positive_integer)
    tools.add_argument("assessment_run_id", type=_positive_integer)
    tools.add_argument("assessment_run_attempt", type=_positive_integer)
    tools.add_argument("output", type=pathlib.Path)
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
        elif args.command == "migrate-manifest":
            print(
                migrate_manifest(
                    args.path,
                    args.frame_run_id,
                    args.target_collector_sha,
                    args.migration_name,
                    args.source_run_id,
                    args.source_head_sha,
                    args.source_artifact_id,
                    args.source_artifact_digest,
                    args.source_artifact_size,
                )
            )
        elif args.command == "validate-tools-provenance":
            provenance = validate_tools_provenance(
                args.run,
                args.artifacts,
                args.repository,
                args.head_sha,
                args.tools_run_id,
                args.assessment_run_id,
                args.assessment_run_attempt,
                args.output,
            )
            print(f"TOOLS_ARTIFACT_ID={provenance['artifact_id']}")
            print(f"TOOLS_ARTIFACT_DIGEST={provenance['artifact_digest']}")
            print(f"TOOLS_ARTIFACT_SIZE={provenance['artifact_size']}")
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
