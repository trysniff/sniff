#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import tarfile
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("historical_v2_assessment_transport.py")
WORKFLOW_PATH = pathlib.Path(__file__).parents[1].joinpath(
    "workflows", "sniffbench-historical-v2-assessment.yml"
)
TOOLS_WORKFLOW_PATH = pathlib.Path(__file__).parents[1].joinpath(
    "workflows", "sniffbench-historical-v2-tools.yml"
)
GO_DEPENDENCY_PATH = pathlib.Path(__file__).parents[2].joinpath(
    "src", "benchmark_intentional_boundary_project_model_go_dependency.rs"
)
SCIP_REPLAY_FIXTURE_ROOT = pathlib.Path(__file__).with_name("fixtures").joinpath(
    "historical-v2-scip-kind-replay"
)
SPEC = importlib.util.spec_from_file_location("assessment_transport", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load assessment transport helper")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


class ToolsProvenanceTests(unittest.TestCase):
    HEAD_SHA = "a" * 40
    REPOSITORY = "trysniff/sniff"
    TOOLS_RUN_ID = 123456
    ASSESSMENT_RUN_ID = 123789

    @classmethod
    def _run(cls) -> dict:
        return {
            "id": cls.TOOLS_RUN_ID,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_repository": {"full_name": cls.REPOSITORY},
            "path": transport.TOOLS_WORKFLOW,
            "status": "completed",
            "conclusion": "success",
            "head_sha": cls.HEAD_SHA,
            "run_attempt": 1,
        }

    @classmethod
    def _artifacts(cls) -> dict:
        return {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 987654,
                    "name": f"{transport.TOOLS_ARTIFACT_PREFIX}{cls.HEAD_SHA}",
                    "expired": False,
                    "size_in_bytes": 69_709_459,
                    "digest": f"sha256:{'b' * 64}",
                }
            ],
        }

    @staticmethod
    def _write(path: pathlib.Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_exact_tools_run_writes_canonical_create_new_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run_path = root.joinpath("run.json")
            artifacts_path = root.joinpath("artifacts.json")
            output = root.joinpath("provenance.json")
            self._write(run_path, self._run())
            self._write(artifacts_path, self._artifacts())

            result = transport.validate_tools_provenance(
                run_path,
                artifacts_path,
                self.REPOSITORY,
                self.HEAD_SHA,
                self.TOOLS_RUN_ID,
                self.ASSESSMENT_RUN_ID,
                1,
                output,
            )

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
            self.assertEqual(result["schema"], transport.TOOLS_PROVENANCE_SCHEMA)
            self.assertEqual(result["artifact_id"], 987654)
            self.assertEqual(result["assessment_run_id"], self.ASSESSMENT_RUN_ID)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            )
            with self.assertRaises(ValueError):
                transport.validate_tools_provenance(
                    run_path,
                    artifacts_path,
                    self.REPOSITORY,
                    self.HEAD_SHA,
                    self.TOOLS_RUN_ID,
                    self.ASSESSMENT_RUN_ID,
                    1,
                    output,
                )

    def test_tools_run_or_artifact_drift_is_rejected(self) -> None:
        cases = (
            ("run-id", lambda run, _: run.__setitem__("id", 999)),
            ("event", lambda run, _: run.__setitem__("event", "push")),
            ("branch", lambda run, _: run.__setitem__("head_branch", "other")),
            (
                "repository",
                lambda run, _: run["head_repository"].__setitem__(
                    "full_name", "other/sniff"
                ),
            ),
            ("workflow", lambda run, _: run.__setitem__("path", "other.yml")),
            ("status", lambda run, _: run.__setitem__("status", "in_progress")),
            ("conclusion", lambda run, _: run.__setitem__("conclusion", "failure")),
            ("head-sha", lambda run, _: run.__setitem__("head_sha", "c" * 40)),
            ("attempt", lambda run, _: run.__setitem__("run_attempt", 2)),
            ("count", lambda _, artifacts: artifacts.__setitem__("total_count", 2)),
            ("extra", lambda _, artifacts: artifacts["artifacts"].append({})),
            (
                "name",
                lambda _, artifacts: artifacts["artifacts"][0].__setitem__(
                    "name", "replacement"
                ),
            ),
            (
                "expired",
                lambda _, artifacts: artifacts["artifacts"][0].__setitem__(
                    "expired", True
                ),
            ),
            (
                "non-boolean-expiry",
                lambda _, artifacts: artifacts["artifacts"][0].__setitem__(
                    "expired", 0
                ),
            ),
            ("boolean-count", lambda _, artifacts: artifacts.__setitem__("total_count", True)),
            (
                "size",
                lambda _, artifacts: artifacts["artifacts"][0].__setitem__(
                    "size_in_bytes", transport.TOOLS_ARTIFACT_MAX_BYTES + 1
                ),
            ),
            (
                "digest",
                lambda _, artifacts: artifacts["artifacts"][0].__setitem__(
                    "digest", "sha256:not-a-digest"
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name, mutate in cases:
                run = copy.deepcopy(self._run())
                artifacts = copy.deepcopy(self._artifacts())
                mutate(run, artifacts)
                run_path = root.joinpath(f"{name}-run.json")
                artifacts_path = root.joinpath(f"{name}-artifacts.json")
                output = root.joinpath(f"{name}-provenance.json")
                self._write(run_path, run)
                self._write(artifacts_path, artifacts)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    transport.validate_tools_provenance(
                        run_path,
                        artifacts_path,
                        self.REPOSITORY,
                        self.HEAD_SHA,
                        self.TOOLS_RUN_ID,
                        self.ASSESSMENT_RUN_ID,
                        1,
                        output,
                    )
                self.assertFalse(output.exists())

    def test_tools_provenance_cli_emits_only_validated_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run_path = root.joinpath("run.json")
            artifacts_path = root.joinpath("artifacts.json")
            output = root.joinpath("provenance.json")
            self._write(run_path, self._run())
            self._write(artifacts_path, self._artifacts())
            stdout = io.StringIO()

            with mock.patch("sys.stdout", stdout):
                status = transport.main(
                    [
                        "validate-tools-provenance",
                        str(run_path),
                        str(artifacts_path),
                        self.REPOSITORY,
                        self.HEAD_SHA,
                        str(self.TOOLS_RUN_ID),
                        str(self.ASSESSMENT_RUN_ID),
                        "1",
                        str(output),
                    ]
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                stdout.getvalue().splitlines(),
                [
                    "TOOLS_ARTIFACT_ID=987654",
                    f"TOOLS_ARTIFACT_DIGEST=sha256:{'b' * 64}",
                    "TOOLS_ARTIFACT_SIZE=69709459",
                ],
            )
            self.assertTrue(output.is_file())


class ArchiveTests(unittest.TestCase):
    def test_valid_archive_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root.joinpath("state.tar.gz")
            self._write_archive(archive)

            transport.validate_archive(archive)
            destination = root.joinpath("restore")
            destination.mkdir()
            transport.extract_resume(archive, destination)
            for name in transport.ALLOWED_ARCHIVE_ROOTS:
                self.assertEqual(
                    destination.joinpath(name, "proof.txt").read_text(), "ok\n"
                )

    @unittest.skipIf(os.name == "nt", "POSIX symlink extraction regression")
    def test_valid_in_root_symlink_through_gitfile_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root.joinpath("state.tar.gz")
            self._write_archive(archive, self._gitfile_symlink)

            transport.validate_archive(archive)
            destination = root.joinpath("restore")
            destination.mkdir()
            transport.extract_resume(archive, destination)

            archive_root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
            link = destination.joinpath(archive_root, "snapshot", "kodata", "HEAD")
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.readlink(), pathlib.Path("../.git/HEAD"))

    def test_traversal_hard_links_and_cross_root_links_are_rejected(self) -> None:
        attacks = {
            "traversal": self._traversal,
            "hard-link": self._hard_link,
            "cross-root-link": self._cross_root_link,
            "backslash-member": self._backslash_member,
            "backslash-link": self._backslash_link,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name, attack in attacks.items():
                archive = root.joinpath(f"{name}.tar.gz")
                self._write_archive(archive, attack)
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        transport.validate_archive(archive)

    def test_missing_root_and_duplicate_member_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            missing = root.joinpath("missing.tar.gz")
            self._write_archive(
                missing, omitted_root=next(iter(transport.ALLOWED_ARCHIVE_ROOTS))
            )
            with self.assertRaises(ValueError):
                transport.validate_archive(missing)

            duplicate = root.joinpath("duplicate.tar.gz")
            self._write_archive(duplicate, self._duplicate)
            with self.assertRaises(ValueError):
                transport.validate_archive(duplicate)

    def test_root_file_and_symlink_parent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            root_file = root.joinpath("root-file.tar.gz")
            replaced = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
            self._write_archive(
                root_file, self._replace_root_with_file, omitted_root=replaced
            )
            with self.assertRaises(ValueError):
                transport.validate_archive(root_file)

            linked_parent = root.joinpath("linked-parent.tar.gz")
            self._write_archive(linked_parent, self._linked_parent)
            with self.assertRaises(ValueError):
                transport.validate_archive(linked_parent)

    @staticmethod
    def _write_archive(
        path: pathlib.Path,
        attack=None,
        omitted_root: str | None = None,
    ) -> None:
        with tarfile.open(path, "w:gz") as payload:
            for root in sorted(transport.ALLOWED_ARCHIVE_ROOTS):
                if root == omitted_root:
                    continue
                directory = tarfile.TarInfo(root)
                directory.type = tarfile.DIRTYPE
                payload.addfile(directory)
                ArchiveTests._plain_file(payload, f"{root}/proof.txt", b"ok\n")
            if attack is not None:
                attack(payload)

    @staticmethod
    def _plain_file(payload: tarfile.TarFile, name: str, data: bytes) -> None:
        item = tarfile.TarInfo(name)
        item.size = len(data)
        payload.addfile(item, io.BytesIO(data))

    @staticmethod
    def _traversal(payload: tarfile.TarFile) -> None:
        ArchiveTests._plain_file(payload, "../escape", b"bad")

    @staticmethod
    def _hard_link(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        item = tarfile.TarInfo(f"{root}/hard-link")
        item.type = tarfile.LNKTYPE
        item.linkname = f"{root}/proof.txt"
        payload.addfile(item)

    @staticmethod
    def _cross_root_link(payload: tarfile.TarFile) -> None:
        first, second = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[:2]
        item = tarfile.TarInfo(f"{first}/cross-root")
        item.type = tarfile.SYMTYPE
        item.linkname = f"../../{second}/proof.txt"
        payload.addfile(item)

    @staticmethod
    def _backslash_member(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        ArchiveTests._plain_file(payload, f"{root}/..\\escape", b"bad")

    @staticmethod
    def _backslash_link(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        item = tarfile.TarInfo(f"{root}/backslash-link")
        item.type = tarfile.SYMTYPE
        item.linkname = "..\\escape"
        payload.addfile(item)

    @staticmethod
    def _gitfile_symlink(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        for name in (f"{root}/snapshot", f"{root}/snapshot/kodata"):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            payload.addfile(directory)
        ArchiveTests._plain_file(
            payload,
            f"{root}/snapshot/.git",
            b"gitdir: /tmp/example.git/worktrees/snapshot\n",
        )
        item = tarfile.TarInfo(f"{root}/snapshot/kodata/HEAD")
        item.type = tarfile.SYMTYPE
        item.linkname = "../.git/HEAD"
        payload.addfile(item)

    @staticmethod
    def _duplicate(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        ArchiveTests._plain_file(payload, f"{root}/proof.txt", b"again")

    @staticmethod
    def _replace_root_with_file(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        ArchiveTests._plain_file(payload, root, b"not a directory")

    @staticmethod
    def _linked_parent(payload: tarfile.TarFile) -> None:
        root = sorted(transport.ALLOWED_ARCHIVE_ROOTS)[0]
        item = tarfile.TarInfo(f"{root}/linked")
        item.type = tarfile.SYMTYPE
        item.linkname = "."
        payload.addfile(item)
        ArchiveTests._plain_file(payload, f"{root}/linked/child", b"bad")


class ManifestTests(unittest.TestCase):
    @staticmethod
    def _write_go_module_download_manifest(path: pathlib.Path) -> None:
        storage_source = transport.STORAGE_MIGRATION_FROM_COLLECTOR_SHA
        storage_target = transport.STORAGE_MIGRATION_TO_COLLECTOR_SHA
        preparation_target = transport.GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
        module_download_target = transport.GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
        transport.initialize_manifest(path, storage_source, transport.FRAME_RUN_ID)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            storage_target,
            transport.STORAGE_MIGRATION_NAME,
            transport.STORAGE_MIGRATION_SOURCE_RUN_ID,
            storage_source,
            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            preparation_target,
            transport.GO_PREPARATION_MIGRATION_NAME,
            transport.GO_PREPARATION_MIGRATION_SOURCE_RUN_ID,
            storage_target,
            transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            module_download_target,
            transport.GO_MODULE_DOWNLOAD_MIGRATION_NAME,
            transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID,
            preparation_target,
            transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_project_root_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_module_download_manifest(path)
        source = transport.GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_PROJECT_ROOT_MIGRATION_NAME,
            transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
            source,
            transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_resume_symlink_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_project_root_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_EOF_PARSER_MIGRATION_NAME,
            transport.GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
            transport.GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA,
            transport.RESUME_SYMLINK_MIGRATION_NAME,
            transport.RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
            transport.RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA,
            transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_git_blob_source_census_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_resume_symlink_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_bounded_go_semantic_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_git_blob_source_census_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_hosted_seal_margin_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_bounded_go_semantic_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_NAME,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_semantic_assembly_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_hosted_seal_margin_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_finalized_go_semantic_compaction_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_semantic_assembly_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_indexed_semantic_snapshot_projection_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_finalized_go_semantic_compaction_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_normalized_semantic_snapshot_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_indexed_semantic_snapshot_projection_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_public_surface_replay_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_normalized_semantic_snapshot_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_NAME,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_executable_blob_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_public_surface_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.EXECUTABLE_BLOB_MIGRATION_NAME,
            transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID,
            transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA,
            transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_project_model_dependency_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_executable_blob_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_source_census_progress_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_project_model_dependency_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_NAME,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_bounded_source_census_artifact_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_source_census_progress_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_exact_go_semantic_compiler_world_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_bounded_source_census_artifact_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_source_required_go_semantic_world_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_exact_go_semantic_compiler_world_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_progress_observability_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_source_required_go_semantic_world_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_incomplete_world_first_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_semantic_progress_observability_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_bounded_semantic_duration_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_semantic_incomplete_world_first_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_inferred_scip_kind_replay_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_bounded_semantic_duration_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_package_root_world_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_inferred_scip_kind_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_variant_assembly_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_package_root_world_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_qualification_project_model_replay_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_semantic_variant_assembly_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_qualification_project_model_v9_replay_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_qualification_project_model_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_qualification_project_model_v10_replay_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_qualification_project_model_v9_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_FROM_COLLECTOR_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_standalone_source_ownership_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_qualification_project_model_v10_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_RUN_ID,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_semantic_boundary_assembly_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_standalone_source_ownership_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_semantic_unit_phase_timing_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_semantic_boundary_assembly_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_validation_assembly_timing_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_go_semantic_unit_phase_timing_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_projection_indexing_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_semantic_validation_assembly_timing_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_semantic_public_binding_index_manifest(path: pathlib.Path) -> None:
        ManifestTests._write_semantic_projection_indexing_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_compiler_census_evidence_replay_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_semantic_public_binding_index_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _write_go_semantic_required_document_coverage_manifest(
        path: pathlib.Path,
    ) -> None:
        ManifestTests._write_go_compiler_census_evidence_replay_manifest(path)
        transport.migrate_manifest(
            path,
            transport.FRAME_RUN_ID,
            transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    def test_manifest_round_trips_and_is_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            collector = "a" * 40
            transport.initialize_manifest(path, collector, transport.FRAME_RUN_ID)
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), collector
            )
            with self.assertRaises(ValueError):
                transport.initialize_manifest(path, collector, transport.FRAME_RUN_ID)

    def test_manifest_tampering_and_wrong_frame_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            transport.initialize_manifest(path, "b" * 40, transport.FRAME_RUN_ID)
            value = json.loads(path.read_text())
            value["payloads_sha256"] = "0" * 64
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID + 1)

    def test_storage_migration_is_explicit_bound_and_one_way(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            source = transport.STORAGE_MIGRATION_FROM_COLLECTOR_SHA
            target = transport.STORAGE_MIGRATION_TO_COLLECTOR_SHA
            transport.initialize_manifest(path, source, transport.FRAME_RUN_ID)
            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.STORAGE_MIGRATION_NAME,
                    transport.STORAGE_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 2)
            self.assertEqual(
                value["collector_migrations"],
                [
                    {
                        "from_collector_sha": source,
                        "migration_contract": transport.STORAGE_MIGRATION_CONTRACT,
                        "migration_name": transport.STORAGE_MIGRATION_NAME,
                        "source_artifact_digest": (
                            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST
                        ),
                        "source_artifact_id": (
                            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_ID
                        ),
                        "source_artifact_size": (
                            transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE
                        ),
                        "source_head_sha": source,
                        "source_run_id": transport.STORAGE_MIGRATION_SOURCE_RUN_ID,
                        "to_collector_sha": target,
                    }
                ],
            )
            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][0][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "e" * 40,
                    transport.STORAGE_MIGRATION_NAME,
                    1,
                    target,
                    1,
                    "sha256:" + "f" * 64,
                    1,
                )

    def test_go_preparation_migration_preserves_the_exact_storage_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            first_source = transport.STORAGE_MIGRATION_FROM_COLLECTOR_SHA
            first_target = transport.STORAGE_MIGRATION_TO_COLLECTOR_SHA
            final_target = "e" * 40
            transport.initialize_manifest(path, first_source, transport.FRAME_RUN_ID)
            transport.migrate_manifest(
                path,
                transport.FRAME_RUN_ID,
                first_target,
                transport.STORAGE_MIGRATION_NAME,
                transport.STORAGE_MIGRATION_SOURCE_RUN_ID,
                first_source,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )
            first_manifest = json.loads(path.read_text(encoding="utf-8"))
            first_record = first_manifest["collector_migrations"][0]

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    final_target,
                    transport.GO_PREPARATION_MIGRATION_NAME,
                    transport.GO_PREPARATION_MIGRATION_SOURCE_RUN_ID,
                    first_target,
                    transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                final_target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 3)
            self.assertEqual(value["collector_migrations"][0], first_record)
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID),
                final_target,
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][1][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"].reverse()
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "f" * 40,
                    transport.GO_PREPARATION_MIGRATION_NAME,
                    1,
                    final_target,
                    1,
                    "sha256:" + "f" * 64,
                    1,
                )

    def test_go_module_download_migration_preserves_the_exact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            storage_source = transport.STORAGE_MIGRATION_FROM_COLLECTOR_SHA
            storage_target = transport.STORAGE_MIGRATION_TO_COLLECTOR_SHA
            preparation_target = (
                transport.GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
            )
            final_target = "f" * 40
            transport.initialize_manifest(
                path, storage_source, transport.FRAME_RUN_ID
            )
            transport.migrate_manifest(
                path,
                transport.FRAME_RUN_ID,
                storage_target,
                transport.STORAGE_MIGRATION_NAME,
                transport.STORAGE_MIGRATION_SOURCE_RUN_ID,
                storage_source,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )
            transport.migrate_manifest(
                path,
                transport.FRAME_RUN_ID,
                preparation_target,
                transport.GO_PREPARATION_MIGRATION_NAME,
                transport.GO_PREPARATION_MIGRATION_SOURCE_RUN_ID,
                storage_target,
                transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID,
                transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    final_target,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_NAME,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID,
                    preparation_target,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                final_target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 4)
            self.assertEqual(value["collector_migrations"][:2], prior_records)
            self.assertEqual(
                value["collector_migrations"][2],
                {
                    "from_collector_sha": preparation_target,
                    "migration_contract": (
                        transport.GO_MODULE_DOWNLOAD_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.GO_MODULE_DOWNLOAD_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": preparation_target,
                    "source_run_id": (
                        transport.GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": final_target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID),
                final_target,
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][2][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][1:] = reversed(
                reordered["collector_migrations"][1:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "a" * 40,
                    transport.GO_MODULE_DOWNLOAD_MIGRATION_NAME,
                    1,
                    final_target,
                    1,
                    "sha256:" + "a" * 64,
                    1,
                )

    def test_go_project_root_migration_preserves_and_closes_the_exact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_module_download_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_PROJECT_ROOT_MIGRATION_NAME,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 5)
            self.assertEqual(value["collector_migrations"][:3], prior_records)
            self.assertEqual(
                value["collector_migrations"][3],
                {
                    "from_collector_sha": source,
                    "migration_contract": transport.GO_PROJECT_ROOT_MIGRATION_CONTRACT,
                    "migration_name": transport.GO_PROJECT_ROOT_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][3][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][2:] = reversed(
                reordered["collector_migrations"][2:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.GO_PROJECT_ROOT_MIGRATION_NAME,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_go_eof_parser_migration_preserves_and_closes_the_exact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_project_root_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_EOF_PARSER_MIGRATION_NAME,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 6)
            self.assertEqual(value["collector_migrations"][:4], prior_records)
            self.assertEqual(
                value["collector_migrations"][4],
                {
                    "from_collector_sha": source,
                    "migration_contract": transport.GO_EOF_PARSER_MIGRATION_CONTRACT,
                    "migration_name": transport.GO_EOF_PARSER_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": transport.GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][4][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][3:] = reversed(
                reordered["collector_migrations"][3:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.GO_EOF_PARSER_MIGRATION_NAME,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_resume_symlink_migration_preserves_the_exact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_project_root_manifest(path)
            transport.migrate_manifest(
                path,
                transport.FRAME_RUN_ID,
                transport.RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA,
                transport.GO_EOF_PARSER_MIGRATION_NAME,
                transport.GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
                transport.GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA,
                transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
                transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
            target = "b" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.RESUME_SYMLINK_MIGRATION_NAME,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 7)
            self.assertEqual(value["collector_migrations"][:5], prior_records)
            self.assertEqual(
                value["collector_migrations"][5],
                {
                    "from_collector_sha": source,
                    "migration_contract": transport.RESUME_SYMLINK_MIGRATION_CONTRACT,
                    "migration_name": transport.RESUME_SYMLINK_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": transport.RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][5][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.RESUME_SYMLINK_MIGRATION_NAME,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_git_blob_source_census_migration_is_exact_bound_and_one_way(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_resume_symlink_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
            target = "d" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 8)
            self.assertEqual(value["collector_migrations"][:6], prior_records)
            self.assertEqual(
                value["collector_migrations"][6],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][6][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "e" * 40,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_bounded_go_semantic_migration_is_bound_to_the_accepted_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_git_blob_source_census_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
            target = "e" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 9)
            self.assertEqual(value["collector_migrations"][:7], prior_records)
            self.assertEqual(
                value["collector_migrations"][7],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.BOUNDED_GO_SEMANTIC_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][7][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "f" * 40,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_hosted_seal_margin_migration_is_bound_to_the_accepted_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_bounded_go_semantic_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
            target = "f" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_NAME,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 10)
            self.assertEqual(value["collector_migrations"][:8], prior_records)
            self.assertEqual(
                value["collector_migrations"][8],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.HOSTED_SEAL_MARGIN_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.HOSTED_SEAL_MARGIN_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][8][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "1" * 40,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_NAME,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_go_semantic_assembly_migration_is_bound_to_the_accepted_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_hosted_seal_margin_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
            target = "1" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 11)
            self.assertEqual(value["collector_migrations"][:9], prior_records)
            self.assertEqual(
                value["collector_migrations"][9],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][9][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "2" * 40,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_finalized_go_semantic_compaction_migration_is_exact_and_one_way(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_semantic_assembly_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "1" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 12)
            self.assertEqual(value["collector_migrations"][:10], prior_records)
            self.assertEqual(
                value["collector_migrations"][10],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][10][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][9:] = reversed(
                reordered["collector_migrations"][9:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "2" * 40,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_indexed_semantic_snapshot_projection_migration_is_exact_and_one_way(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_finalized_go_semantic_compaction_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "2" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 13)
            self.assertEqual(value["collector_migrations"][:11], prior_records)
            self.assertEqual(
                value["collector_migrations"][11],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][11][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][10:] = reversed(
                reordered["collector_migrations"][10:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "3" * 40,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_normalized_semantic_snapshot_migration_is_exact_and_one_way(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_indexed_semantic_snapshot_projection_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "3" * 40

            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    "batched-semantic-source-reconstruction-v1",
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")), prior_manifest
            )

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 14)
            self.assertEqual(value["collector_migrations"][:12], prior_records)
            self.assertEqual(
                value["collector_migrations"][12],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": (
                        transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in (
                "from_collector_sha",
                "migration_contract",
                "migration_name",
                "source_artifact_digest",
                "source_artifact_id",
                "source_artifact_size",
                "source_head_sha",
                "source_run_id",
                "to_collector_sha",
            ):
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][12][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][11:] = reversed(
                reordered["collector_migrations"][11:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "4" * 40,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_public_surface_replay_migration_is_exact_and_preserves_the_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_normalized_semantic_snapshot_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
            target = "4" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_NAME,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    source,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 15)
            self.assertEqual(value["collector_migrations"][:13], prior_records)
            self.assertEqual(
                value["collector_migrations"][13],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.PUBLIC_SURFACE_REPLAY_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.PUBLIC_SURFACE_REPLAY_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": source,
                    "source_run_id": transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][13]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][13][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][12:] = reversed(
                reordered["collector_migrations"][12:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "5" * 40,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_NAME,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    target,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_executable_blob_migration_is_exact_and_preserves_the_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_public_surface_replay_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA
            target = "5" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.EXECUTABLE_BLOB_MIGRATION_NAME,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 16)
            self.assertEqual(value["collector_migrations"][:14], prior_records)
            self.assertEqual(
                value["collector_migrations"][14],
                {
                    "from_collector_sha": source,
                    "migration_contract": transport.EXECUTABLE_BLOB_MIGRATION_CONTRACT,
                    "migration_name": transport.EXECUTABLE_BLOB_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID,
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][14]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][14][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][13:] = reversed(
                reordered["collector_migrations"][13:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "6" * 40,
                    transport.EXECUTABLE_BLOB_MIGRATION_NAME,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_go_project_model_dependency_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_executable_blob_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "6" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 17)
            self.assertEqual(value["collector_migrations"][:15], prior_records)
            self.assertEqual(
                value["collector_migrations"][15],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][15]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][15][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][14:] = reversed(
                reordered["collector_migrations"][14:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "7" * 40,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_source_census_progress_migration_is_exact_and_only_opens_the_next_migration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_project_model_dependency_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA
            target = "7" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_NAME,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 18)
            self.assertEqual(value["collector_migrations"][:16], prior_records)
            self.assertEqual(
                value["collector_migrations"][16],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.SOURCE_CENSUS_PROGRESS_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][16]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][16][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][15:] = reversed(
                reordered["collector_migrations"][15:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "8" * 40,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_NAME,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_bounded_source_census_artifact_migration_is_exact_and_one_way(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_source_census_progress_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "8" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 19)
            self.assertEqual(value["collector_migrations"][:17], prior_records)
            self.assertEqual(
                value["collector_migrations"][17],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][17]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][17][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][16:] = reversed(
                reordered["collector_migrations"][16:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "9" * 40,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "9" * 40,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_exact_go_semantic_compiler_world_migration_is_exact_and_advances_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_bounded_source_census_artifact_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = (
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
            )

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 20)
            self.assertEqual(value["collector_migrations"][:18], prior_records)
            self.assertEqual(
                value["collector_migrations"][18],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][18]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][18][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            reordered = json.loads(json.dumps(value))
            reordered["collector_migrations"][17:] = reversed(
                reordered["collector_migrations"][17:]
            )
            path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "a" * 40,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_source_required_go_semantic_world_migration_is_exact_and_rejects_repeat(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_exact_go_semantic_compiler_world_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 21)
            self.assertEqual(value["collector_migrations"][:19], prior_records)
            self.assertEqual(
                value["collector_migrations"][19],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][19]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][19][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_semantic_progress_observability_migration_is_exact_and_closes_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path = root.joinpath("manifest.json")
            sentinel = root.joinpath("semantic-state.bin")
            sentinel.write_bytes(b"semantic-state-must-not-change")
            self._write_source_required_go_semantic_world_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 22)
            self.assertEqual(value["collector_migrations"][:20], prior_records)
            self.assertEqual(
                value["collector_migrations"][20],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(sentinel.read_bytes(), b"semantic-state-must-not-change")
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][20]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][20][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_semantic_incomplete_world_first_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path = root.joinpath("manifest.json")
            sentinel = root.joinpath("semantic-state.bin")
            sentinel.write_bytes(b"semantic-state-must-not-change")
            self._write_semantic_progress_observability_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = (
                transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA
            )
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 23)
            self.assertEqual(value["collector_migrations"][:21], prior_records)
            self.assertEqual(
                value["collector_migrations"][21],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(sentinel.read_bytes(), b"semantic-state-must-not-change")
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][21]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][21][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_bounded_semantic_duration_migration_is_exact_and_closes_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path = root.joinpath("manifest.json")
            sentinel = root.joinpath("semantic-state.bin")
            sentinel.write_bytes(b"semantic-state-must-not-change")
            self._write_semantic_incomplete_world_first_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            source = transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 24)
            self.assertEqual(value["collector_migrations"][:22], prior_records)
            self.assertEqual(
                value["collector_migrations"][22],
                {
                    "from_collector_sha": source,
                    "migration_contract": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(sentinel.read_bytes(), b"semantic-state-must-not-change")
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][22]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][22][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_inferred_scip_kind_replay_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_bounded_semantic_duration_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 25)
            self.assertEqual(value["collector_migrations"][:23], prior_records)
            self.assertEqual(
                value["collector_migrations"][23],
                {
                    "from_collector_sha": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    ),
                    "migration_contract": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][23]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][23][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_go_package_root_world_migration_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_inferred_scip_kind_replay_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            target = transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 26)
            self.assertEqual(value["collector_migrations"][:24], prior_records)
            self.assertEqual(
                value["collector_migrations"][24],
                {
                    "from_collector_sha": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA
                    ),
                    "migration_contract": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_CONTRACT
                    ),
                    "migration_name": transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME,
                    "source_artifact_digest": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][24]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][24][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_semantic_variant_assembly_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_package_root_world_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            target = (
                transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
            )

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 27)
            self.assertEqual(value["collector_migrations"][:25], prior_records)
            self.assertEqual(
                value["collector_migrations"][25],
                {
                    "from_collector_sha": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
                    ),
                    "migration_contract": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][25]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][25][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_qualification_project_model_replay_migration_is_exact_and_advances_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_semantic_variant_assembly_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            target = "a" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 28)
            self.assertEqual(value["collector_migrations"][:26], prior_records)
            self.assertEqual(
                value["collector_migrations"][26],
                {
                    "from_collector_sha": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    ),
                    "migration_contract": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][26]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][26][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "b" * 40,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

    def test_qualification_project_model_v9_replay_migration_is_exact_and_closes_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_qualification_project_model_replay_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            prior_records = prior_manifest["collector_migrations"]
            target = "b" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 29)
            self.assertEqual(value["collector_migrations"][:27], prior_records)
            self.assertEqual(
                value["collector_migrations"][27],
                {
                    "from_collector_sha": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    ),
                    "migration_contract": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_CONTRACT
                    ),
                    "migration_name": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME
                    ),
                    "source_artifact_digest": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
                    ),
                    "source_artifact_id": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                    ),
                    "source_artifact_size": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                    ),
                    "source_head_sha": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA
                    ),
                    "source_run_id": (
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID
                    ),
                    "to_collector_sha": target,
                },
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][27]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][27][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_qualification_project_model_v10_replay_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_qualification_project_model_v9_replay_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            target = "b" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 30)
            self.assertEqual(
                value["collector_migrations"][:28],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][28],
                transport._expected_qualification_project_model_v10_replay_migration(
                    target
                ),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )

            for field in value["collector_migrations"][28]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][28][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_standalone_source_ownership_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_qualification_project_model_v10_replay_manifest(path)
            prior_manifest = json.loads(path.read_text(encoding="utf-8"))
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 31)
            self.assertEqual(
                value["collector_migrations"][:29],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][29],
                transport._expected_go_standalone_source_ownership_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][29]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][29][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_semantic_boundary_assembly_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_standalone_source_ownership_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 32)
            self.assertEqual(
                value["collector_migrations"][:30],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][30],
                transport._expected_go_semantic_boundary_assembly_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][30]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][30][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_semantic_unit_phase_timing_migration_is_exact_and_precedes_next(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_semantic_boundary_assembly_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 33)
            self.assertEqual(
                value["collector_migrations"][:31],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][31],
                transport._expected_go_semantic_unit_phase_timing_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][31]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][31][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_semantic_validation_assembly_timing_migration_is_exact_and_precedes_next(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_semantic_unit_phase_timing_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 34)
            self.assertEqual(
                value["collector_migrations"][:32],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][32],
                transport._expected_semantic_validation_assembly_timing_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][32]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][32][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_semantic_projection_indexing_migration_is_exact_before_next_migration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_semantic_validation_assembly_timing_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 35)
            self.assertEqual(
                value["collector_migrations"][:33],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][33],
                transport._expected_semantic_projection_indexing_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][33]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][33][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_semantic_public_binding_index_migration_is_exact_before_next_migration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_semantic_projection_indexing_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 36)
            self.assertEqual(
                value["collector_migrations"][:34],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][34],
                transport._expected_semantic_public_binding_index_migration(target),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][34]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][34][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_compiler_census_evidence_replay_migration_is_exact_before_next_migration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_semantic_public_binding_index_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            state_sentinel = pathlib.Path(temporary, "state-sentinel.bin")
            state_sentinel.write_bytes(b"assessment-state-must-not-change\x00\xff")
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID + 1,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 37)
            self.assertEqual(
                value["collector_migrations"][:35],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][35],
                transport._expected_go_compiler_census_evidence_replay_migration(
                    target
                ),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            self.assertEqual(
                state_sentinel.read_bytes(), b"assessment-state-must-not-change\x00\xff"
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][35]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][35][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_semantic_required_document_coverage_migration_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_compiler_census_evidence_replay_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID
                    + 1,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 38)
            self.assertEqual(
                value["collector_migrations"][:36],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][36],
                transport._expected_go_semantic_required_document_coverage_migration(
                    target
                ),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            with self.assertRaisesRegex(ValueError, "migration is out of order"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][36]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][36][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    def test_go_semantic_effective_test_coverage_migration_is_exact_and_closes_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "manifest.json")
            self._write_go_semantic_required_document_coverage_manifest(path)
            prior_bytes = path.read_bytes()
            prior_manifest = json.loads(prior_bytes)
            target = "b" * 40

            with self.assertRaisesRegex(ValueError, "migration chain drifted"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID
                    + 1,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(path.read_bytes(), prior_bytes)

            self.assertEqual(
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    target,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                ),
                target,
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 39)
            self.assertEqual(
                value["collector_migrations"][:37],
                prior_manifest["collector_migrations"],
            )
            self.assertEqual(
                value["collector_migrations"][37],
                transport._expected_go_semantic_effective_test_coverage_migration(
                    target
                ),
            )
            self.assertEqual(
                transport.validate_manifest(path, transport.FRAME_RUN_ID), target
            )
            with self.assertRaisesRegex(ValueError, "migration chain is closed"):
                transport.migrate_manifest(
                    path,
                    transport.FRAME_RUN_ID,
                    "c" * 40,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_NAME,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_RUN_ID,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.GO_SEMANTIC_EFFECTIVE_TEST_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )

            for field in value["collector_migrations"][37]:
                tampered = json.loads(json.dumps(value))
                tampered["collector_migrations"][37][field] = True
                path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.subTest(field=field), self.assertRaises(ValueError):
                    transport.validate_manifest(path, transport.FRAME_RUN_ID)

    @staticmethod
    def _write_inferred_scip_kind_replay_fixture(
        root: pathlib.Path,
    ) -> dict[str, pathlib.Path]:
        manifest = root.joinpath("manifest.json")
        ManifestTests._write_bounded_semantic_duration_manifest(manifest)
        state_root = root.joinpath("historical-v2-assessment-state")
        work_root = root.joinpath("historical-v2-assessment-work")
        state_language = state_root.joinpath("go")
        work_language = work_root.joinpath("go")
        state_slot = state_language.joinpath("slot-0122")
        state_slot.mkdir(parents=True)
        state_language.joinpath("slot-0122.lock").write_bytes(b"locked")
        for name in (
            "0001-payload",
            "0002-materialization",
            "0003-test-materialization",
            "0004-source-census",
            "0005-semantic-census",
        ):
            stage = state_slot.joinpath(name)
            stage.mkdir()
            for file_name in ("_transaction.json", "artifact.json", "checkpoint.json"):
                stage.joinpath(file_name).write_bytes(
                    f"{name}/{file_name}\n".encode()
                )

        source_checkpoint = state_slot.joinpath(
            "0004-source-census", "checkpoint.json"
        )
        source_checkpoint.write_bytes(
            SCIP_REPLAY_FIXTURE_ROOT.joinpath("source-checkpoint.json")
            .read_text(encoding="utf-8")
            .encode("utf-8")
        )
        semantic_stage = state_slot.joinpath("0005-semantic-census")
        for name in ("_transaction.json", "artifact.json", "checkpoint.json"):
            semantic_stage.joinpath(name).write_bytes(
                SCIP_REPLAY_FIXTURE_ROOT.joinpath(name)
                .read_text(encoding="utf-8")
                .encode("utf-8")
            )

        expected_hashes = {
            stage.name: {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in stage.iterdir()
            }
            for stage in state_slot.iterdir()
        }

        prior_state = state_language.joinpath("slot-0121", "complete")
        prior_state.mkdir(parents=True)
        prior_state.joinpath("checkpoint.json").write_bytes(b"prior-slot")
        state_language.joinpath("slot-0121.lock").write_bytes(b"locked")
        unrelated_work = work_language.joinpath("slot-0123", "repository")
        unrelated_work.mkdir(parents=True)
        unrelated_work.joinpath("go.mod").write_bytes(b"next-slot")
        return {
            "manifest": manifest,
            "state_root": state_root,
            "work_root": work_root,
            "state_slot": state_slot,
            "payload_stage": state_slot.joinpath("0001-payload"),
            "materialization_stage": state_slot.joinpath("0002-materialization"),
            "test_materialization_stage": state_slot.joinpath(
                "0003-test-materialization"
            ),
            "source_stage": state_slot.joinpath("0004-source-census"),
            "source_checkpoint": source_checkpoint,
            "semantic_stage": semantic_stage,
            "artifact": semantic_stage.joinpath("artifact.json"),
            "checkpoint": semantic_stage.joinpath("checkpoint.json"),
            "transaction": semantic_stage.joinpath("_transaction.json"),
            "prior_state": prior_state.joinpath("checkpoint.json"),
            "unrelated_work": unrelated_work.joinpath("go.mod"),
            "expected_hashes": expected_hashes,
        }

    @staticmethod
    def _migrate_inferred_scip_kind_replay(
        paths: dict[str, pathlib.Path],
        *,
        source_artifact_id: int | None = None,
    ) -> None:
        with mock.patch.object(
            transport,
            "INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256",
            paths["expected_hashes"],
        ):
            transport.migrate_inferred_scip_kind_replay(
                paths["manifest"],
                paths["state_root"],
                paths["work_root"],
                transport.FRAME_RUN_ID,
                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID,
                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                (
                    transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                    if source_artifact_id is None
                    else source_artifact_id
                ),
                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )

    def test_inferred_scip_kind_replay_rewinds_to_executable_payload_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inferred_scip_kind_replay_fixture(
                pathlib.Path(temporary)
            )
            manifest_before = paths["manifest"].read_bytes()
            with mock.patch.object(
                transport,
                "INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256",
                paths["expected_hashes"],
            ):
                self.assertEqual(
                    transport.main(
                        [
                            "migrate-inferred-scip-kind-replay",
                            str(paths["manifest"]),
                            str(paths["state_root"]),
                            str(paths["work_root"]),
                            str(transport.FRAME_RUN_ID),
                            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
                            str(
                                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID
                            ),
                            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                            str(
                                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                            ),
                            transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                            str(
                                transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                            ),
                        ]
                    ),
                    0,
                )

            self.assertFalse(paths["semantic_stage"].exists())
            self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
            self.assertEqual(paths["prior_state"].read_bytes(), b"prior-slot")
            self.assertEqual(paths["unrelated_work"].read_bytes(), b"next-slot")
            self.assertEqual(
                {path.name for path in paths["state_slot"].iterdir()},
                {"0001-payload"},
            )
            self.assertTrue(paths["payload_stage"].is_dir())
            self.assertFalse(paths["materialization_stage"].exists())
            self.assertFalse(paths["test_materialization_stage"].exists())
            self.assertFalse(paths["source_stage"].exists())

    def test_inferred_scip_kind_replay_hashes_match_exact_evidence_fixtures(
        self,
    ) -> None:
        self.assertEqual(
            set(transport.INFERRED_SCIP_KIND_REPLAY_STAGE_ORDER),
            set(transport.INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256),
        )
        fixture_paths = {
            ("0004-source-census", "checkpoint.json"): "source-checkpoint.json",
            ("0005-semantic-census", "_transaction.json"): "_transaction.json",
            ("0005-semantic-census", "artifact.json"): "artifact.json",
            ("0005-semantic-census", "checkpoint.json"): "checkpoint.json",
        }
        for (stage, name), fixture_name in fixture_paths.items():
            with self.subTest(stage=stage, name=name):
                fixture = (
                    SCIP_REPLAY_FIXTURE_ROOT.joinpath(fixture_name)
                    .read_text(encoding="utf-8")
                    .encode("utf-8")
                )
                self.assertEqual(
                    hashlib.sha256(fixture).hexdigest(),
                    transport.INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256[stage][name],
                )

    def test_inferred_scip_kind_replay_fails_before_deleting_on_drift(
        self,
    ) -> None:
        def add_byte(path_key: str):
            def mutate(paths: dict[str, pathlib.Path]) -> None:
                path = paths[path_key]
                path.write_bytes(path.read_bytes() + b" ")

            return mutate

        def add_stage_file(paths: dict[str, pathlib.Path]) -> None:
            paths["semantic_stage"].joinpath("unexpected").write_bytes(b"drift")

        def add_materialization_file(paths: dict[str, pathlib.Path]) -> None:
            paths["materialization_stage"].joinpath("unexpected").write_bytes(b"drift")

        def add_stale_work(paths: dict[str, pathlib.Path]) -> None:
            paths["work_root"].joinpath("go", "slot-0122").mkdir()

        def replace_source_with_directory(paths: dict[str, pathlib.Path]) -> None:
            paths["source_checkpoint"].unlink()
            paths["source_checkpoint"].mkdir()

        cases = {
            "artifact": add_byte("artifact"),
            "checkpoint": add_byte("checkpoint"),
            "transaction": add_byte("transaction"),
            "source": add_byte("source_checkpoint"),
            "stage-file": add_stage_file,
            "materialization-stage-file": add_materialization_file,
            "stale-work": add_stale_work,
            "source-directory": replace_source_with_directory,
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                paths = self._write_inferred_scip_kind_replay_fixture(
                    pathlib.Path(temporary)
                )
                mutate(paths)
                with self.assertRaises(ValueError):
                    self._migrate_inferred_scip_kind_replay(paths)
                self.assertTrue(paths["semantic_stage"].is_dir())
                self.assertTrue(paths["artifact"].is_file())
                self.assertTrue(paths["materialization_stage"].is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inferred_scip_kind_replay_fixture(
                pathlib.Path(temporary)
            )
            with self.assertRaises(ValueError):
                self._migrate_inferred_scip_kind_replay(
                    paths,
                    source_artifact_id=(
                        transport.INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        + 1
                    ),
                )
            self.assertTrue(paths["semantic_stage"].is_dir())

    @staticmethod
    def _write_qualification_project_model_replay_fixture(
        root: pathlib.Path,
    ) -> dict[str, object]:
        manifest = root.joinpath("manifest.json")
        ManifestTests._write_semantic_variant_assembly_manifest(manifest)
        state_root = root.joinpath("historical-v2-assessment-state")
        work_root = root.joinpath("historical-v2-assessment-work")
        state_language = state_root.joinpath("go")
        work_language = work_root.joinpath("go")
        stage_names = (
            "payload",
            "materialization",
            "test_materialization",
            "source_census",
            "semantic_census",
            "assessment_identity",
        )
        state_slots: dict[int, pathlib.Path] = {}
        work_slots: dict[int, pathlib.Path] = {}
        retained_hashes: dict[int, dict[str, dict[str, str]]] = {}
        for slot_number, expected in (
            (122, transport.QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[122]),
            (123, transport.QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[123]),
        ):
            state_slot = state_language.joinpath(f"slot-{slot_number:04}")
            state_slot.mkdir(parents=True)
            state_language.joinpath(f"slot-{slot_number:04}.lock").write_bytes(
                b"locked"
            )
            previous_checkpoint_sha256 = None
            committed_stage_count = int(expected["committed_stage_count"])
            for sequence in range(1, committed_stage_count + 1):
                stage_name = stage_names[sequence - 1]
                stage = state_slot.joinpath(
                    f"{sequence:04}-{stage_name.replace('_', '-')}"
                )
                stage.mkdir()
                checkpoint_sha256 = hashlib.sha256(
                    f"checkpoint/{slot_number}/{sequence}".encode()
                ).hexdigest()
                if sequence == 3:
                    checkpoint_sha256 = str(expected["retained_checkpoint_sha256"])
                artifact_sha256 = hashlib.sha256(
                    f"artifact-commitment/{slot_number}/{sequence}".encode()
                ).hexdigest()
                artifact = json.dumps(
                    {"slot_number": slot_number, "stage": stage_name},
                    separators=(",", ":"),
                ).encode()
                stage.joinpath("artifact.json").write_bytes(artifact)
                checkpoint = {
                    "schema_version": 1,
                    "checkpoint_contract": (
                        "sniffbench-historical-v2-slot-stage-checkpoint-v1"
                    ),
                    "selection_sha256": transport.SELECTION_SHA256,
                    "language": "go",
                    "slot_number": slot_number,
                    "canonical_repository": expected["canonical_repository"],
                    "sequence": sequence,
                    "previous_checkpoint_sha256": previous_checkpoint_sha256,
                    "stage": stage_name,
                    "outcome": {
                        "status": "completed",
                        "artifact_kind": stage_name,
                        "artifact_sha256": artifact_sha256,
                    },
                    "checkpoint_sha256": checkpoint_sha256,
                }
                checkpoint_bytes = (json.dumps(checkpoint, indent=2) + "\n").encode()
                stage.joinpath("checkpoint.json").write_bytes(checkpoint_bytes)
                transaction = {
                    "schema_version": 1,
                    "transaction_contract": (
                        "sniffbench-historical-v2-slot-stage-transaction-v1"
                    ),
                    "sequence": sequence,
                    "checkpoint_sha256": checkpoint_sha256,
                    "files": [
                        {
                            "name": "artifact.json",
                            "sha256": hashlib.sha256(artifact).hexdigest(),
                            "byte_count": len(artifact),
                        },
                        {
                            "name": "checkpoint.json",
                            "sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
                            "byte_count": len(checkpoint_bytes),
                        },
                    ],
                }
                stage.joinpath("_transaction.json").write_text(
                    json.dumps(transaction, indent=2) + "\n", encoding="utf-8"
                )
                previous_checkpoint_sha256 = checkpoint_sha256
            state_slots[slot_number] = state_slot
            retained_hashes[slot_number] = {
                stage.name: {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in stage.iterdir()
                }
                for stage in state_slot.iterdir()
                if stage.name.startswith(("0001-", "0002-", "0003-"))
            }

            work_slot = work_language.joinpath(f"slot-{slot_number:04}")
            for side in ("base", "patched"):
                progress = work_slot.joinpath("source-progress", side)
                progress.mkdir(parents=True)
                progress.joinpath("progress.json").write_text(
                    f"source/{slot_number}/{side}\n", encoding="utf-8"
                )
            repository = work_slot.joinpath("repository")
            repository.mkdir()
            repository.joinpath("go.mod").write_text(
                f"module fixture/{slot_number}\n", encoding="utf-8"
            )
            if slot_number == 122:
                semantic_progress = work_slot.joinpath(
                    "semantic-progress", "base", "world"
                )
                semantic_progress.mkdir(parents=True)
                semantic_progress.joinpath("progress.json").write_text(
                    "semantic\n", encoding="utf-8"
                )
            work_slots[slot_number] = work_slot

        slot_number = 124
        expected = transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_SLOTS[slot_number]
        state_slot = state_language.joinpath(f"slot-{slot_number:04}")
        state_slot.mkdir(parents=True)
        state_language.joinpath(f"slot-{slot_number:04}.lock").write_bytes(b"locked")
        previous_checkpoint_sha256 = None
        for sequence, stage_name in enumerate(stage_names[:3], start=1):
            stage = state_slot.joinpath(
                f"{sequence:04}-{stage_name.replace('_', '-')}"
            )
            stage.mkdir()
            checkpoint_sha256 = hashlib.sha256(
                f"checkpoint/{slot_number}/{sequence}".encode()
            ).hexdigest()
            artifact_sha256 = hashlib.sha256(
                f"artifact-commitment/{slot_number}/{sequence}".encode()
            ).hexdigest()
            artifact = json.dumps(
                {"slot_number": slot_number, "stage": stage_name},
                separators=(",", ":"),
            ).encode()
            stage.joinpath("artifact.json").write_bytes(artifact)
            checkpoint = {
                "schema_version": 1,
                "checkpoint_contract": (
                    "sniffbench-historical-v2-slot-stage-checkpoint-v1"
                ),
                "selection_sha256": transport.SELECTION_SHA256,
                "language": "go",
                "slot_number": slot_number,
                "canonical_repository": expected["canonical_repository"],
                "sequence": sequence,
                "previous_checkpoint_sha256": previous_checkpoint_sha256,
                "stage": stage_name,
                "outcome": {
                    "status": "completed",
                    "artifact_kind": stage_name,
                    "artifact_sha256": artifact_sha256,
                },
                "checkpoint_sha256": checkpoint_sha256,
            }
            checkpoint_bytes = (json.dumps(checkpoint, indent=2) + "\n").encode()
            stage.joinpath("checkpoint.json").write_bytes(checkpoint_bytes)
            transaction = {
                "schema_version": 1,
                "transaction_contract": (
                    "sniffbench-historical-v2-slot-stage-transaction-v1"
                ),
                "sequence": sequence,
                "checkpoint_sha256": checkpoint_sha256,
                "files": [
                    {
                        "name": "artifact.json",
                        "sha256": hashlib.sha256(artifact).hexdigest(),
                        "byte_count": len(artifact),
                    },
                    {
                        "name": "checkpoint.json",
                        "sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
                        "byte_count": len(checkpoint_bytes),
                    },
                ],
            }
            stage.joinpath("_transaction.json").write_text(
                json.dumps(transaction, indent=2) + "\n", encoding="utf-8"
            )
            previous_checkpoint_sha256 = checkpoint_sha256
        state_slots[slot_number] = state_slot

        unrelated_work = work_language.joinpath("slot-0124", "repository")
        unrelated_work.mkdir(parents=True)
        unrelated_work.joinpath("go.mod").write_text(
            "module fixture/124\n", encoding="utf-8"
        )
        work_slots[slot_number] = unrelated_work.parent
        return {
            "manifest": manifest,
            "state_root": state_root,
            "work_root": work_root,
            "state_slots": state_slots,
            "work_slots": work_slots,
            "retained_hashes": retained_hashes,
            "unrelated_work": unrelated_work.joinpath("go.mod"),
        }

    @staticmethod
    def _migrate_qualification_project_model_replay(
        paths: dict[str, object], *, source_artifact_id: int | None = None
    ) -> None:
        transport.migrate_qualification_project_model_replay(
            paths["manifest"],
            paths["state_root"],
            paths["work_root"],
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            (
                transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                if source_artifact_id is None
                else source_artifact_id
            ),
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _prepare_qualification_project_model_v9_replay(
        paths: dict[str, object],
    ) -> None:
        ManifestTests._migrate_qualification_project_model_replay(paths)
        transport.migrate_manifest(
            paths["manifest"],
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _migrate_qualification_project_model_v9_replay(
        paths: dict[str, object], *, source_artifact_id: int | None = None
    ) -> None:
        transport.migrate_qualification_project_model_v9_replay(
            paths["manifest"],
            paths["state_root"],
            paths["work_root"],
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            (
                transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                if source_artifact_id is None
                else source_artifact_id
            ),
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    @staticmethod
    def _prepare_qualification_project_model_v10_replay(
        paths: dict[str, object],
    ) -> None:
        ManifestTests._prepare_qualification_project_model_v9_replay(paths)
        ManifestTests._migrate_qualification_project_model_v9_replay(paths)
        transport.migrate_manifest(
            paths["manifest"],
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )
        source_stages = {}
        for slot_number in (122, 123):
            state_slot = paths["state_slots"][slot_number]
            stage = state_slot.joinpath("0004-source-census")
            stage.mkdir()
            artifact = json.dumps(
                {"slot_number": slot_number, "stage": "source_census"},
                separators=(",", ":"),
            ).encode()
            stage.joinpath("artifact.json").write_bytes(artifact)
            previous_checkpoint_sha256 = json.loads(
                state_slot.joinpath(
                    "0003-test-materialization", "checkpoint.json"
                ).read_text(encoding="utf-8")
            )["checkpoint_sha256"]
            checkpoint_sha256 = hashlib.sha256(
                f"checkpoint/{slot_number}/4".encode()
            ).hexdigest()
            checkpoint = {
                "schema_version": 1,
                "checkpoint_contract": (
                    "sniffbench-historical-v2-slot-stage-checkpoint-v1"
                ),
                "selection_sha256": transport.SELECTION_SHA256,
                "language": "go",
                "slot_number": slot_number,
                "canonical_repository": transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_SLOTS[
                    slot_number
                ]["canonical_repository"],
                "sequence": 4,
                "previous_checkpoint_sha256": previous_checkpoint_sha256,
                "stage": "source_census",
                "outcome": {
                    "status": "completed",
                    "artifact_kind": "source_census",
                    "artifact_sha256": hashlib.sha256(
                        f"artifact-commitment/{slot_number}/4".encode()
                    ).hexdigest(),
                },
                "checkpoint_sha256": checkpoint_sha256,
            }
            checkpoint_bytes = (json.dumps(checkpoint, indent=2) + "\n").encode()
            stage.joinpath("checkpoint.json").write_bytes(checkpoint_bytes)
            stage.joinpath("_transaction.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "transaction_contract": (
                            "sniffbench-historical-v2-slot-stage-transaction-v1"
                        ),
                        "sequence": 4,
                        "checkpoint_sha256": checkpoint_sha256,
                        "files": [
                            {
                                "name": "artifact.json",
                                "sha256": hashlib.sha256(artifact).hexdigest(),
                                "byte_count": len(artifact),
                            },
                            {
                                "name": "checkpoint.json",
                                "sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
                                "byte_count": len(checkpoint_bytes),
                            },
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            source_stages[slot_number] = stage
        for slot_number in transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_SLOTS:
            for side in ("base", "patched"):
                progress = paths["work_slots"][slot_number].joinpath(
                    "source-progress", side
                )
                progress.mkdir(parents=True)
                progress.joinpath("progress.json").write_text(
                    f"source-v10/{slot_number}/{side}\n", encoding="utf-8"
                )
        paths["v10_source_stages"] = source_stages

    @staticmethod
    def _migrate_qualification_project_model_v10_replay(
        paths: dict[str, object], *, source_artifact_id: int | None = None
    ) -> None:
        transport.migrate_qualification_project_model_v10_replay(
            paths["manifest"],
            paths["state_root"],
            paths["work_root"],
            transport.FRAME_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
            (
                transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                if source_artifact_id is None
                else source_artifact_id
            ),
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
        )

    def test_qualification_project_model_replay_rewinds_exact_stale_slots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            manifest_before = paths["manifest"].read_bytes()
            self.assertEqual(
                transport.main(
                    [
                        "migrate-bounded-qualification-project-model-v8-replay",
                        str(paths["manifest"]),
                        str(paths["state_root"]),
                        str(paths["work_root"]),
                        str(transport.FRAME_RUN_ID),
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                        ),
                    ]
                ),
                0,
            )
            self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
            for slot_number in (122, 123):
                state_slot = paths["state_slots"][slot_number]
                self.assertEqual(
                    {stage.name for stage in state_slot.iterdir()},
                    {
                        "0001-payload",
                        "0002-materialization",
                        "0003-test-materialization",
                    },
                )
                observed_hashes = {
                    stage.name: {
                        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in stage.iterdir()
                    }
                    for stage in state_slot.iterdir()
                }
                self.assertEqual(observed_hashes, paths["retained_hashes"][slot_number])
                work_slot = paths["work_slots"][slot_number]
                self.assertFalse(work_slot.joinpath("source-progress").exists())
                self.assertFalse(work_slot.joinpath("semantic-progress").exists())
                self.assertTrue(work_slot.joinpath("repository", "go.mod").is_file())
            self.assertEqual(
                paths["unrelated_work"].read_text(encoding="utf-8"),
                "module fixture/124\n",
            )

    def test_qualification_project_model_replay_fails_before_deleting_on_drift(
        self,
    ) -> None:
        def mutate_artifact(paths: dict[str, object]) -> None:
            artifact = paths["state_slots"][123].joinpath(
                "0004-source-census", "artifact.json"
            )
            artifact.write_bytes(artifact.read_bytes() + b" ")

        def add_unexpected_progress(paths: dict[str, object]) -> None:
            progress = paths["work_root"].joinpath(
                "go", "slot-0124", "source-progress", "base"
            )
            progress.mkdir(parents=True)

        for name, mutate in {
            "committed-artifact": mutate_artifact,
            "unexpected-progress": add_unexpected_progress,
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                paths = self._write_qualification_project_model_replay_fixture(
                    pathlib.Path(temporary)
                )
                mutate(paths)
                with self.assertRaises(ValueError):
                    self._migrate_qualification_project_model_replay(paths)
                self.assertTrue(
                    paths["state_slots"][122]
                    .joinpath("0006-assessment-identity")
                    .is_dir()
                )
                self.assertTrue(
                    paths["state_slots"][123].joinpath("0004-source-census").is_dir()
                )
                self.assertTrue(
                    paths["work_slots"][122].joinpath("semantic-progress").is_dir()
                )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            with self.assertRaises(ValueError):
                self._migrate_qualification_project_model_replay(
                    paths,
                    source_artifact_id=(
                        transport.QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        + 1
                    ),
                )
            self.assertTrue(
                paths["state_slots"][122].joinpath("0006-assessment-identity").is_dir()
            )

    def test_qualification_project_model_v9_replay_validates_exact_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            self._prepare_qualification_project_model_v9_replay(paths)
            manifest_before = paths["manifest"].read_bytes()
            trees_before = {
                str(path.relative_to(temporary)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for root_name in (
                    "historical-v2-assessment-state",
                    "historical-v2-assessment-work",
                )
                for path in pathlib.Path(temporary, root_name).rglob("*")
                if path.is_file()
            }

            self.assertEqual(
                transport.main(
                    [
                        "migrate-bounded-qualification-project-model-v9-replay",
                        str(paths["manifest"]),
                        str(paths["state_root"]),
                        str(paths["work_root"]),
                        str(transport.FRAME_RUN_ID),
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                        ),
                    ]
                ),
                0,
            )
            self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
            self.assertEqual(
                {
                    str(path.relative_to(temporary)): hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                    for root_name in (
                        "historical-v2-assessment-state",
                        "historical-v2-assessment-work",
                    )
                    for path in pathlib.Path(temporary, root_name).rglob("*")
                    if path.is_file()
                },
                trees_before,
            )

    def test_qualification_project_model_v9_replay_fails_closed_on_drift(
        self,
    ) -> None:
        def add_stale_stage(paths: dict[str, object]) -> None:
            paths["state_slots"][124].joinpath("0004-source-census").mkdir()

        def add_stale_progress(paths: dict[str, object]) -> None:
            progress = paths["work_root"].joinpath(
                "go", "slot-0124", "source-progress", "base"
            )
            progress.mkdir(parents=True)

        for name, mutate in {
            "stale-stage": add_stale_stage,
            "stale-progress": add_stale_progress,
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                paths = self._write_qualification_project_model_replay_fixture(
                    pathlib.Path(temporary)
                )
                self._prepare_qualification_project_model_v9_replay(paths)
                mutate(paths)
                with self.assertRaises(ValueError):
                    self._migrate_qualification_project_model_v9_replay(paths)

        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            self._prepare_qualification_project_model_v9_replay(paths)
            with self.assertRaises(ValueError):
                self._migrate_qualification_project_model_v9_replay(
                    paths,
                    source_artifact_id=(
                        transport.QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        + 1
                    ),
                )

    def test_qualification_project_model_v10_replay_rewinds_only_stale_sources(
        self,
    ) -> None:
        def snapshot(root: pathlib.Path) -> tuple[tuple[str, str, str], ...]:
            return tuple(
                (
                    "directory" if path.is_dir() else "file",
                    path.relative_to(root).as_posix(),
                    "" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest(),
                )
                for path in sorted(root.rglob("*"))
            )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            self._prepare_qualification_project_model_v10_replay(paths)
            manifest_before = paths["manifest"].read_bytes()
            slot_124_state_before = snapshot(paths["state_slots"][124])
            slot_124_repository = paths["work_slots"][124].joinpath("repository")
            slot_124_repository_before = snapshot(slot_124_repository)

            self.assertEqual(
                transport.main(
                    [
                        "migrate-bounded-qualification-project-model-v10-replay",
                        str(paths["manifest"]),
                        str(paths["state_root"]),
                        str(paths["work_root"]),
                        str(transport.FRAME_RUN_ID),
                        transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        ),
                        transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                        str(
                            transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
                        ),
                    ]
                ),
                0,
            )

            self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
            for slot_number in (122, 123):
                state_slot = paths["state_slots"][slot_number]
                self.assertEqual(
                    {stage.name for stage in state_slot.iterdir()},
                    {
                        "0001-payload",
                        "0002-materialization",
                        "0003-test-materialization",
                    },
                )
                observed_hashes = {
                    stage.name: {
                        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in stage.iterdir()
                    }
                    for stage in state_slot.iterdir()
                }
                self.assertEqual(observed_hashes, paths["retained_hashes"][slot_number])
                self.assertFalse(
                    paths["work_slots"][slot_number].joinpath("source-progress").exists()
                )
                self.assertFalse(
                    paths["work_slots"][slot_number]
                    .joinpath("semantic-progress")
                    .exists()
                )
            self.assertEqual(snapshot(paths["state_slots"][124]), slot_124_state_before)
            self.assertEqual(snapshot(slot_124_repository), slot_124_repository_before)
            self.assertFalse(
                paths["work_slots"][124].joinpath("source-progress").exists()
            )

    def test_qualification_project_model_v10_replay_fails_before_mutation_on_drift(
        self,
    ) -> None:
        def snapshot(paths: dict[str, object]) -> tuple[tuple[str, str, str], ...]:
            root = paths["state_root"].parent
            return tuple(
                (
                    "directory" if path.is_dir() else "file",
                    path.relative_to(root).as_posix(),
                    "" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest(),
                )
                for root_name in (
                    "historical-v2-assessment-state",
                    "historical-v2-assessment-work",
                )
                for path in sorted(root.joinpath(root_name).rglob("*"))
            )

        def tamper_source_stage(paths: dict[str, object]) -> None:
            artifact = paths["v10_source_stages"][123].joinpath("artifact.json")
            artifact.write_bytes(artifact.read_bytes() + b" ")

        def remove_source_progress_side(paths: dict[str, object]) -> None:
            side = paths["work_slots"][122].joinpath("source-progress", "patched")
            side.joinpath("progress.json").unlink()
            side.rmdir()

        def remove_slot_124_source_progress(paths: dict[str, object]) -> None:
            progress = paths["work_slots"][124].joinpath("source-progress")
            for side_name in ("base", "patched"):
                side = progress.joinpath(side_name)
                side.joinpath("progress.json").unlink()
                side.rmdir()
            progress.rmdir()

        def add_unexpected_source_progress(paths: dict[str, object]) -> None:
            progress = paths["work_root"].joinpath(
                "go", "slot-0125", "source-progress", "base"
            )
            progress.mkdir(parents=True)

        def add_semantic_progress(paths: dict[str, object]) -> None:
            progress = paths["work_slots"][123].joinpath("semantic-progress", "base")
            progress.mkdir(parents=True)

        def add_slot_124_source_stage(paths: dict[str, object]) -> None:
            paths["state_slots"][124].joinpath("0004-source-census").mkdir()

        for name, mutate in {
            "tampered-source-stage": tamper_source_stage,
            "missing-source-progress-side": remove_source_progress_side,
            "missing-slot-124-source-progress": remove_slot_124_source_progress,
            "unexpected-source-progress": add_unexpected_source_progress,
            "semantic-progress": add_semantic_progress,
            "unexpected-slot-124-source-stage": add_slot_124_source_stage,
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                paths = self._write_qualification_project_model_replay_fixture(
                    pathlib.Path(temporary)
                )
                self._prepare_qualification_project_model_v10_replay(paths)
                mutate(paths)
                manifest_before = paths["manifest"].read_bytes()
                trees_before = snapshot(paths)
                with self.assertRaises(ValueError):
                    self._migrate_qualification_project_model_v10_replay(paths)
                self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
                self.assertEqual(snapshot(paths), trees_before)
                for slot_number in (122, 123):
                    self.assertTrue(
                        paths["state_slots"][slot_number]
                        .joinpath("0004-source-census")
                        .is_dir()
                    )

        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_qualification_project_model_replay_fixture(
                pathlib.Path(temporary)
            )
            self._prepare_qualification_project_model_v10_replay(paths)
            manifest_before = paths["manifest"].read_bytes()
            trees_before = snapshot(paths)
            with self.assertRaises(ValueError):
                self._migrate_qualification_project_model_v10_replay(
                    paths,
                    source_artifact_id=(
                        transport.QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
                        + 1
                    ),
                )
            self.assertEqual(paths["manifest"].read_bytes(), manifest_before)
            self.assertEqual(snapshot(paths), trees_before)

    def test_source_required_progress_migration_preserves_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            manifest = root.joinpath("manifest.json")
            self._write_exact_go_semantic_compiler_world_manifest(manifest)
            state_root = root.joinpath("historical-v2-assessment-state")
            work_root = root.joinpath("historical-v2-assessment-work")
            state_slot = state_root.joinpath("go", "slot-0122")
            source_stage = state_slot.joinpath("0004-source-census")
            source_stage.mkdir(parents=True)
            state_slot.with_name("slot-0122.lock").write_text("locked", encoding="utf-8")
            prior_state = state_root.joinpath("go", "slot-0121", "complete")
            prior_state.mkdir(parents=True)
            prior_state.joinpath("checkpoint.json").write_bytes(b"prior-slot")
            state_root.joinpath("go", "slot-0121.lock").write_text(
                "locked", encoding="utf-8"
            )
            checkpoint = {
                "schema_version": 1,
                "checkpoint_contract": "sniffbench-historical-v2-slot-stage-checkpoint-v1",
                "selection_sha256": transport.SELECTION_SHA256,
                "language": "go",
                "slot_number": 122,
                "sequence": 4,
                "stage": "source_census",
                "outcome": {
                    "status": "completed",
                    "artifact_kind": "source_census",
                },
            }
            source_checkpoint = source_stage.joinpath("checkpoint.json")
            source_checkpoint.write_text(json.dumps(checkpoint), encoding="utf-8")

            work_slot = work_root.joinpath("go", "slot-0122")
            source_progress = work_slot.joinpath("source-progress")
            source_progress.joinpath("base").mkdir(parents=True)
            source_progress.joinpath("patched").mkdir()
            base_evidence = source_progress.joinpath("base", "snapshot.json")
            patched_evidence = source_progress.joinpath("patched", "snapshot.json")
            base_evidence.write_bytes(b"base-source-evidence")
            patched_evidence.write_bytes(b"patched-source-evidence")
            semantic_progress = work_slot.joinpath("semantic-progress")
            semantic_unit = semantic_progress.joinpath("base", "go", "old-world")
            semantic_unit.mkdir(parents=True)
            semantic_unit.joinpath("scope.json").write_bytes(b"old-semantic-world")
            next_slot = work_root.joinpath("go", "slot-0123", "repository")
            next_slot.mkdir(parents=True)
            next_slot.joinpath("go.mod").write_bytes(b"next-slot")
            manifest_before = manifest.read_bytes()
            checkpoint_before = source_checkpoint.read_bytes()

            transport.migrate_source_required_go_semantic_progress(
                manifest,
                state_root,
                work_root,
                transport.FRAME_RUN_ID,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
            )

            self.assertFalse(semantic_progress.exists())
            self.assertEqual(base_evidence.read_bytes(), b"base-source-evidence")
            self.assertEqual(patched_evidence.read_bytes(), b"patched-source-evidence")
            self.assertEqual(source_checkpoint.read_bytes(), checkpoint_before)
            self.assertEqual(manifest.read_bytes(), manifest_before)
            self.assertEqual(
                prior_state.joinpath("checkpoint.json").read_bytes(), b"prior-slot"
            )
            self.assertEqual(next_slot.joinpath("go.mod").read_bytes(), b"next-slot")

    def test_source_required_progress_migration_fails_before_deleting_on_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            manifest = root.joinpath("manifest.json")
            self._write_exact_go_semantic_compiler_world_manifest(manifest)
            state_root = root.joinpath("historical-v2-assessment-state")
            work_root = root.joinpath("historical-v2-assessment-work")
            state_slot = state_root.joinpath("go", "slot-0122")
            source_stage = state_slot.joinpath("0004-source-census")
            source_stage.mkdir(parents=True)
            state_slot.with_name("slot-0122.lock").write_text("locked", encoding="utf-8")
            source_stage.joinpath("checkpoint.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "checkpoint_contract": (
                            "sniffbench-historical-v2-slot-stage-checkpoint-v1"
                        ),
                        "selection_sha256": transport.SELECTION_SHA256,
                        "language": "go",
                        "slot_number": 122,
                        "sequence": 4,
                        "stage": "source_census",
                        "outcome": {
                            "status": "completed",
                            "artifact_kind": "source_census",
                        },
                    }
                ),
                encoding="utf-8",
            )
            work_slot = work_root.joinpath("go", "slot-0122")
            source_progress = work_slot.joinpath("source-progress")
            source_progress.joinpath("base").mkdir(parents=True)
            source_progress.joinpath("patched").mkdir()
            semantic_progress = work_slot.joinpath("semantic-progress")
            semantic_progress.mkdir()
            semantic_marker = semantic_progress.joinpath("must-survive")
            semantic_marker.write_bytes(b"evidence")
            unexpected_progress = work_root.joinpath(
                "go", "slot-0123", "semantic-progress"
            )
            unexpected_progress.mkdir(parents=True)
            unexpected_marker = unexpected_progress.joinpath("must-survive")
            unexpected_marker.write_bytes(b"unexpected-evidence")

            with self.assertRaises(ValueError):
                transport.migrate_source_required_go_semantic_progress(
                    manifest,
                    state_root,
                    work_root,
                    transport.FRAME_RUN_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID
                    + 1,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(semantic_marker.read_bytes(), b"evidence")
            self.assertEqual(unexpected_marker.read_bytes(), b"unexpected-evidence")

            with self.assertRaises(ValueError):
                transport.migrate_source_required_go_semantic_progress(
                    manifest,
                    state_root,
                    work_root,
                    transport.FRAME_RUN_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
                    transport.SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
                )
            self.assertEqual(semantic_marker.read_bytes(), b"evidence")
            self.assertEqual(
                unexpected_marker.read_bytes(), b"unexpected-evidence"
            )

    def test_storage_migration_rejects_unapproved_source_or_name(self) -> None:
        attempts = (
            ("a" * 40, transport.STORAGE_MIGRATION_NAME),
            (transport.STORAGE_MIGRATION_FROM_COLLECTOR_SHA, "generic-migration"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, (source, name) in enumerate(attempts):
                path = root.joinpath(f"manifest-{index}.json")
                transport.initialize_manifest(path, source, transport.FRAME_RUN_ID)
                with self.subTest(source=source, name=name), self.assertRaises(ValueError):
                    transport.migrate_manifest(
                        path,
                        transport.FRAME_RUN_ID,
                        "b" * 40,
                        name,
                        1,
                        source,
                        1,
                        "sha256:" + "c" * 64,
                        1,
                    )


class FrameTests(unittest.TestCase):
    def test_exact_synthetic_frame_contract_passes_and_tampering_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self._write_frame(root)
            file_hashes = {
                name: self._sha256(root.joinpath(name))
                for name in transport.FRAME_FILE_SHA256
            }
            checksums = "".join(
                f"{digest}  {name}\n" for name, digest in file_hashes.items()
            )
            root.joinpath("SHA256SUMS").write_text(
                checksums, encoding="utf-8", newline="\n"
            )
            checksum_hash = self._sha256(root.joinpath("SHA256SUMS"))
            with (
                mock.patch.object(transport, "FRAME_FILE_SHA256", file_hashes),
                mock.patch.object(transport, "FRAME_CHECKSUMS_SHA256", checksum_hash),
            ):
                transport.validate_frame(root)
                root.joinpath("environment.txt").write_text("tampered\n")
                with self.assertRaises(ValueError):
                    transport.validate_frame(root)

    @staticmethod
    def _write_frame(root: pathlib.Path) -> None:
        root.joinpath("environment.txt").write_text("fixture\n", encoding="utf-8")
        FrameTests._json(
            root.joinpath("provenance.json"),
            {
                "schema_version": 1,
                "repository": "trysniff/sniff",
                "collector_revision": transport.FRAME_COLLECTOR_SHA,
                "workflow_run_id": str(transport.FRAME_RUN_ID),
                "workflow_run_attempt": str(transport.FRAME_RUN_ATTEMPT),
                "model_provider_access": False,
            },
        )
        FrameTests._json(
            root.joinpath("frame.json"),
            {
                "dataset_revision": transport.DATASET_REVISION,
                "protocol_sha256": transport.PROTOCOL_SHA256,
                "frame_sha256": transport.FRAME_SHA256,
                "row_count": 126_300,
                "eligible_count": 13_774,
                "excluded_count": 112_526,
            },
        )
        FrameTests._json(
            root.joinpath("exclusions.json"),
            {
                "protocol_sha256": transport.PROTOCOL_SHA256,
                "manifest_sha256": transport.EXCLUSION_MANIFEST_SHA256,
                "repository_count": 615,
            },
        )
        FrameTests._json(
            root.joinpath("selection.json"),
            {
                "protocol_sha256": transport.PROTOCOL_SHA256,
                "frame_sha256": transport.FRAME_SHA256,
                "selection_sha256": transport.SELECTION_SHA256,
                "selected_count": 664,
                "unfilled_slot_count": 104,
            },
        )
        FrameTests._json(
            root.joinpath("selected-payloads.json"),
            {
                "protocol_sha256": transport.PROTOCOL_SHA256,
                "frame_sha256": transport.FRAME_SHA256,
                "selection_sha256": transport.SELECTION_SHA256,
                "payloads_sha256": transport.PAYLOADS_SHA256,
                "selected_count": 664,
            },
        )

    @staticmethod
    def _json(path: pathlib.Path, value) -> None:
        path.write_text(json.dumps(value), encoding="utf-8", newline="\n")

    @staticmethod
    def _sha256(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()


class WorkflowContractTests(unittest.TestCase):
    def test_dispatch_exposes_exact_stage_bounds(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        for stage in (
            "payload",
            "materialization",
            "test-materialization",
            "source-census",
            "semantic-census",
            "assessment-identity",
            "qualification",
            "test-recipe",
            "identical-tests",
            "ready-for-review",
        ):
            self.assertIn(f"          - {stage}\n", workflow)
        self.assertIn(
            "      MAX_NEW_STAGES_PER_SLOT: ${{ inputs.max_new_stages_per_slot }}",
            workflow,
        )
        self.assertIn("      THROUGH_STAGE: ${{ inputs.through_stage }}", workflow)
        self.assertIn(
            '--max-new-stages-per-slot "$MAX_NEW_STAGES_PER_SLOT"', workflow
        )
        self.assertIn("--through-stage \"$THROUGH_STAGE\"", workflow)
        self.assertIn(
            "max_new_stages_per_slot must be an integer from 1 through 10",
            workflow,
        )
        self.assertIn(
            "max_new_slots must be an integer from 0 through 768",
            workflow,
        )
        self.assertIn("max_new_slots=0 requires resume_run_id", workflow)
        self.assertIn("through_stage is not a historical-v2 slot stage", workflow)

    def test_assessment_budget_reserves_time_for_setup_sealing_and_upload(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        go_dependency = GO_DEPENDENCY_PATH.read_text(encoding="utf-8")
        lines = workflow.splitlines()
        assess = workflow.index("  assess:\n")
        assess_lines = workflow[assess:].splitlines()
        job_minutes = int(
            next(
                line
                for line in assess_lines
                if line.startswith("    timeout-minutes:")
            )
            .split(":", 1)[1]
            .strip()
        )
        assessment_minutes = int(
            re.search(
                r"assessment_timeout_minutes:\n"
                r"(?:        .*\n)*?"
                r'        default: "(\d+)"',
                workflow,
            ).group(1)
        )
        max_assessment_minutes = int(
            next(
                line
                for line in lines
                if line.startswith("      MAX_ASSESSMENT_TIMEOUT_MINUTES:")
            )
            .split('"', 2)[1]
        )
        reserve_minutes = int(
            next(
                line
                for line in lines
                if line.startswith("      NON_ASSESSMENT_RESERVE_MINUTES:")
            )
            .split('"', 2)[1]
        )
        heartbeat_seconds = int(
            next(
                line
                for line in lines
                if line.startswith("      ASSESSMENT_HEARTBEAT_SECONDS:")
            )
            .split('"', 2)[1]
        )

        self.assertEqual(job_minutes, 45)
        go_timeout = re.search(
            r"GO_COMMAND_TIMEOUT: Duration = Duration::from_secs\((\d+) \* 60\)",
            go_dependency,
        )
        self.assertIsNotNone(go_timeout)

        self.assertEqual(assessment_minutes, 6)
        self.assertEqual(max_assessment_minutes, 18)
        self.assertEqual(reserve_minutes, 27)
        self.assertEqual(heartbeat_seconds, 60)
        self.assertEqual(max_assessment_minutes + reserve_minutes, job_minutes)
        self.assertIn("historical-v2-durable-progress.diff", workflow)
        self.assertLess(int(go_timeout.group(1)), assessment_minutes)
        self.assertIn(
            "      ASSESSMENT_TIMEOUT_MINUTES: ${{ inputs.assessment_timeout_minutes }}",
            workflow,
        )
        self.assertIn(
            "assessment_timeout_minutes must be an integer from 1 through "
            "${MAX_ASSESSMENT_TIMEOUT_MINUTES}",
            workflow,
        )
        self.assertIn(
            '"${ASSESSMENT_TIMEOUT_MINUTES}m" \\',
            workflow,
        )
        self.assertIn(
            'python3 "$GITHUB_WORKSPACE/.github/scripts/run_with_heartbeat.py"',
            workflow,
        )
        self.assertIn(
            '--interval-seconds "$ASSESSMENT_HEARTBEAT_SECONDS"',
            workflow,
        )
        self.assertIn("--label historical-v2-assessment", workflow)
        self.assertIn("--linux-proc-stats", workflow)
        self.assertIn(
            "      - name: Capture durable progress before bounded assessment",
            workflow,
        )
        self.assertIn(
            "      - name: Capture durable progress after bounded assessment",
            workflow,
        )
        self.assertEqual(
            workflow.count(
                "| grep -E '^(Started semantic compiler worlds:|"
                "Durable semantic checkpoints:|  [a-z]+/slot-)'"
            ),
            2,
        )
        before_start = workflow.index(
            "      - name: Capture durable progress before bounded assessment"
        )
        assess_start = workflow.index(
            "      - name: Assess a bounded resumable slot slice",
            before_start,
        )
        after_start = workflow.index(
            "      - name: Capture durable progress after bounded assessment"
        )
        upload_start = workflow.index(
            "      - name: Upload immutable resumable assessment state",
            after_start,
        )
        for body in (
            workflow[before_start:assess_start],
            workflow[after_start:upload_start],
        ):
            self.assertIn(
                '--state-root "$STATE_ROOT" \\\n'
                "              2>&1",
                body,
            )
            self.assertIn(
                '--work-root "$WORK_ROOT" \\\n'
                "              2>&1 \\\n"
                "              | grep -E",
                body,
            )
        self.assertIn(
            "          DURABLE_PROGRESS_CHANGED: "
            "${{ steps.durable_progress.outputs.changed }}",
            workflow,
        )
        self.assertIn(
            "historical-v2 bounded assessment made no durable progress",
            workflow,
        )
        self.assertNotIn("--kill-after=60s 300m", workflow)

    def test_exact_collector_tools_are_built_in_a_prior_workflow_run(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        tools_workflow = TOOLS_WORKFLOW_PATH.read_text(encoding="utf-8")
        transport_source = MODULE_PATH.read_text(encoding="utf-8")
        tools_input = workflow[
            workflow.index("      tools_run_id:\n") : workflow.index(
                "      max_new_slots:\n"
            )
        ]

        self.assertNotIn("  build-tools:\n", workflow)
        self.assertNotIn("    needs: build-tools\n", workflow)
        self.assertIn("permissions:\n  actions: read\n  contents: read\n", workflow)
        self.assertIn("required: true", tools_input)
        self.assertIn("TOOLS_RUN_ID: ${{ inputs.tools_run_id }}", workflow)
        self.assertIn(
            "cargo build --release --locked --features sniffbench-frame",
            tools_workflow,
        )
        self.assertNotIn("run-slots", tools_workflow)
        self.assertIn(
            "name: historical-v2-assessment-tools-${{ github.sha }}",
            tools_workflow,
        )
        self.assertIn(
            "validate-tools-provenance",
            workflow,
        )
        for required in (
            'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${TOOLS_RUN_ID}"',
            'actions/runs/${TOOLS_RUN_ID}/artifacts?per_page=100',
            'artifact-ids: ${{ env.TOOLS_ARTIFACT_ID }}',
            'run-id: ${{ inputs.tools_run_id }}',
            'digest-mismatch: error',
            'tools_provenance_target="$transport_root/tools-provenance-${GITHUB_RUN_ID}.json"',
        ):
            self.assertIn(required, workflow)
        for required in (
            '.github/workflows/sniffbench-historical-v2-tools.yml',
            'sniffbench-historical-v2-tools-provenance-v1',
            'TOOLS_ARTIFACT_MAX_BYTES = 128 * 1024 * 1024',
            'run.get("run_attempt"), "tools workflow run attempt"',
            'tools workflow must publish exactly one artifact',
            'artifact.get("expired") is not False',
            'r"sha256:[0-9a-f]{64}"',
        ):
            self.assertIn(required, transport_source)
        self.assertIn("github-token: ${{ github.token }}", workflow)
        self.assertIn("repository: ${{ github.repository }}", workflow)
        observer = workflow.index("Verify and isolate the current state observer")
        initialize = workflow.index("Initialize or restore assessment roots")
        self.assertLess(
            workflow.index("Download the exact assessment tools"), observer
        )
        self.assertLess(observer, initialize)
        self.assertIn(
            'if [[ "$COLLECTOR_SHA" == "$GITHUB_SHA" ]]; then', workflow
        )
        self.assertIn(
            'test "$(cat "$tools/collector-sha256")" = "$GITHUB_SHA"',
            workflow,
        )
        self.assertIn("sha256sum --check", workflow)
        self.assertIn(
            'find "$tools" -mindepth 1 -maxdepth 1 -printf', workflow
        )
        self.assertNotIn(
            'find "$tools" -mindepth 1 -maxdepth 1 -type f', workflow
        )
        self.assertIn(
            "sha256sum collector-sha256 sniff sniffbench-frame > SHA256SUMS",
            tools_workflow,
        )
        self.assertIn(
            'test -f "$tools/$name" && test ! -L "$tools/$name"', workflow
        )
        self.assertIn("STATE_OBSERVER=%s", workflow)
        self.assertIn("EXACT_TOOLS_ROOT=%s", workflow)
        self.assertIn(
            "cargo build --release --locked --features sniffbench-frame", workflow
        )
        self.assertLess(
            workflow.index("Validate exact assessment tools provenance"),
            workflow.index("Download the exact assessment tools"),
        )
        self.assertLess(
            workflow.index("Initialize or restore assessment roots"),
            workflow.index("tools_provenance_target="),
        )
        self.assertLess(
            workflow.index("tools_provenance_target="),
            workflow.index("Validate the frozen frame and transport"),
        )
        self.assertLess(
            workflow.index("Materialize the frozen assessment tools"),
            workflow.index("Install every pinned semantic indexer"),
        )

    def test_marker_recovery_precedes_snapshot_archival(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        seal = workflow.index("- name: Seal resumable assessment state")
        recover = workflow.index("recover-slot-work", seal)
        archive = workflow.index("tar --create", recover)
        upload = workflow.index("- name: Upload immutable resumable assessment state", archive)
        seal_body = workflow[seal:upload]

        self.assertLess(seal, recover)
        self.assertLess(recover, archive)
        for required in (
            '--protocol "$COLLECTOR_ROOT/sniffbench/historical-v2-protocol.json"',
            '--artifact-root "$FRAME_ARTIFACT_ROOT"',
            '--frame "$FRAME_ROOT/frame.json"',
            '--exclusions "$FRAME_ROOT/exclusions.json"',
            '--selection "$FRAME_ROOT/selection.json"',
            '--payloads "$FRAME_ROOT/selected-payloads.json"',
            '--work-root "$WORK_ROOT"',
        ):
            self.assertIn(required, seal_body)
        for provider_variable in (
            "SNIFF_API_KEY",
            "SNIFF_ENDPOINT",
            "SNIFF_MODEL",
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            self.assertNotIn(provider_variable, seal_body)

    def test_read_only_state_verification_precedes_sealing(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        assess = workflow.index("- name: Assess a bounded resumable slot slice")
        status = workflow.index("- name: Verify resumable assessment state", assess)
        seal = workflow.index("- name: Seal resumable assessment state", status)
        status_body = workflow[status:seal]

        self.assertLess(assess, status)
        self.assertLess(status, seal)
        self.assertIn('"$STATE_OBSERVER" state-status', status_body)
        self.assertNotIn(
            '"$COLLECTOR_ROOT/target/release/sniffbench-frame" state-status',
            status_body,
        )
        for required in (
            '--protocol "$COLLECTOR_ROOT/sniffbench/historical-v2-protocol.json"',
            '--artifact-root "$FRAME_ARTIFACT_ROOT"',
            '--frame "$FRAME_ROOT/frame.json"',
            '--exclusions "$FRAME_ROOT/exclusions.json"',
            '--selection "$FRAME_ROOT/selection.json"',
            '--payloads "$FRAME_ROOT/selected-payloads.json"',
            '--state-root "$STATE_ROOT"',
            '>> "$GITHUB_STEP_SUMMARY"',
            "set -uo pipefail",
            "set +e",
            "status=$?",
            "set -e",
            'exit "$status"',
        ):
            self.assertIn(required, status_body)
        self.assertLess(
            status_body.index("printf '%s\\n' \"$status_output\""),
            status_body.index('exit "$status"'),
        )
        self.assertNotIn("recover-slot-work", status_body)
        for provider_variable in (
            "SNIFF_API_KEY",
            "SNIFF_ENDPOINT",
            "SNIFF_MODEL",
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            self.assertNotIn(provider_variable, status_body)

    def test_semantic_failure_details_are_opt_in_and_not_durable_progress(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        status = workflow.index("- name: Verify resumable assessment state")
        seal = workflow.index("- name: Seal resumable assessment state", status)
        status_body = workflow[status:seal]
        before = workflow.index("- name: Capture durable progress before bounded assessment")
        assess = workflow.index("- name: Assess a bounded resumable slot slice", before)
        after = workflow.index("- name: Capture durable progress after bounded assessment")
        upload = workflow.index("- name: Upload immutable resumable assessment state", after)

        self.assertIn("show_semantic_failures:", workflow)
        self.assertIn("SHOW_SEMANTIC_FAILURES: ${{ inputs.show_semantic_failures }}", status_body)
        self.assertIn("diagnostic_args=()", status_body)
        self.assertIn("diagnostic_args+=(--show-semantic-failures)", status_body)
        self.assertIn('"${diagnostic_args[@]}"', status_body)
        self.assertNotIn("show-semantic-failures", workflow[before:assess])
        self.assertNotIn("show-semantic-failures", workflow[after:upload])

    def test_inspection_only_verifies_prior_state_without_assessing_or_uploading(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        def step(name: str) -> str:
            start = workflow.index(f"      - name: {name}")
            end = workflow.find("\n      - ", start + 1)
            return workflow[start:] if end == -1 else workflow[start:end]

        self.assertIn("inspect_only:\n", workflow)
        self.assertIn("INSPECT_ONLY: ${{ inputs.inspect_only }}", workflow)
        self.assertIn("if [[ \"$INSPECT_ONLY\" == 'true' ]]; then", workflow)
        self.assertIn(
            "inspect_only requires resume_run_id, max_new_slots=0, and no collector_migration",
            workflow,
        )
        self.assertIn(
            "if: ${{ success() && (inputs.inspect_only || steps.assess.outcome == 'success') }}",
            step("Verify resumable assessment state"),
        )
        restore = step("Initialize or restore assessment roots")
        self.assertIn("if [[ \"$INSPECT_ONLY\" != 'true' ]]; then", restore)
        self.assertLess(
            restore.index("if [[ \"$INSPECT_ONLY\" != 'true' ]]; then"),
            restore.index('install -m 0644 "$tools_provenance" "$tools_provenance_target"'),
        )
        self.assertIn('"$STATE_OBSERVER" state-status', step("Verify resumable assessment state"))
        self.assertNotIn("run-slots", step("Verify resumable assessment state"))
        for name in (
            "Configure the Rust toolchain for sandboxed Rust indexing",
            "Install the hardened Linux sandbox",
            "Enable Linux user namespaces for the assessment sandbox",
            "Enable project-selected Node package managers",
            "Materialize the exact execution harness",
            "Require and freeze the production runtime",
            "Materialize the frozen assessment tools",
            "Install every pinned semantic indexer",
            "Capture durable progress before bounded assessment",
            "Assess a bounded resumable slot slice",
        ):
            self.assertIn("if: ${{ !inputs.inspect_only }}", step(name), name)
        self.assertIn(
            "if: ${{ !inputs.inspect_only && always() && steps.assess.outcome == 'success' }}",
            step("Seal resumable assessment state"),
        )
        self.assertIn(
            "if: ${{ always() && steps.seal.outcome == 'success' }}",
            step("Upload immutable resumable assessment state"),
        )
        for action in (
            "dtolnay/rust-toolchain",
            "actions/setup-node",
            "actions/setup-java",
            "actions/setup-go",
            "astral-sh/setup-uv",
            "gradle/actions/setup-gradle",
            "oven-sh/setup-bun",
        ):
            start = workflow.index(f"      - uses: {action}")
            self.assertIn("if: ${{ !inputs.inspect_only }}", workflow[start:start + 250], action)

    def test_resume_freezes_collector_and_migration_is_explicit(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        for required in (
            "collector_migration:",
            "COLLECTOR_MIGRATION: ${{ inputs.collector_migration }}",
            "compact-stage-artifact-json-v1",
            "package-scoped-go-dependency-preparation-v1",
            "declared-go-module-dependency-preparation-v1",
            "strict-go-project-root-validation-v1",
            "valid-go-eof-parser-v1",
            "validated-resume-symlink-extraction-v1",
            "committed-git-blob-source-census-v1",
            "bounded-go-semantic-indexing-v1",
            "hosted-semantic-seal-margin-v1",
            "resumable-go-semantic-assembly-v1",
            "finalized-go-semantic-compaction-v1",
            "indexed-semantic-snapshot-projection-v1",
            "batched-source-normalized-semantic-snapshot-v1",
            "compiler-public-surface-replay-v1",
            "executable-git-blob-project-model-v1",
            "go-project-model-dependency-preparation-v1",
            "resumable-source-census-progress-v1",
            "bounded-source-census-artifact-v1",
            "exact-go-semantic-compiler-world-v1",
            "source-required-go-semantic-worlds-v1",
            "semantic-progress-observability-v1",
            "semantic-incomplete-world-first-v1",
            "bounded-semantic-duration-v1",
            "inferred-scip-kind-replay-v1",
            "committed-go-package-root-worlds-v1",
            "checkpointed-semantic-variant-assembly-v1",
            "bounded-qualification-project-model-v8-replay-v1",
            "bounded-qualification-project-model-v9-replay-v1",
            "bounded-qualification-project-model-v10-replay-v1",
            "go-standalone-source-ownership-v1",
            "go-semantic-boundary-assembly-v1",
            "go-semantic-unit-phase-timing-v1",
            "semantic-validation-assembly-timing-v1",
            "semantic-projection-indexing-v1",
            "semantic-public-binding-index-v1",
            "go-compiler-census-evidence-replay-v1",
            "go-semantic-required-document-coverage-v1",
            "go-semantic-effective-test-coverage-v1",
            'migrate-source-required-go-semantic-progress',
            'migrate-inferred-scip-kind-replay',
            'migrate-bounded-qualification-project-model-v8-replay',
            'migrate-bounded-qualification-project-model-v9-replay',
            'migrate-bounded-qualification-project-model-v10-replay',
            "'f464096ca72580e12b2da10389a24d4389754d2b'",
            '"$manifest" "$STATE_ROOT" "$WORK_ROOT" "$FRAME_RUN_ID"',
            '"$transport" migrate-manifest',
            '"$PRIOR_HEAD_SHA" "$PRIOR_ARTIFACT_ID"',
            '"$PRIOR_ARTIFACT_DIGEST" "$PRIOR_ARTIFACT_SIZE"',
            'collector_root="${RUNNER_TEMP}/historical-v2-assessment-collector"',
            'git -C "$collector_root" checkout --quiet --detach FETCH_HEAD',
            'test "$(git -C "$collector_root" rev-parse HEAD)" = "$collector_sha"',
            'frozen_transport="$collector_root/.github/scripts/historical_v2_assessment_transport.py"',
            'python3 "$frozen_transport" validate-manifest',
            'test "$frozen_collector_sha" = "$collector_sha"',
            "- name: Materialize the immutable frame evidence root",
            "'8681f9c379c4e4817c7ed49f06f47f4c47d1f91b'",
            'config core.autocrlf false',
            'config core.eol lf',
            'FRAME_ARTIFACT_ROOT=%s',
            'cd "$COLLECTOR_ROOT"',
            'replay-public-surface-census',
            'replay-compiler-census',
            'replay-go-semantic-coverage',
            'for slot_number in 123 124 125; do',
            '--state-root "$STATE_ROOT"',
            '--work-root "$WORK_ROOT"',
            '--language go',
            '--slot-number 122',
            '--slot-number 123',
            '--slot-number 124',
            '"$COLLECTOR_ROOT/target/release/sniffbench-frame" run-slots',
            '--artifact-root "$FRAME_ARTIFACT_ROOT"',
            'python3 "$COLLECTOR_ROOT/.github/scripts/historical_v2_assessment_transport.py"',
        ):
            self.assertIn(required, workflow)
        self.assertNotIn('target/release/sniffbench-frame run-slots', workflow)
        self.assertNotIn('--artifact-root "$GITHUB_WORKSPACE"', workflow)
        self.assertNotIn('--artifact-root "$COLLECTOR_ROOT"', workflow)
        self.assertNotIn('migrate-go-standalone-source-ownership', workflow)
        cleanup = workflow.index("migrate-source-required-go-semantic-progress")
        semantic_replay = workflow.index("migrate-inferred-scip-kind-replay")
        project_model_replay = workflow.index(
            "migrate-bounded-qualification-project-model-v8-replay"
        )
        project_model_v9_replay = workflow.index(
            "migrate-bounded-qualification-project-model-v9-replay"
        )
        project_model_v10_replay = workflow.index(
            "migrate-bounded-qualification-project-model-v10-replay"
        )
        manifest_migration = workflow.index('"$transport" migrate-manifest')
        v10_manifest_migration = workflow.index(
            '"$transport" migrate-manifest', project_model_v10_replay
        )
        self.assertLess(cleanup, manifest_migration)
        self.assertLess(semantic_replay, manifest_migration)
        self.assertLess(project_model_replay, manifest_migration)
        self.assertLess(manifest_migration, project_model_v9_replay)
        self.assertLess(project_model_v10_replay, v10_manifest_migration)
        replay = workflow.index("- name: Replay stale compiler public-surface censuses")
        install = workflow.index("- name: Install every pinned semantic indexer")
        assess = workflow.index("- name: Assess a bounded resumable slot slice")
        self.assertLess(replay, install)
        self.assertLess(install, assess)


if __name__ == "__main__":
    unittest.main()
