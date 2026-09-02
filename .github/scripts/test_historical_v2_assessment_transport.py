#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
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
        self.assertIn("through_stage is not a historical-v2 slot stage", workflow)

    def test_assessment_budget_reserves_time_for_setup_sealing_and_upload(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
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
            next(
                line
                for line in lines
                if line.startswith("      ASSESSMENT_TIMEOUT_MINUTES:")
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

        self.assertEqual(job_minutes, 30)
        self.assertEqual(assessment_minutes, 8)
        self.assertEqual(reserve_minutes, 22)
        self.assertEqual(heartbeat_seconds, 60)
        self.assertEqual(assessment_minutes + reserve_minutes, job_minutes)
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
        self.assertIn(
            'if [[ "$COLLECTOR_SHA" == "$GITHUB_SHA" ]]; then', workflow
        )
        self.assertIn(
            'test "$(cat "$tools/collector-sha256")" = "$COLLECTOR_SHA"',
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
            '--artifact-root "$COLLECTOR_ROOT"',
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
            '"$transport" migrate-manifest',
            '"$PRIOR_HEAD_SHA" "$PRIOR_ARTIFACT_ID"',
            '"$PRIOR_ARTIFACT_DIGEST" "$PRIOR_ARTIFACT_SIZE"',
            'collector_root="${RUNNER_TEMP}/historical-v2-assessment-collector"',
            'git -C "$collector_root" checkout --quiet --detach FETCH_HEAD',
            'test "$(git -C "$collector_root" rev-parse HEAD)" = "$collector_sha"',
            'frozen_transport="$collector_root/.github/scripts/historical_v2_assessment_transport.py"',
            'python3 "$frozen_transport" validate-manifest',
            'test "$frozen_collector_sha" = "$collector_sha"',
            'cd "$COLLECTOR_ROOT"',
            '"$COLLECTOR_ROOT/target/release/sniffbench-frame" run-slots',
            '--artifact-root "$COLLECTOR_ROOT"',
            'python3 "$COLLECTOR_ROOT/.github/scripts/historical_v2_assessment_transport.py"',
        ):
            self.assertIn(required, workflow)
        self.assertNotIn('target/release/sniffbench-frame run-slots', workflow)
        self.assertNotIn('--artifact-root "$GITHUB_WORKSPACE"', workflow)


if __name__ == "__main__":
    unittest.main()
