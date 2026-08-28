#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("historical_v2_assessment_transport.py")
WORKFLOW_PATH = pathlib.Path(__file__).parents[1].joinpath(
    "workflows", "sniffbench-historical-v2-assessment.yml"
)
SPEC = importlib.util.spec_from_file_location("assessment_transport", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load assessment transport helper")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


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

    def test_traversal_hard_links_and_cross_root_links_are_rejected(self) -> None:
        attacks = {
            "traversal": self._traversal,
            "hard-link": self._hard_link,
            "cross-root-link": self._cross_root_link,
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
