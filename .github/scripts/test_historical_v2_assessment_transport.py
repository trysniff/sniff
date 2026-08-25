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
        recover = workflow.index("sniffbench-frame recover-slot-work", seal)
        archive = workflow.index("tar --create", recover)
        upload = workflow.index("- name: Upload immutable resumable assessment state", archive)
        seal_body = workflow[seal:upload]

        self.assertLess(seal, recover)
        self.assertLess(recover, archive)
        for required in (
            "--protocol sniffbench/historical-v2-protocol.json",
            '--artifact-root "$GITHUB_WORKSPACE"',
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


if __name__ == "__main__":
    unittest.main()
