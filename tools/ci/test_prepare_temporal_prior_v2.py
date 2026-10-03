import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import prepare_temporal_prior_v2 as prepare

MINIMAL_SOURCES = ("sniffbench/p.json", "gold_fixtures/repo/a.py")

def metadata():
    return {
        "id": prepare.FRAME_ID, "name": f"historical-v2-frame-{prepare.FRAME_RUN}",
        "digest": "sha256:" + prepare.ARCHIVE_SHA, "size_in_bytes": prepare.ARCHIVE_BYTES,
        "expired": False,
        "workflow_run": {"id": prepare.FRAME_RUN, "head_sha": prepare.FRAME_SHA, "head_branch": "main"},
    }, {
        "id": prepare.FRAME_RUN, "run_attempt": 1, "event": "workflow_dispatch",
        "status": "completed", "conclusion": "success", "head_sha": prepare.FRAME_SHA,
        "path": ".github/workflows/sniffbench-historical-v2-frame.yml",
        "repository": {"full_name": "trysniff/sniff"},
    }


def tree(*names):
    return b"".join(b"100644 blob " + b"a" * 40 + b"\t" + n.encode() + b"\0" for n in names)


class FrozenPriorInputTests(unittest.TestCase):
    def verify_metadata(self, artifact, run):
        with patch.object(prepare, "read_capture", side_effect=[json.dumps(artifact).encode(), json.dumps(run).encode()]):
            prepare.validate_metadata("artifact", "run")

    def test_exact_metadata_allows_irrelevant_api_fields(self):
        artifact, run = metadata()
        artifact["extra"] = "ignored metadata"
        run["repository"]["extra"] = 123
        self.verify_metadata(artifact, run)

    def test_changed_artifact_or_run_identity_and_types_fail(self):
        artifact, run = metadata()
        for source in [artifact, run]:
            for key in source:
                changed = copy.deepcopy(source)
                changed[key] = None
                with self.subTest(source=source, key=key), self.assertRaises(ValueError):
                    self.verify_metadata(changed, run) if source is artifact else self.verify_metadata(artifact, changed)
        for attempt in [True, 1.0, "1", 2]:
            changed = copy.deepcopy(run)
            changed["run_attempt"] = attempt
            with self.subTest(attempt=attempt), self.assertRaises(ValueError):
                self.verify_metadata(artifact, changed)
        for expired in [True, 0, None]:
            changed = copy.deepcopy(artifact)
            changed["expired"] = expired
            with self.subTest(expired=expired), self.assertRaises(ValueError):
                self.verify_metadata(changed, run)

    def archive(self, root, names=None, symlink=False):
        path = root / "archive.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name in sorted(prepare.FRAME_FILES) if names is None else names:
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16 if symlink else (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, b'abc')
        return path

    def extract(self, archive, destination):
        with patch.object(prepare, "ARCHIVE_BYTES", archive.stat().st_size), \
             patch.object(prepare, "ARCHIVE_SHA", hashlib.sha256(archive.read_bytes()).hexdigest()):
            prepare.extract_frame(archive, destination)

    def test_pinned_archive_extracts_exact_files_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root)
            destination = root / "frame"
            self.extract(archive, destination)
            self.assertEqual({p.name for p in destination.iterdir()}, prepare.FRAME_FILES)
            self.assertTrue(all(p.read_bytes() == b'abc' for p in destination.iterdir()))
            with self.assertRaises(FileExistsError):
                self.extract(archive, destination)

    def test_archive_digest_and_size_fail_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root)
            destination = root / "frame"
            with self.assertRaises(ValueError):
                prepare.extract_frame(archive, destination)
            with patch.object(prepare, "ARCHIVE_BYTES", archive.stat().st_size), self.assertRaises(ValueError):
                prepare.extract_frame(archive, destination)
            self.assertFalse(destination.exists())

    def test_archive_layout_links_and_bounds_fail_before_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for names in [["../frame.json"], ["frame.json"] * 7, sorted(prepare.FRAME_FILES) + ["extra"]]:
                archive = self.archive(root, names)
                with self.subTest(names=names), self.assertRaises(ValueError):
                    self.extract(archive, root / "frame")
                self.assertFalse((root / "frame").exists())
            archive = self.archive(root, symlink=True)
            with self.assertRaises(ValueError):
                self.extract(archive, root / "frame")
            archive = self.archive(root)
            with patch.object(prepare, "MAX_MEMBER_BYTES", 2), self.assertRaises(ValueError):
                self.extract(archive, root / "frame")
            with patch.object(prepare, "MAX_EXPANDED_BYTES", 20), self.assertRaises(ValueError):
                self.extract(archive, root / "frame")
            self.assertFalse((root / "frame").exists())

    @patch.object(prepare, "SOURCE_FILES", MINIMAL_SOURCES)
    @patch.object(prepare.subprocess, "run")
    def test_git_source_export_preserves_blob_bytes_not_worktree_endings(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, tree("sniffbench/p.json", "gold_fixtures/repo/a.py")),
            subprocess.CompletedProcess([], 0, b'3'), subprocess.CompletedProcess([], 0, b'{}\n'),
            subprocess.CompletedProcess([], 0, b'2'), subprocess.CompletedProcess([], 0, b'x\n'),
        ]
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "source"
            prepare.export_source("repo", destination)
            self.assertEqual((destination / "sniffbench/p.json").read_bytes(), b'{}\n')
            self.assertEqual((destination / "gold_fixtures/repo/a.py").read_bytes(), b'x\n')
        self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
        self.assertEqual(run.call_args_list[0].args[0][-2:], list(MINIMAL_SOURCES))

    @patch.object(prepare, "SOURCE_FILES", MINIMAL_SOURCES)
    @patch.object(prepare.subprocess, "run")
    def test_git_source_unsafe_repeated_or_missing_roots_fail(self, run):
        good = tree("sniffbench/p.json", "gold_fixtures/repo/a.py")
        for bad in [b'', tree("sniffbench/p.json"), good + tree("sniffbench/P.json"),
                    good.replace(b'100644', b'120000', 1),
                    tree("sniffbench/../outside", "gold_fixtures/repo/a.py"),
                    tree("sniffbench/a\\outside", "gold_fixtures/repo/a.py")]:
            run.return_value = subprocess.CompletedProcess([], 0, bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                prepare.source_entries("repo")

    @patch.object(prepare, "SOURCE_FILES", MINIMAL_SOURCES)
    @patch.object(prepare.subprocess, "run")
    def test_git_preflight_bounds_and_failures_never_read_oversized_blob(self, run):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run.side_effect = [subprocess.CompletedProcess([], 0, tree(*MINIMAL_SOURCES)),
                               subprocess.CompletedProcess([], 0, str(prepare.MAX_MEMBER_BYTES + 1).encode())]
            with self.assertRaises(ValueError):
                prepare.export_source("repo", root / "source")
            self.assertEqual(run.call_count, 2)
            run.side_effect = subprocess.CalledProcessError(1, ["git"])
            with self.assertRaises(subprocess.CalledProcessError):
                prepare.export_source("repo", root / "failed")
            self.assertFalse((root / "failed").exists())

    @patch.object(prepare.subprocess, "run")
    def test_windows_devices_and_aliases_fail_even_in_source_allowlist(self, run):
        for component in ["NUL", "CON.txt", "AUX", "COM1.json", "LPT9", "file.", "file ", "a?b"]:
            names = ("sniffbench/" + component, "gold_fixtures/repo/a.py")
            run.return_value = subprocess.CompletedProcess([], 0, tree(*names))
            with patch.object(prepare, "SOURCE_FILES", names), self.subTest(component=component), self.assertRaises(ValueError):
                prepare.source_entries("repo")

    @patch.object(prepare, "SOURCE_FILES", MINIMAL_SOURCES)
    @patch.object(prepare.subprocess, "run")
    def test_cumulative_source_bound_fails_before_second_blob_read(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, tree(*MINIMAL_SOURCES)),
            subprocess.CompletedProcess([], 0, b'3'), subprocess.CompletedProcess([], 0, b'abc'),
            subprocess.CompletedProcess([], 0, b'3'),
        ]
        with tempfile.TemporaryDirectory() as temp, patch.object(prepare, "MAX_EXPANDED_BYTES", 5):
            with self.assertRaises(ValueError):
                prepare.export_source("repo", Path(temp) / "source")
        self.assertEqual(run.call_count, 4)

    def test_bounded_archive_capture_accepts_exact_bytes_only(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(prepare, "ARCHIVE_BYTES", 3), \
             patch.object(prepare, "ARCHIVE_SHA", hashlib.sha256(b'abc').hexdigest()):
            for index, data in enumerate([b'abc', b'ab', b'xyz', b'abcd']):
                target = Path(temp) / str(index)
                with patch.object(prepare.sys, "stdin") as stdin:
                    stdin.buffer = io.BytesIO(data)
                    if data == b'abc':
                        prepare.capture_archive(target)
                        self.assertEqual(target.read_bytes(), data)
                    else:
                        with self.assertRaises(ValueError):
                            prepare.capture_archive(target)
                    self.assertLessEqual(target.stat().st_size, 3)

    def dataset(self, root):
        (root / "data").mkdir()
        shards = []
        for index in range(3):
            name = f"data/shard-{index}.parquet"
            data = bytes([index]) * (index + 2)
            (root / name).write_bytes(data)
            shards.append({"path": name, "size_bytes": len(data), "lfs_sha256": hashlib.sha256(data).hexdigest()})
        protocol = root / "protocol.json"
        protocol.write_bytes(json.dumps({"dataset": {"shards": shards}}).encode())
        return protocol

    def verify_dataset(self, protocol, root):
        with patch.object(prepare, "PROTOCOL_SHA", hashlib.sha256(protocol.read_bytes()).hexdigest()):
            prepare.verify_dataset(protocol, root)

    def test_dataset_exact_inventory_sizes_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            protocol = self.dataset(root)
            self.verify_dataset(protocol, root)
            for data in [b'\x00', b'\x00\x00\x00', b'xx']:
                (root / "data/shard-0.parquet").write_bytes(data)
                with self.subTest(data=data), self.assertRaises(ValueError):
                    self.verify_dataset(protocol, root)
            (root / "data/shard-0.parquet").write_bytes(b'\x00\x00')
            (root / "data/extra").write_bytes(b'')
            with self.assertRaises(ValueError):
                self.verify_dataset(protocol, root)

    def test_wrong_protocol_fails_before_dataset_inspection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            protocol = root / "wrong.json"
            protocol.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, "SHA-256 changed"):
                prepare.verify_dataset(protocol, root / "missing")

    @patch.object(prepare, "verify_dataset")
    @patch.object(prepare.subprocess, "run")
    def test_downloads_require_bounded_curl_and_exact_per_shard_limits(self, run, verify):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            protocol = self.dataset(root)
            body = json.loads(protocol.read_bytes())
            body["dataset"]["revision"] = "a" * 40
            protocol.write_bytes(json.dumps(body).encode())
            run.return_value = subprocess.CompletedProcess([], 0, 'curl 8.4.0 (test)\n')
            with patch.object(prepare, "PROTOCOL_SHA", hashlib.sha256(protocol.read_bytes()).hexdigest()):
                prepare.download_dataset(protocol, root / "download", "selected-curl")
            self.assertEqual(run.call_count, 4)
            for call, shard in zip(run.call_args_list[1:], body["dataset"]["shards"]):
                command = call.args[0]
                self.assertEqual(command[0], "selected-curl")
                self.assertEqual(command[command.index("--max-filesize") + 1], str(shard["size_bytes"] + 1))
                self.assertTrue(command[-1].endswith("/" + shard["path"] + "?download=true"))
                self.assertTrue(call.kwargs["check"])
            verify.assert_called_once_with(protocol, root / "download")

    @patch.object(prepare.subprocess, "run")
    def test_old_unknown_or_failed_curl_never_downloads(self, run):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            protocol = self.dataset(root)
            with patch.object(prepare, "PROTOCOL_SHA", hashlib.sha256(protocol.read_bytes()).hexdigest()):
                for version in ['curl 8.3.0 (test)', 'curl unknown', 'other 9.0.0']:
                    run.reset_mock()
                    run.return_value = subprocess.CompletedProcess([], 0, version)
                    with self.assertRaises(ValueError):
                        prepare.download_dataset(protocol, root / "download")
                    self.assertEqual(run.call_count, 1)
                    self.assertFalse((root / "download").exists())
                run.side_effect = subprocess.CalledProcessError(1, ["curl"])
                with self.assertRaises(subprocess.CalledProcessError):
                    prepare.download_dataset(protocol, root / "failed")
                self.assertFalse((root / "failed").exists())


if __name__ == "__main__":
    unittest.main()
