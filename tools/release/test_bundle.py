import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from bundle import create, digest, encode, validate_portable_paths, verify
from sbom import source_sbom


COMMIT = "a" * 40
TARGET = "x86_64-unknown-linux-gnu"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
LOCK = f'[[package]]\nname = "dep"\nversion = "1.0.0"\nsource = "{SOURCE}"\nchecksum = "{"b" * 64}"\n'.encode()
METADATA = {
    "packages": [
        {
            "id": "root",
            "name": "sniff-cli",
            "version": "0.2.2",
            "source": None,
            "license": "AGPL-3.0-only",
        },
        {
            "id": "dependency",
            "name": "dep",
            "version": "1.0.0",
            "source": SOURCE,
            "license": "MIT",
        },
    ],
    "resolve": {
        "root": "root",
        "nodes": [
            {
                "id": "root",
                "deps": [
                    {
                        "pkg": "dependency",
                        "dep_kinds": [
                            {"kind": None},
                            {"kind": "dev"},
                            {"kind": "build"},
                        ],
                    }
                ],
            },
            {"id": "dependency", "deps": []},
        ],
    },
}


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "LICENSES").mkdir()
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "LICENSES/MIT.txt"):
            (self.root / name).write_text(name)
        (self.root / "Cargo.lock").write_bytes(LOCK)
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"native executable fixture")
        self.metadata = self.root / "metadata.json"
        self.metadata.write_text(json.dumps(METADATA))
        self.rustc = self.root / "rustc.txt"
        self.rustc.write_text("rustc fixture")
        self.archive = create(
            self.root,
            self.binary,
            self.metadata,
            self.rustc,
            self.root / "bundle",
            TARGET,
            COMMIT,
            0,
        )

    def test_archive_roundtrip_and_deterministic_packaging(self):
        binary = verify(self.archive, TARGET, COMMIT, self.root / "extracted")
        self.assertEqual(binary.read_bytes(), self.binary.read_bytes())
        with zipfile.ZipFile(self.archive) as archive:
            self.assertEqual(
                stat.S_IMODE(archive.getinfo("bin/sniff").external_attr >> 16), 0o755
            )
        second = create(
            self.root,
            self.binary,
            self.metadata,
            self.rustc,
            self.root / "second",
            TARGET,
            COMMIT,
            0,
        )
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())

    def test_wrong_source_and_target_fail_before_extraction(self):
        for target, commit in [(TARGET, "c" * 40), ("aarch64-apple-darwin", COMMIT)]:
            with self.assertRaisesRegex(ValueError, "identity"):
                verify(self.archive, target, commit, self.root / "extracted")
            self.assertFalse((self.root / "extracted").exists())

    def test_archive_checksum_and_rehashed_payload_tampering_fail(self):
        original = self.archive.read_bytes()
        self.archive.write_bytes(original + b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            verify(self.archive, TARGET, COMMIT, self.root / "extracted")
        self.archive.write_bytes(original)
        with zipfile.ZipFile(self.archive) as archive:
            entries = [
                (item, archive.read(item.filename)) for item in archive.infolist()
            ]
        with zipfile.ZipFile(self.archive, "w") as archive:
            for item, data in entries:
                archive.writestr(
                    item, b"changed" if item.filename == "bin/sniff" else data
                )
        (self.archive.parent / "SHA256SUMS").write_text(
            f"{digest(self.archive.read_bytes())}  {self.archive.name}\n"
        )
        with self.assertRaisesRegex(ValueError, "commitment"):
            verify(self.archive, TARGET, COMMIT, self.root / "extracted")

    def test_unsafe_entry_rejected_even_with_rehashed_archive(self):
        with zipfile.ZipFile(self.archive, "a") as archive:
            archive.writestr("../escape", b"escape")
        (self.archive.parent / "SHA256SUMS").write_text(
            f"{digest(self.archive.read_bytes())}  {self.archive.name}\n"
        )
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            verify(self.archive, TARGET, COMMIT, self.root / "extracted")
        self.assertFalse((self.root.parent / "escape").exists())

    def test_rooted_and_noncanonical_archive_paths_rejected(self):
        original = self.archive.read_bytes()
        for name in ["/escape", "//server/share/escape", "bin//extra", "bin/./extra"]:
            with self.subTest(name=name):
                self.archive.write_bytes(original)
                with zipfile.ZipFile(self.archive, "a") as archive:
                    archive.writestr(name, b"escape")
                (self.archive.parent / "SHA256SUMS").write_text(
                    f"{digest(self.archive.read_bytes())}  {self.archive.name}\n"
                )
                with self.assertRaisesRegex(ValueError, "Unsafe"):
                    verify(self.archive, TARGET, COMMIT, self.root / "extracted")
                self.assertFalse((self.root / "extracted").exists())

    def test_no_overwrite_of_existing_extraction(self):
        target = self.root / "existing"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            verify(self.archive, TARGET, COMMIT, target)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_portable_paths_rejected_before_any_extraction(self):
        original = self.archive.read_bytes()
        invalid = [
            "bin/.. /escape",
            "bin/sniff.",
            "bin /extra",
            "bin/NUL",
            "bin/CON.txt",
            "bin/con .txt",
            "bin/COM1.log",
            "bin/LPT9",
            "bin/CONIN$",
            "bin/a?b",
            "bin/a\x01b",
            "bin/COM\u00b9",
            "BIN/SNIFF",
            "BIN/extra",
            "bin",
        ]
        for name in invalid:
            with self.subTest(name=name):
                self.archive.write_bytes(original)
                with zipfile.ZipFile(self.archive) as archive:
                    entries = [
                        (item, archive.read(item.filename))
                        for item in archive.infolist()
                    ]
                data = b"unsafe path fixture"
                manifest = json.loads(
                    next(
                        payload
                        for item, payload in entries
                        if item.filename == "manifest.json"
                    )
                )
                manifest["files"][name] = {
                    "sha256": digest(data),
                    "size_bytes": len(data),
                }
                manifest_bytes = encode(manifest)
                with zipfile.ZipFile(self.archive, "w") as archive:
                    for item, payload in entries:
                        archive.writestr(
                            item,
                            manifest_bytes
                            if item.filename == "manifest.json"
                            else payload,
                        )
                    item = zipfile.ZipInfo(name)
                    item.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(item, data)
                (self.archive.parent / "manifest.json").write_bytes(manifest_bytes)
                (self.archive.parent / "SHA256SUMS").write_text(
                    f"{digest(self.archive.read_bytes())}  {self.archive.name}\n"
                )
                with (
                    patch(
                        "bundle.Path.mkdir",
                        side_effect=AssertionError("extraction must not begin"),
                    ),
                    self.assertRaisesRegex(ValueError, "Unsafe"),
                ):
                    verify(self.archive, TARGET, COMMIT, self.root / "extracted")
                self.assertFalse((self.root / "extracted").exists())

    def test_non_device_portable_names_remain_valid(self):
        validate_portable_paths(
            [
                "bin/sniff",
                "LICENSES/MIT.txt",
                "doc/COM10.txt",
                "doc/LPT0.txt",
                "doc/auxiliary.txt",
            ]
        )

    def test_archive_and_extraction_size_limits_fail_before_writes(self):
        for constant, limit in [
            ("MAX_ARCHIVE_BYTES", 1),
            ("MAX_ENTRIES", 1),
            ("MAX_FILE_BYTES", 1),
        ]:
            with self.subTest(constant=constant), patch("bundle." + constant, limit):
                with self.assertRaisesRegex(ValueError, "limit"):
                    verify(self.archive, TARGET, COMMIT, self.root / "extracted")
                self.assertFalse((self.root / "extracted").exists())

    def test_privileged_archive_permissions_rejected(self):
        with zipfile.ZipFile(self.archive) as archive:
            entries = [
                (item, archive.read(item.filename)) for item in archive.infolist()
            ]
        with zipfile.ZipFile(self.archive, "w") as archive:
            for item, data in entries:
                if item.filename == "bin/sniff":
                    item.external_attr = (stat.S_IFREG | 0o4755) << 16
                archive.writestr(item, data)
        (self.archive.parent / "SHA256SUMS").write_text(
            f"{digest(self.archive.read_bytes())}  {self.archive.name}\n"
        )
        with self.assertRaisesRegex(ValueError, "permissions"):
            verify(self.archive, TARGET, COMMIT, self.root / "extracted")
        self.assertFalse((self.root / "extracted").exists())

    def test_dependency_inventory_preserves_checksum_and_kinds(self):
        sbom = source_sbom(METADATA, LOCK, COMMIT, TARGET, 0, "bin/sniff", "f" * 64)
        dependency = next(
            package for package in sbom["packages"] if package["name"] == "dep"
        )
        self.assertEqual(dependency["checksums"][0]["checksumValue"], "b" * 64)
        self.assertEqual(
            {edge["relationshipType"] for edge in sbom["relationships"]},
            {
                "DESCRIBES",
                "CONTAINS",
                "DEPENDS_ON",
                "DEV_DEPENDENCY_OF",
                "BUILD_DEPENDENCY_OF",
            },
        )
        with self.assertRaisesRegex(ValueError, "checksum"):
            source_sbom(
                METADATA,
                LOCK.replace(b"checksum", b"unrecognized"),
                COMMIT,
                TARGET,
                0,
                "bin/sniff",
                "f" * 64,
            )

    def test_sbom_namespace_binds_document_content(self):
        first = source_sbom(METADATA, LOCK, COMMIT, TARGET, 0, "bin/sniff", "f" * 64)
        rebuilt = source_sbom(METADATA, LOCK, COMMIT, TARGET, 0, "bin/sniff", "e" * 64)
        self.assertNotEqual(first["documentNamespace"], rebuilt["documentNamespace"])
        repeated = source_sbom(METADATA, LOCK, COMMIT, TARGET, 0, "bin/sniff", "f" * 64)
        self.assertEqual(first, repeated)


if __name__ == "__main__":
    unittest.main()
