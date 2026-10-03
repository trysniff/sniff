"""Offline mutation tests for record inventory, not temporal admission."""

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import audit_historical_source_records as audit


TASK = "a" * 64


def fixture(state="inaccessible", source=False):
    repository = "github.com/owner/repository"
    candidate = {"rank": 1, "repository": repository, "rank_sha256": "b" * 64}
    prefix = "artifacts/rank-0001/"
    refs = {"repository": repository, "state": state, "discovery": None,
            "inaccessible_probe": None}
    facts = {"repository": repository, "accessible": state != "inaccessible",
             "repository_empty": state == "empty", "selected_commit": None}
    if state == "inaccessible":
        refs["inaccessible_probe"] = {
            "url": f"https://{repository}.git/info/refs?service=git-upload-pack", "status": 401,
        }
    elif state == "complete":
        selected = {"parent_sha": "c" * 40, "commit_sha": "d" * 40} if source else None
        facts["selected_commit"] = selected
        refs["discovery"] = {"repository": repository, "selected_commit": selected}
    members = {prefix + "repository-refs.json": audit.encode(refs)}
    evidence = [{"kind": "repository_refs", "source": (refs["inaccessible_probe"] or {}).get("url"),
                 "artifact_path": prefix + "repository-refs.json",
                 "sha256": audit.digest(members[prefix + "repository-refs.json"])}]
    if state == "complete":
        kinds = ["commit_metadata", "source_census", "source_delta"] if source else ["commit_metadata"]
        for kind in kinds:
            path = prefix + kind.replace("_", "-") + ".json"
            census = {"parent_revision": "c" * 40, "commit_revision": "d" * 40}
            content = (refs["discovery"] if kind == "commit_metadata" else census
                       if kind == "source_census" else {**census, "census": census})
            members[path] = audit.encode(content)
            evidence.append({"kind": kind, "artifact_path": path, "sha256": audit.digest(members[path])})
    if source:
        members[prefix + "sources/before/main.py"] = b"def before(): pass\n"
    assessment = {**candidate, "facts": facts, "evidence": evidence,
                  "disposition": "excluded", "exclusion_reason": state,
                  "selected_provenance": None}
    checkpoint = {"schema_version": 1, "task_sha256": TASK, "assessment": assessment}
    transaction = {**checkpoint, "rank": 1, "files": [
        {"artifact_path": p, "sha256": audit.digest(data)} for p, data in members.items()
    ]}
    members["checkpoints/rank-0001.json"] = audit.encode(checkpoint)
    members[prefix + "_transaction.json"] = audit.encode(transaction)
    worksheet = audit.encode({"schema_version": 1, "rank_contract": "sniffbench-non-blind-history-v1",
                              "candidates": [candidate]})
    return members, worksheet


def archive_bytes(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in members.items():
            archive.writestr(path, data)
    return stream.getvalue()


def run(members, worksheet, count=1):
    archive = archive_bytes(members)
    return audit.inventory(archive, audit.digest(archive), worksheet, audit.digest(worksheet), TASK, count)


def mutate_records(members, change):
    for path in ["checkpoints/rank-0001.json", "artifacts/rank-0001/_transaction.json"]:
        record = audit.decode(members[path])
        change(record)
        members[path] = audit.encode(record)


class InventoryTests(unittest.TestCase):
    def test_failed_clone_never_proves_no_source_access(self):
        result = run(*fixture())
        self.assertEqual(result["summary"]["recorded_stage_counts"], {"failed_clone_probe_only": 1})
        self.assertFalse(result["source_access_absence_proven"])
        self.assertFalse(result["records"][0]["source_access_absence_proven"])
        self.assertFalse(result["benchmark_admission_performed"])
        self.assertFalse(result["temporal_identity_proof_issued"])
        self.assertTrue(result["contract"].endswith("not-admission"))

    def test_complete_and_empty_are_not_no_access_proofs(self):
        for state, stage in [("complete", "complete_clone_recorded"), ("empty", "empty_repository_recorded")]:
            with self.subTest(state=state):
                result = run(*fixture(state))
                self.assertEqual(result["records"][0]["recorded_stage"], stage)
                self.assertFalse(result["source_access_absence_proven"])

    def test_source_inspection_and_retained_bytes_are_separate_stages(self):
        members, worksheet = fixture("complete", source=True)
        result = run(members, worksheet)
        self.assertEqual(result["records"][0]["recorded_stage"], "source_bytes_retained")
        self.assertEqual(result["summary"]["retained_source_file_count"], 1)
        path = "artifacts/rank-0001/sources/before/main.py"
        del members[path]
        def remove_source(record):
            if "files" in record:
                record["files"] = [e for e in record["files"] if e["artifact_path"] != path]
        mutate_records(members, remove_source)
        self.assertEqual(run(members, worksheet)["records"][0]["recorded_stage"], "source_inspection_recorded")

    def test_archive_and_worksheet_commitments_are_required(self):
        members, worksheet = fixture()
        data = archive_bytes(members)
        for archive_hash, worksheet_hash in [("0" * 64, audit.digest(worksheet)), (audit.digest(data), "0" * 64)]:
            with self.subTest(archive_hash=archive_hash, worksheet_hash=worksheet_hash), self.assertRaises(ValueError):
                audit.inventory(data, archive_hash, worksheet, worksheet_hash, TASK, 1)

    def test_rehashed_artifact_drift_still_fails_transaction_binding(self):
        members, worksheet = fixture()
        members["artifacts/rank-0001/repository-refs.json"] += b" "
        with self.assertRaisesRegex(ValueError, "artifact digest mismatch"):
            run(members, worksheet)

    def test_uncommitted_and_missing_members_fail(self):
        original, worksheet = fixture()
        for mutation in ["extra", "missing", "outside"]:
            members = deepcopy(original)
            if mutation == "extra":
                members["artifacts/rank-0001/unrecorded.py"] = b"pass"
            elif mutation == "missing":
                del members["artifacts/rank-0001/repository-refs.json"]
            else:
                members["unrecorded.py"] = b"pass"
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                run(members, worksheet)

    def test_forged_task_candidate_or_transaction_fails(self):
        original, worksheet = fixture()
        for key, value in [("task_sha256", "0" * 64), ("repository", "github.com/other/repo"), ("rank_sha256", "0" * 64)]:
            members = deepcopy(original)
            def change(record):
                if key == "task_sha256":
                    record[key] = value
                else:
                    record["assessment"][key] = value
            mutate_records(members, change)
            with self.subTest(key=key), self.assertRaises(ValueError):
                run(members, worksheet)
        members = deepcopy(original)
        transaction = audit.decode(members["artifacts/rank-0001/_transaction.json"])
        transaction["assessment"]["disposition"] = "selected"
        members["artifacts/rank-0001/_transaction.json"] = audit.encode(transaction)
        with self.assertRaisesRegex(ValueError, "transaction assessment mismatch"):
            run(members, worksheet)

    def test_inaccessible_with_retained_source_is_not_silently_classified(self):
        members, worksheet = fixture("inaccessible", source=True)
        with self.assertRaisesRegex(ValueError, "contradictory inaccessible"):
            run(members, worksheet)

    def test_duplicate_and_unknown_evidence_fail(self):
        for kind in ["repository_refs", "new_unknown_stage"]:
            members, worksheet = fixture()
            def change(record):
                entry = deepcopy(record["assessment"]["evidence"][0])
                entry["kind"] = kind
                record["assessment"]["evidence"].append(entry)
            mutate_records(members, change)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unknown or duplicate"):
                run(members, worksheet)

    def test_missing_checkpoint_and_noncontiguous_scope_fail(self):
        members, worksheet = fixture()
        with self.assertRaisesRegex(ValueError, "candidate inventory"):
            run(members, worksheet, 2)
        data = audit.decode(worksheet)
        data["candidates"][0]["rank"] = 2
        with self.assertRaisesRegex(ValueError, "non-contiguous"):
            run(members, audit.encode(data))
        del members["checkpoints/rank-0001.json"]
        with self.assertRaisesRegex(ValueError, "checkpoint inventory"):
            run(members, worksheet)

    def test_duplicate_json_keys_and_nonfinite_values_fail(self):
        for data in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                audit.decode(data)

    def test_boolean_rank_and_schema_do_not_match_integer_commitments(self):
        for mutation in ["rank", "schema"]:
            members, worksheet = fixture()
            def change(record):
                if mutation == "rank":
                    record["assessment"]["rank"] = True
                    if "rank" in record:
                        record["rank"] = True
                else:
                    record["schema_version"] = True
            mutate_records(members, change)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                run(members, worksheet)

    def test_rehashed_mismatched_discovery_and_source_revision_fail(self):
        for path in ["commit-metadata.json", "source-census.json"]:
            members, worksheet = fixture("complete", source=True)
            artifact = "artifacts/rank-0001/" + path
            data = audit.decode(members[artifact])
            if path == "commit-metadata.json":
                data["repository"] = "github.com/other/repository"
            else:
                data["parent_revision"] = "e" * 40
            members[artifact] = audit.encode(data)
            sha256 = audit.digest(members[artifact])
            def change(record):
                for entry in record["assessment"]["evidence"]:
                    if entry["artifact_path"] == artifact:
                        entry["sha256"] = sha256
                for entry in record.get("files", []):
                    if entry["artifact_path"] == artifact:
                        entry["sha256"] = sha256
            mutate_records(members, change)
            with self.subTest(path=path), self.assertRaises(ValueError):
                run(members, worksheet)

    def test_unsafe_duplicate_and_symlink_archive_members_fail(self):
        for path in ["../escape", "C:\\escape", "/absolute", "a//b", "a/./b", "a:b", "a\\..\\b"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.archive_members(archive_bytes({path: b"x"}))
        for symlink in [False, True]:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                if symlink:
                    info = zipfile.ZipInfo("link")
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, b"target")
                else:
                    archive.writestr("a/b", b"x")
                    archive.writestr("a\\b", b"x")
            with self.subTest(symlink=symlink), self.assertRaises(ValueError):
                audit.archive_members(stream.getvalue())

    def test_archive_resource_bounds_fail(self):
        data = archive_bytes({"first": b"data", "second": b"data"})
        for bound, value in [("MAX_ARCHIVE_BYTES", 1), ("MAX_MEMBERS", 1), ("MAX_MEMBER_BYTES", 1), ("MAX_EXPANDED_BYTES", 5)]:
            with self.subTest(bound=bound), patch.object(audit, bound, value), self.assertRaises(ValueError):
                audit.archive_members(data)

    def test_unsupported_decoders_are_rejected_before_opening_members(self):
        for compression in [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression) as archive:
                archive.writestr("member", b"data")
            with self.subTest(compression=compression), patch.object(zipfile.ZipFile, "open") as open_member:
                with self.assertRaisesRegex(ValueError, "unsupported archive compression"):
                    audit.archive_members(stream.getvalue())
                open_member.assert_not_called()

    def test_raw_nul_zip_names_fail_before_truncated_name_can_be_used(self):
        data = archive_bytes({"aXb": b"data"}).replace(b"aXb", b"a\x00b")
        with self.assertRaisesRegex(ValueError, "raw ZIP name contains NUL"):
            audit.archive_members(data)

    def test_matching_invalid_revisions_are_rejected_even_after_rehashing(self):
        for value in [None, 12, "", "x" * 40, "C" * 40, "d" * 40]:
            members, worksheet = fixture("complete", source=True)
            for path in ["repository-refs.json", "commit-metadata.json", "source-census.json", "source-delta.json"]:
                artifact = "artifacts/rank-0001/" + path
                record = audit.decode(members[artifact])
                if path == "repository-refs.json":
                    record["discovery"]["selected_commit"]["parent_sha"] = value
                elif path == "commit-metadata.json":
                    record["selected_commit"]["parent_sha"] = value
                else:
                    record["parent_revision"] = value
                    if path == "source-delta.json":
                        record["census"]["parent_revision"] = value
                members[artifact] = audit.encode(record)
            def reseal(record):
                record["assessment"]["facts"]["selected_commit"]["parent_sha"] = value
                for entry in record["assessment"]["evidence"] + record.get("files", []):
                    entry["sha256"] = audit.digest(members[entry["artifact_path"]])
            mutate_records(members, reseal)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid selected revisions"):
                run(members, worksheet)

    def test_windows_separators_inside_transactions_and_evidence_are_supported(self):
        members, worksheet = fixture("complete", source=True)
        expected = run(members, worksheet)["records"][0]
        def change(record):
            for entry in record["assessment"]["evidence"] + record.get("files", []):
                entry["artifact_path"] = entry["artifact_path"].replace("/", "\\")
        mutate_records(members, change)
        actual = run(members, worksheet)["records"][0]
        self.assertEqual(actual["recorded_stage"], expected["recorded_stage"])
        self.assertEqual(actual["retained_source_files"], expected["retained_source_files"])

    def test_windows_archive_separators_are_canonicalized(self):
        members, worksheet = fixture()
        windows_members = {path.replace("/", "\\"): data for path, data in members.items()}
        self.assertEqual(run(members, worksheet), run(windows_members, worksheet) | {
            "archive_sha256": audit.digest(archive_bytes(members))
        })

    def test_cli_create_new_and_verify_only(self):
        members, worksheet = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = archive_bytes(members)
            (root / "archive.zip").write_bytes(archive)
            (root / "worksheet.json").write_bytes(worksheet)
            args = ["audit", str(root / "archive.zip"), str(root / "worksheet.json"), str(root / "output.json"),
                    "--archive-sha256", audit.digest(archive), "--worksheet-sha256", audit.digest(worksheet),
                    "--task-sha256", TASK]
            actual_inventory = audit.inventory
            def one_candidate(*values):
                return actual_inventory(*values, expected_count=1)
            with patch.object(audit, "inventory", side_effect=one_candidate), redirect_stdout(io.StringIO()):
                with patch.object(sys, "argv", args):
                    audit.main()
                    with self.assertRaises(FileExistsError):
                        audit.main()
                with patch.object(sys, "argv", args + ["--verify-only"]):
                    audit.main()
                    (root / "output.json").write_bytes(b"{}")
                    with self.assertRaisesRegex(ValueError, "does not replay"):
                        audit.main()


if __name__ == "__main__":
    unittest.main()
