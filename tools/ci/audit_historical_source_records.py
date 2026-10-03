"""Inventory a pinned historical-v1 archive offline; never issue admission proof."""

import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import zipfile


CONTRACT = "sniffbench-historical-v1-source-record-inventory-v1-not-admission"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 12000
KINDS = {
    "repository_refs", "commit_metadata", "source_census", "source_delta",
    "license", "test_recipe", "parent_test", "commit_test",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(data):
    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(
        data.decode("utf-8"), object_pairs_hook=object_pairs,
        parse_constant=invalid_constant,
    )


def canonical_path(name):
    require(isinstance(name, str), "artifact path must be a string")
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    require(
        bool(name) and not path.is_absolute() and not PureWindowsPath(name).drive
        and all(part not in {"", ".", ".."} for part in name.split("/"))
        and ":" not in name and "\x00" not in name,
        f"unsafe artifact path: {name!r}",
    )
    return name


def read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f"input exceeds byte bound: {path}")
    return data


def archive_members(data):
    require(len(data) <= MAX_ARCHIVE_BYTES, "archive exceeds byte bound")
    result = {}
    expanded = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        require(len(members) <= MAX_MEMBERS, "archive exceeds member bound")
        for member in members:
            require(not member.is_dir(), "directory entries are outside this contract")
            require("\x00" not in member.orig_filename, "raw ZIP name contains NUL")
            require(member.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                    "unsupported archive compression method")
            name = canonical_path(member.filename)
            require(name not in result, f"duplicate archive member: {name}")
            mode = member.external_attr >> 16
            require(not stat.S_ISLNK(mode), f"archive symlink: {name}")
            require(not member.flag_bits & 1, "encrypted archive member")
            require(0 <= member.file_size <= MAX_MEMBER_BYTES, "member exceeds byte bound")
            expanded += member.file_size
            require(expanded <= MAX_EXPANDED_BYTES, "archive exceeds expanded byte bound")
            with archive.open(member) as stream:
                contents = stream.read(MAX_MEMBER_BYTES + 1)
            require(len(contents) == member.file_size, f"member size mismatch: {name}")
            result[name] = contents
    return result


def checked_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "invalid SHA-256 commitment")
    return value


def rank_records(members, candidate, task_sha256):
    rank = candidate["rank"]
    tag = f"rank-{rank:04d}"
    prefix = f"artifacts/{tag}/"
    checkpoint_path = f"checkpoints/{tag}.json"
    transaction_path = prefix + "_transaction.json"
    checkpoint = decode(members[checkpoint_path])
    transaction = decode(members[transaction_path])
    require(type(checkpoint["schema_version"]) is int and type(transaction["schema_version"]) is int
            and checkpoint["schema_version"] == transaction["schema_version"] == 1,
            f"unsupported record schema at {tag}")
    require(checkpoint["task_sha256"] == transaction["task_sha256"] == task_sha256,
            f"task binding mismatch at {tag}")
    assessment = checkpoint["assessment"]
    require(encode(assessment) == encode(transaction["assessment"])
            and type(transaction["rank"]) is int and transaction["rank"] == rank,
            f"transaction assessment mismatch at {tag}")
    require(all(encode(assessment[key]) == encode(candidate[key])
                for key in ("rank", "repository", "rank_sha256")),
            f"worksheet binding mismatch at {tag}")
    files = {}
    for entry in transaction["files"]:
        path = canonical_path(entry["artifact_path"])
        require(path.startswith(prefix) and path != transaction_path and path not in files,
                f"transaction path mismatch at {tag}")
        sha256 = checked_hash(entry["sha256"])
        require(digest(members[path]) == sha256, f"artifact digest mismatch: {path}")
        files[path] = sha256
    require(set(files) | {transaction_path} == {p for p in members if p.startswith(prefix)},
            f"uncommitted or missing artifact at {tag}")
    evidence = {}
    for entry in assessment["evidence"]:
        kind = entry["kind"]
        require(kind in KINDS and kind not in evidence, f"unknown or duplicate evidence at {tag}")
        path = canonical_path(entry["artifact_path"])
        require(files.get(path) == checked_hash(entry["sha256"]),
                f"evidence binding mismatch at {tag}")
        evidence[kind] = {**entry, "artifact_path": path}
    refs = decode(members[evidence["repository_refs"]["artifact_path"]])
    facts = assessment["facts"]
    require(refs["repository"] == facts["repository"] == candidate["repository"],
            f"repository binding mismatch at {tag}")
    source_files = sorted(p for p in files if p.startswith(prefix + "sources/"))
    state = refs["state"]
    if state == "inaccessible":
        require(facts["accessible"] is False and facts["repository_empty"] is False
                and refs["discovery"] is None and refs["inaccessible_probe"] is not None
                and facts["selected_commit"] is None and assessment["selected_provenance"] is None
                and assessment["disposition"] == "excluded"
                and assessment["exclusion_reason"] == "inaccessible"
                and set(evidence) == {"repository_refs"} and len(files) == 1,
                f"contradictory inaccessible record at {tag}")
        probe = refs["inaccessible_probe"]
        require(probe["url"] == evidence["repository_refs"]["source"]
                == f"https://{candidate['repository']}.git/info/refs?service=git-upload-pack"
                and type(probe["status"]) is int and probe["status"] in {401, 403, 404, 410},
                f"invalid inaccessible probe at {tag}")
        stage = "failed_clone_probe_only"
    elif state == "empty":
        require(facts["accessible"] is True and facts["repository_empty"] is True
                and refs["discovery"] is None and refs["inaccessible_probe"] is None
                and set(evidence) == {"repository_refs"} and len(files) == 1
                and assessment["disposition"] == "excluded"
                and facts["selected_commit"] is None and assessment["selected_provenance"] is None,
                f"contradictory empty record at {tag}")
        stage = "empty_repository_recorded"
    elif state == "complete":
        require(facts["accessible"] is True and facts["repository_empty"] is False
                and refs["discovery"] is not None and refs["inaccessible_probe"] is None
                and "commit_metadata" in evidence,
                f"contradictory complete record at {tag}")
        require(refs["discovery"]["repository"] == candidate["repository"],
                f"discovery repository mismatch at {tag}")
        metadata = decode(members[evidence["commit_metadata"]["artifact_path"]])
        require(encode(metadata) == encode(refs["discovery"]),
                f"commit metadata differs from discovery at {tag}")
        require(encode(facts["selected_commit"]) == encode(refs["discovery"]["selected_commit"]),
                f"selected commit differs from discovery at {tag}")
        selected = facts["selected_commit"]
        if selected is not None:
            require(all(isinstance(selected[key], str) and re.fullmatch(r"[0-9a-f]{40}", selected[key])
                        for key in ("parent_sha", "commit_sha"))
                    and selected["parent_sha"] != selected["commit_sha"],
                    f"invalid selected revisions at {tag}")
        require(("source_census" in evidence) == ("source_delta" in evidence),
                f"incomplete source inspection record at {tag}")
        require(not source_files or "source_census" in evidence,
                f"source snapshots without inspection record at {tag}")
        if "source_census" in evidence:
            census = decode(members[evidence["source_census"]["artifact_path"]])
            delta = decode(members[evidence["source_delta"]["artifact_path"]])
            require(selected is not None and encode(census) == encode(delta["census"])
                    and census["parent_revision"] == delta["parent_revision"] == selected["parent_sha"]
                    and census["commit_revision"] == delta["commit_revision"] == selected["commit_sha"],
                    f"source inspection revision binding mismatch at {tag}")
        stage = ("source_bytes_retained" if source_files else
                 "source_inspection_recorded" if "source_census" in evidence else
                 "complete_clone_recorded")
    else:
        raise ValueError(f"unknown repository state at {tag}: {state}")
    return {
        "rank": rank, "repository": candidate["repository"], "recorded_stage": stage,
        "probe_http_status": (refs["inaccessible_probe"] or {}).get("status"),
        "disposition": assessment["disposition"],
        "source_access_absence_proven": False,
        "retained_source_files": [{"path": p, "sha256": files[p]} for p in source_files],
        "checkpoint_sha256": digest(members[checkpoint_path]),
        "transaction_sha256": digest(members[transaction_path]),
        "artifact_count": len(files),
        "artifact_manifest_sha256": digest(encode(files)),
    }


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def inventory(archive_bytes, archive_sha256, worksheet_bytes, worksheet_sha256,
              task_sha256, expected_count=600):
    require(digest(archive_bytes) == checked_hash(archive_sha256), "archive digest mismatch")
    require(digest(worksheet_bytes) == checked_hash(worksheet_sha256), "worksheet digest mismatch")
    checked_hash(task_sha256)
    worksheet = decode(worksheet_bytes)
    require(type(worksheet["schema_version"]) is int and worksheet["schema_version"] == 1
            and worksheet["rank_contract"] == "sniffbench-non-blind-history-v1",
            "unsupported worksheet")
    candidates = worksheet["candidates"]
    require(type(expected_count) is int and len(candidates) == expected_count and expected_count > 0,
            "candidate inventory differs from expected scope")
    repositories = set()
    for rank, candidate in enumerate(candidates, 1):
        require(type(candidate["rank"]) is int and candidate["rank"] == rank,
                "non-contiguous candidate ranks")
        name = candidate["repository"]
        require(isinstance(name, str) and re.fullmatch(r"github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name)
                and name.casefold() not in repositories, "invalid or repeated candidate repository")
        repositories.add(name.casefold())
        checked_hash(candidate["rank_sha256"])
    members = archive_members(archive_bytes)
    require({p for p in members if p.startswith("checkpoints/")}
            == {f"checkpoints/rank-{r:04d}.json" for r in range(1, expected_count + 1)},
            "checkpoint inventory differs from worksheet")
    rows = [rank_records(members, candidate, task_sha256) for candidate in candidates]
    allowed_prefixes = tuple(f"artifacts/rank-{r:04d}/" for r in range(1, expected_count + 1))
    require(all(p.startswith("checkpoints/") or p.startswith(allowed_prefixes) for p in members),
            "archive contains records outside committed ranks")
    return {
        "contract": CONTRACT, "archive_sha256": archive_sha256,
        "worksheet_sha256": worksheet_sha256, "assessment_task_sha256": task_sha256,
        "expected_candidate_count": expected_count, "archive_member_count": len(members),
        "benchmark_admission_performed": False, "temporal_identity_proof_issued": False,
        "source_access_absence_proven": False,
        "summary": {"recorded_stage_counts": dict(sorted(Counter(r["recorded_stage"] for r in rows).items())),
                    "retained_source_file_count": sum(len(r["retained_source_files"]) for r in rows)},
        "records": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("worksheet", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--worksheet-sha256", required=True)
    parser.add_argument("--task-sha256", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    result = inventory(
        read_bounded(args.archive, MAX_ARCHIVE_BYTES), args.archive_sha256,
        read_bounded(args.worksheet, MAX_MEMBER_BYTES), args.worksheet_sha256,
        args.task_sha256,
    )
    output = encode(result)
    if args.verify_only:
        require(read_bounded(args.output, MAX_MEMBER_BYTES) == output, "saved inventory does not replay")
    else:
        with args.output.open("xb") as stream:
            stream.write(output)
    print(json.dumps(result["summary"], sort_keys=True))
    print(f"Diagnostic SHA-256: {digest(output)}")


if __name__ == "__main__":
    main()
