"""Portable guards for the pinned temporal-prior CI replays, not admission."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess


MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
PREFIX = "benchmark::release::"
PROOFS = {
    "prior-union": (
        PREFIX + "history_v3_prior_artifacts::tests::",
        ("verifies_the_real_frozen_prior_repository_union",), True,
    ),
    "prior-v2": (
        PREFIX + "history_v3_prior_artifacts::tests::",
        ("verifies_real_frozen_v2_temporal_proof",), True,
    ),
    "scorecard": (
        PREFIX + "history_v3_scorecard_publication::tests::",
        ("verifies_real_scorecard_publication_witness",), True,
    ),
    "blind": (
        PREFIX + "history_v3_blind_temporal::tests::",
        ("verifies_real_blind_prior_temporal_proof",), True,
    ),
    "small": (
        PREFIX + "history_v3_small_prior_temporal::tests::",
        (
            "proves_policy_bound_research_and_synthetic_repositories",
            "rejects_changed_frozen_policy_and_capture",
            "rejects_changed_frozen_partition_membership_and_gold_hash",
            "rejects_changed_identity_revision_tree_and_cutoff",
        ), False,
    ),
}


def read_capture(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(data) > MAX_CAPTURE_BYTES:
        raise ValueError("temporal capture exceeds byte bound")
    return data


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate temporal capture JSON key: {key}")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite temporal capture number")
    return number


def invalid_constant(value):
    raise ValueError(f"invalid temporal capture constant: {value}")


def decode(data):
    return json.loads(
        data.decode("utf-8"), object_pairs_hook=object_pairs,
        parse_float=finite_float, parse_constant=invalid_constant,
    )


def compare_capture(live_path, pinned_path, data_only=False):
    live = decode(read_capture(live_path))
    pinned = decode(read_capture(pinned_path))
    if not isinstance(live, dict) or "errors" in live:
        raise ValueError("temporal GraphQL capture is not an error-free object")
    if data_only:
        live = live.get("data")
    if not isinstance(live, dict) or not isinstance(pinned, dict):
        raise ValueError("temporal capture projection is not an object")
    # Canonical bytes distinguish bools, integers and floats unlike dict equality.
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if canonical(live) != canonical(pinned):
        raise ValueError("temporal live capture differs from pinned evidence")


def verify_sha256(path, expected):
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("invalid temporal capture SHA-256")
    hasher = hashlib.sha256()
    total = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(min(HASH_CHUNK_BYTES, MAX_ARTIFACT_BYTES - total + 1)):
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("temporal artifact exceeds byte bound")
            hasher.update(chunk)
    if hasher.hexdigest() != expected:
        raise ValueError("temporal capture SHA-256 changed")


def run_proof(proof, cargo="cargo"):
    scope, names, ignored = PROOFS[proof]
    expected = {scope + name for name in names}
    selection = [scope + names[0], "--exact"] if len(names) == 1 else [scope]
    command = [cargo, "test", "--lib", "--locked"]
    if proof == "prior-v2":
        command += ["--features", "sniffbench-frame"]
    command += [selection[0], "--"]
    harness = selection[1:] + (["--ignored"] if ignored else [])
    inventory = subprocess.run(
        command + harness + ["--list"], check=True, capture_output=True, text=True,
    )
    discovered = [line.removesuffix(": test") for line in inventory.stdout.splitlines()
                  if line.endswith(": test")]
    if len(discovered) != len(expected) or set(discovered) != expected:
        raise ValueError(f"temporal {proof} proof inventory changed: {discovered!r}")
    if not ignored:
        ignored_inventory = subprocess.run(
            command + harness + ["--ignored", "--list"],
            check=True, capture_output=True, text=True,
        )
        if any(line.endswith(": test") for line in ignored_inventory.stdout.splitlines()):
            raise ValueError(f"temporal {proof} ordinary proof became ignored")
    subprocess.run(
        command + harness + ["--test-threads=1", "--nocapture"], check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("live")
    compare.add_argument("pinned")
    compare.add_argument("--data-only", action="store_true")
    sha = commands.add_parser("sha256")
    sha.add_argument("path")
    sha.add_argument("expected")
    test = commands.add_parser("test")
    test.add_argument("proof", choices=PROOFS)
    test.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    if args.command == "compare":
        compare_capture(args.live, args.pinned, args.data_only)
    elif args.command == "sha256":
        verify_sha256(args.path, args.expected)
    else:
        run_proof(args.proof, args.cargo)


if __name__ == "__main__":
    main()
