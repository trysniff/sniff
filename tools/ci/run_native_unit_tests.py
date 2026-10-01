"""Run every enabled native integration target except the separate dogfood suite."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


# This target is required by the separate all-feature command-recovery job.
FEATURE_JOB_TARGETS = {"historical_v2_command_recovery": ["sniffbench-frame"]}
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def integration_targets(metadata):
    packages = [p for p in metadata["packages"] if p["name"] == "sniff-cli"]
    if len(packages) != 1:
        raise ValueError(
            "native target discovery requires exactly one sniff-cli package"
        )
    package = packages[0]
    if package["features"].get("default", []):
        raise ValueError(
            "default features changed; qualify the native target scope explicitly"
        )
    seen = set()
    selected = []
    for target in package["targets"]:
        if any(kind in {"example", "bench"} for kind in target["kind"]):
            raise ValueError(
                "auxiliary Cargo targets need an explicit native test suite"
            )
        if "test" not in target["kind"]:
            continue
        name = target["name"]
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_-]*", name
        ):
            raise ValueError("invalid native integration target name")
        if name in seen:
            raise ValueError(f"duplicate native integration target: {name}")
        seen.add(name)
        features = target.get("required-features", [])
        if not isinstance(features, list) or any(
            not isinstance(f, str) for f in features
        ):
            raise ValueError(f"invalid required features for native target: {name}")
        if features:
            if FEATURE_JOB_TARGETS.get(name) != features:
                raise ValueError(f"native target has no qualified feature job: {name}")
            continue
        if name != "dogfood_suite":
            selected.append(name)
    if "dogfood_suite" not in seen or not selected:
        raise ValueError("native integration scope is missing dogfood or enabled tests")
    return sorted(selected)


def run_tests(targets, suite="all"):
    unit_scopes = {
        "all": ["--lib", "--bins"],
        "library": ["--lib"],
        "binaries": ["--bins"],
        "integrations": [],
    }
    flags = unit_scopes[suite]
    if flags:
        subprocess.run(
            ["cargo", "test", *flags, "--locked"],
            check=True,
            cwd=REPOSITORY_ROOT,
        )
    if suite in {"all", "integrations"}:
        arguments = ["cargo", "test", "--locked"]
        for name in targets:
            arguments.extend(["--test", name])
        subprocess.run(
            [*arguments, "--", "--test-threads=1"], check=True, cwd=REPOSITORY_ROOT
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument(
        "--suite",
        choices=["all", "library", "binaries", "integrations"],
        default="all",
    )
    args = parser.parse_args(argv)
    try:
        output = subprocess.run(
            [
                "cargo",
                "metadata",
                "--no-deps",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
                str(REPOSITORY_ROOT / "Cargo.toml"),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPOSITORY_ROOT,
        )
        targets = integration_targets(json.loads(output.stdout))
        for name in targets:
            print(name, flush=True)
        if not args.list_only:
            run_tests(targets, args.suite)
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        return error.returncode if error.returncode > 0 else 1
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"native target discovery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
