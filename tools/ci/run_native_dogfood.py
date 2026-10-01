"""Run one exhaustive dogfood module after validating the actual native test list."""

import argparse
import json
import re
import subprocess
import sys

from run_native_unit_tests import REPOSITORY_ROOT


GROUPS = (
    "brandset",
    "bumpkin_github",
    "bumpkin_release",
    "contracts",
    "core",
    "surfaces",
)


def validate_inventory(output):
    groups = {group: [] for group in GROUPS}
    summary = None
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*): test", line
        )
        if match:
            group, _ = match.groups()
            name = line.removesuffix(": test")
            if group not in groups or name in groups[group]:
                raise ValueError(f"unassigned or duplicate native dogfood test: {name}")
            groups[group].append(name)
            continue
        match = re.fullmatch(r"([0-9]+) tests?, ([0-9]+) benchmarks?", line)
        if not match or summary is not None:
            raise ValueError(f"unrecognized native dogfood inventory line: {line}")
        summary = tuple(map(int, match.groups()))
    if any(not tests for tests in groups.values()):
        raise ValueError("native dogfood inventory is missing a required group")
    if summary != (sum(map(len, groups.values())), 0):
        raise ValueError("native dogfood inventory count does not match its test list")
    return groups


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=GROUPS, nargs="?")
    parser.add_argument("--groups", action="store_true")
    args = parser.parse_args(argv)
    if args.groups:
        if args.group is not None:
            parser.error("--groups cannot execute a dogfood group")
        print(json.dumps(GROUPS))
        return 0
    if args.group is None:
        parser.error("a dogfood group is required unless --groups is requested")
    try:
        # --list compiles the current native target but executes no test body.
        output = subprocess.run(
            ["cargo", "test", "--locked", "--test", "dogfood_suite", "--", "--list"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
            cwd=REPOSITORY_ROOT,
        )
        groups = validate_inventory(output.stdout)
        print(
            f"Required {args.group} dogfood tests: {len(groups[args.group])}",
            flush=True,
        )
        subprocess.run(
            [
                "cargo",
                "test",
                "--locked",
                "--test",
                "dogfood_suite",
                f"{args.group}::",
                "--",
                "--test-threads=1",
                "--nocapture",
            ],
            check=True,
            cwd=REPOSITORY_ROOT,
        )
    except subprocess.CalledProcessError as error:
        return error.returncode if error.returncode > 0 else 1
    except (OSError, ValueError) as error:
        print(f"native dogfood scope failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
