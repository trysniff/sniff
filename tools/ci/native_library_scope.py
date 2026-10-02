"""Partition enabled library cases without dropping expensive native proofs."""

import re
import subprocess


LIBRARY_PROOFS = {
    "go-project-model": (
        "benchmark::release::intentional_boundary_project_model_go::tests::"
        "real_go_list_is_sandboxed_or_fails_as_typed_unavailable"
    ),
    "gradle-project-model": (
        "benchmark::release::intentional_boundary_project_model_gradle::tests::"
        "real_gradle_tooling_model_is_sandboxed_or_typed_unavailable"
    ),
    "gradle-generator": (
        "benchmark::release::intentional_boundary_generator::gradle::tests::"
        "real_gradle_generator_reproduces_the_compiler_owned_output_twice_offline"
    ),
}

CASE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")
SUMMARY = re.compile(r"(\d+) tests?, (\d+) benchmarks?")


def parse_inventory(output):
    cases = set()
    summary = None
    for line in output.splitlines():
        if line.endswith(": test"):
            case = line[:-6]
            if not CASE.fullmatch(case) or case in cases:
                raise ValueError("invalid or duplicated library test identity")
            cases.add(case)
        elif match := SUMMARY.fullmatch(line):
            if summary is not None:
                raise ValueError("repeated library inventory summary")
            summary = (int(match[1]), int(match[2]))
        elif line.strip():
            raise ValueError("unexpected library inventory output")
    if summary != (len(cases), 0):
        raise ValueError("incomplete library inventory or unassigned benchmarks")
    return cases


def validate_partition(cases, ignored):
    isolated = set(LIBRARY_PROOFS.values())
    if len(isolated) != len(LIBRARY_PROOFS) or not ignored <= cases:
        raise ValueError("library proof assignments overlap or ignored scope changed")
    if not isolated <= cases or isolated & ignored:
        raise ValueError("a required isolated library proof is missing or ignored")
    for case in isolated:
        if any(case in other and case != other for other in cases):
            raise ValueError("a library skip filter would also exclude another case")
    return cases - ignored - isolated


def partition_inventory(root):
    inventories = []
    for extra in [[], ["--ignored"]]:
        output = subprocess.run(
            ["cargo", "test", "--lib", "--locked", "--", "--list", *extra],
            check=True,
            capture_output=True,
            text=True,
            cwd=root,
        )
        inventories.append(parse_inventory(output.stdout))
    cases, ignored = inventories
    core = validate_partition(cases, ignored)
    print(
        f"Enabled library inventory: {len(core)} core cases; "
        f"{len(LIBRARY_PROOFS)} separately required native proofs; "
        f"{len(ignored)} intentionally ignored cases",
        flush=True,
    )
    return core


def library_arguments():
    arguments = ["--nocapture"]
    for case in sorted(LIBRARY_PROOFS.values()):
        arguments.extend(["--skip", case])
    return arguments


def run_proof(root, proof):
    case = LIBRARY_PROOFS[proof]
    partition_inventory(root)
    print(f"Required isolated library proof: {case}", flush=True)
    subprocess.run(
        [
            "cargo", "test", "--lib", "--locked", case, "--", "--exact",
            "--test-threads=1", "--nocapture",
        ],
        check=True,
        cwd=root,
    )
