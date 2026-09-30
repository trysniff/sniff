"""Exercise an extracted executable using offline commands only."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def smoke(executable, manifest_path):
    manifest = json.loads(manifest_path.read_bytes())
    executable = executable.resolve(strict=True)
    provider_prefixes = ("SNIFF_", "DEEPSEEK_", "OPENAI_", "ANTHROPIC_")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(provider_prefixes)
    }
    with tempfile.TemporaryDirectory(prefix="sniff-candidate-smoke-") as directory:
        root = Path(directory)
        (root / "sample.rs").write_text(
            'fn main() { println!("hello"); }\n',
            encoding="utf-8",
        )
        checks = [
            (["--version"], f"sniff {manifest['version']}"),
            (["--help"], "Find unnecessary or misleading implementation machinery"),
            (["--skip-dotenv", "--estimate", str(root)], "no LLM requests were made"),
            (["status", str(root)], "No Sniff journal found"),
        ]
        for arguments, expected in checks:
            result = subprocess.run(
                [str(executable), *arguments],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=90,
            )
            if result.returncode != 0 or expected not in result.stdout + result.stderr:
                raise RuntimeError(
                    f"Candidate smoke failed for {arguments}: {result.returncode}\n"
                    f"{result.stdout}\n{result.stderr}"
                )
        print(f"Extracted candidate passed offline smoke checks: {manifest['target']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    smoke(args.executable, args.manifest)
