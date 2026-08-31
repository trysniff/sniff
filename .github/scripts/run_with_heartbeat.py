#!/usr/bin/env python3
"""Run one command while emitting bounded progress heartbeats."""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
TERMINATION_GRACE_SECONDS = 10


def _arguments(argv: Sequence[str]) -> tuple[int, str, list[str]]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval-seconds", required=True, type=int)
    parser.add_argument("--label", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not 1 <= args.interval_seconds <= 3600:
        parser.error("--interval-seconds must be between 1 and 3600")
    if LABEL.fullmatch(args.label) is None:
        parser.error("--label must be a safe 1-64 character identifier")
    if not command:
        parser.error("a command is required after --")
    return args.interval_seconds, args.label, command


def _shell_exit_status(return_code: int) -> int:
    return return_code if return_code >= 0 else min(255, 128 - return_code)


def _signal_process(process: subprocess.Popen[bytes], signum: int) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signum)
        else:
            process.send_signal(signum)
    except ProcessLookupError:
        pass


def run(interval_seconds: int, label: str, command: Sequence[str]) -> int:
    try:
        process = subprocess.Popen(command, start_new_session=os.name == "posix")
    except OSError as error:
        print(f"heartbeat runner could not start {label}: {error}", file=sys.stderr)
        return 127

    started = time.monotonic()
    previous_handlers: dict[signal.Signals, signal.Handlers] = {}
    termination_deadline: float | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal termination_deadline
        if process.poll() is None:
            if termination_deadline is None:
                termination_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
            _signal_process(process, signum)

    for candidate in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[candidate] = signal.getsignal(candidate)
        signal.signal(candidate, forward)

    try:
        while True:
            wait_seconds = interval_seconds
            if termination_deadline is not None:
                wait_seconds = max(
                    0.05,
                    min(wait_seconds, termination_deadline - time.monotonic()),
                )
            try:
                return _shell_exit_status(process.wait(timeout=wait_seconds))
            except subprocess.TimeoutExpired:
                if (
                    termination_deadline is not None
                    and time.monotonic() >= termination_deadline
                ):
                    _signal_process(process, KILL_SIGNAL)
                    return _shell_exit_status(process.wait())
                if termination_deadline is not None:
                    continue
                elapsed = int(time.monotonic() - started)
                print(
                    f"heartbeat label={label} elapsed_seconds={elapsed}",
                    file=sys.stderr,
                    flush=True,
                )
    finally:
        for candidate, handler in previous_handlers.items():
            signal.signal(candidate, handler)
        if process.poll() is None:
            _signal_process(process, KILL_SIGNAL)
            process.wait()


def main(argv: Sequence[str] | None = None) -> int:
    interval_seconds, label, command = _arguments(
        sys.argv[1:] if argv is None else argv
    )
    return run(interval_seconds, label, command)


if __name__ == "__main__":
    raise SystemExit(main())
