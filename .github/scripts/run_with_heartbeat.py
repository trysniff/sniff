#!/usr/bin/env python3
"""Run one command while emitting bounded progress heartbeats."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
TERMINATION_GRACE_SECONDS = 10


def _arguments(argv: Sequence[str]) -> tuple[int, str, bool, list[str]]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval-seconds", required=True, type=int)
    parser.add_argument("--label", required=True)
    parser.add_argument("--linux-proc-stats", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not 1 <= args.interval_seconds <= 3600:
        parser.error("--interval-seconds must be between 1 and 3600")
    if LABEL.fullmatch(args.label) is None:
        parser.error("--label must be a safe 1-64 character identifier")
    if args.linux_proc_stats and not sys.platform.startswith("linux"):
        parser.error("--linux-proc-stats requires Linux procfs")
    if args.linux_proc_stats and not pathlib.Path("/proc/self/status").is_file():
        parser.error("--linux-proc-stats requires Linux procfs")
    if not command:
        parser.error("a command is required after --")
    return args.interval_seconds, args.label, args.linux_proc_stats, command


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


def _proc_status(pid: int) -> tuple[int, int, int] | None:
    try:
        lines = pathlib.Path(f"/proc/{pid}/status").read_text(
            encoding="ascii", errors="strict"
        ).splitlines()
    except FileNotFoundError:
        return None
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition(":")
        if separator:
            values[key] = value.strip()
    try:
        rss_kib = int(values.get("VmRSS", "0 kB").split()[0])
        high_water_kib = int(values.get("VmHWM", "0 kB").split()[0])
        threads = int(values["Threads"])
    except (KeyError, ValueError, IndexError) as error:
        raise RuntimeError(f"invalid procfs status for process {pid}") from error
    return rss_kib, high_water_kib, threads


def _parse_proc_cpu_ticks(value: str) -> int:
    end = value.rfind(") ")
    fields = value[end + 2 :].split() if end >= 0 else []
    if len(fields) < 13:
        raise RuntimeError("invalid procfs CPU data")
    try:
        ticks = int(fields[11]) + int(fields[12])
    except ValueError as error:
        raise RuntimeError("invalid procfs CPU data") from error
    if ticks < 0:
        raise RuntimeError("invalid procfs CPU data")
    return ticks


def _proc_cpu_ticks(pid: int) -> int | None:
    try:
        value = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError):
        return None
    return _parse_proc_cpu_ticks(value)


def _parse_proc_io_counters(value: str) -> tuple[int, int, int, int]:
    fields = dict(line.split(":", 1) for line in value.splitlines() if ":" in line)
    try:
        counters = tuple(
            int(fields[key].strip())
            for key in ("rchar", "wchar", "read_bytes", "write_bytes")
        )
    except (KeyError, ValueError) as error:
        raise RuntimeError("invalid procfs I/O data") from error
    if any(counter < 0 for counter in counters):
        raise RuntimeError("invalid procfs I/O data")
    return counters


def _proc_io_counters(pid: int) -> tuple[int, int, int, int] | None:
    try:
        value = pathlib.Path(f"/proc/{pid}/io").read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError):
        return None
    return _parse_proc_io_counters(value)


def _proc_children(pid: int) -> list[int]:
    try:
        tasks = list(pathlib.Path(f"/proc/{pid}/task").iterdir())
    except FileNotFoundError:
        return []
    children: set[int] = set()
    for task in tasks:
        if not task.name.isdigit():
            continue
        try:
            value = task.joinpath("children").read_text(
                encoding="ascii", errors="strict"
            )
            children.update(int(child) for child in value.split())
        except FileNotFoundError:
            continue
        except ValueError as error:
            raise RuntimeError(f"invalid procfs children for process {pid}") from error
    return sorted(children)


def _meminfo() -> tuple[int, int]:
    values: dict[str, int] = {}
    try:
        lines = pathlib.Path("/proc/meminfo").read_text(
            encoding="ascii", errors="strict"
        ).splitlines()
    except OSError as error:
        raise RuntimeError("could not read Linux procfs memory data") from error
    for line in lines:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        fields = value.split()
        if fields and fields[0].isdigit():
            values[key] = int(fields[0])
    try:
        return values["MemTotal"], values["MemAvailable"]
    except KeyError as error:
        raise RuntimeError("Linux procfs memory data is incomplete") from error


def _filesystem_info() -> tuple[int, int]:
    try:
        values = os.statvfs("/")
    except OSError as error:
        raise RuntimeError("could not read Linux filesystem data") from error
    block_size = values.f_frsize or values.f_bsize
    return (
        block_size * values.f_blocks // 1024,
        block_size * values.f_bavail // 1024,
    )


def _linux_proc_stats(root_pid: int) -> str:
    pending = [root_pid]
    seen: set[int] = set()
    process_count = 0
    rss_kib = 0
    high_water_kib = 0
    thread_count = 0
    cpu_ticks = 0
    cpu_observed_processes = 0
    io_counters = [0, 0, 0, 0]
    io_observed_processes = 0
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        status = _proc_status(pid)
        if status is None:
            continue
        process_count += 1
        rss_kib += status[0]
        high_water_kib += status[1]
        thread_count += status[2]
        observed_cpu = _proc_cpu_ticks(pid)
        if observed_cpu is not None:
            cpu_ticks += observed_cpu
            cpu_observed_processes += 1
        observed_io = _proc_io_counters(pid)
        if observed_io is not None:
            for index, counter in enumerate(observed_io):
                io_counters[index] += counter
            io_observed_processes += 1
        pending.extend(_proc_children(pid))
    total_kib, available_kib = _meminfo()
    filesystem_total_kib, filesystem_available_kib = _filesystem_info()
    cpu_ms = cpu_ticks * 1000 // os.sysconf("SC_CLK_TCK")
    return (
        f"processes={process_count} rss_kib={rss_kib} "
        f"high_water_kib={high_water_kib} threads={thread_count} "
        f"host_mem_total_kib={total_kib} host_mem_available_kib={available_kib} "
        f"host_fs_total_kib={filesystem_total_kib} "
        f"host_fs_available_kib={filesystem_available_kib} "
        f"cpu_ms={cpu_ms} cpu_observed_processes={cpu_observed_processes} "
        f"io_rchar_bytes={io_counters[0]} io_wchar_bytes={io_counters[1]} "
        f"io_read_bytes={io_counters[2]} io_write_bytes={io_counters[3]} "
        f"io_observed_processes={io_observed_processes}"
    )


def run(
    interval_seconds: int,
    label: str,
    command: Sequence[str],
    linux_proc_stats: bool = False,
) -> int:
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
                resources = (
                    f" {_linux_proc_stats(process.pid)}" if linux_proc_stats else ""
                )
                print(
                    f"heartbeat label={label} elapsed_seconds={elapsed}{resources}",
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
    interval_seconds, label, linux_proc_stats, command = _arguments(
        sys.argv[1:] if argv is None else argv
    )
    return run(interval_seconds, label, command, linux_proc_stats)


if __name__ == "__main__":
    raise SystemExit(main())
