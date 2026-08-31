import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = pathlib.Path(__file__).with_name("run_with_heartbeat.py")


def invoke(*command: str, interval: str = "1", label: str = "fixture"):
    return subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "--interval-seconds",
            interval,
            "--label",
            label,
            "--",
            *command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


class HeartbeatRunnerTests(unittest.TestCase):
    def test_preserves_success_without_spurious_heartbeat(self) -> None:
        result = invoke(sys.executable, "-c", "print('complete')")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "complete\n")
        self.assertEqual(result.stderr, "")

    def test_preserves_nonzero_child_status(self) -> None:
        result = invoke(sys.executable, "-c", "raise SystemExit(17)")

        self.assertEqual(result.returncode, 17)

    def test_reports_command_start_failure_without_a_fallback(self) -> None:
        result = invoke("sniff-heartbeat-command-that-does-not-exist")

        self.assertEqual(result.returncode, 127)
        self.assertIn("heartbeat runner could not start fixture", result.stderr)

    def test_emits_heartbeat_while_child_is_running(self) -> None:
        result = invoke(sys.executable, "-c", "import time; time.sleep(1.2)")

        self.assertEqual(result.returncode, 0)
        self.assertIn("heartbeat label=fixture elapsed_seconds=1", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX signal-forwarding regression")
    def test_forwards_termination_and_returns_the_child_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ready = pathlib.Path(directory, "ready")
            child = (
                "import pathlib, signal, sys, time; "
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(23)); "
                f"pathlib.Path({str(ready)!r}).write_text('ready'); "
                "time.sleep(30)"
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(HELPER),
                    "--interval-seconds",
                    "1",
                    "--label",
                    "signal-fixture",
                    "--",
                    sys.executable,
                    "-c",
                    child,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists(), "child did not become ready")
                process.terminate()
                _stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        self.assertEqual(process.returncode, 23, stderr)

    def test_rejects_unsafe_configuration_before_starting_child(self) -> None:
        bad_interval = invoke(sys.executable, "-c", "pass", interval="0")
        bad_label = invoke(sys.executable, "-c", "pass", label="bad label")

        self.assertEqual(bad_interval.returncode, 2)
        self.assertIn("must be between 1 and 3600", bad_interval.stderr)
        self.assertEqual(bad_label.returncode, 2)
        self.assertIn("must be a safe 1-64 character identifier", bad_label.stderr)


if __name__ == "__main__":
    unittest.main()
