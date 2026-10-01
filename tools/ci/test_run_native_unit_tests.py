from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import run_native_unit_tests as runner


def fixture(*extra):
    return {
        "packages": [
            {
                "name": "sniff-cli",
                "features": {"default": []},
                "targets": [
                    {"name": "sniff", "kind": ["lib"]},
                    {"name": "sniff", "kind": ["bin"]},
                    {"name": "dogfood_suite", "kind": ["test"]},
                    {"name": "existing", "kind": ["test"]},
                    *extra,
                ],
            }
        ],
    }


class NativeTargetTests(unittest.TestCase):
    def test_new_enabled_targets_are_included_without_a_manual_list(self):
        data = fixture({"name": "added", "kind": ["test"], "required-features": []})
        self.assertEqual(runner.integration_targets(data), ["added", "existing"])

    def test_only_the_exact_separate_feature_job_is_excluded(self):
        data = fixture(
            {
                "name": "historical_v2_command_recovery",
                "kind": ["test"],
                "required-features": ["sniffbench-frame"],
            }
        )
        self.assertEqual(runner.integration_targets(data), ["existing"])
        data["packages"][0]["targets"][-1]["required-features"] = ["other"]
        with self.assertRaises(ValueError):
            runner.integration_targets(data)

    def test_unknown_feature_target_fails_instead_of_disappearing(self):
        with self.assertRaises(ValueError):
            runner.integration_targets(
                fixture(
                    {
                        "name": "added",
                        "kind": ["test"],
                        "required-features": ["feature"],
                    }
                )
            )

    def test_duplicate_invalid_and_null_feature_targets_fail(self):
        for target in [
            {"name": "existing", "kind": ["test"]},
            {"name": "--skip", "kind": ["test"]},
            {"name": "added", "kind": ["test"], "required-features": None},
        ]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                runner.integration_targets(fixture(target))

    def test_missing_dogfood_and_changed_default_features_fail(self):
        data = fixture()
        data["packages"][0]["targets"] = [{"name": "existing", "kind": ["test"]}]
        with self.assertRaises(ValueError):
            runner.integration_targets(data)
        data = fixture()
        data["packages"][0]["features"]["default"] = ["feature"]
        with self.assertRaises(ValueError):
            runner.integration_targets(data)

    def test_missing_or_duplicate_package_fails(self):
        data = fixture()
        data["packages"].append(data["packages"][0])
        with self.assertRaises(ValueError):
            runner.integration_targets(data)
        with self.assertRaises(ValueError):
            runner.integration_targets({"packages": []})

    @patch.object(runner.subprocess, "run")
    def test_execution_includes_every_target_as_a_separate_cargo_argument(self, run):
        runner.run_tests(["added", "existing"])
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "cargo",
                "test",
                "--lib",
                "--bins",
                "--locked",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "cargo",
                "test",
                "--locked",
                "--test",
                "added",
                "--test",
                "existing",
                "--",
                "--test-threads=1",
            ],
        )
        self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
        self.assertTrue(
            all(
                call.kwargs["cwd"] == runner.REPOSITORY_ROOT
                for call in run.call_args_list
            )
        )

    @patch.object(runner.subprocess, "run")
    def test_library_failure_stops_before_integration_commands(self, run):
        run.side_effect = subprocess.CalledProcessError(101, ["cargo", "test"])
        with self.assertRaises(subprocess.CalledProcessError):
            runner.run_tests(["existing"])
        run.assert_called_once()

    @patch.object(runner.subprocess, "run")
    def test_list_only_never_runs_a_build_or_test(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, json.dumps(fixture()), "")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(runner.main(["--list-only"]), 0)
        self.assertEqual(output.getvalue(), "existing\n")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][:2], ["cargo", "metadata"])
        self.assertEqual(run.call_args.kwargs["cwd"], runner.REPOSITORY_ROOT)

    @patch.object(runner.subprocess, "run")
    def test_metadata_failure_preserves_exit_code_without_test_execution(self, run):
        run.side_effect = subprocess.CalledProcessError(
            23, ["cargo", "metadata"], stderr="failed"
        )
        output = io.StringIO()
        with redirect_stderr(output):
            self.assertEqual(runner.main([]), 23)
        self.assertIn("failed", output.getvalue())
        run.assert_called_once()

    @patch.object(runner.subprocess, "run")
    def test_integration_failure_reaches_main_as_a_nonzero_exit(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(fixture()), ""),
            subprocess.CompletedProcess([], 0),
            subprocess.CalledProcessError(
                101, ["cargo", "test"], stderr="integration failed"
            ),
        ]
        error = io.StringIO()
        with redirect_stderr(error), redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main([]), 101)
        self.assertIn("integration failed", error.getvalue())
        self.assertEqual(run.call_count, 3)
        self.assertIn("--test", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
