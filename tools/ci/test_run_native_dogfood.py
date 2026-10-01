from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import run_native_dogfood as runner


def inventory(*extra):
    names = [f"{group}::first: test" for group in runner.GROUPS] + list(extra)
    return "\n".join([*names, "", f"{len(names)} tests, 0 benchmarks"])


class DogfoodScopeTests(unittest.TestCase):
    @patch.object(runner.subprocess, "run")
    def test_matrix_discovery_lists_every_group_without_a_build_or_test(self, run):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(runner.main(["--groups"]), 0)
        self.assertEqual(json.loads(output.getvalue()), list(runner.GROUPS))
        run.assert_not_called()

    def test_every_group_is_nonempty_and_new_tests_in_a_group_are_retained(self):
        groups = runner.validate_inventory(inventory("core::added: test"))
        self.assertEqual(groups["core"], ["core::first", "core::added"])
        self.assertEqual(set(groups), set(runner.GROUPS))

    def test_new_groups_nested_groups_and_top_level_tests_cannot_disappear(self):
        for name in ["new_group::first", "core::brandset::nested", "unassigned"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.validate_inventory(inventory(f"{name}: test"))

    def test_missing_groups_duplicates_and_drifted_summary_fail(self):
        original = inventory()
        for output in [
            original.replace("core::first: test\n", ""),
            inventory("core::first: test"),
            original.replace("6 tests, 0 benchmarks", "7 tests, 0 benchmarks"),
            original.replace("6 tests, 0 benchmarks", "6 tests, 1 benchmark"),
            original.replace("6 tests, 0 benchmarks", ""),
            original + "\n6 tests, 0 benchmarks",
        ]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                runner.validate_inventory(output)

    @patch.object(runner.subprocess, "run")
    def test_listing_precedes_one_serial_complete_module_command(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, inventory("core::added: test")),
            subprocess.CompletedProcess([], 0),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["core"]), 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][-2:], ["--", "--list"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "cargo",
                "test",
                "--locked",
                "--test",
                "dogfood_suite",
                "core::",
                "--",
                "--test-threads=1",
                "--nocapture",
            ],
        )
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["cwd"], runner.REPOSITORY_ROOT)

    @patch.object(runner.subprocess, "run")
    def test_listing_failures_prevent_execution_and_preserve_exit_code(self, run):
        run.side_effect = subprocess.CalledProcessError(101, ["cargo", "test"])
        self.assertEqual(runner.main(["core"]), 101)
        run.assert_called_once()

    @patch.object(runner.subprocess, "run")
    def test_invalid_inventory_prevents_execution(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(["core"]), 1)
        run.assert_called_once()

    @patch.object(runner.subprocess, "run")
    def test_dogfood_failure_is_not_converted_into_success(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, inventory()),
            subprocess.CalledProcessError(23, ["cargo", "test"]),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["core"]), 23)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
