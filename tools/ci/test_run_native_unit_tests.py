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

    def test_new_examples_and_benchmarks_cannot_be_silently_omitted(self):
        for kind in ["example", "bench"]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                runner.integration_targets(fixture({"name": "added", "kind": [kind]}))

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
                "--",
                "--nocapture",
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
                "--nocapture",
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

    @patch.object(runner.library_scope, "partition_inventory")
    @patch.object(runner.subprocess, "run")
    def test_independent_suites_partition_the_original_commands(self, run, inventory):
        for suite, flag in [("library", "--lib"), ("binaries", "--bins")]:
            with self.subTest(suite=suite):
                run.reset_mock()
                inventory.reset_mock()
                runner.run_tests(["existing"], suite)
                arguments = (
                    runner.library_scope.library_arguments()
                    if suite == "library" else ["--nocapture"]
                )
                run.assert_called_once_with(
                    ["cargo", "test", flag, "--locked", "--", *arguments],
                    check=True,
                    cwd=runner.REPOSITORY_ROOT,
                )
                if suite == "library":
                    inventory.assert_called_once_with(runner.REPOSITORY_ROOT)
                else:
                    inventory.assert_not_called()
        run.reset_mock()
        runner.run_tests(["added", "existing"], "integrations")
        run.assert_called_once_with(
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
                "--nocapture",
            ],
            check=True,
            cwd=runner.REPOSITORY_ROOT,
        )

    @patch.object(runner.subprocess, "run")
    def test_main_selects_only_the_requested_suite(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(fixture()), ""),
            subprocess.CompletedProcess([], 0),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["--suite", "binaries"]), 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args.args[0],
            ["cargo", "test", "--bins", "--locked", "--", "--nocapture"],
        )

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


def library_inventory(cases):
    return "\n".join([
        *(f"{case}: test" for case in sorted(cases)),
        "",
        f"{len(cases)} tests, 0 benchmarks",
    ])


class LibraryPartitionTests(unittest.TestCase):
    def setUp(self):
        self.scope = runner.library_scope
        self.proofs = set(self.scope.LIBRARY_PROOFS.values())
        self.ignored = {"native::explicit_ignored_proof"}
        self.cases = self.proofs | self.ignored | {"ordinary::first", "ordinary::new"}

    def test_partition_preserves_every_enabled_case_in_exactly_one_group(self):
        core = self.scope.validate_partition(self.cases, self.ignored)
        self.assertEqual(core, {"ordinary::first", "ordinary::new"})
        self.assertFalse(core & self.proofs)
        self.assertEqual(core | self.proofs, self.cases - self.ignored)

    def test_missing_or_ignored_required_proof_is_rejected(self):
        case = sorted(self.proofs)[0]
        for cases, ignored in [
            (self.cases - {case}, self.ignored),
            (self.cases, self.ignored | {case}),
            (self.cases, self.ignored | {"missing"}),
        ]:
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                self.scope.validate_partition(cases, ignored)

    def test_duplicate_assignment_cannot_silently_remove_a_matrix_proof(self):
        assignments = dict(self.scope.LIBRARY_PROOFS)
        assignments["duplicate"] = sorted(self.proofs)[0]
        with patch.object(self.scope, "LIBRARY_PROOFS", assignments):
            with self.assertRaises(ValueError):
                self.scope.validate_partition(self.cases, self.ignored)

    def test_substring_skip_collision_is_rejected_not_dropped(self):
        collision = sorted(self.proofs)[0] + "_additional_case"
        with self.assertRaisesRegex(ValueError, "skip filter"):
            self.scope.validate_partition(self.cases | {collision}, self.ignored)

    def test_complete_and_empty_ignored_inventories_are_accepted(self):
        self.assertEqual(
            self.scope.parse_inventory(library_inventory(self.cases)), self.cases,
        )
        self.assertEqual(self.scope.parse_inventory("0 tests, 0 benchmarks\n"), set())
        self.assertEqual(self.scope.parse_inventory("one: test\n1 test, 0 benchmarks"), {"one"})

    def test_malformed_or_incomplete_inventory_is_rejected(self):
        for output in [
            "one: test\none: test\n2 tests, 0 benchmarks",
            "--skip: test\n1 test, 0 benchmarks",
            "one: test",
            "one: test\n0 tests, 0 benchmarks",
            "one: test\n1 test, 1 benchmark",
            "0 tests, 0 benchmarks\n0 tests, 0 benchmarks",
            "unexpected diagnostic\n0 tests, 0 benchmarks",
        ]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.scope.parse_inventory(output)

    @patch.object(runner.subprocess, "run")
    def test_real_inventory_commands_precede_exact_proof_execution(self, run):
        proof = "gradle-generator"
        run.side_effect = [
            subprocess.CompletedProcess([], 0, library_inventory(self.cases), ""),
            subprocess.CompletedProcess([], 0, library_inventory(self.ignored), ""),
            subprocess.CompletedProcess([], 0),
        ]
        with redirect_stdout(io.StringIO()):
            self.scope.run_proof(runner.REPOSITORY_ROOT, proof)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [
            ["cargo", "test", "--lib", "--locked", "--", "--list"],
            ["cargo", "test", "--lib", "--locked", "--", "--list", "--ignored"],
            ["cargo", "test", "--lib", "--locked", self.scope.LIBRARY_PROOFS[proof],
             "--", "--exact", "--test-threads=1", "--nocapture"],
        ])
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["cwd"], runner.REPOSITORY_ROOT)

    @patch.object(runner.subprocess, "run")
    def test_inventory_failure_stops_before_executing_the_proof(self, run):
        run.side_effect = subprocess.CalledProcessError(101, ["cargo", "test"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.scope.run_proof(runner.REPOSITORY_ROOT, "go-project-model")
        run.assert_called_once()

    @patch.object(runner.subprocess, "run")
    def test_missing_proof_stops_after_inventory_before_execution(self, run):
        cases = self.cases - {sorted(self.proofs)[0]}
        run.side_effect = [
            subprocess.CompletedProcess([], 0, library_inventory(cases), ""),
            subprocess.CompletedProcess([], 0, library_inventory(self.ignored), ""),
        ]
        with self.assertRaises(ValueError):
            self.scope.run_proof(runner.REPOSITORY_ROOT, "go-project-model")
        self.assertEqual(run.call_count, 2)

    @patch.object(runner.subprocess, "run")
    def test_matrix_inventory_is_complete_and_never_launches_cargo(self, run):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(runner.main(["--library-proofs"]), 0)
        self.assertEqual(json.loads(output.getvalue()), sorted(self.scope.LIBRARY_PROOFS))
        self.assertEqual(len(json.loads(output.getvalue())), 3)
        run.assert_not_called()

    @patch.object(runner.subprocess, "run")
    def test_selected_proof_failure_preserves_exit_code(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, json.dumps(fixture()), ""),
            subprocess.CompletedProcess([], 0, library_inventory(self.cases), ""),
            subprocess.CompletedProcess([], 0, library_inventory(self.ignored), ""),
            subprocess.CalledProcessError(101, ["cargo", "test"]),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["--library-proof", "gradle-project-model"]), 101)
        self.assertEqual(run.call_count, 4)
        self.assertIn(self.scope.LIBRARY_PROOFS["gradle-project-model"], run.call_args.args[0])

    @patch.object(runner.subprocess, "run")
    def test_conflicting_execution_modes_are_rejected_before_cargo(self, run):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            runner.main(["--suite", "library", "--library-proof", "go-project-model"])
        self.assertEqual(error.exception.code, 2)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
