import hashlib
import io
import subprocess
import unittest
from unittest.mock import patch

import temporal_prior_replay as replay


class TemporalReplayTests(unittest.TestCase):
    def compare(self, live, pinned, data_only=False):
        with patch.object(replay, "read_capture", side_effect=[live, pinned]):
            replay.compare_capture("live", "pinned", data_only)

    def test_order_and_whitespace_do_not_change_capture(self):
        self.compare(b'{"data":{"b":2,"a":1}}', b'{ "data": {"a":1,"b":2} }')

    def test_only_explicit_data_projection_ignores_extensions(self):
        live = b'{"data":{"id":"R_1"},"extensions":{"cost":1}}'
        pinned = b'{"id":"R_1"}'
        self.compare(live, pinned, True)
        with self.assertRaises(ValueError):
            self.compare(live, pinned)

    def test_errors_even_empty_cannot_be_projected_away(self):
        for errors in [b'[]', b'null', b'[{"message":"bad"}]']:
            with self.subTest(errors=errors), self.assertRaises(ValueError):
                self.compare(b'{"data":{},"errors":' + errors + b'}', b'{}', True)

    def test_duplicate_decoded_keys_including_ignored_extensions_fail(self):
        for live in [
            b'{"data":{},"data":{}}',
            b'{"data":{"id":1,"i\\u0064":1}}',
            b'{"data":{},"extensions":{"x":1,"x":1}}',
        ]:
            with self.subTest(live=live), self.assertRaises(ValueError):
                self.compare(live, b'{}', True)
        with self.assertRaises(ValueError):
            self.compare(b'{"data":{}}', b'{"x":1,"x":1}')

    def test_invalid_json_utf8_trailing_and_nonfinite_numbers_fail(self):
        for data in [b'\xff', b'{} {}', b'{', b'{"x":NaN}', b'{"x":1e999}']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                replay.decode(data)

    def test_projection_requires_objects(self):
        for live in [b'null', b'[]', b'{}', b'{"data":null}', b'{"data":[]}']:
            with self.subTest(live=live), self.assertRaises(ValueError):
                self.compare(live, b'{}', True)
        with self.assertRaises(ValueError):
            self.compare(b'{"data":{}}', b'[]', True)

    def test_changed_values_and_types_fail(self):
        for live in [b'{"id":2}', b'{"id":true}', b'{"id":1.0}']:
            with self.subTest(live=live), self.assertRaises(ValueError):
                self.compare(live, b'{"id":1}')

    def test_sha256_is_exact_and_requires_lowercase_hex(self):
        digest = hashlib.sha256(b'evidence').hexdigest()
        with patch.object(replay.Path, "open", side_effect=lambda *a, **kw: io.BytesIO(b'evidence')):
            replay.verify_sha256("path", digest)
            for expected in ["0" * 64, "g" * 64, digest.upper(), digest[:-1]]:
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    replay.verify_sha256("path", expected)

    def test_artifact_hash_streams_under_separate_exact_bound(self):
        with patch.object(replay, "MAX_CAPTURE_BYTES", 1), \
             patch.object(replay, "MAX_ARTIFACT_BYTES", 8), \
             patch.object(replay, "HASH_CHUNK_BYTES", 3):
            for data in [b'12345678', b'123456789']:
                stream = io.BytesIO(data)
                with patch.object(replay.Path, "open", return_value=stream), \
                     patch.object(stream, "read", wraps=stream.read) as read:
                    expected = hashlib.sha256(data).hexdigest()
                    if len(data) == 8:
                        replay.verify_sha256("path", expected)
                    else:
                        with self.assertRaisesRegex(ValueError, "exceeds byte bound"):
                            replay.verify_sha256("path", expected)
                    self.assertGreater(len(read.call_args_list), 1)
                    self.assertTrue(all(0 < call.args[0] <= 3 for call in read.call_args_list))

    def test_byte_bound_is_checked_before_decoding_or_hashing(self):
        with patch.object(replay, "MAX_CAPTURE_BYTES", 4):
            for data in [b'1234', b'12345']:
                with patch.object(replay.Path, "open") as opened:
                    opened.return_value.__enter__.return_value = io.BytesIO(data)
                    if len(data) == 4:
                        self.assertEqual(replay.read_capture("path"), data)
                    else:
                        with self.assertRaises(ValueError):
                            replay.read_capture("path")

    @patch.object(replay.subprocess, "run")
    def test_each_proof_discovers_exact_inventory_before_running(self, run):
        for proof, (scope, names, ignored) in replay.PROOFS.items():
            with self.subTest(proof=proof):
                run.reset_mock()
                inventory_result = subprocess.CompletedProcess(
                    [], 0, "\n".join(scope + name + ": test" for name in reversed(names)), "",
                )
                if not ignored:
                    run.side_effect = [inventory_result, subprocess.CompletedProcess([], 0, "", ""), None]
                else:
                    run.side_effect = [inventory_result, None]
                replay.run_proof(proof, "selected-cargo")
                inventory = run.call_args_list[0].args[0]
                execution = run.call_args_list[-1].args[0]
                self.assertEqual(run.call_count, 2 if ignored else 3)
                if not ignored:
                    self.assertEqual(run.call_args_list[1].args[0][-2:], ["--ignored", "--list"])
                self.assertEqual(inventory[0], "selected-cargo")
                self.assertEqual("--features" in inventory, proof in {"prior-v2", "prior-coverage"})
                if proof in {"prior-v2", "prior-coverage"}:
                    self.assertEqual(inventory[inventory.index("--features") + 1], "sniffbench-frame")
                self.assertEqual(inventory[:-1], execution[:-2])
                self.assertEqual(inventory[-1], "--list")
                self.assertEqual(execution[-2:], ["--test-threads=1", "--nocapture"])
                self.assertEqual("--ignored" in inventory, ignored)
                self.assertEqual("--exact" in inventory, len(names) == 1)
                self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))

    @patch.object(replay.subprocess, "run")
    def test_ordinary_proof_becoming_ignored_never_executes(self, run):
        scope, names, _ = replay.PROOFS["small"]
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "\n".join(scope + n + ": test" for n in names), ""),
            subprocess.CompletedProcess([], 0, scope + names[0] + ": test", ""),
        ]
        with self.assertRaises(ValueError):
            replay.run_proof("small")
        self.assertEqual(run.call_count, 2)

    @patch.object(replay.subprocess, "run")
    def test_zero_renamed_added_duplicate_or_missing_tests_never_execute(self, run):
        scope, names, _ = replay.PROOFS["small"]
        valid = [scope + name + ": test" for name in names]
        for rows in [[], valid[:-1], valid + [valid[0]], valid + [scope + "new: test"],
                     ["wrong: test"] + valid[1:]]:
            with self.subTest(rows=rows):
                run.reset_mock()
                run.return_value = subprocess.CompletedProcess([], 0, "\n".join(rows), "")
                with self.assertRaises(ValueError):
                    replay.run_proof("small")
                self.assertEqual(run.call_count, 1)

    @patch.object(replay.subprocess, "run")
    def test_inventory_and_execution_failures_propagate(self, run):
        failure = subprocess.CalledProcessError(1, ["cargo"])
        run.side_effect = failure
        with self.assertRaises(subprocess.CalledProcessError):
            replay.run_proof("blind")
        self.assertEqual(run.call_count, 1)
        scope, names, _ = replay.PROOFS["blind"]
        run.reset_mock()
        run.side_effect = [subprocess.CompletedProcess([], 0, scope + names[0] + ": test\n", ""), failure]
        with self.assertRaises(subprocess.CalledProcessError):
            replay.run_proof("blind")
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
