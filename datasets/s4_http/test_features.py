import unittest
from features import aggregate
from runner import schedule, validate_args, es_join
import random
from types import SimpleNamespace
from unittest.mock import patch


class FeatureTests(unittest.TestCase):
    def row(self, offset, size=100, status=200, error=None):
        return {"offset_s": offset, "client_observed_body_bytes": size, "status": status,
                "error": error, "method": "GET", "route": "/users/me"}

    def test_original_first_zero_and_sample_variance(self):
        f = aggregate([self.row(9, 300), self.row(3, 100)])
        self.assertEqual(f["mean_interval_s"], 3)
        self.assertAlmostEqual(f["response_bytes_std"], 141.421356237)
        self.assertEqual(f["successful_2xx_count"], 2)

    def test_failed_observation_cannot_become_normal(self):
        for rows in ([], [self.row(1, error="TimeoutError")], [self.row(1, size=None)]):
            with self.assertRaises(ValueError):
                aggregate(rows)

    def test_3xx_is_not_successful_2xx(self):
        self.assertEqual(aggregate([self.row(1, status=302)])["successful_2xx_count"], 0)

    def test_label_identity_never_exported(self):
        row = self.row(1)
        row.update(label=1, cohort_id="secret-id", profile="attack")
        self.assertFalse({"label", "cohort_id", "profile"} & aggregate([row]).keys())

    def test_profile_window_bounds_and_determinism(self):
        for profile in ("normal_slow", "normal_active", "normal_burst",
                        "s4_repeated", "s4_burst", "s4_broad"):
            a = schedule(random.Random(42), profile)
            self.assertEqual(a, schedule(random.Random(42), profile))
            self.assertTrue(all(0 <= value < 60 for value in a))
            self.assertLessEqual(len(a), 140)


class GuardTests(unittest.TestCase):
    def args(self, **changes):
        values = dict(actors=20, train_windows=3, calibration_windows=2,
                      test_windows=5, attack_ratio=0.05, concurrency=4,
                      max_requests=15000, max_seconds=900, account_start=300)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_ttl_and_request_guards_before_login(self):
        for values in ({"test_windows": 15}, {"max_requests": 100001},
                       {"concurrency": 9}, {"account_start": 299},
                       {"max_seconds": 599}):
            with self.assertRaises(ValueError):
                validate_args(self.args(**values))
        self.assertEqual(validate_args(self.args()), 5)

    def test_ratio_must_be_exact_in_real_windows(self):
        with self.assertRaises(ValueError):
            validate_args(self.args(actors=19))

    @patch("runner.time.sleep")
    @patch("runner.subprocess.run")
    def test_missing_actor_event_is_not_assumed_normal(self, run, sleep):
        run.return_value = SimpleNamespace(returncode=0, stdout='{"hits":{"hits":[]}}')
        resolved, actors = es_join([{"request_id": "probe", "cohort_id": "cohort-0"}])
        self.assertEqual(resolved, {})
        self.assertEqual(dict(actors), {})
        self.assertEqual(run.call_count, 10)
        arguments = run.call_args.kwargs["input"]
        self.assertIn('"actor.subject_key"', arguments)
        self.assertNotIn('"token_ref"', arguments)


if __name__ == "__main__":
    unittest.main()
