"""Bounded real HTTP capture for local mock accounts; no token/body persistence."""
import argparse
import ast
import collections
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
import pathlib
import platform
import random
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from features import FEATURE_COLUMNS, aggregate

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKSPACE = REPO.parent
BASE = "https://127.0.0.1:8443"
CA = WORKSPACE / "zero-trust-architecture/compose/tls/ca.crt"
ROUTES = ("/mypage", "/users/me", "/orders?page=0&size=20", "/addresses",
          "/payments/balance", "/payments/history")
WINDOW_SECONDS = 60


def utc(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self):
        self.context = ssl.create_default_context(cafile=str(CA))

    def opener(self):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context), NoRedirect())

    def login(self, account):
        # Existing public mock fixture only; never read .env or persisted credentials.
        tree = ast.parse((REPO / "scenarios/v2/s4_behavior.py").read_text())
        password = next(ast.literal_eval(n.value) for n in tree.body
                        if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "PW" for t in n.targets))
        request = urllib.request.Request(BASE + "/auth/login", method="POST",
            data=json.dumps({"email": f"user{account:03d}@zetty.test",
                             "password": password}).encode(),
            headers={"Content-Type": "application/json"})
        with self.opener().open(request, timeout=10) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise RuntimeError("Login response exceeds bound")
            token = json.loads(body)["accessToken"]
        return token

    def observe(self, token, cohort, window_id, route, start_epoch, start_mono):
        begin = time.monotonic()
        request = urllib.request.Request(BASE + route,
            headers={"Authorization": "Bearer " + token})
        row = {"window_id": window_id, "cohort_id": cohort, "event_time": utc(time.time()),
               "offset_s": begin - start_mono, "method": "GET", "route": route.split("?")[0],
               "status": None, "client_observed_body_bytes": None,
               "request_id": None, "latency_ms": None, "error": None}
        try:
            try:
                response = self.opener().open(request, timeout=8)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                row["status"] = response.status
                row["request_id"] = response.headers.get("X-Request-Id")
                size = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 2_000_000:
                        raise RuntimeError("Response exceeds byte bound")
                row["client_observed_body_bytes"] = size
        except Exception as error:
            # Exception strings can contain URLs or headers; retain class only.
            row["error"] = type(error).__name__
        row["latency_ms"] = round((time.monotonic() - begin) * 1000, 3)
        return row


def schedule(rng, profile):
    if profile == "normal_slow":
        return sorted(rng.uniform(1, 57) for _ in range(rng.randint(6, 12)))
    if profile == "normal_active":
        return sorted(rng.uniform(1, 57) for _ in range(rng.randint(24, 40)))
    if profile == "normal_burst":
        center = rng.uniform(10, 42)
        return sorted([rng.uniform(1, 57) for _ in range(12)]
                      + [min(57, max(1, rng.gauss(center, 1.8))) for _ in range(rng.randint(48, 108))])
    if profile == "s4_repeated":
        return sorted(rng.uniform(1, 57) for _ in range(120))
    if profile == "s4_burst":
        return sorted([rng.uniform(1, 57) for _ in range(20)]
                      + [rng.uniform(15, 35) for _ in range(120)])
    if profile == "s4_broad":
        return sorted(rng.uniform(1, 57) for _ in range(100))
    raise ValueError("Unknown profile")


def es_join(rows):
    ids = [r["request_id"] for r in rows if r["request_id"]]
    resolved = {}
    for attempt in range(10):
        missing = [rid for rid in ids if rid not in resolved]
        if not missing:
            break
        for offset in range(0, len(missing), 400):
            query = {"size": 400, "query": {"bool": {"filter": [
                     {"terms": {"request_id": missing[offset:offset + 400]}},
                     {"term": {"event_type": "ACCESS_DECISION"}},
                     {"term": {"producer": "api"}}]}},
                     "_source": ["request_id", "actor.subject_key"]}
            command = ["docker", "exec", "-i", "zetty-elasticsearch-1",
                       "curl", "--fail", "--silent", "--show-error",
                       "-H", "Content-Type: application/json",
                       "http://localhost:9200/zetty-security-events-v2-*/_search",
                       "--data-binary", "@-"]
            result = subprocess.run(command, input=json.dumps(query),
                                    capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise RuntimeError("Restricted event join failed")
            for hit in json.loads(result.stdout).get("hits", {}).get("hits", []):
                source = hit["_source"]
                subject = source.get("actor", {}).get("subject_key")
                if subject:
                    resolved[source["request_id"]] = subject
        if len(resolved) != len(ids):
            time.sleep(1)
    actors = collections.defaultdict(set)
    for row in rows:
        if row["request_id"] in resolved:
            actors[row["cohort_id"]].add(resolved[row["request_id"]])
    return resolved, actors


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def write_jsonl(path, rows):
    with path.open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def validate_args(args):
    if not (2 <= args.actors <= 100 and 1 <= args.train_windows <= 14
            and 1 <= args.calibration_windows <= 14 and 1 <= args.test_windows <= 14):
        raise ValueError("Actor/window bounds exceeded")
    if not (1 <= args.concurrency <= 8 and 1 <= args.max_requests <= 100000):
        raise ValueError("Concurrency/request bounds exceeded")
    if args.attack_ratio not in (0.05, 0.01):
        raise ValueError("Supported planned prevalence: 0.05 or 0.01")
    if args.account_start < 300 or args.account_start + args.actors > 400:
        raise ValueError("Only existing local S4 mock-account range 300..399")
    total_seconds = (args.train_windows + args.calibration_windows + args.test_windows) * 60
    if total_seconds > args.max_seconds:
        raise ValueError("Planned capture exceeds duration guard")
    test_count = args.actors * args.test_windows
    attack_count = round(test_count * args.attack_ratio)
    if not attack_count or attack_count / test_count != args.attack_ratio:
        raise ValueError("Test actor/window count must realize exact requested prevalence")
    if not 1 <= args.max_seconds <= 3600:
        raise ValueError("Duration guard must be at most 3600 seconds")
    return attack_count


def run(args):
    attack_count = validate_args(args)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = REPO / "results/s4-http" / run_id
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + args.max_seconds
    client = Client()
    tokens = {}
    for i in range(args.actors):
        tokens[f"cohort-{i:03d}"] = client.login(args.account_start + i)
        time.sleep(0.3)
    cohort_ids = list(tokens)
    test_count = args.actors * args.test_windows
    # Rotate attack ownership across windows; legitimate accounts switch to abuse.
    positions = list(range(test_count))
    random.Random(args.seed + 999).shuffle(positions)
    attack_positions = set(positions[:attack_count])
    attack_profiles = {position: ("s4_repeated", "s4_burst", "s4_broad")[i % 3]
                       for i, position in enumerate(sorted(attack_positions))}
    rows, truth = [], []
    started = time.time()
    write_json(output / "manifest.json", {
        "schema_version": "zetty.s4-http/1", "dataset_version": "1",
        "profile_version": "2-overlapping-normal-peaks",
        "run_id": run_id, "status": "capturing", "window_seconds": 60,
        "arguments": vars(args), "target": BASE, "tls_verified": True,
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "source_sha256": {name: hashlib.sha256((pathlib.Path(__file__).parent / name).read_bytes()).hexdigest()
                          for name in ("runner.py", "features.py")},
        "body_bytes_provenance": "client_observed_body_bytes",
        "label_unit": "cohort x real fixed 60-second window",
        "label_note": "controlled scenario, valid mock token reuse; no actual theft demonstrated"})
    try:
        for split_index, (split, windows) in enumerate((
                ("train", args.train_windows), ("calibration", args.calibration_windows),
                ("test", args.test_windows))):
            # Renew per split; every capture fits within fixed 900-second AT lifetime.
            if split_index:
                tokens = {}
                for i, cohort in enumerate(cohort_ids):
                    tokens[cohort] = client.login(args.account_start + i)
                    time.sleep(0.3)
            for window in range(windows):
                if time.monotonic() + 60 > deadline:
                    raise RuntimeError("Insufficient remaining duration for complete window")
                start_epoch, start_mono = time.time(), time.monotonic()
                tasks, window_truth = [], []
                rng = random.Random(args.seed + split_index * 10000 + window)
                for i, cohort in enumerate(cohort_ids):
                    attacked = split == "test" and window * args.actors + i in attack_positions
                    profile = attack_profiles[window * args.actors + i] if attacked else (
                        "normal_slow", "normal_slow", "normal_active", "normal_burst")[rng.randrange(4)]
                    window_id = f"{split}-{window:03d}-{cohort}"
                    window_truth.append({"window_id": window_id, "label": int(attacked),
                        "split": split, "profile": profile, "cohort_id": cohort,
                        "window_start_utc": utc(start_epoch),
                        "window_end_utc": utc(start_epoch + 60)})
                    for order, offset in enumerate(schedule(rng, profile)):
                        narrow = profile in ("normal_slow", "s4_repeated")
                        route = ROUTES[order % (2 if narrow else len(ROUTES))]
                        tasks.append((offset, i, order, cohort, window_id, route))
                if len(rows) + len(tasks) > args.max_requests:
                    raise RuntimeError("Request budget would be exceeded; capture aborted")
                pending = set()
                with concurrent.futures.ThreadPoolExecutor(args.concurrency) as pool:
                    for offset, _, _, cohort, window_id, route in sorted(tasks):
                        wait = start_mono + offset - time.monotonic()
                        if wait > 0:
                            time.sleep(wait)
                        while len(pending) >= args.concurrency:
                            done, pending = concurrent.futures.wait(pending,
                                return_when=concurrent.futures.FIRST_COMPLETED)
                            rows.extend(f.result() for f in done)
                        if time.monotonic() - start_mono >= 60:
                            raise RuntimeError("Scheduler exceeds fixed window; invalid capture")
                        pending.add(pool.submit(client.observe, tokens[cohort], cohort,
                                                window_id, route, start_epoch, start_mono))
                    if pending:
                        rows.extend(f.result() for f in concurrent.futures.as_completed(pending))
                if time.monotonic() - start_mono > 60:
                    raise RuntimeError("Responses extend beyond fixed window; invalid capture")
                remaining = 60 - (time.monotonic() - start_mono)
                if remaining > 0:
                    time.sleep(remaining)
                truth.extend(window_truth)
                write_jsonl(output / "observations.jsonl", rows)
                write_jsonl(output / "ground_truth.jsonl", truth)
                print(json.dumps({"capture": run_id, "split": split, "window": window + 1,
                                  "completed_actor_windows": len(truth), "requests": len(rows)}),
                      flush=True)
        resolved, actors = es_join(rows)
        errors = sum(bool(r["error"]) for r in rows)
        denied = sum(r["status"] not in range(200, 300) for r in rows)
        absent_ids = sum(not r["request_id"] for r in rows)
        duplicate_ids = len(rows) - len({r["request_id"] for r in rows})
        missing_join = len(rows) - len(resolved)
        inconsistent_actor = sum(len(values) != 1 for values in actors.values())
        duplicate_actors = len(actors) - len({subject for values in actors.values() for subject in values})
        grouped = collections.defaultdict(list)
        for row in rows:
            grouped[row["window_id"]].append(row)
        invalid_windows = [t["window_id"] for t in truth
                           if not grouped[t["window_id"]]
                           or any(r["error"] or r["status"] is None
                                  or r["client_observed_body_bytes"] is None
                                  or not 0 <= r["offset_s"] < 60
                                  for r in grouped[t["window_id"]])]
        passed = not any((errors, denied, absent_ids, duplicate_ids, missing_join,
                          inconsistent_actor, duplicate_actors, invalid_windows)) and len(actors) == args.actors
        quality = {"status": "pass" if passed else "fail", "pass": passed,
                   "request_count": len(rows), "actor_window_count": len(truth),
                   "transport_errors": errors, "non_2xx_requests": denied,
                   "missing_request_ids": absent_ids, "duplicate_request_ids": duplicate_ids,
                   "missing_verified_actor_join": missing_join,
                   "inconsistent_actor_mappings": inconsistent_actor,
                   "duplicate_actor_mappings": duplicate_actors,
                   "invalid_windows": invalid_windows,
                   "split_counts": {s: {"normal": sum(t["split"] == s and t["label"] == 0 for t in truth),
                                       "attack": sum(t["split"] == s and t["label"] == 1 for t in truth)}
                                    for s in ("train", "calibration", "test")}}
        write_json(output / "quality.json", quality)
        write_json(output / "actor_mapping.json",
                   {"verification": "api ACCESS_DECISION request_id join",
                    "cohorts": {c: sorted(v) for c, v in actors.items()}})
        if not invalid_windows:
            with (output / "features.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=("window_id",) + FEATURE_COLUMNS)
                writer.writeheader()
                for t in truth:
                    writer.writerow({"window_id": t["window_id"], **aggregate(grouped[t["window_id"]])})
            with (output / "labels.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=tuple(truth[0]))
                writer.writeheader()
                writer.writerows(truth)
        manifest = json.loads((output / "manifest.json").read_text())
        manifest.update({"status": quality["status"], "capture_started_utc": utc(started),
                         "capture_ended_utc": utc(time.time()),
                         "elapsed_seconds": time.time() - started,
                         "feature_columns": list(FEATURE_COLUMNS),
                         "statistics": {"interval_first_zero_included": True, "std_ddof": 1},
                         "files_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in output.iterdir() if p.is_file() and p.name != "manifest.json"}})
        write_json(output / "manifest.json", manifest)
        print(json.dumps({"output": str(output), "quality": quality}), flush=True)
        if not passed:
            raise RuntimeError("Capture quality failed; never train as normal silently")
    except BaseException as error:
        write_jsonl(output / "observations.jsonl", rows)
        write_jsonl(output / "ground_truth.jsonl", truth)
        manifest = json.loads((output / "manifest.json").read_text())
        manifest["status"] = "failed"
        write_json(output / "manifest.json", manifest)
        write_json(output / "failure.json", {"error_type": type(error).__name__,
                   "completed_requests": len(rows), "completed_actor_windows": len(truth)})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actors", type=int, default=20)
    parser.add_argument("--account-start", type=int, default=300)
    parser.add_argument("--train-windows", type=int, default=3)
    parser.add_argument("--calibration-windows", type=int, default=2)
    parser.add_argument("--test-windows", type=int, default=5)
    parser.add_argument("--attack-ratio", type=float, default=0.05)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-requests", type=int, default=15000)
    parser.add_argument("--max-seconds", type=int, default=900)
    parser.add_argument("--seed", type=int, default=20261003)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        # Runtime exceptions may contain credentials (HTTP library); never dump traceback.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
