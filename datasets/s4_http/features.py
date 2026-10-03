"""Pure actor/window aggregation. IDs and labels never enter numeric features."""
import collections
import statistics

FEATURE_COLUMNS = ("request_count", "mean_interval_s", "interval_std_s",
                   "distinct_uri_count", "response_bytes_sum", "response_bytes_mean",
                   "response_bytes_std", "4xx_ratio", "5xx_ratio", "GET_ratio",
                   "POST_ratio", "burst_max_per_s", "GET_count", "successful_2xx_count")


def aggregate(observations):
    rows = sorted(observations, key=lambda r: r["offset_s"])
    if not rows:
        raise ValueError("Empty windows are invalid, not normal training examples")
    n = len(rows)
    gaps = [0.0] + [b["offset_s"] - a["offset_s"] for a, b in zip(rows, rows[1:])]
    sizes = [r["client_observed_body_bytes"] for r in rows]
    if any(r["error"] or r["status"] is None or size is None
           for r, size in zip(rows, sizes)):
        raise ValueError("Failed observations require explicit quality failure")
    get_count = sum(r["method"] == "GET" for r in rows)
    values = (n, statistics.mean(gaps), statistics.stdev(gaps) if n > 1 else 0.0,
              len({r["route"] for r in rows}), sum(sizes), statistics.mean(sizes),
              statistics.stdev(sizes) if n > 1 else 0.0,
              sum(400 <= r["status"] < 500 for r in rows) / n,
              sum(500 <= r["status"] < 600 for r in rows) / n, get_count / n,
              sum(r["method"] == "POST" for r in rows) / n,
              max(collections.Counter(int(r["offset_s"]) for r in rows).values()),
              get_count, sum(200 <= r["status"] < 300 for r in rows))
    return dict(zip(FEATURE_COLUMNS, values))
