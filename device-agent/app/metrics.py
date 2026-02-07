import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List


@dataclass
class MetricRow:
    ts_iso: str
    iteration: int
    t_sign_ms: float
    t_authorize_ms: float
    decision: str
    reason: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return float(ordered[low])
    weight = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * weight)


def write_csv(path: str, rows: Iterable[MetricRow]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["ts_iso", "iteration", "t_sign_ms", "t_authorize_ms", "decision", "reason"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.ts_iso,
                    row.iteration,
                    f"{row.t_sign_ms:.3f}",
                    f"{row.t_authorize_ms:.3f}",
                    row.decision,
                    row.reason,
                ]
            )


def summarize(rows: Iterable[MetricRow]) -> dict:
    row_list = list(rows)
    sign_values = [row.t_sign_ms for row in row_list]
    auth_values = [row.t_authorize_ms for row in row_list]
    allow_count = sum(1 for row in row_list if row.decision == "allow")
    deny_count = len(row_list) - allow_count
    return {
        "runs": len(row_list),
        "allow_count": allow_count,
        "deny_count": deny_count,
        "sign_p50_ms": percentile(sign_values, 50),
        "sign_p95_ms": percentile(sign_values, 95),
        "authorize_p50_ms": percentile(auth_values, 50),
        "authorize_p95_ms": percentile(auth_values, 95),
    }
