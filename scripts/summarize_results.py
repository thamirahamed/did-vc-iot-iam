import csv
import math
import sys
from pathlib import Path
from statistics import mean
from typing import Iterable


NUMERIC_METRICS = [
    "did_create_ms",
    "did_resolve_ms",
    "identity_vc_issue_ms",
    "capability_vc_issue_ms",
    "auth_allow_ms",
    "auth_wrong_action_deny_ms",
    "revoke_capability_ms",
    "auth_revoked_or_stale_deny_ms",
    "replacement_capability_issue_ms",
    "proof_refresh_ms",
    "auth_replacement_allow_ms",
    "full_iteration_ms",
    "identity_vc_bytes",
    "capability_vc_bytes",
    "identity_proof_bytes",
    "capability_proof_bytes",
    "auth_allow_request_bytes",
    "auth_allow_response_bytes",
    "revoke_response_bytes",
    "accumulator_state_bytes",
]

SUMMARY_FIELDS = ["metric", "count", "mean", "min", "max", "p50", "p95"]
RESOURCE_METRICS = [
    "cpu_percent",
    "memory_usage_bytes",
    "memory_percent",
    "network_rx_bytes",
    "network_tx_bytes",
    "block_read_bytes",
    "block_write_bytes",
]
RESOURCE_SUMMARY_FIELDS = ["container_name", *SUMMARY_FIELDS]


def summarize_csv(csv_path: str | Path) -> Path:
    path = Path(csv_path)
    fieldnames = read_fieldnames(path)
    if is_resource_csv(fieldnames):
        return summarize_resource_csv(path)
    return summarize_raw_csv(path)


def summarize_raw_csv(raw_csv_path: str | Path) -> Path:
    raw_path = Path(raw_csv_path)
    rows = read_raw_rows(raw_path)
    summary_path = raw_path.with_name(raw_path.name.replace("benchmark_raw_", "benchmark_summary_", 1))
    if summary_path == raw_path:
        summary_path = raw_path.with_name(f"{raw_path.stem}_summary{raw_path.suffix}")

    summary_rows = build_summary(rows)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)

    print_summary(summary_rows)
    return summary_path


def summarize_resource_csv(resource_csv_path: str | Path) -> Path:
    resource_path = Path(resource_csv_path)
    rows = read_resource_rows(resource_path)
    summary_path = resource_path.with_name(
        resource_path.name.replace("resource_usage_", "resource_summary_", 1)
    )
    if summary_path == resource_path:
        summary_path = resource_path.with_name(f"{resource_path.stem}_summary{resource_path.suffix}")

    summary_rows = build_resource_summary(rows)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESOURCE_SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)

    print_resource_summary(summary_rows)
    return summary_path


def read_fieldnames(path: Path) -> list[str]:
    if not path.exists():
        raise SystemExit(f"CSV not found: {path}")
    if not path.is_file():
        raise SystemExit(f"CSV path is not a file: {path}")
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise SystemExit(f"CSV is empty or missing a header: {path}")
        return reader.fieldnames


def read_raw_rows(raw_path: Path) -> list[dict[str, str]]:
    if not raw_path.exists():
        raise SystemExit(f"raw CSV not found: {raw_path}")
    if not raw_path.is_file():
        raise SystemExit(f"raw CSV path is not a file: {raw_path}")

    with raw_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise SystemExit(f"raw CSV is empty or missing a header: {raw_path}")
        missing = [field for field in NUMERIC_METRICS if field not in reader.fieldnames]
        if "error" not in reader.fieldnames:
            missing.append("error")
        if missing:
            raise SystemExit(f"raw CSV missing expected columns: {', '.join(missing)}")
        return list(reader)


def read_resource_rows(resource_path: Path) -> list[dict[str, str]]:
    if not resource_path.exists():
        raise SystemExit(f"resource CSV not found: {resource_path}")
    if not resource_path.is_file():
        raise SystemExit(f"resource CSV path is not a file: {resource_path}")

    with resource_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise SystemExit(f"resource CSV is empty or missing a header: {resource_path}")
        missing = [
            field
            for field in ["container_name", *RESOURCE_METRICS]
            if field not in reader.fieldnames
        ]
        if missing:
            raise SystemExit(f"resource CSV missing expected columns: {', '.join(missing)}")
        return list(reader)


def build_summary(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    successful_rows = [row for row in rows if not row.get("error", "").strip()]
    summary_rows = []
    for metric in NUMERIC_METRICS:
        values = []
        for row in successful_rows:
            value = row.get(metric, "").strip()
            if value == "":
                continue
            try:
                values.append(float(value))
            except ValueError:
                continue
        summary_rows.append(summarize_metric(metric, values))
    return summary_rows


def build_resource_summary(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        container_name = row.get("container_name", "").strip()
        if not container_name:
            continue
        grouped.setdefault(container_name, []).append(row)

    summary_rows = []
    for container_name in sorted(grouped):
        container_rows = grouped[container_name]
        for metric in RESOURCE_METRICS:
            values = []
            for row in container_rows:
                value = row.get(metric, "").strip()
                if value == "":
                    continue
                try:
                    values.append(float(value))
                except ValueError:
                    continue
            metric_summary = summarize_metric(metric, values)
            summary_rows.append({"container_name": container_name, **metric_summary})
    return summary_rows


def is_resource_csv(fieldnames: list[str]) -> bool:
    fields = set(fieldnames)
    return {"container_name", *RESOURCE_METRICS}.issubset(fields)


def summarize_metric(metric: str, values: list[float]) -> dict[str, str]:
    if not values:
        return {
            "metric": metric,
            "count": "0",
            "mean": "",
            "min": "",
            "max": "",
            "p50": "",
            "p95": "",
        }
    values = sorted(values)
    return {
        "metric": metric,
        "count": str(len(values)),
        "mean": format_number(mean(values)),
        "min": format_number(values[0]),
        "max": format_number(values[-1]),
        "p50": format_number(percentile(values, 50)),
        "p95": format_number(percentile(values, 95)),
    }


def percentile(sorted_values: list[float], percentile_value: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (percentile_value / 100) * (len(sorted_values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_values[int(rank)]
    weight = rank - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def format_number(value: float) -> str:
    return f"{value:.3f}"


def print_summary(summary_rows: list[dict[str, str]]) -> None:
    widths = {
        "metric": max(len("metric"), *(len(row["metric"]) for row in summary_rows)),
        "count": len("count"),
        "mean": len("mean"),
        "min": len("min"),
        "max": len("max"),
        "p50": len("p50"),
        "p95": len("p95"),
    }
    for row in summary_rows:
        for field in widths:
            widths[field] = max(widths[field], len(row[field]))

    header = "  ".join(field.ljust(widths[field]) for field in SUMMARY_FIELDS)
    print(header)
    print("  ".join("-" * widths[field] for field in SUMMARY_FIELDS))
    for row in summary_rows:
        print("  ".join(row[field].ljust(widths[field]) for field in SUMMARY_FIELDS))


def print_resource_summary(summary_rows: list[dict[str, str]]) -> None:
    widths = {
        "container_name": max(
            len("container_name"),
            *(len(row["container_name"]) for row in summary_rows),
        )
        if summary_rows
        else len("container_name"),
        "metric": max(len("metric"), *(len(row["metric"]) for row in summary_rows))
        if summary_rows
        else len("metric"),
        "count": len("count"),
        "mean": len("mean"),
        "min": len("min"),
        "max": len("max"),
        "p50": len("p50"),
        "p95": len("p95"),
    }
    for row in summary_rows:
        for field in widths:
            widths[field] = max(widths[field], len(row[field]))

    header = "  ".join(field.ljust(widths[field]) for field in RESOURCE_SUMMARY_FIELDS)
    print(header)
    print("  ".join("-" * widths[field] for field in RESOURCE_SUMMARY_FIELDS))
    for row in summary_rows:
        print(
            "  ".join(row[field].ljust(widths[field]) for field in RESOURCE_SUMMARY_FIELDS)
        )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/summarize_results.py <csv_path>")
    summary_path = summarize_csv(sys.argv[1])
    print(f"Summary results: {summary_path}")


if __name__ == "__main__":
    main()
