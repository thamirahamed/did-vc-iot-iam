import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path


FIELDS = [
    "metric",
    "left_p50",
    "right_p50",
    "p50_delta",
    "p50_ratio",
    "left_p95",
    "right_p95",
    "p95_delta",
    "p95_ratio",
]


def main() -> None:
    args = parse_args()
    left = read_summary(args.left_summary)
    right = read_summary(args.right_summary)
    rows = build_comparison(left, right)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"benchmark_comparison_{timestamp}.csv"
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Left: {args.left_label} ({args.left_summary})")
    print(f"Right: {args.right_label} ({args.right_summary})")
    print_table(rows)
    print(f"Comparison results: {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two benchmark summary CSV files.")
    parser.add_argument("left_summary")
    parser.add_argument("right_summary")
    parser.add_argument("--left-label", default="left")
    parser.add_argument("--right-label", default="right")
    parser.add_argument("--output-dir", default="results")
    return parser.parse_args()


def read_summary(path_value: str) -> dict[str, dict[str, float]]:
    path = Path(path_value)
    if not path.exists():
        raise SystemExit(f"summary CSV not found: {path}")
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"metric", "p50", "p95"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise SystemExit(f"summary CSV missing required columns: {path}")
        rows = {}
        for row in reader:
            metric = row.get("metric", "").strip()
            if not metric:
                continue
            try:
                rows[metric] = {
                    "p50": float(row.get("p50", "")),
                    "p95": float(row.get("p95", "")),
                }
            except ValueError:
                continue
        return rows


def build_comparison(
    left: dict[str, dict[str, float]], right: dict[str, dict[str, float]]
) -> list[dict[str, str]]:
    rows = []
    for metric in sorted(set(left) & set(right)):
        left_p50 = left[metric]["p50"]
        right_p50 = right[metric]["p50"]
        left_p95 = left[metric]["p95"]
        right_p95 = right[metric]["p95"]
        rows.append(
            {
                "metric": metric,
                "left_p50": fmt(left_p50),
                "right_p50": fmt(right_p50),
                "p50_delta": fmt(right_p50 - left_p50),
                "p50_ratio": ratio(right_p50, left_p50),
                "left_p95": fmt(left_p95),
                "right_p95": fmt(right_p95),
                "p95_delta": fmt(right_p95 - left_p95),
                "p95_ratio": ratio(right_p95, left_p95),
            }
        )
    if not rows:
        raise SystemExit("no comparable metrics found")
    return rows


def ratio(numerator: float, denominator: float) -> str:
    if denominator == 0:
        return ""
    return fmt(numerator / denominator)


def fmt(value: float) -> str:
    return f"{value:.3f}"


def print_table(rows: list[dict[str, str]]) -> None:
    widths = {field: len(field) for field in FIELDS}
    for row in rows:
        for field in FIELDS:
            widths[field] = max(widths[field], len(row[field]))
    print("  ".join(field.ljust(widths[field]) for field in FIELDS))
    print("  ".join("-" * widths[field] for field in FIELDS))
    for row in rows:
        print("  ".join(row[field].ljust(widths[field]) for field in FIELDS))


if __name__ == "__main__":
    main()
