import csv
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


AGENT_URL = os.getenv("BENCHMARK_AGENT_GATEWAY_URL", "http://benchmark-agent-gateway:8031").rstrip("/")
RUNS = int(os.getenv("BENCHMARK_RUNS", "1"))
WARMUP_RUNS = int(os.getenv("BENCHMARK_WARMUP_RUNS", "0"))
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "900"))
FORCE_FRESH_VERIFIER_STATE = (
    os.getenv("BENCHMARK_FORCE_FRESH_VERIFIER_STATE", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)

# Map from agent summary keys to the metric column names expected by
# _parse_pipeline_summary() / BENCHMARK_LABELS in dashboard-api/app/main.py.
# Keys that the agent does not expose are intentionally absent — the backend
# will treat them as missing rather than zero.
AGENT_TO_METRIC = {
    "full_lifecycle_ms": "full_iteration_ms",
    "auth_allow_ms": "auth_allow_ms",
    "proof_refresh_ms": "proof_refresh_ms",
    "did_create_ms": "did_create_ms",
    "did_resolve_ms": "did_resolve_ms",
    "identity_vc_issue_ms": "identity_vc_issue_ms",
    "capability_vc_issue_ms": "capability_vc_issue_ms",
    "revoke_capability_ms": "revoke_capability_ms",
    "auth_wrong_action_deny_ms": "auth_wrong_action_deny_ms",
    "auth_revoked_or_stale_deny_ms": "auth_revoked_or_stale_deny_ms",
    "replacement_capability_issue_ms": "replacement_capability_issue_ms",
    "auth_replacement_allow_ms": "auth_replacement_allow_ms",
    # size fields passed through as extra rows (float-safe)
    "auth_allow_request_bytes": "auth_allow_request_bytes",
    "identity_vc_bytes": "identity_vc_bytes",
    "capability_vc_bytes": "capability_vc_bytes",
    "identity_proof_bytes": "identity_proof_bytes",
    "capability_proof_bytes": "capability_proof_bytes",
    "auth_allow_response_bytes": "auth_allow_response_bytes",
    "revoke_response_bytes": "revoke_response_bytes",
    "accumulator_state_bytes": "accumulator_state_bytes",
}


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    response = post_json(
        f"{AGENT_URL}/run-pipeline",
        {
            "runs": RUNS,
            "warmup_runs": WARMUP_RUNS,
            "profile": os.getenv("BENCHMARK_AGENT_PROFILE", "gateway"),
            "preserve_wallet": False,
            "network_profile": os.getenv("NETWORK_PROFILE", "none"),
            "force_fresh_verifier_state": FORCE_FRESH_VERIFIER_STATE,
        },
    )
    summary = response.get("summary") if isinstance(response, dict) else {}
    if not isinstance(summary, dict):
        raise RuntimeError(f"agent response missing summary: {response}")

    # Always write a local benchmark_summary_*.csv so that the dashboard-api
    # _parse_pipeline_summary() can find and parse it.  The agent may return a
    # "source" path pointing to its own file, but that file lives inside the
    # agent container and is not readable by the dashboard-api process.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    summary_path = OUTPUT_DIR / f"benchmark_summary_{timestamp}.csv"
    rows = summary_to_rows(summary)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "count", "mean", "min", "max", "p50", "p95"])
        writer.writeheader()
        writer.writerows(rows)

    agent_source = summary.get("source") or summary.get("raw_source") or ""
    print(f"Agent pipeline summary results written to: {summary_path}")
    if agent_source:
        print(f"Agent internal source: {agent_source}")
    print(f"Agent pipeline proxy duration: {round((time.perf_counter() - started) * 1000, 3)} ms")


def summary_to_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert an agent /run-pipeline summary dict into CSV rows that match the
    format written by benchmark_pipeline.py and expected by _parse_pipeline_summary()."""
    rows = []
    for agent_key, metric in AGENT_TO_METRIC.items():
        value = summary.get(agent_key)
        if isinstance(value, (int, float)):
            rows.append(
                {
                    "metric": metric,
                    "count": 1,
                    "mean": value,
                    "min": value,
                    "max": value,
                    "p50": value,
                    "p95": value,
                }
            )
    return rows


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    except (ConnectionError, TimeoutError, URLError) as exc:
        raise RuntimeError(f"request failed: {url}: {exc}") from exc


if __name__ == "__main__":
    main()
