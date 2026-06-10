import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


FABRIC_ADAPTER_URL = os.getenv("FABRIC_ADAPTER_URL", "http://localhost:8010").rstrip("/")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20"))


def main() -> None:
    health = http_get_json(f"{FABRIC_ADAPTER_URL}/health")
    if not health.get("ok"):
        raise RuntimeError(f"adapter health failed: {health}")
    print("Adapter health ok")

    ping = chaincode_query("Ping", [])
    expect_ok(ping, "adapter ping")
    print("Adapter ping ok")

    event = {
        "event_id": f"adapter-smoke-{uuid.uuid4()}",
        "event_type": "FABRIC_ADAPTER_SMOKE_TEST",
        "subject_did": "did:iot:adapter-smoke",
        "credential_id": f"urn:uuid:adapter-smoke-{uuid.uuid4()}",
        "decision": "allow",
        "reason": "smoke test",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "service": "fabric-adapter-smoke-test",
        "metadata": {"source": "scripts/fabric_adapter_smoke_test.py"},
    }
    invoke = chaincode_invoke(
        "AddAuditEvent",
        [json.dumps(event, sort_keys=True, separators=(",", ":"))],
    )
    expect_ok(invoke, "adapter invoke")
    print("Adapter invoke ok")

    audit_events = chaincode_query("ListAuditEvents", ["5"])
    if audit_events.get("ok"):
        print("Adapter list audit events ok")
    else:
        print(f"Adapter list audit events skipped: {error_message(audit_events)}")

    print("Fabric adapter smoke test passed")


def chaincode_query(function: str, args: list[str]) -> dict:
    return http_post_json(f"{FABRIC_ADAPTER_URL}/chaincode/query", {"function": function, "args": args})


def chaincode_invoke(function: str, args: list[str]) -> dict:
    return http_post_json(f"{FABRIC_ADAPTER_URL}/chaincode/invoke", {"function": function, "args": args})


def http_get_json(url: str) -> dict:
    return http_json(Request(url, method="GET"))


def http_post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return http_json(
        Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    )


def http_json(request: Request) -> dict:
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    except (ConnectionError, TimeoutError, URLError) as exc:
        raise RuntimeError(f"request failed: {request.full_url}: {exc}") from exc

    return json.loads(raw.decode("utf-8"))


def expect_ok(result: dict, label: str) -> None:
    if not result.get("ok"):
        raise RuntimeError(f"{label} failed: {error_message(result)}")


def error_message(result: dict) -> str:
    return str(result.get("error") or result.get("stderr") or result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"Fabric adapter smoke test failed: {exc}", file=sys.stderr)
        sys.exit(1)
