import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from network_faults import (
    PacketLossUnsupported,
    ToxiproxyUnavailable,
    apply_disconnect,
    apply_latency_250,
    apply_packet_loss_10,
    clear_toxics,
    setup_proxies,
)


ISSUER_URL = os.getenv("ISSUER_URL", "http://issuer:8000").rstrip("/")
AGENT_A_URL = os.getenv("BENCHMARK_AGENT_GATEWAY_URL", "http://benchmark-agent-gateway:8031").rstrip("/")
AGENT_B_URL = os.getenv("BENCHMARK_AGENT_CONSTRAINED_URL", "http://benchmark-agent-constrained:8031").rstrip("/")
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
REVOCATION_DELAY_SECONDS = float(os.getenv("REVOCATION_DELAY_SECONDS", "5"))
VERIFIER_CACHE_WAIT_SECONDS = float(os.getenv("VERIFIER_CACHE_WAIT_SECONDS", "2.2"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "60"))
SHOW_UNSUPPORTED_NETWORK_TESTS = os.getenv("SHOW_UNSUPPORTED_NETWORK_TESTS", "false").strip().lower() == "true"
ACTION = "read"
RESOURCE = "iot:device:example"
DEVICE_A_LABEL = os.getenv("BENCHMARK_DEVICE_A_LABEL", "benchmark-device-01")
DEVICE_B_LABEL = os.getenv("BENCHMARK_DEVICE_B_LABEL", "benchmark-device-02")
DEVICE_A_ACTOR = DEVICE_A_LABEL
DEVICE_A_STALE_AFTER_B_ACTOR = f"{DEVICE_A_LABEL}, stale after {DEVICE_B_LABEL} update"
DEVICE_A_REVOKED_ACTOR = f"{DEVICE_A_LABEL} revoked capability"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = OUTPUT_DIR / f"revocation_connectivity_{timestamp}.json"
    reset_agent(AGENT_A_URL)
    reset_agent(AGENT_B_URL)
    toxiproxy_available, toxiproxy_reason = setup_network_faults()
    rows = [
        run_case("Valid proof authorization", DEVICE_A_ACTOR, "allow", valid_allow),
        run_case("Active stale proof denial", DEVICE_A_STALE_AFTER_B_ACTOR, "deny", active_stale_deny),
        run_case("Active stale proof refresh recovery", DEVICE_A_ACTOR, "allow", active_stale_refresh_recovery),
        run_case("Revoked stale proof denial", DEVICE_A_REVOKED_ACTOR, "deny", revoked_stale_deny),
        run_case("Revoked proof refresh blocked", DEVICE_A_REVOKED_ACTOR, "blocked", revoked_refresh_blocked),
        run_case("Restore access recovery", DEVICE_A_ACTOR, "allow", restore_access_recovery),
        run_case("Delayed reconnect refresh", DEVICE_A_STALE_AFTER_B_ACTOR, "allow", delayed_reconnect_refresh),
        network_fault_case(
            "Latency affected proof refresh",
            DEVICE_A_STALE_AFTER_B_ACTOR,
            "allow",
            toxiproxy_available,
            toxiproxy_reason,
            latency_affected_proof_refresh,
        ),
        network_fault_case(
            "Connection disruption recovery",
            DEVICE_A_ACTOR,
            "allow",
            toxiproxy_available,
            toxiproxy_reason,
            connection_disruption_recovery,
        ),
    ]
    debug_unsupported_tests = []
    packet_loss_row = network_fault_case(
        "Packet loss / loss-like disruption",
        DEVICE_A_ACTOR,
        "not_supported",
        toxiproxy_available,
        toxiproxy_reason,
        packet_loss_or_loss_like,
    )
    if packet_loss_row.get("status") == "not-supported" and not SHOW_UNSUPPORTED_NETWORK_TESTS:
        debug_unsupported_tests.append(packet_loss_row)
    else:
        rows.append(packet_loss_row)
    result = {
        "benchmark_type": "revocation_connectivity",
        "profile": "accumulator_connectivity",
        "mode": "fabric device agent workflow",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "devices": {
            "Device A": DEVICE_A_LABEL,
            "Device B": DEVICE_B_LABEL,
        },
        "tests": rows,
    }
    if debug_unsupported_tests:
        result["debug_unsupported_tests"] = debug_unsupported_tests
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Revocation connectivity results: {output_path}")


def valid_allow() -> tuple[str, str, dict[str, Any]]:
    onboard_issue_refresh(AGENT_A_URL)
    response = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    return response["final_decision"], response["final_reason"], {
        "valid_allow_ms": response["total_latency_ms"],
    }


def active_stale_deny() -> tuple[str, str, dict[str, Any]]:
    # Device B changes the accumulator while Device A remains active and unrefreshed.
    onboard_issue_refresh(AGENT_B_URL)
    b_wallet = get_wallet(AGENT_B_URL)
    revoke_credential(str(b_wallet["capability_credential_id"]), "active stale proof benchmark")
    wait_for_verifier_cache()
    response = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    return response["final_decision"], response["final_reason"], {
        "active_stale_deny_ms": response["total_latency_ms"],
    }


def active_stale_refresh_recovery() -> tuple[str, str, dict[str, Any]]:
    response = authorize(AGENT_A_URL, auto_refresh=True, retry_on_stale=True)
    return response["final_decision"], response["final_reason"], {
        "active_stale_refresh_ms": response["refresh_latency_ms"],
        "active_stale_retry_allow_ms": response["authorization_latency_ms"],
        "refresh_attempted": response["refresh_attempted"],
    }


def revoked_stale_deny() -> tuple[str, str, dict[str, Any]]:
    a_wallet = get_wallet(AGENT_A_URL)
    revoke_credential(str(a_wallet["capability_credential_id"]), "revoked stale proof benchmark")
    wait_for_verifier_cache()
    response = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    return response["final_decision"], response["final_reason"], {
        "revoked_stale_deny_ms": response["total_latency_ms"],
    }


def revoked_refresh_blocked() -> tuple[str, str, dict[str, Any]]:
    started = time.perf_counter()
    try:
        post_json(f"{AGENT_A_URL}/refresh-proof", {"credential_type": "capability"})
    except RuntimeError as exc:
        reason = str(exc)
        return "blocked", reason, {
            "revoked_refresh_failure_ms": elapsed_ms(started),
        }
    return "allow", "revoked credential unexpectedly refreshed", {
        "revoked_refresh_failure_ms": elapsed_ms(started),
    }


def restore_access_recovery() -> tuple[str, str, dict[str, Any]]:
    started = time.perf_counter()
    old_wallet = get_wallet(AGENT_A_URL)
    old_id = old_wallet.get("capability_credential_id")
    post_json(f"{AGENT_A_URL}/issue-capability", {"action": ACTION, "resource": RESOURCE})
    refresh(AGENT_A_URL, "identity")
    refresh(AGENT_A_URL, "capability")
    new_wallet = get_wallet(AGENT_A_URL)
    new_id = new_wallet.get("capability_credential_id")
    if new_id == old_id:
        return "deny", "replacement capability id reused", {"restore_access_ms": elapsed_ms(started)}
    response = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    return response["final_decision"], response["final_reason"], {
        "restore_access_ms": elapsed_ms(started),
        "old_capability_id": old_id,
        "new_capability_id": new_id,
    }


def delayed_reconnect_refresh() -> tuple[str, str, dict[str, Any]]:
    # Device A stays active but does not refresh while Device B changes accumulator state.
    onboard_issue_refresh(AGENT_B_URL)
    b_wallet = get_wallet(AGENT_B_URL)
    revoke_credential(str(b_wallet["capability_credential_id"]), "delayed reconnect benchmark")
    time.sleep(REVOCATION_DELAY_SECONDS)
    started = time.perf_counter()
    refresh(AGENT_A_URL, "identity")
    refresh(AGENT_A_URL, "capability")
    response = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    return response["final_decision"], response["final_reason"], {
        "delayed_reconnect_refresh_ms": elapsed_ms(started),
    }


def latency_affected_proof_refresh() -> tuple[str, str, dict[str, Any]]:
    clear_toxics()
    onboard_issue_refresh(AGENT_A_URL)
    onboard_issue_refresh(AGENT_B_URL)
    b_wallet = get_wallet(AGENT_B_URL)
    revoke_credential(str(b_wallet["capability_credential_id"]), "latency network fault benchmark")
    wait_for_verifier_cache()
    apply_latency_250()
    started = time.perf_counter()
    refresh_response = refresh(
        AGENT_A_URL,
        "identity",
        network_profile="latency_250",
        network_retries=2,
        network_retry_delay_ms=500,
    )
    refresh(AGENT_A_URL, "capability", network_profile="latency_250")
    auth_response = authorize(
        AGENT_A_URL,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile="latency_250",
        network_retries=2,
        network_retry_delay_ms=500,
    )
    return auth_response["final_decision"], auth_response["final_reason"], {
        "latency_refresh_ms": refresh_response.get("latency_ms"),
        "latency_authorize_ms": auth_response.get("authorization_latency_ms"),
        "total_latency_ms": elapsed_ms(started),
        "network_retries_used": auth_response.get("network_retries_used"),
    }


def connection_disruption_recovery() -> tuple[str, str, dict[str, Any]]:
    clear_toxics()
    onboard_issue_refresh(AGENT_A_URL)
    apply_disconnect()
    failure_started = time.perf_counter()
    failure = authorize(
        AGENT_A_URL,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile="disconnect",
        network_retries=1,
        network_retry_delay_ms=250,
    )
    failure_latency = elapsed_ms(failure_started)
    clear_toxics()
    recovery_started = time.perf_counter()
    recovery = authorize(AGENT_A_URL, auto_refresh=False, retry_on_stale=False)
    recovery_latency = elapsed_ms(recovery_started)
    expected_failure = failure.get("final_decision") in {"network_error", "connection_timeout"}
    actual = recovery["final_decision"] if expected_failure else "fail"
    reason = recovery["final_reason"] if expected_failure else f"expected network error, got {failure}"
    return actual, reason, {
        "failure_latency_ms": failure_latency,
        "recovery_latency_ms": recovery_latency,
        "network_error": failure.get("network_error"),
    }


def packet_loss_or_loss_like() -> tuple[str, str, dict[str, Any]]:
    try:
        apply_packet_loss_10()
    except PacketLossUnsupported as exc:
        return "not_supported", str(exc), {}
    onboard_issue_refresh(AGENT_A_URL)
    response = authorize(
        AGENT_A_URL,
        auto_refresh=True,
        retry_on_stale=True,
        network_profile="packet_loss_10",
        network_retries=2,
        network_retry_delay_ms=500,
    )
    return response["final_decision"], response["final_reason"], {
        "network_retries_used": response.get("network_retries_used"),
        "network_error": response.get("network_error"),
    }


def setup_network_faults() -> tuple[bool, str | None]:
    try:
        setup_proxies()
        clear_toxics()
        return True, None
    except ToxiproxyUnavailable as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"Toxiproxy setup failed: {exc}"


def onboard_issue_refresh(agent_url: str) -> None:
    post_json(f"{agent_url}/wallet/reset", {})
    post_json(f"{agent_url}/onboard", {})
    post_json(f"{agent_url}/issue-identity", {})
    post_json(f"{agent_url}/issue-capability", {"action": ACTION, "resource": RESOURCE})
    refresh(agent_url, "identity")
    refresh(agent_url, "capability")


def run_case(name: str, actor: str, expected: str, callback) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        actual, reason, details = callback()
        status = "not-supported" if actual == "not_supported" else "pass" if actual == expected else "fail"
    except Exception as exc:
        actual = "error"
        reason = str(exc)
        details = {}
        status = "fail"
    return {
        "test": name,
        "actor": actor,
        "expected": expected,
        "actual": actual,
        "reason": reason,
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "status": status,
        "details": details,
    }


def network_fault_case(
    name: str,
    actor: str,
    expected: str,
    toxiproxy_available: bool,
    toxiproxy_reason: str | None,
    callback,
) -> dict[str, Any]:
    if not toxiproxy_available:
        return {
            "test": name,
            "actor": actor,
            "expected": expected,
            "actual": "not_supported",
            "reason": toxiproxy_reason or "Toxiproxy service unavailable",
            "latency_ms": None,
            "status": "not-supported",
            "details": {},
        }
    row = run_case(name, actor, expected, callback)
    try:
        clear_toxics()
    except Exception:
        pass
    return row


def reset_agent(agent_url: str) -> None:
    post_json(f"{agent_url}/wallet/reset", {})


def refresh(
    agent_url: str,
    credential_type: str,
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
) -> dict[str, Any]:
    return post_json(
        f"{agent_url}/refresh-proof",
        {
            "credential_type": credential_type,
            "network_profile": network_profile,
            "network_retries": network_retries,
            "network_retry_delay_ms": network_retry_delay_ms,
        },
    )


def authorize(
    agent_url: str,
    auto_refresh: bool,
    retry_on_stale: bool,
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
) -> dict[str, Any]:
    return post_json(
        f"{agent_url}/authorize",
        {
            "requested_action": ACTION,
            "requested_resource": RESOURCE,
            "auto_refresh": auto_refresh,
            "retry_on_stale": retry_on_stale,
            "network_profile": network_profile,
            "network_retries": network_retries,
            "network_retry_delay_ms": network_retry_delay_ms,
        },
    )


def get_wallet(agent_url: str) -> dict[str, Any]:
    return get_json(f"{agent_url}/wallet")


def revoke_credential(credential_id: str, reason: str) -> dict[str, Any]:
    return post_json(f"{ISSUER_URL}/vc/revoke", {"credential_id": credential_id, "reason": reason})


def wait_for_verifier_cache() -> None:
    if VERIFIER_CACHE_WAIT_SECONDS > 0:
        time.sleep(VERIFIER_CACHE_WAIT_SECONDS)


def get_json(url: str) -> dict[str, Any]:
    request = Request(url, method="GET")
    return send_json(request)


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    return send_json(request)


def send_json(request: Request) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(extract_error_detail(exc.code, body)) from exc
    except (ConnectionError, TimeoutError, URLError) as exc:
        raise RuntimeError(f"request failed: {request.full_url}: {exc}") from exc


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def extract_error_detail(status_code: int, body: str) -> str:
    try:
        parsed = json.loads(body)
        detail = parsed.get("detail")
        if detail:
            return str(detail)
    except Exception:
        pass
    return f"request failed: {status_code} {body}"


if __name__ == "__main__":
    main()
