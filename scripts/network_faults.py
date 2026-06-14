import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


TOXIPROXY_URL = os.getenv("TOXIPROXY_URL", "http://toxiproxy:8474").rstrip("/")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
PROXIES = {
    "issuer_proxy": {
        "listen": "0.0.0.0:18000",
        "upstream": "issuer:8000",
    },
    "verifier_proxy": {
        "listen": "0.0.0.0:18001",
        "upstream": "verifier:8001",
    },
    "fabric_adapter_proxy": {
        "listen": "0.0.0.0:18010",
        "upstream": "fabric-adapter:8010",
    },
}


class ToxiproxyUnavailable(RuntimeError):
    pass


class PacketLossUnsupported(RuntimeError):
    pass


def setup_proxies() -> dict[str, Any]:
    health_check()
    created = {}
    for name, config in PROXIES.items():
        delete_proxy(name, ignore_missing=True)
        created[name] = create_proxy(name, config["listen"], config["upstream"])
        clear_toxics(name)
    return created


def health_check() -> dict[str, Any]:
    try:
        return get_json("/proxies")
    except Exception as exc:
        raise ToxiproxyUnavailable(f"Toxiproxy service unavailable: {exc}") from exc


def clear_toxics(proxy_name: str | None = None) -> None:
    proxies = [proxy_name] if proxy_name else list(PROXIES)
    for name in proxies:
        try:
            proxy = get_json(f"/proxies/{name}")
        except Exception:
            continue
        toxics = proxy.get("toxics", [])
        if isinstance(toxics, list):
            for toxic in toxics:
                toxic_name = toxic.get("name") if isinstance(toxic, dict) else None
                if toxic_name:
                    delete_json(f"/proxies/{name}/toxics/{toxic_name}", ignore_missing=True)


def apply_packet_loss_10() -> None:
    raise PacketLossUnsupported(
        "Toxiproxy does not expose a direct packet loss toxic in this environment"
    )


def apply_latency_250() -> None:
    clear_toxics()
    toxic = {
        "name": "latency_250_downstream",
        "type": "latency",
        "stream": "downstream",
        "toxicity": 1.0,
        "attributes": {"latency": 250, "jitter": 50},
    }
    post_json("/proxies/issuer_proxy/toxics", toxic)
    post_json("/proxies/verifier_proxy/toxics", toxic)


def apply_timeout() -> None:
    clear_toxics()
    toxic = {
        "name": "timeout_downstream",
        "type": "timeout",
        "stream": "downstream",
        "toxicity": 1.0,
        "attributes": {"timeout": 1},
    }
    post_json("/proxies/verifier_proxy/toxics", toxic)


def apply_disconnect() -> None:
    clear_toxics()
    toxic = {
        "name": "reset_peer_downstream",
        "type": "reset_peer",
        "stream": "downstream",
        "toxicity": 1.0,
        "attributes": {"timeout": 0},
    }
    post_json("/proxies/verifier_proxy/toxics", toxic)


def create_proxy(name: str, listen: str, upstream: str) -> dict[str, Any]:
    return post_json(
        "/proxies",
        {
            "name": name,
            "listen": listen,
            "upstream": upstream,
            "enabled": True,
        },
    )


def delete_proxy(name: str, ignore_missing: bool = False) -> None:
    delete_json(f"/proxies/{name}", ignore_missing=ignore_missing)


def get_json(path: str) -> dict[str, Any]:
    request = Request(f"{TOXIPROXY_URL}{path}", method="GET")
    return send_json(request)


def post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        f"{TOXIPROXY_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return send_json(request)


def delete_json(path: str, ignore_missing: bool = False) -> None:
    request = Request(f"{TOXIPROXY_URL}{path}", method="DELETE")
    try:
        send_json(request, allow_empty=True)
    except RuntimeError as exc:
        if ignore_missing and ("404" in str(exc) or "not found" in str(exc).lower()):
            return
        raise


def send_json(request: Request, allow_empty: bool = False) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    except (ConnectionError, TimeoutError, URLError) as exc:
        raise RuntimeError(f"request failed: {request.full_url}: {exc}") from exc
    if not body and allow_empty:
        return {}
    return json.loads(body) if body else {}

