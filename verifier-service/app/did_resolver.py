import json
import os
from typing import Optional, Tuple
from urllib.parse import urlencode
from urllib.request import urlopen


def resolve_did(did: str) -> Tuple[Optional[dict], str]:
    issuer_url = os.getenv("ISSUER_URL", "http://issuer:8000").rstrip("/")
    fail_closed = os.getenv("DID_RESOLUTION_FAIL_CLOSED", "true").strip().lower() != "false"
    url = f"{issuer_url}/did/resolve?{urlencode({'did': did})}"

    try:
        with urlopen(url, timeout=5) as response:
            body = response.read().decode("utf-8")
        result = json.loads(body)
    except Exception:
        if fail_closed:
            return None, "DID resolution unavailable"
        return None, "device DID not registered"

    if result.get("found") is not True:
        return None, "device DID not registered"

    did_document = result.get("did_document")
    if not isinstance(did_document, dict):
        return None, "device DID not registered"

    return did_document, ""
