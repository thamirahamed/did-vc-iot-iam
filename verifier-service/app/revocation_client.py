import json
import os
from typing import Tuple
from urllib.parse import urlencode
from urllib.request import urlopen


def check_revoked(credential_id: str) -> Tuple[bool, str]:
    issuer_url = os.getenv("ISSUER_URL", "http://issuer:8000").rstrip("/")
    fail_closed = os.getenv("REVOCATION_FAIL_CLOSED", "true").strip().lower() != "false"
    url = f"{issuer_url}/vc/status?{urlencode({'credential_id': credential_id})}"

    try:
        with urlopen(url, timeout=5) as response:
            body = response.read().decode("utf-8")
        status = json.loads(body)
    except Exception:
        if fail_closed:
            return True, "revocation status unavailable"
        return False, ""

    if status.get("revoked") is True:
        return True, ""

    return False, ""
