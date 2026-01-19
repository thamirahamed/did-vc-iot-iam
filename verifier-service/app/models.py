from typing import Any, Dict

from pydantic import BaseModel


class AuthorizeRequest(BaseModel):
    capability_vc: Dict[str, Any]
    nonce: str
    device_signature: str
    device_public_key: str
    requested_action: str
    requested_resource: str


class AuthorizeResponse(BaseModel):
    decision: str
    reason: str
