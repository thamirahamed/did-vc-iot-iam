from typing import Any, Dict

from pydantic import BaseModel


class AuthorizeRequest(BaseModel):
    identity_vc: Dict[str, Any]
    capability_vc: Dict[str, Any]
    nonce: str
    device_signature: str
    requested_action: str
    requested_resource: str


class AuthorizeResponse(BaseModel):
    decision: str
    reason: str
