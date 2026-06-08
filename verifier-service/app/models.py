from typing import Any, Dict, Optional

from pydantic import BaseModel


class AuthorizeRequest(BaseModel):
    identity_vc: Dict[str, Any]
    capability_vc: Dict[str, Any]
    identity_accumulator_proof: Optional[Dict[str, Any]] = None
    capability_accumulator_proof: Optional[Dict[str, Any]] = None
    accumulator_state_version: Optional[int] = None
    accumulator_root: Optional[str] = None
    nonce: str
    device_signature: str
    requested_action: str
    requested_resource: str


class AuthorizeResponse(BaseModel):
    decision: str
    reason: str
