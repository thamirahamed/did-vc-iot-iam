import base64
import json
import uuid
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519


def issue_identity_vc(
    subject_did: str,
    device_public_key: str,
    issuer_did: str,
    issuer_private_key: ed25519.Ed25519PrivateKey,
) -> dict:
    now = datetime.utcnow()
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    vc = {
        "id": credential_id,
        "type": ["VerifiableCredential", "IdentityCredential"],
        "issuer": issuer_did,
        "issuanceDate": now.isoformat(timespec="seconds") + "Z",
        "expirationDate": (now + timedelta(days=365)).isoformat(timespec="seconds") + "Z",
        "credentialStatus": {
            "id": f"urn:status:{credential_id}",
            "type": "SimpleRevocationList2026",
        },
        "credentialSubject": {
            "id": subject_did,
            "devicePublicKey": device_public_key,
        },
    }

    signing_input = json.dumps(vc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = issuer_private_key.sign(signing_input)
    signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii")

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.isoformat(timespec="seconds") + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{issuer_did}#key-1",
        "signature": signature_b64,
    }

    return vc


def issue_capability_vc(
    subject_did: str,
    action: str,
    resource: str,
    issuer_did: str,
    issuer_private_key: ed25519.Ed25519PrivateKey,
) -> dict:
    now = datetime.utcnow()
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    vc = {
        "id": credential_id,
        "type": ["VerifiableCredential", "CapabilityCredential"],
        "issuer": issuer_did,
        "issuanceDate": now.isoformat(timespec="seconds") + "Z",
        "expirationDate": (now + timedelta(days=365)).isoformat(timespec="seconds") + "Z",
        "credentialStatus": {
            "id": f"urn:status:{credential_id}",
            "type": "SimpleRevocationList2026",
        },
        "credentialSubject": {
            "id": subject_did,
            "action": action,
            "resource": resource,
        },
    }

    signing_input = json.dumps(vc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = issuer_private_key.sign(signing_input)
    signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii")

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.isoformat(timespec="seconds") + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{issuer_did}#key-1",
        "signature": signature_b64,
    }

    return vc
