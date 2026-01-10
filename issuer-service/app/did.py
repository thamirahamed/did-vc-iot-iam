import base64
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def create_did() -> str:
    return f"did:iot:{uuid.uuid4()}"


def generate_keypair() -> tuple[str, ed25519.Ed25519PrivateKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_b64 = base64.urlsafe_b64encode(public_bytes).decode("ascii")
    return public_key_b64, private_key
