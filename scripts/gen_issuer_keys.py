import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def main() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_key_b64 = base64.urlsafe_b64encode(private_bytes).decode("ascii")
    public_key_b64 = base64.urlsafe_b64encode(public_bytes).decode("ascii")

    repo_root = Path(__file__).resolve().parents[1]
    env_path = repo_root / ".env.dev"

    content = "\n".join(
        [
            f"ISSUER_PRIVATE_KEY_B64={private_key_b64}",
            f"ISSUER_PUBLIC_KEY_B64={public_key_b64}",
            "",
        ]
    )
    env_path.write_text(content, encoding="ascii")


if __name__ == "__main__":
    main()
