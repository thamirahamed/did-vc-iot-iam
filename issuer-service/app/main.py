from fastapi import FastAPI

from .did import create_did, generate_keypair

app = FastAPI()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/did/create")
def did_create() -> dict:
    did = create_did()
    public_key_b64, _private_key = generate_keypair()
    # Never return private keys in API responses.
    return {"did": did, "public_key": public_key_b64}
