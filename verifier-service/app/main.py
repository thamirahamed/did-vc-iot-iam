from fastapi import FastAPI
from .verify import verify_vc

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/verify")
def verify(payload: dict):
    return verify_vc(payload)
