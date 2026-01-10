from fastapi import FastAPI
from .vc import issue_vc

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/issue")
def issue(payload: dict):
    return issue_vc(payload)
