from fastapi import FastAPI

from .models import AuthorizeRequest, AuthorizeResponse
from .verify import authorize_request

app = FastAPI()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/authorize", response_model=AuthorizeResponse)
def authorize(payload: AuthorizeRequest) -> AuthorizeResponse:
    return authorize_request(payload)
