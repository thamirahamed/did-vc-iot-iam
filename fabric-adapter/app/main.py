import json
import os
import subprocess
import time
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel, Field


app = FastAPI(title="Fabric Adapter")


class ChaincodeRequest(BaseModel):
    function: str = Field(min_length=1)
    args: List[str] = Field(default_factory=list)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "fabric-adapter"}


@app.post("/chaincode/query")
def chaincode_query(request: ChaincodeRequest) -> dict:
    command = [
        "peer",
        "chaincode",
        "query",
        "-C",
        _channel(),
        "-n",
        _chaincode(),
        "-c",
        _chaincode_payload(request.function, request.args),
    ]
    return _run_peer(command)


@app.post("/chaincode/invoke")
def chaincode_invoke(request: ChaincodeRequest) -> dict:
    command = [
        "peer",
        "chaincode",
        "invoke",
        "-o",
        os.getenv("FABRIC_ORDERER_ADDRESS", ""),
    ]
    if _tls_enabled():
        command.extend(["--tls", "--cafile", os.getenv("FABRIC_ORDERER_CA", "")])
    command.extend(
        [
            "-C",
            _channel(),
            "-n",
            _chaincode(),
            "-c",
            _chaincode_payload(request.function, request.args),
        ]
    )
    command.extend(_peer_connection_args())
    command.append("--waitForEvent")
    return _run_peer(command)


def _run_peer(command: list[str]) -> dict:
    start = time.perf_counter()
    timeout = _timeout_seconds()
    env = os.environ.copy()
    env["CORE_PEER_TLS_ENABLED"] = os.getenv(
        "FABRIC_CORE_PEER_TLS_ENABLED",
        os.getenv("CORE_PEER_TLS_ENABLED", os.getenv("FABRIC_TLS_ENABLED", "true")),
    )

    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": f"Fabric peer CLI timed out after {timeout} seconds",
            "duration_ms": _elapsed_ms(start),
        }
    except Exception as exc:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
            "duration_ms": _elapsed_ms(start),
        }

    result = {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "duration_ms": _elapsed_ms(start),
    }
    if completed.returncode != 0:
        result["error"] = completed.stderr.strip()
    return result


def _chaincode_payload(function: str, args: list[str]) -> str:
    return json.dumps({"Args": [function] + args}, separators=(",", ":"))


def _channel() -> str:
    return os.getenv("FABRIC_CHANNEL_NAME", "mychannel")


def _chaincode() -> str:
    return os.getenv("FABRIC_CHAINCODE_NAME", "iam")


def _tls_enabled() -> bool:
    return os.getenv("FABRIC_TLS_ENABLED", "true").strip().lower() != "false"


def _peer_connection_args() -> list[str]:
    peer_addresses = _csv_env(
        "FABRIC_PEER_ADDRESSES",
        "peer0.org1.example.com:7051,peer0.org2.example.com:9051",
    )
    tls_root_cert_files = _csv_env(
        "FABRIC_PEER_TLS_ROOTCERT_FILES",
        ",".join(
            [
                "/fabric/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
                "/fabric/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt",
            ]
        ),
    )

    args: list[str] = []
    for index, peer_address in enumerate(peer_addresses):
        args.extend(["--peerAddresses", peer_address])
        if _tls_enabled() and index < len(tls_root_cert_files):
            args.extend(["--tlsRootCertFiles", tls_root_cert_files[index]])
    return args


def _csv_env(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _timeout_seconds() -> float:
    try:
        value = float(os.getenv("FABRIC_ADAPTER_TIMEOUT_SECONDS", "20"))
    except ValueError:
        return 20.0
    return value if value > 0 else 20.0


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)
