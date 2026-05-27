import json
import os
import subprocess
from typing import Any, Dict, List


def register_did(
    did: str, device_public_key: str, did_document_hash: str, created_at: str
) -> dict:
    return _invoke(
        "RegisterDID",
        [did, device_public_key, did_document_hash, created_at],
    )


def register_credential_status(vc: Dict[str, Any]) -> dict:
    subject = vc.get("credentialSubject", {})
    credential_type = _credential_type(vc)
    return _invoke(
        "RegisterCredentialStatus",
        [
            vc.get("id", ""),
            credential_type,
            subject.get("id", ""),
            vc.get("issuer", ""),
            vc.get("issuanceDate", ""),
            vc.get("expirationDate", ""),
        ],
    )


def revoke_credential_on_ledger(
    credential_id: str, reason: str | None, revoked_at: str
) -> dict:
    return _invoke("RevokeCredential", [credential_id, reason or "", revoked_at])


def get_credential_status(credential_id: str) -> dict:
    return _query_json("GetCredentialStatus", [credential_id])


def is_credential_revoked(credential_id: str) -> dict:
    return _query_json("IsCredentialRevoked", [credential_id])


def fabric_enabled() -> bool:
    return os.getenv("FABRIC_ENABLED", "false").strip().lower() == "true"


def fabric_fail_closed() -> bool:
    return os.getenv("FABRIC_FAIL_CLOSED", "true").strip().lower() != "false"


def _credential_type(vc: Dict[str, Any]) -> str:
    vc_type = vc.get("type", [])
    if isinstance(vc_type, list):
        for item in vc_type:
            if item != "VerifiableCredential":
                return str(item)
    if isinstance(vc_type, str):
        return vc_type
    return ""


def _invoke(function: str, args: List[str]) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    validation = _validate_env(write=True)
    if validation:
        return validation

    command = _base_peer_command() + [
        "chaincode",
        "invoke",
        "-C",
        _channel(),
        "-n",
        _chaincode(),
        "-c",
        _chaincode_payload(function, args),
    ]

    if _tls_enabled():
        command.extend(["--tls", "--cafile", os.getenv("FABRIC_ORDERER_CA", "")])
    command.extend(["-o", os.getenv("FABRIC_ORDERER_ADDRESS", "")])

    return _run(command)


def _query_json(function: str, args: List[str]) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    validation = _validate_env(write=False)
    if validation:
        return validation

    command = _base_peer_command() + [
        "chaincode",
        "query",
        "-C",
        _channel(),
        "-n",
        _chaincode(),
        "-c",
        _chaincode_payload(function, args),
    ]
    result = _run(command)
    if not result.get("ok"):
        return result

    stdout = result.get("stdout", "").strip()
    try:
        result["result"] = json.loads(stdout)
    except json.JSONDecodeError:
        if stdout.lower() in ("true", "false"):
            result["result"] = stdout.lower() == "true"
        else:
            result["result"] = stdout
    return result


def _validate_env(write: bool) -> dict:
    required = [
        "FABRIC_CORE_PEER_LOCALMSPID",
        "FABRIC_CORE_PEER_MSPCONFIGPATH",
        "FABRIC_CORE_PEER_ADDRESS",
        "FABRIC_CORE_PEER_TLS_ROOTCERT_FILE",
    ]
    if write:
        required.extend(["FABRIC_ORDERER_ADDRESS", "FABRIC_ORDERER_CA"])
    if _peer_mode() == "docker":
        required.append("FABRIC_CRYPTO_CONFIG_HOST_PATH")

    missing = [name for name in required if not os.getenv(name)]
    if missing:
        return {
            "enabled": True,
            "ok": False,
            "error": f"missing Fabric peer CLI environment: {', '.join(missing)}",
        }
    return {}


def _run(command: List[str]) -> dict:
    if _peer_mode() == "docker":
        return _run_docker(command)
    return _run_local(command)


def _run_local(command: List[str]) -> dict:
    env = _peer_env(os.environ.copy())

    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return {"enabled": True, "ok": False, "error": str(exc)}

    return {
        "enabled": True,
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": completed.stderr.strip() if completed.returncode != 0 else "",
    }


def _run_docker(command: List[str]) -> dict:
    host_crypto_path = os.getenv("FABRIC_CRYPTO_CONFIG_HOST_PATH", "")
    container_crypto_path = os.getenv(
        "FABRIC_CRYPTO_CONFIG_CONTAINER_PATH",
        "/etc/hyperledger/fabric/crypto",
    )
    docker_command = [
        "docker",
        "run",
        "--rm",
        "--network",
        os.getenv("FABRIC_DOCKER_NETWORK", "fabric_test"),
        "-v",
        f"{host_crypto_path}:{container_crypto_path}:ro",
    ]
    for key, value in _peer_env({}).items():
        docker_command.extend(["-e", f"{key}={value}"])
    docker_command.extend(
        [
            os.getenv("FABRIC_PEER_DOCKER_IMAGE", "hyperledger/fabric-tools:2.5.15"),
        ]
    )
    docker_command.extend(command)

    try:
        completed = subprocess.run(
            docker_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except Exception as exc:
        return {"enabled": True, "ok": False, "error": str(exc)}

    return {
        "enabled": True,
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": completed.stderr.strip() if completed.returncode != 0 else "",
        "peer_mode": "docker",
    }


def _peer_env(env: dict) -> dict:
    env["CORE_PEER_LOCALMSPID"] = os.getenv("FABRIC_CORE_PEER_LOCALMSPID", "")
    env["CORE_PEER_MSPCONFIGPATH"] = os.getenv("FABRIC_CORE_PEER_MSPCONFIGPATH", "")
    env["CORE_PEER_ADDRESS"] = os.getenv("FABRIC_CORE_PEER_ADDRESS", "")
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = os.getenv("FABRIC_CORE_PEER_TLS_ROOTCERT_FILE", "")
    return env


def _base_peer_command() -> List[str]:
    if _peer_mode() == "docker":
        return ["peer"]
    return [os.getenv("FABRIC_PEER_BIN", "peer")]


def _peer_mode() -> str:
    return os.getenv("FABRIC_PEER_MODE", "local").strip().lower()


def _chaincode_payload(function: str, args: List[str]) -> str:
    return json.dumps({"Args": [function] + args})


def _channel() -> str:
    return os.getenv("FABRIC_CHANNEL_NAME", "mychannel")


def _chaincode() -> str:
    return os.getenv("FABRIC_CHAINCODE_NAME", "iam")


def _tls_enabled() -> bool:
    return os.getenv("FABRIC_TLS_ENABLED", "true").strip().lower() != "false"
