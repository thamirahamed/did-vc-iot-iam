import json
import os
import subprocess
from typing import List


def get_did(did: str) -> dict:
    return _query_json("GetDID", [did])


def get_credential_status(credential_id: str) -> dict:
    return _query_json("GetCredentialStatus", [credential_id])


def is_credential_revoked(credential_id: str) -> dict:
    return _query_json("IsCredentialRevoked", [credential_id])


def fabric_enabled() -> bool:
    return os.getenv("FABRIC_ENABLED", "false").strip().lower() == "true"


def fabric_fail_closed() -> bool:
    return os.getenv("FABRIC_FAIL_CLOSED", "true").strip().lower() != "false"


def _query_json(function: str, args: List[str]) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    validation = _validate_env()
    if validation:
        return validation

    command = [
        _peer_bin(),
        "chaincode",
        "query",
        "-C",
        os.getenv("FABRIC_CHANNEL_NAME", "mychannel"),
        "-n",
        os.getenv("FABRIC_CHAINCODE_NAME", "iam"),
        "-c",
        json.dumps({"Args": [function] + args}),
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


def _validate_env() -> dict:
    required = [
        "FABRIC_CORE_PEER_LOCALMSPID",
        "FABRIC_CORE_PEER_MSPCONFIGPATH",
        "FABRIC_CORE_PEER_ADDRESS",
        "FABRIC_CORE_PEER_TLS_ROOTCERT_FILE",
    ]
    if _peer_mode() == "docker" and not _docker_use_volumes_from_self():
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
    ]
    if _docker_use_volumes_from_self():
        docker_command.extend(["--volumes-from", f"{_current_container_id()}:ro"])
    else:
        host_crypto_path = os.getenv("FABRIC_CRYPTO_CONFIG_HOST_PATH", "")
        docker_command.extend(["-v", f"{host_crypto_path}:{container_crypto_path}:ro"])

    for key, value in _peer_env({}).items():
        docker_command.extend(["-e", f"{key}={value}"])
    docker_command.append(
        os.getenv("FABRIC_PEER_DOCKER_IMAGE", "hyperledger/fabric-tools:2.5.15")
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
    env["CORE_PEER_TLS_ENABLED"] = _peer_tls_enabled()
    env["CORE_PEER_LOCALMSPID"] = os.getenv("FABRIC_CORE_PEER_LOCALMSPID", "")
    env["CORE_PEER_MSPCONFIGPATH"] = os.getenv("FABRIC_CORE_PEER_MSPCONFIGPATH", "")
    env["CORE_PEER_ADDRESS"] = os.getenv("FABRIC_CORE_PEER_ADDRESS", "")
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = os.getenv("FABRIC_CORE_PEER_TLS_ROOTCERT_FILE", "")
    return env


def _peer_mode() -> str:
    return os.getenv("FABRIC_PEER_MODE", "local").strip().lower()


def _peer_bin() -> str:
    if _peer_mode() == "docker":
        return "peer"
    return os.getenv("FABRIC_PEER_BIN", "peer")


def _peer_tls_enabled() -> str:
    return os.getenv(
        "FABRIC_CORE_PEER_TLS_ENABLED",
        os.getenv("FABRIC_TLS_ENABLED", "true"),
    )


def _docker_use_volumes_from_self() -> bool:
    return os.getenv("FABRIC_DOCKER_USE_VOLUMES_FROM_SELF", "false").strip().lower() == "true"


def _current_container_id() -> str:
    return os.getenv("HOSTNAME", "").strip()
