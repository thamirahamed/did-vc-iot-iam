import json
import os
import subprocess
from typing import List


def write_audit_event(event: dict) -> dict:
    event_json = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return _invoke("AddAuditEvent", [event_json], timeout_seconds=_audit_write_timeout())


def list_audit_events(limit: int = 50) -> dict:
    return _query_json("ListAuditEvents", [str(limit)])


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


def _invoke(function: str, args: List[str], timeout_seconds: float | None = None) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    validation = _validate_env(write=True)
    if validation:
        return validation

    command = [
        _peer_bin(),
        "chaincode",
        "invoke",
        "-C",
        os.getenv("FABRIC_CHANNEL_NAME", "mychannel"),
        "-n",
        os.getenv("FABRIC_CHAINCODE_NAME", "iam"),
        "-c",
        json.dumps({"Args": [function] + args}),
    ]
    if _tls_enabled():
        command.extend(["--tls", "--cafile", os.getenv("FABRIC_ORDERER_CA", "")])
    command.extend(["-o", os.getenv("FABRIC_ORDERER_ADDRESS", "")])
    command.extend(_peer_connection_args())
    command.append("--waitForEvent")
    return _run(command, timeout_seconds=timeout_seconds)


def _query_json(function: str, args: List[str]) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    validation = _validate_env(write=False)
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


def _validate_env(write: bool) -> dict:
    required = [
        "FABRIC_CORE_PEER_LOCALMSPID",
        "FABRIC_CORE_PEER_MSPCONFIGPATH",
        "FABRIC_CORE_PEER_ADDRESS",
        "FABRIC_CORE_PEER_TLS_ROOTCERT_FILE",
    ]
    if write:
        required.extend(["FABRIC_ORDERER_ADDRESS", "FABRIC_ORDERER_CA"])
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


def _run(command: List[str], timeout_seconds: float | None = None) -> dict:
    if _peer_mode() == "docker":
        return _run_docker(command, timeout_seconds=timeout_seconds)
    return _run_local(command, timeout_seconds=timeout_seconds)


def _run_local(command: List[str], timeout_seconds: float | None = None) -> dict:
    env = _peer_env(os.environ.copy())
    timeout = timeout_seconds or _fabric_cli_timeout()

    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "enabled": True,
            "ok": False,
            "error": f"Fabric peer CLI timed out after {timeout} seconds",
            "timeout": True,
        }
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


def _run_docker(command: List[str], timeout_seconds: float | None = None) -> dict:
    timeout = timeout_seconds or _fabric_cli_timeout()
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
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "enabled": True,
            "ok": False,
            "error": f"Fabric peer CLI timed out after {timeout} seconds",
            "timeout": True,
            "peer_mode": "docker",
        }
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


def _tls_enabled() -> bool:
    return os.getenv("FABRIC_TLS_ENABLED", "true").strip().lower() != "false"


def _docker_use_volumes_from_self() -> bool:
    return os.getenv("FABRIC_DOCKER_USE_VOLUMES_FROM_SELF", "false").strip().lower() == "true"


def _current_container_id() -> str:
    return os.getenv("HOSTNAME", "").strip()


def _peer_connection_args() -> List[str]:
    if _peer_mode() != "docker":
        return []

    crypto_root = os.getenv(
        "FABRIC_CRYPTO_CONFIG_CONTAINER_PATH",
        "/etc/hyperledger/fabric/crypto",
    )
    peer_addresses = _csv_env(
        "FABRIC_PEER_ADDRESSES",
        "peer0.org1.example.com:7051,peer0.org2.example.com:9051",
    )
    tls_root_cert_files = _csv_env(
        "FABRIC_PEER_TLS_ROOTCERT_FILES",
        ",".join(
            [
                f"{crypto_root}/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
                f"{crypto_root}/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt",
            ]
        ),
    )

    args: List[str] = []
    for index, peer_address in enumerate(peer_addresses):
        args.extend(["--peerAddresses", peer_address])
        if _tls_enabled() and index < len(tls_root_cert_files):
            args.extend(["--tlsRootCertFiles", tls_root_cert_files[index]])
    return args


def _csv_env(name: str, default: str) -> List[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _fabric_cli_timeout() -> float:
    return _float_env("FABRIC_CLI_TIMEOUT_SECONDS", 20.0)


def _audit_write_timeout() -> float:
    return _float_env("AUDIT_WRITE_TIMEOUT_SECONDS", 5.0)


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
