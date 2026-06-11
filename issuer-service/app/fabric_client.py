import json
import os
import subprocess
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def register_did(
    did: str, device_public_key: str, did_document_hash: str, created_at: str
) -> dict:
    return _invoke(
        "RegisterDID",
        [did, device_public_key, did_document_hash, created_at],
    )


def register_credential_status(vc: Dict[str, Any]) -> dict:
    status = credential_status_record(vc)
    return _invoke(
        "RegisterCredentialStatus",
        [
            status.get("credential_id", ""),
            status.get("credential_type", ""),
            status.get("subject_did", ""),
            status.get("issuer", ""),
            status.get("issued_at", ""),
            status.get("expires_at", ""),
        ],
    )


def register_credential_with_accumulator_state(
    status_record: Dict[str, Any], accumulator_state: Dict[str, Any]
) -> dict:
    status_json = json.dumps(status_record, sort_keys=True, separators=(",", ":"))
    state_json = json.dumps(accumulator_state, sort_keys=True, separators=(",", ":"))
    return _invoke("RegisterCredentialWithAccumulatorState", [status_json, state_json])


def revoke_credential_on_ledger(
    credential_id: str, reason: str | None, revoked_at: str
) -> dict:
    return _invoke("RevokeCredential", [credential_id, reason or "", revoked_at])


def revoke_credential_with_accumulator_state(
    credential_id: str,
    reason: str | None,
    revoked_at: str,
    accumulator_state: Dict[str, Any],
) -> dict:
    state_json = json.dumps(accumulator_state, sort_keys=True, separators=(",", ":"))
    return _invoke(
        "RevokeCredentialWithAccumulatorState",
        [credential_id, reason or "", revoked_at, state_json],
    )


def write_audit_event(event: dict) -> dict:
    event_json = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return _invoke("AddAuditEvent", [event_json], timeout_seconds=_audit_write_timeout())


def list_audit_events(limit: int = 50) -> dict:
    return _query_json("ListAuditEvents", [str(limit)])


def put_accumulator_state(state: dict) -> dict:
    state_json = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return _invoke("PutAccumulatorState", [state_json])


def get_accumulator_state(accumulator_id: str = "default") -> dict:
    return _query_json("GetAccumulatorState", [accumulator_id])


def list_accumulator_states(limit: int = 20) -> dict:
    return _query_json("ListAccumulatorStates", [str(limit)])


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


def credential_status_record(vc: Dict[str, Any]) -> Dict[str, Any]:
    subject = vc.get("credentialSubject", {})
    return {
        "docType": "CredentialStatus",
        "credential_id": vc.get("id", ""),
        "credential_type": _credential_type(vc),
        "subject_did": subject.get("id", ""),
        "issuer": vc.get("issuer", ""),
        "issued_at": vc.get("issuanceDate", ""),
        "expires_at": vc.get("expirationDate", ""),
        "revoked": False,
        "revoked_at": "",
        "revocation_reason": "",
    }


def _invoke(function: str, args: List[str], timeout_seconds: float | None = None) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    if _client_mode() == "adapter":
        return _adapter_call("invoke", function, args, timeout_seconds=timeout_seconds)

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
    command.extend(_peer_connection_args())
    command.append("--waitForEvent")

    return _run(command, timeout_seconds=timeout_seconds)


def _query_json(function: str, args: List[str]) -> dict:
    if not fabric_enabled():
        return {"enabled": False, "skipped": True}

    if _client_mode() == "adapter":
        result = _adapter_call("query", function, args)
    else:
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


def _adapter_call(
    operation: str,
    function: str,
    args: List[str],
    timeout_seconds: float | None = None,
) -> dict:
    timeout = timeout_seconds or _adapter_timeout()
    url = f"{_adapter_url()}/chaincode/{operation}"
    payload = json.dumps(
        {"function": function, "args": args},
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "ok": False,
            "error": f"Fabric adapter HTTP {exc.code}: {body}",
            "client_mode": "adapter",
            "adapter_url": _adapter_url(),
        }
    except (ConnectionError, TimeoutError, URLError) as exc:
        return {
            "enabled": True,
            "ok": False,
            "error": f"Fabric adapter request failed: {exc}",
            "client_mode": "adapter",
            "adapter_url": _adapter_url(),
        }

    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "enabled": True,
            "ok": False,
            "error": f"Fabric adapter returned invalid JSON: {exc}",
            "stdout": raw.decode("utf-8", errors="replace"),
            "client_mode": "adapter",
            "adapter_url": _adapter_url(),
        }

    result["enabled"] = True
    result["client_mode"] = "adapter"
    result["adapter_url"] = _adapter_url()
    if not result.get("ok") and not result.get("error"):
        result["error"] = result.get("stderr", "").strip() or "Fabric adapter operation failed"
    return result


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


def _base_peer_command() -> List[str]:
    if _peer_mode() == "docker":
        return ["peer"]
    return [os.getenv("FABRIC_PEER_BIN", "peer")]


def _peer_mode() -> str:
    return os.getenv("FABRIC_PEER_MODE", "local").strip().lower()


def _client_mode() -> str:
    mode = os.getenv("FABRIC_CLIENT_MODE", "peer_cli").strip().lower()
    return mode if mode in ("peer_cli", "adapter") else "peer_cli"


def _adapter_url() -> str:
    return os.getenv("FABRIC_ADAPTER_URL", "http://fabric-adapter:8010").rstrip("/")


def _chaincode_payload(function: str, args: List[str]) -> str:
    return json.dumps({"Args": [function] + args})


def _channel() -> str:
    return os.getenv("FABRIC_CHANNEL_NAME", "mychannel")


def _chaincode() -> str:
    return os.getenv("FABRIC_CHAINCODE_NAME", "iam")


def _tls_enabled() -> bool:
    return os.getenv("FABRIC_TLS_ENABLED", "true").strip().lower() != "false"


def _peer_tls_enabled() -> str:
    return os.getenv(
        "FABRIC_CORE_PEER_TLS_ENABLED",
        os.getenv("FABRIC_TLS_ENABLED", "true"),
    )


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


def _adapter_timeout() -> float:
    return _float_env("FABRIC_ADAPTER_TIMEOUT_SECONDS", 20.0)


def _audit_write_timeout() -> float:
    return _float_env("AUDIT_WRITE_TIMEOUT_SECONDS", 5.0)


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
