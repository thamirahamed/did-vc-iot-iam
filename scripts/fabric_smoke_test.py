import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from datetime import datetime, timedelta
from typing import List


def main() -> int:
    if os.getenv("FABRIC_ENABLED", "false").strip().lower() != "true":
        print("FABRIC_ENABLED=true is required for Fabric smoke test", flush=True)
        return 1

    missing = required_env_missing(write=True)
    if missing:
        print(f"missing Fabric peer CLI environment: {', '.join(missing)}", flush=True)
        return 1

    print(f"Peer mode: {peer_mode()}")
    print(f"Channel: {channel()}")
    print(f"Chaincode: {chaincode()}")
    if peer_mode() == "docker":
        crypto_path = Path(os.getenv("FABRIC_CRYPTO_CONFIG_HOST_PATH", ""))
        print(f"Docker crypto host path exists: {crypto_path.exists()}")
        if not crypto_path.exists():
            print(f"missing crypto host path: {crypto_path}", flush=True)
            return 1

    did = f"did:iot:smoke-{uuid.uuid4()}"
    credential_id = f"urn:uuid:smoke-{uuid.uuid4()}"
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    expires = (datetime.utcnow() + timedelta(days=1)).isoformat(timespec="seconds") + "Z"

    print("Query Ping")
    ping = query("Ping", [])
    expect_ok(ping)
    if ping["stdout"].strip() != "pong":
        raise RuntimeError(f"expected pong, got {ping['stdout']}")

    print("Register DID")
    expect_ok(
        invoke(
            "RegisterDID",
            [did, "test-public-key", "test-did-document-hash", now],
        )
    )

    print("Read DID")
    did_result = query_json("GetDID", [did])
    if did_result.get("did") != did:
        raise RuntimeError(f"unexpected DID record: {did_result}")

    print("Register credential status")
    expect_ok(
        invoke(
            "RegisterCredentialStatus",
            [
                credential_id,
                "CapabilityCredential",
                did,
                "did:iot:test-issuer",
                now,
                expires,
            ],
        )
    )

    print("Read credential status")
    status = query_json("GetCredentialStatus", [credential_id])
    if status.get("credential_id") != credential_id or status.get("revoked") is not False:
        raise RuntimeError(f"unexpected credential status: {status}")

    print("Revoke credential")
    expect_ok(invoke("RevokeCredential", [credential_id, "smoke test", now]))

    print("Check revoked")
    revoked = query("IsCredentialRevoked", [credential_id])
    expect_ok(revoked)
    if revoked["stdout"].strip().lower() != "true":
        raise RuntimeError(f"expected true, got {revoked['stdout']}")

    print("Fabric smoke test passed")
    return 0


def invoke(function: str, args: List[str]) -> dict:
    command = base_command() + [
        "chaincode",
        "invoke",
        "-C",
        channel(),
        "-n",
        chaincode(),
        "-c",
        payload(function, args),
    ]
    if tls_enabled():
        command.extend(["--tls", "--cafile", os.getenv("FABRIC_ORDERER_CA", "")])
    command.extend(["-o", os.getenv("FABRIC_ORDERER_ADDRESS", "")])
    return run(command)


def query(function: str, args: List[str]) -> dict:
    command = base_command() + [
        "chaincode",
        "query",
        "-C",
        channel(),
        "-n",
        chaincode(),
        "-c",
        payload(function, args),
    ]
    return run(command)


def query_json(function: str, args: List[str]) -> dict:
    result = query(function, args)
    expect_ok(result)
    return json.loads(result["stdout"])


def expect_ok(result: dict) -> None:
    if not result["ok"]:
        raise RuntimeError(result.get("error") or result.get("stderr") or "peer command failed")


def run(command: List[str]) -> dict:
    if peer_mode() == "docker":
        return run_docker(command)
    return run_local(command)


def run_local(command: List[str]) -> dict:
    env = peer_env(os.environ.copy())
    completed = subprocess.run(
        command,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": completed.stderr.strip() if completed.returncode != 0 else "",
    }


def run_docker(command: List[str]) -> dict:
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
    for key, value in peer_env({}).items():
        docker_command.extend(["-e", f"{key}={value}"])
    docker_command.append(
        os.getenv("FABRIC_PEER_DOCKER_IMAGE", "hyperledger/fabric-tools:2.5.15")
    )
    docker_command.extend(command)

    completed = subprocess.run(
        docker_command,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": completed.stderr.strip() if completed.returncode != 0 else "",
    }


def required_env_missing(write: bool) -> List[str]:
    required = [
        "FABRIC_CORE_PEER_LOCALMSPID",
        "FABRIC_CORE_PEER_MSPCONFIGPATH",
        "FABRIC_CORE_PEER_ADDRESS",
        "FABRIC_CORE_PEER_TLS_ROOTCERT_FILE",
    ]
    if write:
        required.extend(["FABRIC_ORDERER_ADDRESS", "FABRIC_ORDERER_CA"])
    if peer_mode() == "docker":
        required.append("FABRIC_CRYPTO_CONFIG_HOST_PATH")
    return [name for name in required if not os.getenv(name)]


def base_command() -> List[str]:
    if peer_mode() == "docker":
        return ["peer"]
    return [os.getenv("FABRIC_PEER_BIN", "peer")]


def payload(function: str, args: List[str]) -> str:
    return json.dumps({"Args": [function] + args})


def channel() -> str:
    return os.getenv("FABRIC_CHANNEL_NAME", "mychannel")


def chaincode() -> str:
    return os.getenv("FABRIC_CHAINCODE_NAME", "iam")


def tls_enabled() -> bool:
    return os.getenv("FABRIC_TLS_ENABLED", "true").strip().lower() != "false"


def peer_mode() -> str:
    return os.getenv("FABRIC_PEER_MODE", "local").strip().lower()


def peer_env(env: dict) -> dict:
    env["CORE_PEER_LOCALMSPID"] = os.getenv("FABRIC_CORE_PEER_LOCALMSPID", "")
    env["CORE_PEER_MSPCONFIGPATH"] = os.getenv("FABRIC_CORE_PEER_MSPCONFIGPATH", "")
    env["CORE_PEER_ADDRESS"] = os.getenv("FABRIC_CORE_PEER_ADDRESS", "")
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = os.getenv("FABRIC_CORE_PEER_TLS_ROOTCERT_FILE", "")
    return env


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(str(exc), flush=True)
        sys.exit(1)
