# did-vc-iot-iam

Prototype mono repo for a DID and Verifiable Credential based IAM system using Hyperledger Fabric.

## Components

- `fabric/`: placeholder Fabric network scripts and Go chaincode.
- `issuer-service/`: FastAPI service that issues VCs (placeholder).
- `verifier-service/`: FastAPI service that verifies VCs (placeholder).
- `device-simulator/`: Python device simulator (placeholder).

## Notes

This repo contains minimal starter code and simple health checks. It avoids advanced features like DIDComm, wallets, or zero knowledge proofs.

## Revocation status

Each issued VC includes `credentialStatus`. Revocation is currently an MVP simple status lookup backed by a persistent local JSON registry at `REVOCATION_REGISTRY_PATH`, defaulting to `data/revocation_registry.json`. The issuer exposes `/vc/revoke`, `/vc/status`, and `/vc/revoked`, and the verifier checks both Identity VC and Capability VC revocation status during authorization.

This completes local credential lifecycle support for the prototype. Fabric-backed revocation and EVOKE/accumulator-based revocation are not implemented yet; this registry can later be moved to Fabric or replaced with accumulator-based revocation.

## Audit logging

The IAM lifecycle writes audit events for DID registration, Identity VC issuance, Capability VC issuance, VC revocation, authorization allow, and authorization deny. Audit events contain event metadata such as event type, subject DID, credential ID, decision, reason, timestamp, service, and small metadata fields. They do not store full VCs, private keys, or sensor data.

Local mode writes JSONL audit logs:

- Issuer default: `data/audit/issuer_audit.jsonl`
- Verifier default: `data/audit/verifier_audit.jsonl`
- Override path: `AUDIT_LOG_PATH`

Fabric mode writes audit event metadata to IAM chaincode with keys in the form `AUDIT::<created_at>::<event_id>`. The chaincode exposes `AddAuditEvent`, `GetAuditEvent`, and `ListAuditEvents`. `ListAuditEvents` returns recent audit events by reversing deterministic ledger key order.

Both issuer and verifier expose:

```text
GET /audit/events
GET /audit/events?limit=50
```

Audit failure handling is controlled by `AUDIT_FAIL_CLOSED`, defaulting to `false`. When false, the main lifecycle operation continues and the service returns a warning where the response shape allows it or logs a console warning. When true, audit write failures fail issuer operations and force verifier authorization to deny with `audit logging failed`.

Test audit logging in local fallback mode:

```powershell
docker compose up -d --build
python scripts/integration_test.py
```

Test audit logging in Fabric Docker mode:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/integration_test.py
```

## DID onboarding and resolution

The device owns its Ed25519 keypair. During onboarding the device sends its public key to the issuer, and the issuer creates a `did:iot:<uuid>` DID document that stores that key as `publicKeyBase64Url`. DID documents are stored in a local persistent JSON registry at `DID_REGISTRY_PATH`, defaulting to `data/did_registry.json`.

Identity VC issuance requires the DID to be registered and the requested `device_public_key` to match the DID document. During authorization, the verifier resolves the DID through the issuer, checks that the DID document key matches the signed Identity VC key, and then verifies the device nonce signature with the resolved DID document key. The local JSON registry remains the default source; when `FABRIC_ENABLED=true`, DID metadata is also mirrored to Fabric.

## Hyperledger Fabric

This prototype targets Hyperledger Fabric v2.5.15 with Fabric CA v1.5.15. Fabric v2.5.x is used because it is the current LTS line. The local Fabric path uses the official Fabric samples test network with the default Raft ordering service and Go chaincode.

Fabric stores only metadata: DID metadata, credential status metadata, and revocation status. It does not store full VCs, private keys, or sensor data. Local mode remains the default with `FABRIC_ENABLED=false`. Fabric mode uses peer CLI integration first; Fabric Gateway is not used in this pass and can be considered later for cleaner long-running client integration and latency work.

Install Fabric samples matching the target versions:

```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.15 1.5.15
export FABRIC_SAMPLES_PATH=/path/to/fabric-samples
```

On Windows Git Bash, keep both this repository and `fabric-samples` in paths without spaces. Run the wrapper explicitly with `bash ./network.sh ...` so the script can disable MSYS path conversion around Fabric and Docker calls. You can avoid exporting `FABRIC_SAMPLES_PATH` in every terminal session by creating `fabric/.fabric-env` once:

```bash
FABRIC_SAMPLES_PATH="$HOME/Documents/CodingProjects/fabric-samples"
```

Start the test network and deploy this repo's chaincode:

```bash
cd fabric
bash ./network.sh up
bash ./network.sh deployCC-docker
bash ./network.sh ping
```

You do not need Go installed locally for chaincode checks. Run them through Docker:

```bash
cd fabric
bash ./network.sh cc-go-version
bash ./network.sh cc-tidy
bash ./network.sh cc-test
bash ./network.sh cc-build
```

Use `bash ./network.sh deployCC-docker` when Go is not installed locally. The original `bash ./network.sh deployCC` command is still available for setups with local Go installed because Fabric samples package Go chaincode with the host `go` command.

On Windows Git Bash, run the script explicitly with `bash`; it disables MSYS path conversion around Docker commands internally:

```bash
cd fabric
bash ./network.sh up
bash ./network.sh deployCC-docker
bash ./network.sh ping
bash ./network.sh cc-go-version
bash ./network.sh cc-test
```

Peer CLI calls can run in local peer mode or Docker peer mode. Docker peer mode is recommended for this repository. Print the Fabric test-network Org1 environment:

```bash
cd fabric
./network.sh env
```

For PowerShell:

```powershell
cd fabric
./network.sh env-powershell
```

Paste the printed environment variables into the terminal where you run the smoke test. Example values for Fabric samples Org1:

```bash
export FABRIC_ENABLED=true
export FABRIC_PEER_MODE=docker
export FABRIC_CLI_MODE=true
export FABRIC_CHANNEL_NAME=mychannel
export FABRIC_CHAINCODE_NAME=iam
export FABRIC_FAIL_CLOSED=true
export FABRIC_PEER_DOCKER_IMAGE=hyperledger/fabric-tools:2.5.15
export FABRIC_DOCKER_NETWORK=fabric_test
export FABRIC_CRYPTO_CONFIG_HOST_PATH=$FABRIC_SAMPLES_PATH/test-network/organizations
export FABRIC_CRYPTO_CONFIG_CONTAINER_PATH=/etc/hyperledger/fabric/crypto
export FABRIC_CORE_PEER_LOCALMSPID=Org1MSP
export FABRIC_CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export FABRIC_CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export FABRIC_CORE_PEER_TLS_ENABLED=true
export FABRIC_CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export FABRIC_ORDERER_ADDRESS=orderer.example.com:7050
export FABRIC_ORDERER_CA=/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export FABRIC_TLS_ENABLED=true
```

Run the Fabric smoke test:

```bash
python scripts/fabric_smoke_test.py
```

### Fabric Docker Compose mode

Use this mode when the issuer and verifier containers should talk to Fabric. The service images include the Docker CLI only; they use the host Docker socket to start short-lived `hyperledger/fabric-tools` peer CLI containers.

Set the Fabric samples organizations path in PowerShell:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
```

Or copy `.env.fabric.example` to your own local `.env.fabric` and run Compose with `--env-file .env.fabric`. The local `.env.fabric` file is ignored by git.

Start the Fabric network first in Git Bash:

```bash
cd fabric
bash ./network.sh up
bash ./network.sh deployCC-docker
bash ./network.sh ping
```

Then start the services and run the integration test from the repository root:

```powershell
docker compose -f docker-compose.yml -f docker-compose.fabric.yml config
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.fabric.yml logs issuer
docker compose -f docker-compose.yml -f docker-compose.fabric.yml logs verifier
python scripts/integration_test.py
```

Expected integration test result:

```text
All integration tests passed
```

Fabric Docker Compose mode sets `FABRIC_ENABLED=true`, `FABRIC_PEER_MODE=docker`, `FABRIC_DOCKER_USE_VOLUMES_FROM_SELF=true`, `FABRIC_CORE_PEER_TLS_ENABLED=true`, and `FABRIC_TLS_ENABLED=true`. The issuer and verifier mount Fabric crypto material at `/fabric/organizations`, and sibling peer CLI containers inherit that mount through Docker `--volumes-from`.

## Automated Testing

Generate issuer keys and create `.env.dev`:

python scripts/gen_issuer_keys.py

Start services:

docker compose up --build

Run integration tests:

python scripts/integration_test.py

## Performance emulation

This simulates constrained CPU and memory at the application layer. It does not model microcontroller firmware, radio behavior, or physical hardware.

Run a local performance pass:

python scripts/gen_issuer_keys.py
docker compose up --build
python scripts/run_perf.py

Run constrained profiles:

docker compose -f docker-compose.yml -f docker-compose.perf.yml --profile lite up --build

Outputs are written to the `perf-out` folder. Optional per-iteration delay is controlled by `SLEEP_MS`.

## Device agent demo mode

Run the demo walkthrough inside the device agent container:

docker compose -f docker-compose.yml -f docker-compose.perf.yml --profile moderate up --build

Demo environment variables:

MODE=demo SHOW_JSON=1 PAUSE=1 PERF_RUNS=200
