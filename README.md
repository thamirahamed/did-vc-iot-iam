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

Each issued VC includes `credentialStatus`. The baseline revocation path is a simple status lookup backed by a persistent local JSON registry at `REVOCATION_REGISTRY_PATH`, defaulting to `data/revocation_registry.json`. The issuer exposes `/vc/revoke`, `/vc/status`, and `/vc/revoked`, and the verifier can check both Identity VC and Capability VC revocation status during authorization.

Revocation mode is selected with `REVOCATION_MODE`, defaulting to `status`:

- `status`: use the original status lookup only.
- `accumulator`: require accumulator proofs for Identity VC and Capability VC.
- `hybrid`: verify accumulator proofs first and then use status lookup as a safety baseline.

The accumulator implementation is an **EVOKE inspired Merkle accumulator prototype** using deterministic SHA-256 Merkle roots. It is not the exact ECC accumulator from EVOKE. The issuer hashes final signed VCs, maintains active credential records, computes an accumulator root, and issues Merkle witness proofs. Presentations send the signed VC plus the corresponding proof. When credentials are issued or revoked, the root changes and old proofs become stale.

Local accumulator state is stored at `ACCUMULATOR_STORE_PATH`, defaulting to `data/accumulator/issuer_accumulator.json`. Fabric mode stores only compact accumulator state metadata: accumulator id, version, root, algorithm, active count, revoked count, and update time. Full VCs and witness lists are not stored on Fabric.

Accumulator endpoints:

```text
POST /vc/issue/identity-with-proof
POST /vc/issue/capability-with-proof
GET /revocation/accumulator/state
GET /revocation/accumulator/proof?credential_id=...
POST /revocation/accumulator/refresh-proof
```

Devices with intermittent links can refresh active credential proofs through `/revocation/accumulator/refresh-proof` after reconnecting. Refreshing proof for a revoked credential fails.

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

Fabric stores only metadata: DID metadata, credential status metadata, revocation status, audit events, and accumulator root/state metadata. It does not store full VCs, private keys, witness lists, or sensor data. Local mode remains the default with `FABRIC_ENABLED=false`. Fabric mode uses peer CLI integration first; Fabric Gateway is not used in this pass and can be considered later for cleaner long-running client integration and latency work.

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

Use this mode when the issuer and verifier containers should talk to Fabric. By default, this Compose path uses the long-running `fabric-adapter` service. The older peer CLI path is still available with `FABRIC_CLIENT_MODE=peer_cli`; in that mode the service images use the host Docker socket to start short-lived `hyperledger/fabric-tools` peer CLI containers.

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
curl.exe http://localhost:8010/health
python scripts/fabric_adapter_smoke_test.py
python scripts/integration_test.py
```

Expected integration test result:

```text
All integration tests passed
```

Fabric Docker Compose mode sets `FABRIC_ENABLED=true`, `FABRIC_CLIENT_MODE=adapter`, `FABRIC_ADAPTER_URL=http://fabric-adapter:8010`, `FABRIC_PEER_MODE=docker`, `FABRIC_DOCKER_USE_VOLUMES_FROM_SELF=true`, `FABRIC_CORE_PEER_TLS_ENABLED=true`, and `FABRIC_TLS_ENABLED=true`. The issuer, verifier, and adapter mount Fabric crypto material at `/fabric/organizations`. The peer CLI variables remain configured so `FABRIC_CLIENT_MODE=peer_cli` can still be used for compatibility.

### Fabric adapter mode

The old Fabric client mode calls Fabric through `docker run hyperledger/fabric-tools` for each peer CLI query or invoke. That works, but each ledger operation pays Docker container startup overhead. Adapter mode moves those peer CLI calls into a long-running `fabric-adapter` container and issuer/verifier call it over HTTP:

```text
issuer/verifier -> fabric-adapter HTTP API -> peer chaincode query/invoke -> Fabric
```

The adapter does not use Fabric Gateway and does not change DID, VC, revocation, accumulator, or audit semantics. It only changes how peer CLI commands are reached. `docker-compose.fabric.yml` enables adapter mode by default; set `FABRIC_CLIENT_MODE=peer_cli` to use the previous Docker peer CLI mode.

Run adapter mode from PowerShell after the Fabric test network and chaincode are running:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/fabric_adapter_smoke_test.py
python scripts/integration_test.py
```

Run a short async-audit benchmark:

```powershell
$env:AUDIT_MODE="async"
$env:BENCHMARK_PROFILE="async_audit"
$env:BENCHMARK_RUNS="3"
$env:BENCHMARK_WARMUP_RUNS="1"
python scripts/benchmark_pipeline.py
```

### Fabric performance mode

Correctness mode uses hybrid revocation and synchronous audit by default:

```powershell
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/integration_test.py
```

Performance mode is isolated in `docker-compose.perf.yml` so normal Compose files do not need editing. It uses accumulator revocation, async audit, the long-running Fabric adapter client, and short verifier TTL caches. In `REVOCATION_MODE=accumulator`, the verifier treats the accumulator proof as the revocation evidence and skips issuer `/vc/status` plus Fabric credential status reads. Hybrid mode keeps the status lookup safety baseline.

The IAM chaincode also provides combined write functions for accumulator-enabled Fabric mode:

```text
RegisterCredentialWithAccumulatorState
RevokeCredentialWithAccumulatorState
```

These reduce Fabric invoke count by writing credential status metadata and compact accumulator state in one chaincode transaction. Existing `RegisterCredentialStatus`, `RevokeCredential`, and `PutAccumulatorState` remain available, and the issuer falls back to those older calls if a combined invoke is unavailable. Full VCs are still not stored on Fabric.

Verifier cache settings are opt-in and configurable:

```text
DID_CACHE_ENABLED=true
DID_CACHE_TTL_SECONDS=30
ACCUMULATOR_STATE_CACHE_ENABLED=true
ACCUMULATOR_STATE_CACHE_TTL_SECONDS=2
```

Run Fabric performance mode from PowerShell:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"

docker compose -f docker-compose.yml -f docker-compose.fabric.yml -f docker-compose.perf.yml up -d --build

$env:BENCHMARK_PROFILE="fabric_accumulator_perf"
$env:BENCHMARK_RUNS="3"
$env:BENCHMARK_WARMUP_RUNS="1"
$env:BENCHMARK_LABEL="fabric-accumulator-perf"

python scripts/benchmark_pipeline.py
```

## Automated Testing

Generate issuer keys and create `.env.dev`:

python scripts/gen_issuer_keys.py

Start services:

docker compose up --build

Run integration tests:

python scripts/integration_test.py

## Validation tooling

Use these helper scripts for repeatable environment checks, cleanup previews, and validation runs.

Check environment:

```powershell
python scripts/check_environment.py
```

Clean generated files dry run:

```powershell
python scripts/reset_runtime_data.py
```

Clean generated files apply:

```powershell
python scripts/reset_runtime_data.py --apply
```

Run local validation:

```powershell
python scripts/run_all_tests.py --mode local
```

Run Fabric validation:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
python scripts/run_all_tests.py --mode fabric
```

Run performance smoke:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
python scripts/run_all_tests.py --mode perf
```

Run full validation:

```powershell
python scripts/run_all_tests.py --mode all
```

Run full validation with chaincode redeploy:

```powershell
python scripts/run_all_tests.py --mode all --redeploy-chaincode
```

## Performance emulation

This simulates constrained CPU and memory at the application layer. It does not model microcontroller firmware, radio behavior, or physical hardware.

Run a local performance pass:

python scripts/gen_issuer_keys.py
docker compose up --build
python scripts/run_perf.py

Run constrained profiles:

docker compose -f docker-compose.yml -f docker-compose.perf.yml --profile lite up --build

Outputs are written to the `perf-out` folder. Optional per-iteration delay is controlled by `SLEEP_MS`.

## Benchmarking

Batch 1 benchmark scripts exercise the completed IAM pipeline through the running issuer and verifier HTTP APIs. Results are written under `results/`, which is ignored by git.

Run a local benchmark:

```powershell
docker compose up -d --build
python scripts/benchmark_pipeline.py
```

Run a Fabric mode benchmark after the Fabric test network and chaincode are already running:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/benchmark_pipeline.py
```

Benchmark environment variables:

```text
ISSUER_URL=http://localhost:8000
VERIFIER_URL=http://localhost:8001
BENCHMARK_RUNS=30
BENCHMARK_WARMUP_RUNS=3
BENCHMARK_OUTPUT_DIR=results
BENCHMARK_LABEL=manual
BENCHMARK_PROFILE=full
REVOCATION_MODE=hybrid
FABRIC_ENABLED=false
```

The benchmark creates a raw per-iteration CSV and a summarized CSV:

```text
results/benchmark_raw_<timestamp>.csv
results/benchmark_summary_<timestamp>.csv
```

You can regenerate a summary from an existing raw CSV:

```powershell
python scripts/summarize_results.py results/benchmark_raw_<timestamp>.csv
```

Benchmark profiles are metadata unless the services are started with matching environment:

```text
BENCHMARK_PROFILE=full
BENCHMARK_PROFILE=no_audit
BENCHMARK_PROFILE=async_audit
BENCHMARK_PROFILE=status_only
BENCHMARK_PROFILE=accumulator_hybrid
BENCHMARK_PROFILE=fabric_accumulator_perf
```

For `no_audit`, start services with `AUDIT_ENABLED=false`. This skips local audit JSONL writes and Fabric audit chaincode writes while keeping IAM operations unchanged. The default is `AUDIT_ENABLED=true`.

## Audit Benchmark Modes

Audit mode is controlled by `AUDIT_MODE`, defaulting to `sync`.

- `sync`: default correctness mode. Local audit and Fabric audit writes complete before the response returns.
- `async`: performance experiment mode. The response returns after the audit event is queued; a daemon worker writes local audit and Fabric audit in the background.
- `disabled`: overhead isolation mode only. Audit writes are skipped. `AUDIT_ENABLED=false` is treated as disabled.

Async audit queue environment:

```text
AUDIT_MODE=sync
AUDIT_QUEUE_MAX_SIZE=1000
AUDIT_FLUSH_TIMEOUT_SECONDS=10
```

Flush endpoints for tests and benchmarks:

```text
POST /audit/flush
```

Run Fabric benchmark with full sync audit:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
$env:AUDIT_MODE="sync"
$env:AUDIT_ENABLED="true"
$env:BENCHMARK_PROFILE="full"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/benchmark_pipeline.py
```

Run Fabric benchmark with async audit:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
$env:AUDIT_MODE="async"
$env:AUDIT_ENABLED="true"
$env:BENCHMARK_PROFILE="async_audit"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/benchmark_pipeline.py
```

Run Fabric benchmark with audit disabled:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
$env:AUDIT_MODE="disabled"
$env:AUDIT_ENABLED="false"
$env:BENCHMARK_PROFILE="no_audit"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
python scripts/benchmark_pipeline.py
```

Compare audit modes:

```powershell
python scripts/compare_benchmarks.py results\summary_sync.csv results\summary_async.csv --left-label sync --right-label async
```

Print a command plan for all audit profile runs:

```powershell
python scripts/run_profile_benchmarks.py --label-prefix fabric --runs 3 --warmup 1 --fabric
```

## Fabric Overhead Microbenchmarks

Use `scripts/benchmark_fabric_ops.py` to isolate peer CLI, chaincode read/write, audit, and accumulator state overhead without running the full IAM lifecycle. It uses the existing Python Fabric client wrappers and writes synthetic metadata only.

PowerShell Fabric environment:

```powershell
$env:FABRIC_ENABLED="true"
$env:FABRIC_PEER_MODE="docker"
$env:FABRIC_CHANNEL_NAME="mychannel"
$env:FABRIC_CHAINCODE_NAME="iam"
$env:FABRIC_DOCKER_NETWORK="fabric_test"
$env:FABRIC_CRYPTO_CONFIG_HOST_PATH="C:\Users\kebab\Documents\CodingProjects\fabric-samples\test-network\organizations"
$env:FABRIC_CRYPTO_CONFIG_CONTAINER_PATH="/etc/hyperledger/fabric/crypto"
$env:FABRIC_CORE_PEER_TLS_ENABLED="true"
$env:FABRIC_CORE_PEER_LOCALMSPID="Org1MSP"
$env:FABRIC_CORE_PEER_MSPCONFIGPATH="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
$env:FABRIC_CORE_PEER_ADDRESS="peer0.org1.example.com:7051"
$env:FABRIC_CORE_PEER_TLS_ROOTCERT_FILE="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
$env:FABRIC_ORDERER_ADDRESS="orderer.example.com:7050"
$env:FABRIC_ORDERER_CA="/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
$env:FABRIC_TLS_ENABLED="true"
```

Run Fabric operation benchmarks:

```powershell
$env:FABRIC_OPS_RUNS="5"
$env:FABRIC_OPS_WARMUP_RUNS="1"
python scripts/benchmark_fabric_ops.py
```

Outputs:

```text
results/fabric_ops_raw_<timestamp>.csv
results/fabric_ops_summary_<timestamp>.csv
```

Compare two pipeline benchmark summaries:

```powershell
python scripts/compare_benchmarks.py results\benchmark_summary_local.csv results\benchmark_summary_fabric.csv --left-label local --right-label fabric
```

Comparison output:

```text
results/benchmark_comparison_<timestamp>.csv
```

## Resource Usage Benchmarking

Docker resource monitoring samples CPU, memory, network IO, and block IO for the issuer, verifier, and Fabric containers while the benchmark runs. It uses `docker stats --no-stream --format json` and writes results under `results/`, which is ignored by git.

Run a local benchmark with resource monitoring:

```powershell
docker compose up -d --build
$env:BENCHMARK_RUNS="10"
$env:BENCHMARK_WARMUP_RUNS="2"
$env:BENCHMARK_LABEL="local-resource-test"
$env:RESOURCE_MONITOR_ENABLED="true"
python scripts/benchmark_pipeline.py
```

Run a Fabric benchmark with resource monitoring after the Fabric test network and chaincode are already running:

```powershell
$env:FABRIC_SAMPLES_ORGS_HOST_PATH="C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations"
docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
$env:BENCHMARK_RUNS="3"
$env:BENCHMARK_WARMUP_RUNS="1"
$env:BENCHMARK_LABEL="fabric-resource-test"
$env:RESOURCE_MONITOR_ENABLED="true"
python scripts/benchmark_pipeline.py
```

Resource monitor environment variables:

```text
RESOURCE_MONITOR_ENABLED=false
RESOURCE_MONITOR_INTERVAL_SECONDS=1
RESOURCE_MONITOR_CONTAINERS=
RESOURCE_MONITOR_OUTPUT_DIR=results
RESOURCE_MONITOR_LABEL=<BENCHMARK_LABEL>
RESOURCE_MONITOR_FAIL_CLOSED=false
```

Resource output files:

```text
results/resource_usage_<timestamp>.csv
results/resource_summary_<timestamp>.csv
```

Run the monitor standalone for a fixed duration:

```powershell
python scripts/collect_docker_stats.py --duration 60 --label test
python scripts/summarize_results.py results/resource_usage_<label>_<timestamp>.csv
```

## Device agent demo mode

Run the demo walkthrough inside the device agent container:

docker compose -f docker-compose.yml -f docker-compose.perf.yml --profile moderate up --build

Demo environment variables:

MODE=demo SHOW_JSON=1 PAUSE=1 PERF_RUNS=200
