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

Start the test network and deploy this repo's chaincode:

```bash
cd fabric
./network.sh up
./network.sh deployCC
./network.sh ping
```

You do not need Go installed locally for chaincode checks. Run them through Docker:

```bash
cd fabric
./network.sh cc-go-version
./network.sh cc-tidy
./network.sh cc-test
./network.sh cc-build
```

The Fabric samples `deployCC` command may still require its own local prerequisites depending on your Fabric samples setup. The Docker-based commands above validate this repo's Go chaincode without installing Go on the host.

On Windows Git Bash, run the script explicitly with `bash`; it disables MSYS path conversion around Docker commands internally:

```bash
cd fabric
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
export FABRIC_CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export FABRIC_ORDERER_ADDRESS=orderer.example.com:7050
export FABRIC_ORDERER_CA=/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export FABRIC_TLS_ENABLED=true
```

Run the Fabric smoke test:

```bash
python scripts/fabric_smoke_test.py
```

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
