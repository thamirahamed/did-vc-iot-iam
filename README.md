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

Revocation is currently an MVP simple status lookup. The issuer stores revoked credential IDs in memory and exposes `/vc/revoke`, `/vc/status`, and `/vc/revoked`. The verifier checks the issuer status endpoint during authorization and denies revoked identity or capability credentials. This is not Fabric backed yet, and it is not an EVOKE accumulator; it can later be replaced or extended with accumulator or ledger anchored revocation.

## DID onboarding and resolution

The device owns its Ed25519 keypair. During onboarding the device sends its public key to the issuer, and the issuer creates a `did:iot:<uuid>` DID document that stores that key as `publicKeyBase64Url`. DID documents are stored in a local persistent JSON registry at `DID_REGISTRY_PATH`, defaulting to `data/did_registry.json`.

Identity VC issuance requires the DID to be registered and the requested `device_public_key` to match the DID document. During authorization, the verifier resolves the DID through the issuer, checks that the DID document key matches the signed Identity VC key, and then verifies the device nonce signature with the resolved DID document key. This registry is local for now and can later be moved to Fabric; Fabric DID registry support is not implemented yet.

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
