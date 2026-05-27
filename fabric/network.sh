#!/usr/bin/env bash
set -euo pipefail

FABRIC_VERSION="${FABRIC_VERSION:-2.5.15}"
FABRIC_CA_VERSION="${FABRIC_CA_VERSION:-1.5.15}"
CHANNEL_NAME="${CHANNEL_NAME:-mychannel}"
CHAINCODE_NAME="${CHAINCODE_NAME:-iam}"
CHAINCODE_LANG="${CHAINCODE_LANG:-go}"
CHAINCODE_VERSION="${CHAINCODE_VERSION:-1.0}"
CHAINCODE_SEQUENCE="${CHAINCODE_SEQUENCE:-1}"
GO_DOCKER_IMAGE="${GO_DOCKER_IMAGE:-golang:1.23}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHAINCODE_PATH="${CHAINCODE_PATH:-$REPO_ROOT/fabric/chaincode/iam}"
CHAINCODE_PATH_ABS=""

find_test_network() {
  if [[ -n "${FABRIC_SAMPLES_PATH:-}" && -x "$FABRIC_SAMPLES_PATH/test-network/network.sh" ]]; then
    echo "$FABRIC_SAMPLES_PATH/test-network"
    return 0
  fi

  local candidates=(
    "$REPO_ROOT/../fabric-samples/test-network"
    "$REPO_ROOT/fabric-samples/test-network"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate/network.sh" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  cat >&2 <<EOF
Fabric samples test-network was not found.

Install Fabric samples v${FABRIC_VERSION} and Fabric CA v${FABRIC_CA_VERSION}, then set FABRIC_SAMPLES_PATH:

  curl -sSL https://bit.ly/2ysbOFE | bash -s -- ${FABRIC_VERSION} ${FABRIC_CA_VERSION}
  export FABRIC_SAMPLES_PATH=/path/to/fabric-samples

Expected test network script:
  \$FABRIC_SAMPLES_PATH/test-network/network.sh
EOF
  return 1
}

network() {
  local test_network
  test_network="$(find_test_network)"
  (cd "$test_network" && ./network.sh "$@")
}

status() {
  if command -v docker >/dev/null 2>&1; then
    docker ps --filter "name=peer" --filter "name=orderer" --filter "name=ca_" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  else
    echo "docker command not found"
    return 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker command not found. Docker is required for this command." >&2
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running or is not accessible. Start Docker Desktop and try again." >&2
    return 1
  fi
}

chaincode_path_abs() {
  if [[ ! -d "$CHAINCODE_PATH" ]]; then
    echo "Chaincode path does not exist: $CHAINCODE_PATH" >&2
    return 1
  fi

  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$CHAINCODE_PATH" | tr '\\' '/'
    return 0
  fi

  if (cd "$CHAINCODE_PATH" && pwd -W) >/dev/null 2>&1; then
    (cd "$CHAINCODE_PATH" && pwd -W) | tr '\\' '/'
    return 0
  fi

  (cd "$CHAINCODE_PATH" && pwd)
}

run_go_docker() {
  require_docker

  CHAINCODE_PATH_ABS="$(chaincode_path_abs)"

  local uid_args=()
  if [[ "${OS:-}" != "Windows_NT" ]] && command -v id >/dev/null 2>&1; then
    uid_args=(-u "$(id -u):$(id -g)")
  fi

  echo "Docker image: $GO_DOCKER_IMAGE"
  echo "Host chaincode path: $CHAINCODE_PATH_ABS"
  echo "Container chaincode path: /chaincode"
  echo "Command: /usr/local/go/bin/go $*"

  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
    "${uid_args[@]}" \
    -v "${CHAINCODE_PATH_ABS}:/chaincode" \
    -w /chaincode \
    "$GO_DOCKER_IMAGE" \
    /usr/local/go/bin/go "$@"
}

peer_env_ready() {
  [[ -n "${CORE_PEER_LOCALMSPID:-}" &&
     -n "${CORE_PEER_MSPCONFIGPATH:-}" &&
     -n "${CORE_PEER_ADDRESS:-}" &&
     -n "${CORE_PEER_TLS_ROOTCERT_FILE:-}" ]]
}

print_env_bash() {
  local test_network
  test_network="$(find_test_network)"
  local org_path="$test_network/organizations"
  cat <<EOF
export FABRIC_ENABLED=true
export FABRIC_PEER_MODE=docker
export FABRIC_CHANNEL_NAME=${CHANNEL_NAME}
export FABRIC_CHAINCODE_NAME=${CHAINCODE_NAME}
export FABRIC_DOCKER_NETWORK=fabric_test
export FABRIC_CRYPTO_CONFIG_HOST_PATH=${org_path}
export FABRIC_CRYPTO_CONFIG_CONTAINER_PATH=/etc/hyperledger/fabric/crypto
export FABRIC_CORE_PEER_LOCALMSPID=Org1MSP
export FABRIC_CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export FABRIC_CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export FABRIC_CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export FABRIC_ORDERER_ADDRESS=orderer.example.com:7050
export FABRIC_ORDERER_CA=/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export FABRIC_TLS_ENABLED=true
EOF
}

print_env_powershell() {
  local test_network
  test_network="$(find_test_network)"
  local org_path="$test_network/organizations"
  cat <<EOF
\$env:FABRIC_ENABLED="true"
\$env:FABRIC_PEER_MODE="docker"
\$env:FABRIC_CHANNEL_NAME="${CHANNEL_NAME}"
\$env:FABRIC_CHAINCODE_NAME="${CHAINCODE_NAME}"
\$env:FABRIC_DOCKER_NETWORK="fabric_test"
\$env:FABRIC_CRYPTO_CONFIG_HOST_PATH="${org_path}"
\$env:FABRIC_CRYPTO_CONFIG_CONTAINER_PATH="/etc/hyperledger/fabric/crypto"
\$env:FABRIC_CORE_PEER_LOCALMSPID="Org1MSP"
\$env:FABRIC_CORE_PEER_MSPCONFIGPATH="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
\$env:FABRIC_CORE_PEER_ADDRESS="peer0.org1.example.com:7051"
\$env:FABRIC_CORE_PEER_TLS_ROOTCERT_FILE="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
\$env:FABRIC_ORDERER_ADDRESS="orderer.example.com:7050"
\$env:FABRIC_ORDERER_CA="/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
\$env:FABRIC_TLS_ENABLED="true"
EOF
}

ping() {
  if ! command -v peer >/dev/null 2>&1 || ! peer_env_ready; then
    cat <<EOF
Peer CLI environment is not configured.

After starting the Fabric test network, source the peer environment for an org, then run:

  peer chaincode query -C ${CHANNEL_NAME} -n ${CHAINCODE_NAME} -c '{"Args":["Ping"]}'
EOF
    return 1
  fi

  peer chaincode query -C "$CHANNEL_NAME" -n "$CHAINCODE_NAME" -c '{"Args":["Ping"]}'
}

case "${1:-}" in
  up)
    network up createChannel -c "$CHANNEL_NAME"
    ;;
  down)
    network down
    ;;
  deployCC)
    echo "Deploying Go chaincode through Fabric samples test-network."
    echo "If your Fabric samples setup requires local Go for packaging, use cc-tidy/cc-test/cc-build for Docker-based validation first."
    network deployCC \
      -c "$CHANNEL_NAME" \
      -ccn "$CHAINCODE_NAME" \
      -ccp "$CHAINCODE_PATH" \
      -ccl "$CHAINCODE_LANG" \
      -ccv "$CHAINCODE_VERSION" \
      -ccs "$CHAINCODE_SEQUENCE"
    ;;
  status)
    status
    ;;
  ping)
    ping
    ;;
  cc-tidy)
    run_go_docker mod tidy
    ;;
  cc-test)
    run_go_docker test ./...
    ;;
  cc-build)
    run_go_docker build ./...
    ;;
  cc-go-version)
    run_go_docker version
    ;;
  env)
    print_env_bash
    ;;
  env-powershell)
    print_env_powershell
    ;;
  *)
    echo "usage: $0 {up|down|deployCC|status|ping|cc-go-version|cc-tidy|cc-test|cc-build|env|env-powershell}" >&2
    exit 1
    ;;
esac
