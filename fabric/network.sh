#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

load_env_defaults() {
  local file="$1"
  local line
  local key
  local value
  local first
  local last
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    if [[ -z "${!key+x}" ]]; then
      first="${value:0:1}"
      last="${value: -1}"
      if [[ "${#value}" -ge 2 && "$first" == "$last" && ( "$first" == "\"" || "$first" == "'" ) ]]; then
        value="${value:1:${#value}-2}"
      fi
      export "$key=$value"
    fi
  done < "$file"
}

load_env_defaults "$REPO_ROOT/.env.project"
load_env_defaults "$SCRIPT_DIR/.fabric-env"

FABRIC_VERSION="${FABRIC_VERSION:-2.5.15}"
FABRIC_CA_VERSION="${FABRIC_CA_VERSION:-1.5.15}"
CHANNEL_NAME="${CHANNEL_NAME:-${FABRIC_CHANNEL_NAME:-mychannel}}"
CHAINCODE_NAME="${CHAINCODE_NAME:-${FABRIC_CHAINCODE_NAME:-iam}}"
CHAINCODE_LANG="${CHAINCODE_LANG:-go}"
CHAINCODE_VERSION="${CHAINCODE_VERSION:-1.0}"
CHAINCODE_SEQUENCE="${CHAINCODE_SEQUENCE:-1}"
FABRIC_BATCH_TIMEOUT="${FABRIC_BATCH_TIMEOUT:-2s}"
FABRIC_MAX_MESSAGE_COUNT="${FABRIC_MAX_MESSAGE_COUNT:-50}"
FABRIC_PREFERRED_MAX_BYTES="${FABRIC_PREFERRED_MAX_BYTES:-2 MB}"
FABRIC_ABSOLUTE_MAX_BYTES="${FABRIC_ABSOLUTE_MAX_BYTES:-10 MB}"
GO_DOCKER_IMAGE="${GO_DOCKER_IMAGE:-golang:1.23}"
FABRIC_TOOLS_IMAGE="${FABRIC_TOOLS_IMAGE:-hyperledger/fabric-tools:${FABRIC_VERSION}}"
FABRIC_DOCKER_NETWORK="${FABRIC_DOCKER_NETWORK:-fabric_test}"
GO_DOCKER_VOLUME="${GO_DOCKER_VOLUME:-did-vc-iot-iam-go-${FABRIC_VERSION}}"

CHAINCODE_PATH="${CHAINCODE_PATH:-$REPO_ROOT/fabric/chaincode/iam}"
CHAINCODE_PATH_ABS=""

resolve_path() {
  local path="$1"
  if [[ -d "$path" ]]; then
    (cd "$path" && pwd)
    return 0
  fi
  return 1
}

find_fabric_samples_path() {
  if [[ -n "${FABRIC_TEST_NETWORK_PATH:-}" && -f "$FABRIC_TEST_NETWORK_PATH/network.sh" ]]; then
    local explicit_test_network
    explicit_test_network="$(resolve_path "$FABRIC_TEST_NETWORK_PATH")"
    dirname "$explicit_test_network"
    return 0
  fi

  if [[ -n "${FABRIC_SAMPLES_PATH:-}" && -f "$FABRIC_SAMPLES_PATH/test-network/network.sh" ]]; then
    resolve_path "$FABRIC_SAMPLES_PATH"
    return 0
  fi

  local candidates=(
    "$SCRIPT_DIR/../fabric-samples"
    "$SCRIPT_DIR/../../fabric-samples"
    "$HOME/fabric-samples"
    "$HOME/Documents/fabric-samples"
    "$HOME/Documents/Coding Projects/fabric-samples"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate/test-network/network.sh" ]]; then
      resolve_path "$candidate"
      return 0
    fi
  done

  cat >&2 <<EOF
Fabric samples test-network was not found.

Install Fabric samples, or set FABRIC_SAMPLES_PATH in .env.project or fabric/.fabric-env.

  curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.15 1.5.17

You can create:

  .env.project

or:

  fabric/.fabric-env

with:

  FABRIC_SAMPLES_PATH="/path/to/fabric-samples"

Expected test network script:
  \$FABRIC_SAMPLES_PATH/test-network/network.sh
EOF
  return 1
}

find_test_network() {
  if [[ -n "${FABRIC_TEST_NETWORK_PATH:-}" && -f "$FABRIC_TEST_NETWORK_PATH/network.sh" ]]; then
    resolve_path "$FABRIC_TEST_NETWORK_PATH"
    return 0
  fi

  local fabric_samples_path
  fabric_samples_path="$(find_fabric_samples_path)"
  echo "$fabric_samples_path/test-network"
}

print_fabric_samples_path() {
  local fabric_samples_path
  fabric_samples_path="$(find_fabric_samples_path)"
  echo "Using FABRIC_SAMPLES_PATH: $fabric_samples_path"
}

fabric_native() {
  local exe="$1"
  shift
  local env_args=(-u MSYS_NO_PATHCONV -u MSYS2_ARG_CONV_EXCL)
  local name
  local value

  if command -v cygpath >/dev/null 2>&1; then
    for name in FABRIC_CFG_PATH FABRIC_CA_CLIENT_HOME CORE_PEER_MSPCONFIGPATH CORE_PEER_TLS_ROOTCERT_FILE ORDERER_CA PEER0_ORG1_CA PEER0_ORG2_CA PEER0_ORG3_CA; do
      value="${!name:-}"
      if [[ -n "$value" ]]; then
        env_args+=("$name=$(cygpath -w "$value")")
      fi
    done
  fi

  if [[ -x "$REAL_FABRIC_BIN/${exe}.exe" ]]; then
    env "${env_args[@]}" "$REAL_FABRIC_BIN/${exe}.exe" "$@"
    return $?
  fi

  if [[ -x "$REAL_FABRIC_BIN/$exe" ]]; then
    env "${env_args[@]}" "$REAL_FABRIC_BIN/$exe" "$@"
    return $?
  fi

  command "$exe" "$@"
}

peer() {
  fabric_native peer "$@"
}

configtxgen() {
  fabric_native configtxgen "$@"
}

cryptogen() {
  fabric_native cryptogen "$@"
}

fabric-ca-client() {
  fabric_native fabric-ca-client "$@"
}

osnadmin() {
  fabric_native osnadmin "$@"
}

configtxlator() {
  fabric_native configtxlator "$@"
}

jq() {
  env -u MSYS_NO_PATHCONV -u MSYS2_ARG_CONV_EXCL "$REAL_JQ_BIN" "$@"
}

setup_native_fabric_wrappers() {
  local test_network="$1"
  export REAL_FABRIC_BIN="$test_network/../bin"
  export REAL_JQ_BIN
  REAL_JQ_BIN="$(command -v jq)"
  export -f fabric_native
  export -f peer
  export -f configtxgen
  export -f cryptogen
  export -f fabric-ca-client
  export -f osnadmin
  export -f configtxlator
  export -f jq
}

network() {
  local test_network
  test_network="$(find_test_network)"
  local test_network_script="$test_network/network.sh"
  local config_backup=""

  if ! pushd "$test_network" >/dev/null; then
    echo "Failed to enter Fabric samples test-network directory: $test_network" >&2
    return 1
  fi

  if should_apply_batch_config "$@"; then
    config_backup="$(apply_batch_config "$test_network")"
  fi

  setup_native_fabric_wrappers "$test_network"
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" bash "$test_network_script" "$@"
  local rc=$?
  if [[ -n "$config_backup" ]]; then
    restore_batch_config "$test_network" "$config_backup"
  fi
  popd >/dev/null
  return "$rc"
}

should_apply_batch_config() {
  [[ "${1:-}" == "up" ]]
}

apply_batch_config() {
  local test_network="$1"
  local configtx="$test_network/configtx/configtx.yaml"
  local backup
  if [[ ! -f "$configtx" ]]; then
    echo "Fabric configtx.yaml was not found at: $configtx" >&2
    return 1
  fi
  backup="$(mktemp)"
  cp "$configtx" "$backup"
  sed -i \
    -e "s|^\([[:space:]]*BatchTimeout:\).*|\1 ${FABRIC_BATCH_TIMEOUT}|" \
    -e "s|^\([[:space:]]*MaxMessageCount:\).*|\1 ${FABRIC_MAX_MESSAGE_COUNT}|" \
    -e "s|^\([[:space:]]*AbsoluteMaxBytes:\).*|\1 ${FABRIC_ABSOLUTE_MAX_BYTES}|" \
    -e "s|^\([[:space:]]*PreferredMaxBytes:\).*|\1 ${FABRIC_PREFERRED_MAX_BYTES}|" \
    "$configtx" || {
      cp "$backup" "$configtx"
      rm -f "$backup"
      echo "Failed to apply Fabric batch settings to: $configtx" >&2
      return 1
    }
  cat >&2 <<EOF
Applied Fabric channel batch settings for this network startup:
  BatchTimeout: ${FABRIC_BATCH_TIMEOUT}
  MaxMessageCount: ${FABRIC_MAX_MESSAGE_COUNT}
  PreferredMaxBytes: ${FABRIC_PREFERRED_MAX_BYTES}
  AbsoluteMaxBytes: ${FABRIC_ABSOLUTE_MAX_BYTES}
EOF
  echo "$backup"
}

restore_batch_config() {
  local test_network="$1"
  local backup="$2"
  local configtx="$test_network/configtx/configtx.yaml"
  if [[ -f "$backup" ]]; then
    cp "$backup" "$configtx"
    rm -f "$backup"
  fi
}

status() {
  if command -v docker >/dev/null 2>&1; then
    docker ps --filter "name=peer" --filter "name=orderer" --filter "name=ca_" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  else
    echo "docker command not found"
    return 1
  fi
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    cat >&2 <<'EOF'
jq is required by Fabric samples test-network. Install it with:
winget install jqlang.jq
EOF
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

require_chaincode_dir() {
  if [[ ! -d "$CHAINCODE_PATH" ]]; then
    echo "Chaincode directory does not exist: $CHAINCODE_PATH" >&2
    return 1
  fi
}

host_path_for_docker() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "Path does not exist: $path" >&2
    return 1
  fi

  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$path" | tr '\\' '/'
    return 0
  fi

  if (cd "$path" && pwd -W) >/dev/null 2>&1; then
    (cd "$path" && pwd -W) | tr '\\' '/'
    return 0
  fi

  (cd "$path" && pwd)
}

chaincode_path_abs() {
  require_chaincode_dir
  host_path_for_docker "$CHAINCODE_PATH"
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

require_fabric_samples() {
  find_fabric_samples_path >/dev/null
}

require_network_containers() {
  require_docker

  local peer_count
  local orderer_count
  peer_count="$(docker ps --filter "name=peer0.org" --format "{{.Names}}" | wc -l | tr -d '[:space:]')"
  orderer_count="$(docker ps --filter "name=orderer.example.com" --format "{{.Names}}" | wc -l | tr -d '[:space:]')"

  if [[ "$peer_count" -lt 2 || "$orderer_count" -lt 1 ]]; then
    cat >&2 <<EOF
Fabric test-network containers are not running.
Run:
  bash ./network.sh up
EOF
    return 1
  fi
}

ensure_go_volume() {
  require_docker

  docker volume inspect "$GO_DOCKER_VOLUME" >/dev/null 2>&1 || docker volume create "$GO_DOCKER_VOLUME" >/dev/null
  if MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "${GO_DOCKER_VOLUME}:/usr/local/go:ro" "$GO_DOCKER_IMAGE" /bin/sh -c 'test -x /usr/local/go/bin/go' >/dev/null 2>&1; then
    return 0
  fi

  echo "Preparing Docker Go runtime volume: $GO_DOCKER_VOLUME"
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
    -v "${GO_DOCKER_VOLUME}:/go-target" \
    "$GO_DOCKER_IMAGE" \
    /bin/sh -c 'rm -rf /go-target/* && cp -a /usr/local/go/. /go-target/'
}

deploy_cc_docker() {
  require_docker
  require_jq
  require_fabric_samples
  require_network_containers
  require_chaincode_dir
  ensure_go_volume

  local fabric_samples_path
  local test_network
  local repo_root_docker
  local fabric_samples_docker
  local chaincode_container_path="/workspace/fabric/chaincode/iam"

  fabric_samples_path="$(find_fabric_samples_path)"
  test_network="$fabric_samples_path/test-network"
  repo_root_docker="$(host_path_for_docker "$REPO_ROOT")"
  fabric_samples_docker="$(host_path_for_docker "$fabric_samples_path")"

  cat <<EOF
Deploying Go chaincode through Docker.
Fabric tools image: $FABRIC_TOOLS_IMAGE
Go image: $GO_DOCKER_IMAGE
Fabric samples: $fabric_samples_path
Chaincode path: $CHAINCODE_PATH
EOF

  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
    --network "$FABRIC_DOCKER_NETWORK" \
    -v "${fabric_samples_docker}:/fabric-samples" \
    -v "${repo_root_docker}:/workspace" \
    -v "${GO_DOCKER_VOLUME}:/usr/local/go:ro" \
    -e PATH="/usr/local/go/bin:/fabric-samples/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -e CHANNEL_NAME="$CHANNEL_NAME" \
    -e CHAINCODE_NAME="$CHAINCODE_NAME" \
    -e CHAINCODE_LANG="$CHAINCODE_LANG" \
    -e CHAINCODE_VERSION="$CHAINCODE_VERSION" \
    -e CHAINCODE_SEQUENCE="$CHAINCODE_SEQUENCE" \
    "$FABRIC_TOOLS_IMAGE" \
    bash -c '
      set -euo pipefail
      cp -a /fabric-samples/test-network /tmp/test-network
      cp -a /fabric-samples/config /tmp/config
      find /tmp/test-network -type f \( -name "*.sh" -o -name "*.config" \) -exec sed -i "s/\r$//" {} +
      sed -i \
        -e "s/CORE_PEER_ADDRESS=localhost:7051/CORE_PEER_ADDRESS=peer0.org1.example.com:7051/" \
        -e "s/CORE_PEER_ADDRESS=localhost:9051/CORE_PEER_ADDRESS=peer0.org2.example.com:9051/" \
        -e "s/CORE_PEER_ADDRESS=localhost:11051/CORE_PEER_ADDRESS=peer0.org3.example.com:11051/" \
        /tmp/test-network/scripts/envVar.sh
      find /tmp/test-network/scripts -type f -name "*.sh" -exec sed -i \
        -e "s/localhost:7050/orderer.example.com:7050/g" \
        -e "s/localhost:7051/peer0.org1.example.com:7051/g" \
        -e "s/localhost:9051/peer0.org2.example.com:9051/g" \
        -e "s/localhost:11051/peer0.org3.example.com:11051/g" \
        {} +
      cd /tmp/test-network
      bash ./network.sh deployCC \
        -c "$CHANNEL_NAME" \
        -ccn "$CHAINCODE_NAME" \
        -ccp "'"$chaincode_container_path"'" \
        -ccl "$CHAINCODE_LANG" \
        -ccv "$CHAINCODE_VERSION" \
        -ccs "$CHAINCODE_SEQUENCE"
    '
}

ping_docker() {
  require_docker
  require_network_containers

  local test_network
  local org_path
  local org_path_docker
  test_network="$(find_test_network)"
  org_path="$test_network/organizations"
  org_path_docker="$(host_path_for_docker "$org_path")"

  if [[ ! -d "$org_path/peerOrganizations/org1.example.com" ]]; then
    echo "Fabric crypto material was not found at: $org_path" >&2
    echo "Run: bash ./network.sh up" >&2
    return 1
  fi

  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
    --network "$FABRIC_DOCKER_NETWORK" \
    -v "${org_path_docker}:/etc/hyperledger/fabric/crypto:ro" \
    -e CORE_PEER_TLS_ENABLED="true" \
    -e CORE_PEER_LOCALMSPID="Org1MSP" \
    -e CORE_PEER_MSPCONFIGPATH="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" \
    -e CORE_PEER_ADDRESS="peer0.org1.example.com:7051" \
    -e CORE_PEER_TLS_ROOTCERT_FILE="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    "$FABRIC_TOOLS_IMAGE" \
    peer chaincode query -C "$CHANNEL_NAME" -n "$CHAINCODE_NAME" -c '{"Args":["Ping"]}'
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
export FABRIC_CORE_PEER_TLS_ENABLED=true
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
\$env:FABRIC_CORE_PEER_TLS_ENABLED="true"
\$env:FABRIC_CORE_PEER_TLS_ROOTCERT_FILE="/etc/hyperledger/fabric/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
\$env:FABRIC_ORDERER_ADDRESS="orderer.example.com:7050"
\$env:FABRIC_ORDERER_CA="/etc/hyperledger/fabric/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
\$env:FABRIC_TLS_ENABLED="true"
EOF
}

ping() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ping_docker
    return $?
  fi

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
    require_jq
    print_fabric_samples_path
    network up createChannel -c "$CHANNEL_NAME" -ca
    ;;
  down)
    network down
    ;;
  deployCC)
    require_jq
    require_chaincode_dir
    if ! command -v go >/dev/null 2>&1; then
      echo "Local Go not found. Use: bash ./network.sh deployCC-docker" >&2
      exit 1
    fi
    print_fabric_samples_path
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
  deployCC-docker)
    print_fabric_samples_path
    deploy_cc_docker
    ;;
  status)
    require_jq
    print_fabric_samples_path
    status
    ;;
  ping)
    print_fabric_samples_path
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
    echo "usage: $0 {up|down|deployCC|deployCC-docker|status|ping|cc-go-version|cc-tidy|cc-test|cc-build|env|env-powershell}" >&2
    exit 1
    ;;
esac
