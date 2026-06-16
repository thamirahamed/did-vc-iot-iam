#!/usr/bin/env bash
set -euo pipefail

FABRIC_VERSION="${FABRIC_VERSION:-2.5.15}"
FABRIC_CA_VERSION="${FABRIC_CA_VERSION:-1.5.15}"
FORCE="false"

if [[ "${1:-}" == "--force" ]]; then
  FORCE="true"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
THIRD_PARTY="$REPO_ROOT/third_party"
FABRIC_SAMPLES="$THIRD_PARTY/fabric-samples"

print_path() {
  local path="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$path" | tr '\\' '/'
    return 0
  fi
  echo "$path"
}

for command_name in git curl bash; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required to install Fabric Samples." >&2
    exit 1
  fi
done

if [[ -d "$FABRIC_SAMPLES" && "$FORCE" != "true" ]]; then
  echo "Fabric Samples already exists: $FABRIC_SAMPLES"
  echo "Use --force to run the installer again."
else
  mkdir -p "$THIRD_PARTY"
  cd "$THIRD_PARTY"
  curl -sSL https://bit.ly/2ysbOFE | bash -s -- "$FABRIC_VERSION" "$FABRIC_CA_VERSION"
fi

cat <<EOF

Fabric Samples path:
  FABRIC_SAMPLES_PATH=$(print_path "$FABRIC_SAMPLES")
  FABRIC_SAMPLES_ORGS_HOST_PATH=$(print_path "$FABRIC_SAMPLES/test-network/organizations")

Next:
  Copy .env.project.example to .env.project.
  Set those two values in .env.project, using absolute paths with forward slashes on Windows.
EOF
