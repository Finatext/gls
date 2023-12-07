#!/usr/bin/env bash
set -euo pipefail
set -x

VERSION="${VERSION:-v8.18.1}"
DIR="$(dirname "$0")"
ROOT="$(dirname "$DIR")"

(
cd "$ROOT"

out=dev/original.toml
curl --silent --show-error --fail --connect-timeout 3 --max-time= 0 --retry 3 \
  --location --output "${out}" "https://raw.githubusercontent.com/gitleaks/gitleaks/${VERSION}/config/gitleaks.toml"

cargo run extract-allowlist -s "${out}" -o dev/gitleaks-allowlist.toml
cargo run cleanup-allowlist -s "${out}" -o dev/gitleaks.toml

rm "${out}"
)
