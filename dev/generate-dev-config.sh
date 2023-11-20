set -euo pipefail
set -x

VERSION="${VERSION:-v8.18.1}"
DIR="$(dirname "$0")"
ROOT="$(dirname "$DIR")"

(
cd "$ROOT"

out=dev/original.toml
curl -L "https://raw.githubusercontent.com/gitleaks/gitleaks/${VERSION}/config/gitleaks.toml" -o "${out}"

cargo run extract-allowlist -s "${out}" -o dev/gitleaks-allowlist.toml
cargo run cleanup-allowlist -s "${out}" -o dev/gitleaks.toml

rm "${out}"
)
