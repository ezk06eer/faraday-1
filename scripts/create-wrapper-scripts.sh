#!/usr/bin/env bash
# Create wrapper scripts for Faraday entry points
set -euo pipefail

INSTALL_PREFIX="${1:?ERROR: INSTALL_PREFIX required}"
WRAPPER_DIR="${INSTALL_PREFIX}/bin"

mkdir -p "${WRAPPER_DIR}"

ENTRY_POINTS=(
    "faraday-server"
    "faraday-manage"
    "faraday-worker"
    "faraday-worker-gevent"
    "faraday-start-all"
)

for entry in "${ENTRY_POINTS[@]}"; do
    cat > "${WRAPPER_DIR}/${entry}" <<'EOF'
#!/bin/bash
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
INSTALL_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
export LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/usr/lib64:${LD_LIBRARY_PATH:-}"
exec "${INSTALL_DIR}/venv/bin/ENTRY_POINT" "$@"
EOF
    sed -i "s/ENTRY_POINT/${entry}/g" "${WRAPPER_DIR}/${entry}"
    chmod +x "${WRAPPER_DIR}/${entry}"
done

echo "Created wrapper scripts in ${WRAPPER_DIR}:"
ls -la "${WRAPPER_DIR}"
