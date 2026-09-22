#!/usr/bin/env bash
# Cloud Agent environment bootstrap for cfscan.
#
# Idempotent: safe to run repeatedly against a cached or partially prepared
# machine. It installs the Python package in editable mode (so the `cfscan`
# command is live on the checked-out sources) and installs the external
# scanner cfscan wraps, XIU2/CloudflareSpeedTest (`cfst`), which the app runs
# as a separate process. The tests fake `cfst`, so it is not needed for the
# suite - it is here so the app can perform real scans end to end.
set -euo pipefail

CFST_VERSION="v2.3.5"
BIN_DIR="${HOME}/.local/bin"
SHARE_DIR="${HOME}/.local/share/cloudflare-speedtest"
CFST_BIN="${BIN_DIR}/cfst"

mkdir -p "${BIN_DIR}" "${SHARE_DIR}"

echo "==> Installing cfscan (editable)"
python3 -m pip install --user -e .

echo "==> Ensuring cfst (${CFST_VERSION}) is installed"
if [ ! -x "${CFST_BIN}" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' EXIT
    curl -fsSL -o "${tmp}/cfst.tar.gz" \
        "https://github.com/XIU2/CloudflareSpeedTest/releases/download/${CFST_VERSION}/cfst_linux_amd64.tar.gz"
    tar -xzf "${tmp}/cfst.tar.gz" -C "${tmp}"
    cfst_src="$(find "${tmp}" -type f -name cfst | head -n 1)"
    install -m 0755 "${cfst_src}" "${CFST_BIN}"
    # Seed the default Cloudflare range files if the user has none yet. cfscan
    # refreshes them itself via `cfscan --update-ranges`.
    src_dir="$(dirname "${cfst_src}")"
    [ -f "${SHARE_DIR}/ip.txt" ]   || install -m 0644 "${src_dir}/ip.txt"   "${SHARE_DIR}/ip.txt"
    [ -f "${SHARE_DIR}/ipv6.txt" ] || install -m 0644 "${src_dir}/ipv6.txt" "${SHARE_DIR}/ipv6.txt"
else
    echo "    cfst already present at ${CFST_BIN}"
fi

echo "==> Versions"
echo "    cfst ${CFST_VERSION} at ${CFST_BIN}"
python3 -m cfscan --version
