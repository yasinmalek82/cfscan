#!/bin/sh
# cfscan updater: replace the installed copy with this folder, cleanly.
#
# The uninstaller runs first so an old version never lingers next to a new one.
# It keeps your configuration and results (only './uninstall.sh --purge' would
# remove the configuration, and that is never used here). The updater finishes
# by checking that the installed package matches this folder byte for byte, so a
# partial or stale copy cannot go unnoticed.
set -eu

SOURCE="$(cd "$(dirname "$0")" && pwd)"
cd "${SOURCE}"

LIB="${HOME}/.local/share/cfscan/lib/cfscan"
TARGET="${HOME}/.local/bin/cfscan"

echo "cfscan updater"
echo "--------------"
echo "Your configuration and results are kept:"
echo "  config  : ${HOME}/.config/cfscan"
echo "  results : ${HOME}/Documents/Cloudflare Scanner Results"
echo

./uninstall.sh
echo
./install.sh

echo
if [ ! -d "${LIB}" ]; then
    echo "ERROR: ${LIB} is missing after installing." >&2
    exit 1
fi

DIFFERENCES="$(diff -r -x '__pycache__' "${SOURCE}/cfscan" "${LIB}" 2>&1 || true)"
if [ -n "${DIFFERENCES}" ]; then
    echo "ERROR: the installed copy does not match this folder:" >&2
    echo "${DIFFERENCES}" >&2
    exit 1
fi

echo "Check: the installed package matches this folder exactly."
"${TARGET}" --version
echo
echo "Done. Run 'cfscan' for the menu."
