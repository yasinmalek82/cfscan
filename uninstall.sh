#!/bin/sh
# cfscan uninstaller.
#
# Removes the launcher and the installed package. Configuration and results are
# kept unless you pass --purge (configuration only - your results are never
# deleted automatically).
set -eu

PREFIX="${HOME}/.local"
LIB="${PREFIX}/share/cfscan"
TARGET="${PREFIX}/bin/cfscan"
CONFIG_DIR="${HOME}/.config/cfscan"
RESULTS_DIR="${HOME}/Documents/Cloudflare Scanner Results"

echo "cfscan uninstaller"
echo "------------------"

if [ -f "${TARGET}" ]; then
    rm -f "${TARGET}"
    echo "Removed launcher: ${TARGET}"
else
    echo "No launcher found at ${TARGET}"
fi

if [ -d "${LIB}" ]; then
    rm -rf "${LIB}"
    echo "Removed package: ${LIB}"
else
    echo "No package found at ${LIB}"
fi

case "${1:-}" in
    --purge)
        if [ -d "${CONFIG_DIR}" ]; then
            rm -rf "${CONFIG_DIR}"
            echo "Removed configuration: ${CONFIG_DIR}"
        fi
        ;;
    "")
        echo "Kept configuration: ${CONFIG_DIR}"
        echo "Run './uninstall.sh --purge' to remove it as well."
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Usage: ./uninstall.sh [--purge]" >&2
        exit 2
        ;;
esac

if [ -d "${RESULTS_DIR}" ]; then
    echo "Kept your results: ${RESULTS_DIR}"
fi

echo
echo "cfscan has been uninstalled."
