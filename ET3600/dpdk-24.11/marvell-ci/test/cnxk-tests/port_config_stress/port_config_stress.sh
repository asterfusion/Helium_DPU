#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2025 Marvell.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
APP="${SCRIPT_DIR}/port_config_stress"
PCI_DEVICES=("0002:01:00.1" "0002:01:00.2")
LOG_FILE="port_test_log.txt"
APP_PID=0

cleanup() {
    echo -e "\n[INFO] Script interrupted. Cleaning up..."
    if [[ $APP_PID -ne 0 ]] && kill -0 "$APP_PID" 2>/dev/null; then
        echo "[INFO] Killing DPDK app (PID $APP_PID)..."
        kill -TERM "$APP_PID"
        wait "$APP_PID" 2>/dev/null || true
    fi
    echo "CI Test FAILED: Interrupted by user or system signal."
    cat "$LOG_FILE"
    exit 1
}

trap cleanup SIGINT SIGTERM

if [[ ! -f $APP ]]; then
    echo "Error: DPDK application binary not found at $APP"
    exit 1
fi

EAL_ARGS="-l 1-4 -n 4 -a ${PCI_DEVICES[0]} -a ${PCI_DEVICES[1]}"
: > "$LOG_FILE"
echo "Running DPDK application..."

set +e
$APP $EAL_ARGS > "$LOG_FILE" 2>&1 &
APP_PID=$!
wait "$APP_PID"
APP_STATUS=$?
set -e

echo "[DEBUG] Application exited with status: $APP_STATUS"

if (( APP_STATUS > 128 )); then
    SIGNAL_NUM=$((APP_STATUS - 128))
    echo "CI Test FAILED: Application was terminated by signal $SIGNAL_NUM"
    cat "$LOG_FILE"
    exit 1
elif grep -Ei "error|invalid|failed" "$LOG_FILE" >/dev/null; then
    echo "CI Test FAILED: Errors found in log."
    cat "$LOG_FILE"
    exit 1
elif [ "$APP_STATUS" -ne 0 ]; then
    echo "CI Test FAILED: Application exited with status $APP_STATUS."
    cat "$LOG_FILE"
    exit 1
else
    echo "CI Test PASSED!"
    exit 0
fi
