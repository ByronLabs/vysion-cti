#!/bin/sh
set -eu
: "${VYSION_WALLET_CONNECTOR_ID:?Set VYSION_WALLET_CONNECTOR_ID to a unique UUIDv4}"
export CONNECTOR_ID="$VYSION_WALLET_CONNECTOR_ID"
exec python3 wallets.py
