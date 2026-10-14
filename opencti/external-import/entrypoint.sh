#!/bin/sh

# Start the connector (WORKDIR is /opt/connector as set in the Dockerfile)
if [ -z "${VYSION_EXTERNAL_CONNECTOR_ID:-}" ]; then
  echo "VYSION_EXTERNAL_CONNECTOR_ID must be configured" >&2
  exit 1
fi
export CONNECTOR_ID="$VYSION_EXTERNAL_CONNECTOR_ID"
exec python3 vysion-external.py
