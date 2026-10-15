#!/bin/sh

# Start the connector (WORKDIR is /opt/connector as set in the Dockerfile)
if [ -z "${VYSION_ENRICHMENT_CONNECTOR_ID:-}" ]; then
  echo "VYSION_ENRICHMENT_CONNECTOR_ID must be configured" >&2
  exit 1
fi
export CONNECTOR_ID="$VYSION_ENRICHMENT_CONNECTOR_ID"
exec python3 vysion-enrichment.py
