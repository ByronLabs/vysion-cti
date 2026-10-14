# Vysion ransomware feed

Hourly rolling-window ransomware importer for OpenCTI. Creates incidents,
victim organisations, threat actors and available country/sector relationships.

See the [OpenCTI guide](../README.md) for installation, credentials, state and
deduplication limitations. Build this Dockerfile using `external-import/` as its
context, or use the provided Compose service `connector-vysion-external`.
