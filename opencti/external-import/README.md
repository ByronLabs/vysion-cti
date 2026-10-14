# Vysion ransomware feed

Hourly rolling-window ransomware importer for OpenCTI. Creates incidents,
victim organisations, threat actors and available country/sector relationships.

See the [OpenCTI guide](../README.md) for installation, credentials and state.
Build this Dockerfile using the parent `opencti/` directory as its context so
shared modules are included, or use `connector-vysion-external` in Compose.
