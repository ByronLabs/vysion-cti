# Vysion observable enrichment

Manual enrichment with grouped document capture notes, messaging profile
associations and optional leak metadata. Does not automatically create malicious
indicators or change analyst scores.

See the [OpenCTI guide](../README.md) for supported types, configuration and tests.
Build this Dockerfile using the parent `opencti/` directory as its context so
shared modules are included, or use `connector-vysion-enrichment` in Compose.
