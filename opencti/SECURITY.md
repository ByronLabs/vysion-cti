# Security and recovery

## Import state

Feeds persist one bounded deterministic bundle before queue submission. Only a
completed work without worker errors promotes its event IDs and checkpoint.
Pending work is checked every minute; failed, missing, timed-out or interrupted
submissions are replayed from the saved bundle. A one-hour worker timeout can
cause overlapping retries; deterministic IDs make those retries idempotent.
Do not reset connector state to recover a worker failure.

Normal recovery advances in daily windows, with overlap and bounded chunks.
Catch-up beyond 30 days fails explicitly instead of silently dropping events.
Legacy ransomware `last_batch` initializes the cursor at the end of that UTC
day (capped at the current time), retaining last-batch ID suppression. A modern
`window_end` takes precedence. Current-window polling is classified before feed
I/O, so a slow import does not accidentally enable continuous catch-up polling.
Malformed records are listed in `rejected_records` (ID, batch, error class only).
Healthy records are imported and their normal cursor can advance; rejected
batches retry independently in round-robin order between normal polling cycles.
Unresolved IDs stay in the ledger even if absent from a later source response.
Do not clear the ledger without investigating
the rejected record. No credentials or raw rejected source content are stored.
Submitted bundle content is retained temporarily in connector state for replay.

## Limits and single-writer operation

HTTP responses are bounded to 2 MB, searches to 5,000 records, JSON nesting to
32 levels, and durable feed bundles to 1 MB. Wallet detections allow at most
100 addresses, each at most 256 characters. Oversized data fails explicitly.
Runtime containers use a read-only filesystem, dropped capabilities, a non-root
user, a bounded temporary directory and CPU/memory/process limits.

Run exactly one instance for each connector ID. Enrichment serializes local
updates and uses a bounded write-through content cache to retain consecutive
capture additions while workers process the queue. Updated cache entries move
to the most-recent position before eviction. Capture metadata is embedded as
structured data in the note; the visible table is not authoritative. Retention
is capped at 1,000 captures; reaching the limit fails without deleting captures.
Cross-instance atomic merges are not supported. Stop the scheduled connector
before live smoke tests. Do not edit generated note metadata manually.

## Dependency exception

`pycti==7.260917.0` requires `setuptools~=82.0.0`; platform-matching
`pycti==7.261008.0` has the same restriction. Updating to setuptools 83.0.0
would violate that dependency. `CVE-2026-59890` concerns source-distribution
exclusion on normalization-sensitive macOS filesystems. These images build on
Linux and do not build source distributions at runtime. CI suppresses only this
specific advisory in pip-audit; image scans still report it. Revisit the exception
when pycti relaxes its constraint, and no later than 2026-12-31.

PyJWT is updated to a corrected version; lockfiles include artifact hashes.
Runtime images exclude pip and build tools. GitHub Actions and base images are
pinned; Dependabot monitors them. CI scans all reachable Git history with redacted
Gitleaks output, Python code with Bandit, dependencies with pip-audit, and images
with Trivy (HIGH/CRITICAL findings fail the job). CI has no production credentials.

TLS is required for Vysion; redirects are disabled. Keep `.env` private. Use
HTTPS for OpenCTI when crossing an untrusted network and least-privilege connector
tokens. The Compose template's HTTP URL is for a trusted private Docker network.
