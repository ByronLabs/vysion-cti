# Vysion for OpenCTI

Three connectors for an existing OpenCTI installation:

| Connector | Purpose | Compose profile |
| --- | --- | --- |
| Ransomware feed | Incidents, victims, threat actors, countries and sectors | `vysion` |
| Observable enrichment | Cited document, messaging profile and optional leak evidence | `vysion` |
| Wallet detections | Cryptocurrency wallets and evidence notes | `vysion-wallets` |

## Requirements

- A running OpenCTI platform, workers and RabbitMQ. Tested with OpenCTI
  `7.261008.0`; Python dependencies pin `pycti==7.260917.0`.
- Docker with Compose v2.
- An OpenCTI API token with permissions to read observables, register connectors,
  manage connector works and import the relevant STIX objects.
- A Vysion API key authorised for each enabled source.
- Network access to OpenCTI, its advertised RabbitMQ endpoint and the Vysion API.

This Compose file deploys connectors only, not an OpenCTI platform.

## Installation

From the repository root:

```sh
cd opencti
cp env.example .env
```

Edit `.env` with your API credentials and three distinct, stable UUIDv4 connector
IDs. Generate each UUID with `python3 -c 'import uuid; print(uuid.uuid4())'`.
The wallet ID is only required when its profile is enabled. Keep `.env` private;
never commit it. Do not overwrite an existing configuration when upgrading.

Set `OPENCTI_DOCKER_NETWORK` to an existing Docker network shared by OpenCTI and
RabbitMQ. Find the network names with `docker network ls`. The default
`opencti_default` is an example, not a guaranteed name. Set `OPENCTI_URL` to the
platform URL reachable from containers (e.g. `http://opencti:8080`), not the
host's `localhost` address. The broker hostname advertised by OpenCTI must also
resolve from these containers.

Start ransomware import and manual enrichment:

```sh
docker compose --profile vysion up -d --build
```

Enable wallet detection separately:

```sh
docker compose --profile vysion-wallets up -d --build connector-vysion-wallets
```

Both commands use the standalone Compose project in this directory. If migrating
from another deployment, stop the old connector instances before starting these
with the same IDs. Retain the IDs to keep existing connector state; never run two
instances with the same ID against one platform.

## Observable enrichment

Open an observable in OpenCTI, select **Enrichment → Vysion Enrichment**, and
confirm execution. Check the connector's **Works** tab and the observable's
linked notes. `State: null` and no scheduled run are normal for manual enrichment.

| OpenCTI type | Documents | Messaging profiles | Leaks (opt-in) |
| --- | --- | --- | --- |
| Url | Captures of the exact URL | — | — |
| Domain-Name / Hostname | Quoted mention search | — | — |
| Email-Addr | Email lookup | Email association | Email lookup |
| Cryptocurrency-Wallet | Chain/address lookup | Chain/address association | Chain/address lookup |
| User-Account | — | Username search | Username lookup |
| IPv4-Addr / IPv6-Addr | — | — | IP lookup |
| StixFile | — | — | SHA-256, SHA-1 or MD5 lookup |

Wallets require exactly one label specifying the chain: `chain:BTC`, `chain:ETH`,
`chain:XMR`, `chain:XRP`, `chain:ZEC`, `chain:DOT`, `chain:BNB` or `chain:DASH`.
The connector does not guess chains from ambiguous address formats.

Document captures are grouped by exact source URL, title and enriched observable.
Each note has page metadata and a table of detection dates, languages, hashes
and individual `https://app.vysion.ai/document/{id}` links. Subsequent enrichment
retains previously collected captures. Missing source URLs prevent grouping.
Legacy per-document notes are not deleted automatically. IM and leak notes link
to the Vysion app homepage and include selected evidence metadata.

A mention is not proof of maliciousness, ownership or real-world identity.
Enrichment does not create threat indicators or change analyst scores.

### Source and sharing controls

Set these values in `.env`, then recreate the enrichment container:

```sh
docker compose --profile vysion up -d connector-vysion-enrichment
```

| Variable | Default | Behaviour |
| --- | --- | --- |
| `VYSION_ENABLE_IM` | `true` | Messaging profile searches |
| `VYSION_ENABLE_LEAKS` | `false` | Leak metadata searches; required for IPs and files |
| `VYSION_MAX_TLP` | `TLP:GREEN` | Reject higher-TLP observables before external requests |
| `VYSION_MAX_PAGES` | `5` | Maximum pages per enrichment source |
| `VYSION_PAGE_SIZE` | `10` | Results per page; leaks uses five |
| `VYSION_HTTP_ATTEMPTS` | `3` | Shared-client bounded retry attempts |

The `whitelist` label skips enrichment. All TLP markings are checked and object
markings are propagated. Leak imports exclude credentials, highlights, download
URLs and full leaked content. Source errors fail the work rather than reporting
zero matches. Pagination limits are reported in the work completion message.

The shared enrichment/wallet HTTP client uses HTTPS, rejects redirects, validates
schemas, and retries network failures, HTTP 429 and selected 5xx responses. It
honours Retry-After up to 60 seconds. Connect/read deadlines are 10/45 seconds.
401/403 are not retried; disable a source explicitly if your key cannot access it.

## Ransomware feed

Polls hourly using daily API batches intersecting a rolling 24-hour UTC window.
Imports incidents, victim organisations and ransomware threat actors; countries
and sectors are included where available. Configure `CONNECTOR_RUN_EVERY`
(default `1h`) and `VYSION_LOOKBACK_HOURS` (default `24`) in `.env`.

The feed saves imported event IDs in connector state. It still uses random STIX
IDs for some objects: resetting state or retrying a partially imported batch can
duplicate incidents. Do not clear state merely to refresh existing data.
This legacy importer does not use the shared HTTP client.

## Wallet detection feed

The independent profile is opt-in because import volume can be substantial.
Set `VYSION_WALLET_PLATFORM` to `darknet` (default), `telegram`, `discord` or `all`.
Set `VYSION_WALLET_INTERVAL_SECONDS` to change the hourly polling interval.

Uses `feed/{platform}/wallets` with `range_type=day`. It starts with the previous
24 hours, overlaps the prior checkpoint by 24 hours, and catches up after downtime
up to 30 days. Wallet and note IDs are deterministic; chain labels come from the
API's typed address fields, not address guessing. Detections are not automatically
classified as malicious and no ownership assertions are made.

The checkpoint advances after successful queue submission, not worker completion;
check OpenCTI Works for import errors. Source errors or the pagination cap (100
pages of 100 records per day) leave the checkpoint unchanged. Zero detections in
a successful work means no matching records in the queried window.

## Monitoring

```sh
docker compose --profile vysion --profile vysion-wallets ps
docker compose --profile vysion logs -f connector-vysion-enrichment
docker compose --profile vysion-wallets logs -f connector-vysion-wallets
```

## Tests

Offline unit tests do not contact OpenCTI or Vysion:

```sh
docker build -f internal-enrichment/Dockerfile -t vysion-opencti-enrichment:local .
docker run --rm --entrypoint python3 -v "$PWD:/tests:ro" \
  vysion-opencti-enrichment:local -m unittest discover -s /tests/tests -v
```

Tests cover retries, schemas, pagination, capture grouping and retention,
deterministic IDs, chain ambiguity, whitelist/TLP controls, leak redaction,
checkpoint failures and unchanged scores.

Optional live test using the public Bitcoin genesis address (creates/upserts an
annotated observable and requests enrichment; requires configured credentials):

```sh
docker compose --profile vysion run --rm --no-deps -T --entrypoint python3 \
  -v "$PWD/tests/smoke_opencti.py:/smoke_opencti.py:ro" \
  connector-vysion-enrichment /smoke_opencti.py
```

## API reference

- https://developers.vysion.ai/api/documents/
- https://developers.vysion.ai/api/leaks/
- https://developers.vysion.ai/api/instant-messaging/
- https://developers.vysion.ai/api/feeds/
