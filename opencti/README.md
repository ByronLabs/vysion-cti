# Vysion for OpenCTI

| Connector | Purpose | Compose profile |
| --- | --- | --- |
| Ransomware feed | Incidents, victims, threat actors, countries and sectors | `vysion` |
| Observable enrichment | Document, messaging profile and leak evidence | `vysion` |
| Wallet detections | Cryptocurrency wallets and evidence notes | `vysion-wallets` |

## Setup

Requires Docker Compose v2, a running OpenCTI platform with workers and RabbitMQ,
an OpenCTI API token with connector/import permissions, and a Vysion API key.
Tested with OpenCTI `7.261008.0`; dependencies pin `pycti==7.260917.0`.
This deployment includes connectors only.

```sh
cd opencti
cp env.example .env
```

Configure credentials, a different UUIDv4 for each connector, and:
- `OPENCTI_URL`: platform URL reachable from containers.
- `OPENCTI_DOCKER_NETWORK`: existing network shared with OpenCTI and RabbitMQ.

Keep `.env` private. When migrating, retain connector IDs and stop old instances
before starting these. The advertised RabbitMQ hostname must be reachable.

```sh
# Ransomware feed and manual enrichment
docker compose --profile vysion up -d --build

# Optional wallet feed
docker compose --profile vysion-wallets up -d --build connector-vysion-wallets
```

## Enrichment

Select **Enrichment → Vysion Enrichment** on an observable. Results appear in
linked notes; execution details are available in the connector's **Works** tab.

| Observable | Sources |
| --- | --- |
| Url, Domain-Name, Hostname | Documents |
| Email-Addr, Cryptocurrency-Wallet | Documents, IM, leaks |
| User-Account | IM, leaks |
| IPv4-Addr, IPv6-Addr, StixFile | Leaks |

Wallets require one chain label: `chain:BTC`, `chain:ETH`, `chain:XMR`, `chain:XRP`,
`chain:ZEC`, `chain:DOT`, `chain:BNB` or `chain:DASH`. Files use SHA-256, SHA-1 or MD5.

Notes group document captures by URL, title and observable, retaining dates,
hashes and individual Vysion links. Leak notes link to the matching record in
Vysion; credentials and file contents are not imported. Scores remain unchanged.

### Configuration

Edit `.env`, then run `docker compose --profile vysion up -d connector-vysion-enrichment`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `VYSION_ENABLE_IM` | `true` | Messaging profile lookups |
| `VYSION_ENABLE_LEAKS` | `false` | Search leaks for matching observables |
| `VYSION_MAX_TLP` | `TLP:GREEN` | Maximum TLP allowed for external queries |
| `VYSION_MAX_PAGES` | `5` | Pages per source |
| `VYSION_PAGE_SIZE` | `10` | Results per page; leaks uses five |
| `VYSION_HTTP_ATTEMPTS` | `3` | Enrichment/wallet HTTP retry limit |

The `whitelist` label skips enrichment. Markings are propagated; source errors
and pagination limits are reported in Works.

## Feeds

- **Ransomware:** hourly, rolling 24-hour window. Configure `CONNECTOR_RUN_EVERY`
  and `VYSION_LOOKBACK_HOURS`. Resetting state or retrying partial imports can
  duplicate incidents.
- **Wallets:** hourly, initially the previous 24 hours, with overlapping queries
  and up to 30 days of catch-up. Set `VYSION_WALLET_PLATFORM` to `darknet` (default),
  `telegram`, `discord` or `all`; interval: `VYSION_WALLET_INTERVAL_SECONDS`.
  IDs are deterministic. Check Works for worker errors after queue submission.

## Tests

From `opencti/`, run offline tests:

```sh
docker build -f internal-enrichment/Dockerfile -t vysion-opencti-enrichment:local .
docker run --rm --entrypoint python3 -v "$PWD:/tests:ro" \
  vysion-opencti-enrichment:local -m unittest discover -s /tests/tests -v
```

[Vysion API documentation](https://developers.vysion.ai)
