# Live smoke tests

Run from `opencti/` with a configured `.env` and a running platform/workers.
These tests import real data; they are not part of CI. Stop the corresponding
scheduled connector to avoid concurrent instances sharing its ID.

## Wallet feed

Samples a historical month, imports one detection twice and checks wallets,
notes, chain labels and unchanged connector state.

```sh
docker compose --profile vysion-wallets stop connector-vysion-wallets
docker compose --profile vysion-wallets run --rm --no-deps -T --entrypoint python3 \
  -v "$PWD:/tests:ro" connector-vysion-wallets /tests/tests/smoke_wallet_feed.py
docker compose --profile vysion-wallets start connector-vysion-wallets
```

## Ransomware feed

Samples a week around 30 days ago, imports one event twice and checks its STIX
objects/relationships and unchanged state. Existing legacy incidents are not
deleted or migrated.

```sh
docker compose --profile vysion stop connector-vysion-external
docker compose --profile vysion run --rm --no-deps -T --entrypoint python3 \
  -v "$PWD:/tests:ro" connector-vysion-external /tests/tests/smoke_ransomware.py
docker compose --profile vysion start connector-vysion-external
```

Restart the scheduled connector even if a smoke test fails, then inspect Works.
Rebuild images after code changes using
`docker compose --profile vysion --profile vysion-wallets build`.
