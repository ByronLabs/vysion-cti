"""Opt-in live integration test using the public Bitcoin genesis address.

Run via docker compose run --rm --no-deps --entrypoint python3 with this file
mounted. Creates/upserts one annotated public observable and submits an actual
enrichment work. Does not download leaks or delete existing data.
"""
import os
import time

from pycti import OpenCTIApiClient


api = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])
label = api.label.read_or_create_unchecked(value="chain:BTC", color="#607d8b")
obj = api.stix_cyber_observable.create(
    observableData={"type": "cryptocurrency-wallet", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
    objectLabel=[label["id"]],
    simple_observable_description="Public Bitcoin genesis address; Vysion smoke test, not an assertion of maliciousness.",
)
connector = next(item for item in api.connector.list() if item["name"] == "Vysion Enrichment")
score_before = obj.get("x_opencti_score")
work_id = api.stix_cyber_observable.ask_for_enrichment(id=obj["id"], connector_id=connector["id"])
for attempt in range(60):
    work = api.query(
        "query($id:ID!) {work(id:$id) {status completed_number errors {message} messages {message}}}",
        {"id": work_id},
    )["data"]["work"]
    if work["status"] == "complete":
        break
    time.sleep(2)
else:
    raise RuntimeError("Smoke work not complete; inspect OpenCTI Works before retrying")
if work["errors"]:
    raise RuntimeError("Smoke work completed with errors; inspect OpenCTI Works")
after = api.stix_cyber_observable.read(id=obj["id"])
assert after.get("x_opencti_score") == score_before, "Enrichment changed the analyst score"
print("Smoke work complete:", work_id, "processed objects:", work["completed_number"], "score unchanged")
