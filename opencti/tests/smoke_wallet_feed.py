"""Opt-in historical wallet import: one detection, repeated without checkpointing.

Stop the scheduled wallet connector before running this script via its Compose
service. Uses the same production mapper/import path and checks worker results.
No addresses or API credentials are printed or stored in this repository.
"""
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "wallet-feed/src"))

from wallets import WalletFeed, wallet_objects


def completed(helper, work_id):
    for _ in range(120):
        work = helper.api.query(
            "query($id:ID!){work(id:$id){status completed_number errors{message}}}",
            {"id": work_id},
        )["data"]["work"]
        if work["errors"]:
            raise RuntimeError("Historical wallet work failed; inspect OpenCTI Works")
        if work["status"] == "complete":
            return work
        time.sleep(2)
    raise RuntimeError("Historical wallet work not complete; inspect OpenCTI Works")


def detection_time(hit):
    value = datetime.fromisoformat(hit["detectionDate"].replace("Z", "+00:00"))
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


if __name__ == "__main__":
    os.environ["CONNECTOR_ID"] = os.environ["VYSION_WALLET_CONNECTOR_ID"]
    feed = WalletFeed()
    original_state = feed.helper.get_state()
    month = datetime.now(timezone.utc) - timedelta(days=30)
    hits, _ = feed.client.search(
        f"feed/{feed.platform}/wallets",
        {"batch": month.date().isoformat(), "range_type": "month"},
        page_size=5, max_pages=1,
    )
    candidate = next((hit for hit in hits if wallet_objects(hit)), None)
    if candidate is None:
        raise RuntimeError("No supported wallet detections in the sampled historical month")
    detected = detection_time(candidate)
    start = detected.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1) - timedelta(microseconds=1)
    previous_ids = None
    for iteration in range(2):
        # Query the same daily batch as run_once and identify its first supported
        # detection; use the same selection order as the production mapper.
        day_hits, truncated = feed.client.search(
            f"feed/{feed.platform}/wallets", {"batch": start.date().isoformat(), "range_type": "day"},
            page_size=100, max_pages=100,
        )
        if truncated or not day_hits:
            raise RuntimeError("Historical daily batch unavailable or incomplete")
        selected = next((hit for hit in day_hits
                         if start <= detection_time(hit) <= end), None)
        expected = wallet_objects(selected) if selected else []
        if not expected:
            raise RuntimeError("First daily detection has no supported wallet fields")
        result = feed.run_once(start, end, checkpoint=False, max_detections=1)
        work = completed(feed.helper, result["work_id"])
        ids = {}
        for obj in expected:
            reader = feed.helper.api.note if obj.type == "note" else feed.helper.api.stix_cyber_observable
            imported = reader.read(id=obj.id)
            if imported is None:
                raise RuntimeError("Expected wallet feed object not found in OpenCTI")
            ids[obj.id] = imported["id"]
            if obj.type == "note":
                references = {item["standard_id"] for item in imported.get("objects", [])}
                if not set(obj.object_refs).issubset(references):
                    raise RuntimeError("Wallet evidence note is not linked to its observable")
            else:
                labels = {label["value"] for label in imported.get("objectLabel", [])}
                if not set(obj.x_opencti_labels).issubset(labels):
                    raise RuntimeError("Wallet chain labels were not imported")
        if previous_ids is not None and ids != previous_ids:
            raise RuntimeError("Repeated wallet import did not resolve to the same objects")
        previous_ids = ids
        print("Historical wallet test", iteration + 1, "batch", start.date(),
              "detections", result["detections"], "verified objects", len(ids),
              "work status", work["status"])
    if feed.helper.get_state() != original_state:
        raise RuntimeError("Historical wallet test changed the scheduled connector checkpoint")
    print("Verified repeated import, chain labels and unchanged scheduled checkpoint")
