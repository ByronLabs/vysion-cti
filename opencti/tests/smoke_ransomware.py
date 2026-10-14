"""Opt-in historical ransomware import, repeated without changing the checkpoint.

Stop the scheduled ransomware connector before running via its Compose service.
Imports at most one real historical event and verifies worker completion and
idempotency. Existing incidents are not deleted or migrated.
"""
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from smoke_wallet_feed import completed

spec = importlib.util.spec_from_file_location("ransomware", ROOT / "external-import/src/vysion-external.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


if __name__ == "__main__":
    os.environ["CONNECTOR_ID"] = os.environ["VYSION_EXTERNAL_CONNECTOR_ID"]
    feed = module.VysionEI()
    original_state = feed.helper.get_state()
    day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30)
    candidate = None
    for offset in range(7):
        start = day - timedelta(days=offset)
        end = start + timedelta(days=1) - timedelta(microseconds=1)
        hits = feed.get_feed_vysion(start, end)
        if hits:
            candidate = hits[0]
            break
    if candidate is None:
        raise RuntimeError("No ransomware event found in the sampled historical week")
    expected = module.VysionEI.event_to_stix(module.VysionEI.normalize_event(candidate))
    previous_ids = None
    for iteration in range(2):
        result = feed.run_once(original_state or {}, start, end, checkpoint=False, max_events=1)
        work = completed(feed.helper, result["work_id"])
        if result["events"] != 1:
            raise RuntimeError("Historical ransomware import did not select one event")
        ids = {}
        for obj in expected:
            reader = feed.helper.api.stix_core_relationship.read if obj.type == "relationship" else feed.helper.api.stix2.get_reader("Stix-Core-Object")
            imported = reader(id=obj.id)
            if imported is None:
                raise RuntimeError("Expected ransomware object not found in OpenCTI")
            ids[obj.id] = imported["id"]
        if previous_ids is not None and ids != previous_ids:
            raise RuntimeError("Repeated ransomware import did not resolve to the same objects")
        previous_ids = ids
        print("Historical ransomware test", iteration + 1, "batch", start.date(),
              "verified objects", len(ids), "work status", work["status"])
    if feed.helper.get_state() != original_state:
        raise RuntimeError("Historical ransomware test changed the scheduled checkpoint")
    print("Verified stable ransomware objects and unchanged scheduled checkpoint")
