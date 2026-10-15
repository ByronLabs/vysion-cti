"""Verify durable queue delivery against real workers without moving the cursor.

Stop the scheduled wallet service before running via that Compose service.
On interruption, leave pending state intact: the scheduled feed safely resumes it.
"""
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "wallet-feed/src"))
from common.imports import reconcile, submit
from common.evidence import evidence_bundle
from wallets import WalletFeed, wallet_objects


if __name__ == "__main__":
    os.environ["CONNECTOR_ID"] = os.environ["VYSION_WALLET_CONNECTOR_ID"]
    feed = WalletFeed()
    original = feed.helper.get_state() or {}
    if original.get("pending_import"):
        raise RuntimeError("Wait for the scheduled pending import before running this test")
    month = datetime.now(timezone.utc) - timedelta(days=30)
    hits, _ = feed.client.search(
        f"feed/{feed.platform}/wallets",
        {"batch": month.date().isoformat(), "range_type": "month"},
        page_size=5, max_pages=1,
    )
    objects = next((mapped for hit in hits if (mapped := wallet_objects(hit))), None)
    if not objects:
        raise RuntimeError("No supported detection in the sampled historical month")
    work_id = feed.helper.api.work.initiate_work(feed.helper.connect_id, "Vysion durable delivery smoke")
    state, confirmed = submit(
        feed.helper, original, evidence_bundle(objects),
        original, work_id, update=True,
    )
    for _ in range(90):
        if confirmed:
            break
        if state.get("window_end") != original.get("window_end"):
            raise RuntimeError("Cursor changed before worker confirmation")
        time.sleep(2)
        state, confirmed = reconcile(feed.helper, state)
    if not confirmed:
        raise RuntimeError("Worker confirmation still pending; scheduled feed can resume saved delivery")
    if feed.helper.get_state() != original:
        raise RuntimeError("Durable delivery did not preserve the scheduled checkpoint")
    print("Verified durable bundle submission, actual worker confirmation and unchanged checkpoint")
