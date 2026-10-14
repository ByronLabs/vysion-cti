import os
import time
from datetime import datetime, timedelta, timezone

from pycti import CustomObservableCryptocurrencyWallet, OpenCTIConnectorHelper
from stix2 import Bundle

from common.client import VysionClient, VysionError
from common.evidence import evidence_note


ADDRESS_FIELDS = {
    "bitcoin_address": "BTC", "ethereum_address": "ETH", "monero_address": "XMR",
    "ripple_address": "XRP", "zcash_address": "ZEC", "polkadot_address": "DOT",
    "binance_address": "BNB", "binance_addresses": "BNB", "dash_address": "DASH",
}


def wallet_objects(hit):
    if not hit.get("id"):
        raise ValueError("Wallet feed entry has no stable ID")
    objects = {}
    for field, chain in ADDRESS_FIELDS.items():
        addresses = hit.get(field) or []
        if not isinstance(addresses, list):
            raise ValueError("Unexpected wallet address list")
        for item in addresses:
            value = item.get("value") if isinstance(item, dict) else item
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Invalid wallet address in feed")
            wallet = CustomObservableCryptocurrencyWallet(
                value=value.strip(), x_opencti_labels=["vysion", f"chain:{chain}"],
                allow_custom=True,
            )
            note = evidence_note(
                "wallet-feed", f"{hit['id']}:{chain}", wallet.id,
                "Vysion wallet detection",
                f"Chain reported by Vysion: {chain}\nDetected: {hit.get('detectionDate', '')}\n"
                f"Network: {hit.get('network', '')}\n"
                "Detection is not proof of ownership or malicious activity.",
                references=[{"source_name": "Vysion wallet feed", "external_id": str(hit["id"])}],
            )
            objects[wallet.id] = wallet
            objects[note.id] = note
    return list(objects.values())


class WalletFeed:
    def __init__(self):
        self.client = VysionClient(os.getenv("VYSION_API_URL"), os.getenv("VYSION_API_KEY"))
        self.platform = os.getenv("VYSION_WALLET_PLATFORM", "darknet").lower()
        if self.platform not in {"all", "telegram", "discord", "darknet"}:
            raise ValueError("Unsupported VYSION_WALLET_PLATFORM")
        self.interval = int(os.getenv("VYSION_WALLET_INTERVAL_SECONDS", "3600"))
        if self.interval < 60:
            raise ValueError("Wallet polling interval must be at least 60 seconds")
        self.helper = OpenCTIConnectorHelper({})

    def run_once(self, window_start=None, window_end=None, checkpoint=True, max_detections=None):
        now = datetime.now(timezone.utc)
        state = self.helper.get_state() or {}
        previous = state.get("window_end")
        if window_start is not None or window_end is not None:
            if checkpoint or window_start is None or window_end is None:
                raise ValueError("Historical test windows require both dates and checkpoint=False")
            start, now = window_start, window_end
            if start.tzinfo is None or now.tzinfo is None or start >= now or now - start > timedelta(days=31):
                raise ValueError("Invalid historical wallet test window")
        else:
            start = datetime.fromisoformat(previous) - timedelta(hours=24) if previous else now - timedelta(hours=24)
            start = max(start, now - timedelta(days=30))
        if max_detections is not None and (checkpoint or max_detections < 1):
            raise ValueError("Limited test imports require checkpoint=False and a positive limit")
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, "Vysion wallet detections")
        try:
            objects = {}
            batch = start.date()
            seen = 0
            while batch <= now.date():
                hits, truncated = self.client.search(
                    f"feed/{self.platform}/wallets",
                    {"batch": batch.isoformat(), "range_type": "day"},
                    page_size=100, max_pages=100,
                )
                if truncated:
                    raise VysionError("Wallet feed page limit reached; checkpoint not advanced")
                for hit in hits:
                    detected = datetime.fromisoformat(str(hit["detectionDate"]).replace("Z", "+00:00"))
                    if detected.tzinfo is None:
                        detected = detected.replace(tzinfo=timezone.utc)
                    if start <= detected <= now:
                        seen += 1
                        for obj in wallet_objects(hit):
                            objects[obj.id] = obj
                        if max_detections is not None and seen >= max_detections:
                            break
                if max_detections is not None and seen >= max_detections:
                    break
                batch += timedelta(days=1)
            if objects:
                self.helper.send_stix2_bundle(
                    Bundle(objects=list(objects.values()), allow_custom=True).serialize(),
                    work_id=work_id,
                )
            self.helper.api.work.to_processed(work_id, f"Submitted {len(objects)} objects from {seen} detections")
            if checkpoint:
                self.helper.set_state({"last_run": int(time.time()), "window_end": now.isoformat(), "detections": seen})
            return {"work_id": work_id, "objects": len(objects), "detections": seen}
        except Exception:
            self.helper.api.work.to_processed(work_id, "Wallet feed failed; checkpoint unchanged", True)
            raise

    def run(self):
        while True:
            try:
                state = self.helper.get_state() or {}
                if time.time() - state.get("last_run", 0) >= self.interval:
                    self.run_once()
            except Exception as error:
                self.helper.log_error(f"Wallet feed failed: {type(error).__name__}")
            if self.helper.connect_run_and_terminate:
                return
            time.sleep(60)


if __name__ == "__main__":
    WalletFeed().run()
