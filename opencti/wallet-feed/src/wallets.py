import os
import time
from datetime import datetime, timedelta, timezone

from pycti import CustomObservableCryptocurrencyWallet, OpenCTIConnectorHelper
from stix2.exceptions import STIXError

from common.client import VysionClient, VysionError
from common.evidence import evidence_note, evidence_bundle
from common.imports import reconcile, submit, quarantine, window_bounds, is_quarantine_window, merge_rejected


ADDRESS_FIELDS = {
    "bitcoin_address": "BTC", "ethereum_address": "ETH", "monero_address": "XMR",
    "ripple_address": "XRP", "zcash_address": "ZEC", "polkadot_address": "DOT",
    "binance_address": "BNB", "binance_addresses": "BNB", "dash_address": "DASH",
}


def wallet_objects(hit):
    if not isinstance(hit.get("id"), str) or not 1 <= len(hit["id"]) <= 200:
        raise ValueError("Wallet feed entry has no stable ID")
    objects = {}
    total_addresses = 0
    for field, chain in ADDRESS_FIELDS.items():
        addresses = hit.get(field) or []
        if not isinstance(addresses, list):
            raise ValueError("Unexpected wallet address list")
        if len(addresses) > 100:
            raise ValueError("Wallet address limit exceeded")
        total_addresses += len(addresses)
        if total_addresses > 100:
            raise ValueError("Wallet detection address limit exceeded")
        for item in addresses:
            value = item.get("value") if isinstance(item, dict) else item
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
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
            merge_wallet_object(objects, wallet)
            objects[note.id] = note
    return list(objects.values())


def merge_wallet_object(objects, obj):
    previous = objects.get(obj.id)
    if previous is not None and obj.type == "cryptocurrency-wallet":
        obj = CustomObservableCryptocurrencyWallet(
            id=obj.id, value=obj.value,
            x_opencti_labels=sorted(set(previous.x_opencti_labels) | set(obj.x_opencti_labels)),
            allow_custom=True,
        )
    objects[obj.id] = obj


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
        cycle_now = now
        state = self.helper.get_state() or {}
        if checkpoint:
            state, ready = reconcile(self.helper, state)
            if not ready:
                return {"work_id": state["pending_import"]["work_id"], "objects": 0, "detections": 0, "pending": True}
        quarantine_mode = checkpoint and is_quarantine_window(state)
        if window_start is not None or window_end is not None:
            if checkpoint or window_start is None or window_end is None:
                raise ValueError("Historical test windows require both dates and checkpoint=False")
            start, now = window_start, window_end
            if start.tzinfo is None or now.tzinfo is None or start >= now or now - start > timedelta(days=31):
                raise ValueError("Invalid historical wallet test window")
        else:
            start, now = window_bounds(state, now)
        current_window = now == cycle_now
        if max_detections is not None and (checkpoint or max_detections < 1):
            raise ValueError("Limited test imports require checkpoint=False and a positive limit")
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, "Vysion wallet detections")
        try:
            objects = {}
            batch = start.date()
            seen = 0
            rejected = []
            imported = set(state.get("imported_detection_ids", [])) if checkpoint else set()
            selected_ids = []
            resolved = set()
            remaining = False
            while batch <= now.date():
                hits, truncated = self.client.search(
                    f"feed/{self.platform}/wallets",
                    {"batch": batch.isoformat(), "range_type": "day"},
                    page_size=100, max_pages=100,
                )
                if truncated:
                    raise VysionError("Wallet feed page limit reached; checkpoint not advanced")
                for hit in hits:
                    if str(hit.get("id")) in imported:
                        resolved.add(str(hit["id"]))
                        continue
                    try:
                        detected = datetime.fromisoformat(str(hit["detectionDate"]).replace("Z", "+00:00"))
                        if detected.tzinfo is None:
                            detected = detected.replace(tzinfo=timezone.utc)
                        mapped = wallet_objects(hit)
                    except (ValueError, TypeError, KeyError, STIXError) as error:
                        quarantine(rejected, hit, batch.isoformat(), error)
                        continue
                    if start <= detected <= now:
                        if not mapped:
                            continue
                        if checkpoint and seen >= 25:
                            remaining = True
                            break
                        prospective = dict(objects)
                        for obj in mapped:
                            merge_wallet_object(prospective, obj)
                        from common.imports import MAX_BUNDLE_BYTES
                        if len(prospective) > 500 or len(evidence_bundle(prospective.values()).encode("utf-8")) > MAX_BUNDLE_BYTES:
                            if not objects:
                                quarantine(rejected, hit, batch.isoformat(), VysionError("Single wallet detection exceeds chunk limits"))
                                continue
                            remaining = True
                            break
                        seen += 1
                        selected_ids.append(str(hit["id"]))
                        resolved.add(str(hit["id"]))
                        objects = prospective
                        if max_detections is not None and seen >= max_detections:
                            break
                if remaining or (max_detections is not None and seen >= max_detections):
                    break
                batch += timedelta(days=1)
            rejected = merge_rejected(state.get("rejected_records", []), rejected, resolved,
                                      start.date().isoformat() if quarantine_mode else None)
            success = {**state, "last_run": state.get("last_run", 0) if quarantine_mode and not remaining else (int(time.time()) if not remaining and current_window else 0),
                       "detections": seen, "rejected_records": rejected,
                       "imported_detection_ids": list(dict.fromkeys(state.get("imported_detection_ids", []) + selected_ids))[-10000:]}
            if not remaining:
                if not quarantine_mode:
                    success["window_end"] = now.isoformat()
                success["quarantine_due"] = bool(rejected) and not quarantine_mode
                success.pop("retry_window", None)
            else:
                success["retry_window"] = {"start": start.isoformat(), "end": now.isoformat(), "mode": "quarantine" if quarantine_mode else "normal"}
            if objects:
                bundle = evidence_bundle(objects.values())
                if checkpoint:
                    _, ready = submit(self.helper, state, bundle, success, work_id, update=True)
                else:
                    self.helper.send_stix2_bundle(bundle, update=True, work_id=work_id)
                    self.helper.api.work.to_processed(work_id, "Submitted historical wallet test")
                    ready = True
            else:
                self.helper.api.work.to_processed(work_id, "Rejected records retained for retry" if rejected else "No new supported detections", bool(rejected))
                if checkpoint:
                    self.helper.set_state(success)
                ready = True
            return {"work_id": work_id, "objects": len(objects), "detections": seen, "pending": not ready}
        except Exception:
            self.helper.api.work.to_processed(work_id, "Wallet feed failed; checkpoint unchanged", True)
            raise

    def run(self):
        while True:
            try:
                state = self.helper.get_state() or {}
                if state.get("pending_import") or state.get("quarantine_due") or time.time() - state.get("last_run", 0) >= self.interval:
                    self.run_once()
            except Exception as error:
                self.helper.log_error(f"Wallet feed failed: {type(error).__name__}")
            if self.helper.connect_run_and_terminate:
                return
            time.sleep(60)


if __name__ == "__main__":
    WalletFeed().run()
