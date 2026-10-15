"""Durable, bounded replay of queue submissions until workers confirm success."""
import time

from common.client import VysionError

MAX_BUNDLE_BYTES = 1_000_000
WORK_TIMEOUT = 3600


def reconcile(helper, state):
    pending = state.get("pending_import")
    if not pending:
        return state, True
    if pending["phase"] == "submitted":
        work = helper.api.query(
            "query($id:ID!){work(id:$id){status completed_number errors{message}}}",
            {"id": pending["work_id"]},
        )["data"]["work"]
        if work and work["status"] == "complete" and not work.get("errors") and work.get("completed_number", 0) > 0:
            confirmed = pending["success_state"]
            helper.set_state(confirmed)
            return confirmed, True
        if work and work["status"] != "complete" and time.time() - pending["submitted_at"] < WORK_TIMEOUT:
            return state, False
        helper.log_warning("Worker import failed or timed out; replaying the saved deterministic bundle")
    # A crash between saving intent and recording submission is safely replayed.
    work_id = helper.api.work.initiate_work(helper.connect_id, "Vysion import retry")
    pending = {**pending, "work_id": work_id, "phase": "prepared"}
    state = {**state, "pending_import": pending}
    helper.set_state(state)
    helper.send_stix2_bundle(pending["bundle"], update=pending["update"], work_id=work_id)
    helper.api.work.to_processed(work_id, "Submitted saved bundle; awaiting worker confirmation")
    pending = {**pending, "phase": "submitted", "submitted_at": int(time.time())}
    state = {**state, "pending_import": pending}
    helper.set_state(state)
    return state, False


def submit(helper, state, bundle, success_state, work_id, update=True):
    if len(bundle.encode("utf-8")) > MAX_BUNDLE_BYTES:
        raise VysionError("Import chunk exceeds the durable bundle size limit")
    pending = {
        "work_id": work_id, "phase": "prepared", "bundle": bundle,
        "update": update, "success_state": success_state,
    }
    prepared = {**state, "pending_import": pending}
    helper.set_state(prepared)
    helper.send_stix2_bundle(bundle, update=update, work_id=work_id)
    rejected = len(success_state.get("rejected_records", []))
    helper.api.work.to_processed(work_id, f"Submitted bundle; awaiting worker confirmation; quarantined records: {rejected}")
    if rejected:
        helper.log_warning(f"Quarantined {rejected} records retained for independent retry")
    submitted = {**prepared, "pending_import": {**pending, "phase": "submitted", "submitted_at": int(time.time())}}
    helper.set_state(submitted)
    return reconcile(helper, submitted)


def window_start(state, now, lookback_hours=24):
    """Never silently skip data when a checkpoint exceeds retention."""
    from datetime import datetime, timedelta, timezone

    previous = state.get("window_end")
    start = datetime.fromisoformat(previous.replace("Z", "+00:00")) if previous else now - timedelta(hours=lookback_hours)
    if start.tzinfo is None:
        raise VysionError("Checkpoint must have a UTC offset")
    start = start.astimezone(timezone.utc)
    if now - start > timedelta(days=30):
        raise VysionError("Checkpoint exceeds 30-day catch-up limit; explicit historical recovery required")
    if start > now:
        raise VysionError("Checkpoint is in the future")
    return start - timedelta(hours=lookback_hours) if previous else start


def quarantine(rejected, record, batch, error):
    if len(rejected) >= 100:
        raise VysionError("Rejected record limit reached; checkpoint unchanged")
    # Retain identifiers and error classes, never raw source content.
    record_id = record.get("id") if isinstance(record, dict) else None
    rejected.append({"id": str(record_id or "unknown")[:200], "batch": batch, "error": type(error).__name__})


def window_bounds(state, now, lookback_hours=24):
    from datetime import datetime, timedelta

    if state.get("retry_window"):
        retry = state["retry_window"]
        return datetime.fromisoformat(retry["start"]), datetime.fromisoformat(retry["end"])
    if state.get("quarantine_due") and state.get("rejected_records"):
        from datetime import timezone
        start = datetime.fromisoformat(state["rejected_records"][0]["batch"]).replace(tzinfo=timezone.utc)
        return start, min(now, start + timedelta(days=1))
    start = window_start(state, now, lookback_hours)
    anchor = datetime.fromisoformat(state["window_end"].replace("Z", "+00:00")) if state.get("window_end") else start
    end = min(now, anchor.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
    return start, end


def is_quarantine_window(state):
    retry = state.get("retry_window")
    return retry.get("mode") == "quarantine" if retry else bool(state.get("quarantine_due") and state.get("rejected_records"))


def merge_rejected(existing, rejected, resolved, retry_batch=None):
    # Round-robin old batches so one permanently broken record cannot starve
    # newer healthy windows or other quarantined batches.
    retained = [record for record in existing if record["id"] not in resolved or record["id"] == "unknown"]
    retained.sort(key=lambda record: record["batch"] == retry_batch)
    records = {(record["id"], record["batch"]): record for record in retained}
    records.update({(record["id"], record["batch"]): record for record in rejected})
    if len(records) > 100:
        raise VysionError("Quarantine ledger limit reached; explicit investigation required")
    return list(records.values())
