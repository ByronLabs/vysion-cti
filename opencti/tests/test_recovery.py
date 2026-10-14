import copy
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from stix2 import Bundle

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.client import VysionClient, VysionError
from common.imports import reconcile, submit, window_bounds, merge_rejected, MAX_BUNDLE_BYTES


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wallets = load("recovery_wallets", "wallet-feed/src/wallets.py")
ransomware = load("recovery_ransomware", "external-import/src/vysion-external.py")
enrichment = load("recovery_enrichment", "internal-enrichment/src/vysion-enrichment.py")
legacy_ie = load("legacy_ie", "internal-enrichment/src/lib/internal_enrichment.py")
legacy_ei = load("legacy_ei", "external-import/src/lib/external_import.py")


def helper(state=None, status="complete", errors=None):
    obj = Mock()
    obj.state = copy.deepcopy(state or {})
    obj.set_state.side_effect = lambda value: setattr(obj, "state", copy.deepcopy(value))
    obj.get_state.side_effect = lambda: copy.deepcopy(obj.state)
    obj.api.query.return_value = {"data": {"work": {"status": status, "completed_number": 1, "errors": errors or []}}}
    return obj


class DeliveryTests(unittest.TestCase):
    def test_unfinished_worker_does_not_advance_checkpoint(self):
        h = helper(status="progress")
        state, confirmed = submit(h, {"window_end": "old"}, "{}", {"window_end": "new"}, "work")
        self.assertFalse(confirmed)
        self.assertEqual(h.state["window_end"], "old")
        self.assertEqual(h.state["pending_import"]["bundle"], "{}")
        h.api.query.return_value["data"]["work"]["status"] = "complete"
        state, confirmed = reconcile(h, state)
        self.assertTrue(confirmed)
        self.assertEqual(state, {"window_end": "new"})

    def test_failed_worker_replays_saved_bundle(self):
        h = helper(status="progress")
        state, _ = submit(h, {}, '{"saved":true}', {"imported_event_ids": ["one"]}, "work")
        h.send_stix2_bundle.reset_mock()
        h.api.query.return_value["data"]["work"].update(status="complete", errors=[{"message": "worker error"}])
        state, confirmed = reconcile(h, state)
        self.assertFalse(confirmed)
        self.assertNotIn("imported_event_ids", state)
        self.assertEqual(h.send_stix2_bundle.call_args.args[0], '{"saved":true}')
        self.assertTrue(h.send_stix2_bundle.call_args.kwargs["update"])

    def test_partial_queue_failure_keeps_intent(self):
        h = helper()
        h.send_stix2_bundle.side_effect = RuntimeError("partial queue failure")
        with self.assertRaises(RuntimeError):
            submit(h, {"window_end": "old"}, "{}", {"window_end": "new"}, "work")
        self.assertEqual(h.state["pending_import"]["phase"], "prepared")
        h.send_stix2_bundle.side_effect = None
        _, confirmed = reconcile(h, h.state)
        self.assertFalse(confirmed)
        self.assertEqual(h.state["window_end"], "old")

    def test_work_lookup_failure_preserves_pending(self):
        h = helper(status="progress")
        state, _ = submit(h, {}, "{}", {"done": True}, "work")
        h.api.query.side_effect = RuntimeError("unavailable")
        with self.assertRaises(RuntimeError):
            reconcile(h, state)
        self.assertEqual(h.state, state)

    def test_missing_or_timed_out_work_is_replayed(self):
        for missing in [False, True]:
            h = helper(status="progress")
            state, _ = submit(h, {}, "{}", {}, "work")
            if missing:
                h.api.query.return_value = {"data": {"work": None}}
            else:
                state["pending_import"]["submitted_at"] = 0
            h.send_stix2_bundle.reset_mock()
            _, confirmed = reconcile(h, state)
            self.assertFalse(confirmed)
            h.send_stix2_bundle.assert_called_once()

    def test_durable_bundle_limit_before_state_or_send(self):
        h = helper()
        with self.assertRaises(VysionError):
            submit(h, {}, "a" * (MAX_BUNDLE_BYTES + 1), {}, "work")
        h.set_state.assert_not_called()
        h.send_stix2_bundle.assert_not_called()


class WindowTests(unittest.TestCase):
    def test_three_day_outage_catches_up_in_daily_windows(self):
        now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        previous = now - timedelta(days=3)
        start, end = window_bounds({"window_end": previous.isoformat()}, now)
        self.assertLess(start, previous)
        self.assertEqual(end, datetime(2026, 10, 12, tzinfo=timezone.utc))

    def test_expired_checkpoint_fails_instead_of_skipping(self):
        now = datetime.now(timezone.utc)
        with self.assertRaises(VysionError):
            window_bounds({"window_end": (now - timedelta(days=31)).isoformat()}, now)

    def test_rejected_window_does_not_move_on_retry(self):
        state = {"retry_window": {"start": "2026-10-01T00:00:00+00:00", "end": "2026-10-02T00:00:00+00:00"}}
        first = window_bounds(state, datetime(2026, 10, 14, tzinfo=timezone.utc))
        second = window_bounds(state, datetime(2026, 10, 15, tzinfo=timezone.utc))
        self.assertEqual(first, second)

    def test_quarantine_rotates_and_never_silently_drops_missing_records(self):
        records = [{"id": "one", "batch": "2026-10-01", "error": "ValueError"},
                   {"id": "two", "batch": "2026-10-02", "error": "ValueError"}]
        rotated = merge_rejected(records, [], set(), retry_batch="2026-10-01")
        self.assertEqual([r["id"] for r in rotated], ["two", "one"])
        repaired = merge_rejected(rotated, [], {"one"})
        self.assertEqual([r["id"] for r in repaired], ["two"])


class WalletRecoveryTests(unittest.TestCase):
    def connector(self):
        obj = wallets.WalletFeed.__new__(wallets.WalletFeed)
        obj.helper = helper()
        obj.platform = "darknet"
        obj.client = Mock()
        return obj

    def hit(self, record_id, **fields):
        return {"id": record_id, "detectionDate": "2026-09-01T01:00:00Z", **fields}

    def test_chains_are_unioned_within_and_between_detections(self):
        first = wallets.wallet_objects(self.hit("one", ethereum_address=["address"], binance_address=["address"]))
        wallet = next(obj for obj in first if obj.type == "cryptocurrency-wallet")
        self.assertEqual(set(wallet.x_opencti_labels), {"vysion", "chain:ETH", "chain:BNB"})
        merged = {obj.id: obj for obj in first}
        for obj in wallets.wallet_objects(self.hit("two", bitcoin_address=["address"])):
            wallets.merge_wallet_object(merged, obj)
        self.assertIn("chain:BTC", merged[wallet.id].x_opencti_labels)

    def test_enrichment_queries_each_explicit_chain(self):
        obj = enrichment.VysionIE.__new__(enrichment.VysionIE)
        obj.im_enabled = True
        obj.leaks_enabled = True
        entity = {"entity_type": "Cryptocurrency-Wallet", "observable_value": "address"}
        queries = obj.queries(entity, {"labels": ["chain:ETH", "chain:BNB"]})
        self.assertEqual(len(queries), 6)
        self.assertEqual({endpoint.split("/")[-2] for _, endpoint, _ in queries}, {"ETH", "BNB"})

    def test_unsupported_detection_does_not_consume_test_limit(self):
        obj = self.connector()
        obj.client.search.return_value = ([self.hit("unsupported"), self.hit("supported", bitcoin_address=["address"])], False)
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        result = obj.run_once(start, start + timedelta(hours=23), checkpoint=False, max_detections=1)
        self.assertEqual(result["objects"], 2)
        self.assertEqual(result["detections"], 1)
        self.assertTrue(obj.helper.send_stix2_bundle.call_args.kwargs["update"])

    def test_bad_record_does_not_block_healthy_import(self):
        obj = self.connector()
        obj.helper.state = {"retry_window": {"start": "2026-09-01T00:00:00+00:00", "end": "2026-09-01T23:00:00+00:00"}}
        obj.client.search.return_value = ([self.hit("bad", bitcoin_address="invalid"), self.hit("good", bitcoin_address=["address"])], False)
        obj.run_once()
        self.assertEqual(obj.helper.state["imported_detection_ids"], ["good"])
        self.assertEqual(obj.helper.state["rejected_records"][0]["id"], "bad")
        self.assertTrue(obj.helper.state["quarantine_due"])
        self.assertIn("window_end", obj.helper.state)

    def test_wallet_limits(self):
        for fields in [{"bitcoin_address": ["a"] * 101}, {"bitcoin_address": ["a" * 257]},
                       {"bitcoin_address": ["a"] * 60, "ethereum_address": ["b"] * 60}]:
            with self.assertRaises(ValueError):
                wallets.wallet_objects(self.hit("limit", **fields))


class MetadataTests(unittest.TestCase):
    def test_markdown_links_are_literal(self):
        value = enrichment.table_cell("![pixel](https://example.com) **bold** `code`")
        self.assertNotIn("![pixel]", value)
        self.assertIn(r"\[pixel\]", value)
        self.assertIn(r"\*\*bold\*\*", value)

    def test_structured_captures_survive_table_edits(self):
        target = "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3"
        first = {"page": {"id": "one", "pageTitle": "Title", "url": {"url": "https://example.com"}, "sha256sum": "hash"}}
        second = {"page": {**first["page"], "id": "two"}}
        note = enrichment.VysionIE.grouped_document_note([first], target, [])
        edited = note.content.replace("| one |", "| edited |")
        updated = enrichment.VysionIE.grouped_document_note([second], target, [], edited)
        self.assertIn("| one |", updated.content)
        self.assertNotIn("| edited |", updated.content)
        self.assertEqual({r.external_id for r in updated.external_references if getattr(r, "external_id", None)}, {"one", "two"})


class ConfigurationTests(unittest.TestCase):
    def test_yaml_false_is_honored_and_environment_overrides(self):
        config = {"opencti": {}, "vysion": {}, "connector": {"update_existing_data": False, "run_every": "2h"}}
        for env, expected in [({}, False), ({"CONNECTOR_UPDATE_EXISTING_DATA": "true"}, True)]:
            with patch.dict(os.environ, env, clear=True), patch.object(ransomware, "OpenCTIConnectorHelper"), patch.object(ransomware, "VysionClient"), patch.object(ransomware.yaml, "load", return_value=config), patch.object(ransomware.os.path, "isfile", return_value=True), patch("builtins.open", unittest.mock.mock_open()):
                obj = ransomware.VysionEI()
                self.assertEqual(obj.update_existing_data, expected)
                self.assertEqual(obj.interval_seconds, 7200)

    def test_legacy_invalid_boolean_falls_back_without_attribute_error(self):
        with patch.dict(os.environ, {"CONNECTOR_UPDATE_EXISTING_DATA": "invalid", "CONNECTOR_RUN_EVERY": "1h"}), patch.object(legacy_ie, "OpenCTIConnectorHelper"), patch.object(legacy_ei, "OpenCTIConnectorHelper"):
            self.assertIs(legacy_ie.InternalEnrichmentConnector().update_existing_data, False)
            self.assertIs(legacy_ei.ExternalImportConnector().update_existing_data, False)


class RansomwareRecoveryTests(unittest.TestCase):
    def connector(self):
        obj = ransomware.VysionEI.__new__(ransomware.VysionEI)
        obj.helper = helper()
        obj.client = Mock()
        obj.lookback_hours = 24
        obj.update_existing_data = True
        return obj

    def hit(self, record_id, **fields):
        return {"id": record_id, "companyName": "Example", "ransomwareGroup": "Example group",
                "detectionDate": datetime.now(timezone.utc).isoformat(), **fields}

    def test_valid_records_import_while_bad_record_remains_quarantined(self):
        obj = self.connector()
        now = datetime.now(timezone.utc) + timedelta(minutes=1)
        initial = {"retry_window": {"start": (now - timedelta(hours=1)).isoformat(), "end": now.isoformat()}}
        obj.client.search.return_value = ([self.hit("bad", companyName=""), self.hit("good")], False)
        obj.run_once(initial)
        self.assertEqual(obj.helper.state["imported_event_ids"], ["good"])
        self.assertEqual(obj.helper.state["rejected_records"][0]["id"], "bad")
        self.assertEqual(obj.helper.state["window_end"], initial["retry_window"]["end"])
        self.assertTrue(obj.helper.state["quarantine_due"])
        obj.client.search.return_value = ([self.hit("bad"), self.hit("good")], False)
        obj.run_once(obj.helper.state)
        self.assertEqual(set(obj.helper.state["imported_event_ids"]), {"good", "bad"})
        self.assertNotIn("retry_window", obj.helper.state)

    def test_chunks_preserve_progress_and_finish_same_window(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(return_value=[self.hit(str(i)) for i in range(60)])
        first = obj.run_once({})
        self.assertEqual(first["events"], 50)
        self.assertIn("retry_window", obj.helper.state)
        second = obj.run_once(obj.helper.state)
        self.assertEqual(second["events"], 10)
        self.assertEqual(len(obj.helper.state["imported_event_ids"]), 60)
        self.assertNotIn("retry_window", obj.helper.state)

    def test_unfinished_work_prevents_new_fetch(self):
        obj = self.connector()
        obj.helper.api.query.return_value["data"]["work"]["status"] = "progress"
        obj.get_feed_vysion = Mock(return_value=[self.hit("one")])
        obj.run_once({})
        pending = obj.helper.state
        self.assertNotIn("imported_event_ids", pending)
        obj.get_feed_vysion.reset_mock()
        result = obj.run_once(pending)
        self.assertTrue(result["pending"])
        obj.get_feed_vysion.assert_not_called()


class ResponseLimitsTests(unittest.TestCase):
    def client(self, chunks):
        response = Mock(status_code=200)
        response.iter_content.return_value = chunks
        session = Mock()
        session.get.return_value = response
        return VysionClient("https://api.vysion.ai", "test", session=session), response

    def test_response_bytes_are_bounded_and_closed(self):
        client, response = self.client([b"x" * (VysionClient.MAX_RESPONSE_BYTES + 1)])
        with self.assertRaises(VysionError):
            client.get("x")
        response.close.assert_called_once()

    def test_nested_json_and_large_fields_are_rejected(self):
        nested = "value"
        for _ in range(34):
            nested = {"nested": nested}
        for payload in [nested, {"value": "x" * 20001}]:
            client, _ = self.client([json.dumps(payload).encode()])
            with self.assertRaises(VysionError):
                client.get("x")


if __name__ == "__main__":
    unittest.main()
