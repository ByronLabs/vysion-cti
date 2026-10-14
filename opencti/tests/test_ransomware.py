import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

from stix2 import Bundle

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.client import VysionError

spec = importlib.util.spec_from_file_location("ransomware", ROOT / "external-import/src/vysion-external.py")
ransomware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ransomware)


def event(record_id="event-1", detected=None, **fields):
    return {"id": record_id, "companyName": "Example organisation", "ransomwareGroup": "Example group",
            "detectionDate": detected or datetime.now(timezone.utc).isoformat(),
            "url": "https://example.com/victim", "text": "Test detection", **fields}


class RansomwareTests(unittest.TestCase):
    def connector(self):
        obj = ransomware.VysionEI.__new__(ransomware.VysionEI)
        obj.client = Mock()
        obj.helper = Mock()
        obj.lookback_hours = 24
        obj.update_existing_data = True
        return obj

    def test_stable_ids_and_optional_context(self):
        raw = event(country="ES", industry="Energy", naics="22")
        normalized = ransomware.VysionEI.normalize_event(raw)
        first = ransomware.VysionEI.event_to_stix(normalized)
        second = ransomware.VysionEI.event_to_stix(normalized)
        self.assertEqual([o.id for o in first], [o.id for o in second])
        Bundle(objects=first, allow_custom=True).serialize()
        self.assertEqual(len(first), 11)
        incident = next(o for o in first if o.type == "incident")
        self.assertEqual(incident.external_references[0].external_id, raw["id"])
        location = next(o for o in first if o.type == "location")
        self.assertEqual(location.x_opencti_location_type, "Country")

    def test_no_country_or_sector_invented(self):
        objects = ransomware.VysionEI.event_to_stix(ransomware.VysionEI.normalize_event(event()))
        self.assertEqual(len(objects), 5)
        self.assertNotIn("location", [o.type for o in objects])

    def test_incidents_distinct_victim_and_actor_shared(self):
        first = ransomware.VysionEI.event_to_stix(ransomware.VysionEI.normalize_event(event("one")))
        second = ransomware.VysionEI.event_to_stix(ransomware.VysionEI.normalize_event(event("two")))
        self.assertEqual(first[0].id, second[0].id)
        self.assertEqual(first[1].id, second[1].id)
        self.assertNotEqual(first[2].id, second[2].id)

    def test_optional_null_text_and_url(self):
        objects = ransomware.VysionEI.event_to_stix(ransomware.VysionEI.normalize_event(event(text=None, url=None)))
        Bundle(objects=objects, allow_custom=True).serialize()

    def test_invalid_events_fail(self):
        for raw in [None, event(companyName=""), event(ransomwareGroup=None), event(detected="invalid"), event(country=123)]:
            with self.subTest(raw=raw), self.assertRaises(VysionError):
                ransomware.VysionEI.validate_event(raw)

    def test_utc_window_and_deduplication_across_batches(self):
        obj = self.connector()
        end = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        start = end - timedelta(hours=24)
        inside = event(detected="2026-10-14T13:00:00+02:00")
        naive = event("naive", detected="2026-10-13T12:00:00")
        outside = event("old", detected="2026-10-13T11:59:59Z")
        future = event("future", detected="2026-10-14T12:00:01Z")
        obj.get_batch_events = Mock(side_effect=[[inside, naive, outside], [inside, future]])
        hits = obj.get_feed_vysion(start, end)
        self.assertEqual([h["id"] for h in hits], [inside["id"], naive["id"]])
        self.assertEqual([c.args[0] for c in obj.get_batch_events.call_args_list], ["2026-10-13", "2026-10-14"])

    def test_batch_limit_fails(self):
        obj = self.connector()
        obj.client.search.return_value = ([], True)
        with self.assertRaises(VysionError):
            obj.get_batch_events("2026-10-14")

    def test_schema_validation_before_import(self):
        obj = self.connector()
        obj.client.search.return_value = ([event(detected="bad")], False)
        with self.assertRaises(VysionError):
            obj.get_batch_events("2026-10-14")

    def test_import_then_repeat_skipped(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(return_value=[event()])
        obj.run_once({})
        state = obj.helper.set_state.call_args.args[0]
        self.assertEqual(state["events_imported"], 1)
        bundle = json.loads(obj.helper.send_stix2_bundle.call_args.args[0])
        self.assertEqual(len(bundle["objects"]), 5)
        obj.helper.send_stix2_bundle.reset_mock()
        obj.run_once(state)
        obj.helper.send_stix2_bundle.assert_not_called()
        self.assertEqual(obj.helper.set_state.call_args.args[0]["events_imported"], 0)

    def test_retry_without_checkpoint_uses_same_ids(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(return_value=[event()])
        obj.helper.send_stix2_bundle.side_effect = RuntimeError("queue error")
        with self.assertRaises(RuntimeError):
            obj.run_once({})
        first = json.loads(obj.helper.send_stix2_bundle.call_args.args[0])
        obj.helper.set_state.assert_not_called()
        self.assertTrue(obj.helper.api.work.to_processed.call_args.args[2])
        obj.helper.send_stix2_bundle.side_effect = None
        obj.run_once({})
        second = json.loads(obj.helper.send_stix2_bundle.call_args.args[0])
        self.assertEqual([o["id"] for o in first["objects"]], [o["id"] for o in second["objects"]])

    def test_http_failure_preserves_checkpoint(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(side_effect=VysionError("HTTP 403"))
        state = {"last_run": 123, "imported_event_ids": ["existing"]}
        with self.assertRaises(VysionError):
            obj.run_once(state)
        self.assertEqual(state["last_run"], 123)
        obj.helper.set_state.assert_not_called()
        obj.helper.send_stix2_bundle.assert_not_called()

    def test_legacy_state_migration(self):
        obj = self.connector()
        obj.get_batch_events = Mock(return_value=[event("legacy")])
        self.assertEqual(obj.get_legacy_imported_event_ids({"last_batch": "2026-10-13"}), {"legacy"})

    def test_checkpoint_retains_newest_ids_in_order(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(return_value=[event("new")])
        obj.run_once({"imported_event_ids": [f"old-{index}" for index in range(1000)]})
        saved = obj.helper.set_state.call_args.args[0]["imported_event_ids"]
        self.assertEqual(len(saved), 1000)
        self.assertEqual(saved[0], "old-1")
        self.assertEqual(saved[-1], "new")

    def test_shared_entities_not_repeated_in_bundle(self):
        obj = self.connector()
        obj.get_feed_vysion = Mock(return_value=[event("one"), event("two")])
        obj.run_once({})
        objects = json.loads(obj.helper.send_stix2_bundle.call_args.args[0])["objects"]
        self.assertEqual(len(objects), 8)
        self.assertEqual(len({item["id"] for item in objects}), len(objects))

    def test_interval_must_be_positive(self):
        self.assertEqual(ransomware.VysionEI._parse_interval("1h"), 3600)
        for interval in ["0s", "-1h", "daily"]:
            with self.assertRaises(ValueError):
                ransomware.VysionEI._parse_interval(interval)

    def test_historical_import_cannot_advance_checkpoint(self):
        obj = self.connector()
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            obj.run_once({}, start, start + timedelta(hours=23))
        obj.get_feed_vysion = Mock(return_value=[event("one"), event("two")])
        result = obj.run_once({}, start, start + timedelta(hours=23), checkpoint=False, max_events=1)
        self.assertEqual(result["events"], 1)
        obj.helper.set_state.assert_not_called()


if __name__ == "__main__":
    unittest.main()
