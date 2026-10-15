import importlib.util
from pathlib import Path
import sys
import unittest
import json
from unittest.mock import Mock
from pycti import OpenCTIConnectorHelper

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.client import VysionClient, VysionError
from common.evidence import VYSION_AUTHOR


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


enrichment = load("enrichment", "internal-enrichment/src/vysion-enrichment.py")
wallets = load("wallets", "wallet-feed/src/wallets.py")


class ClientTests(unittest.TestCase):
    def client(self, responses):
        session = Mock()
        session.get.side_effect = responses
        return VysionClient("https://api.vysion.ai", "test", sleep=Mock(), session=session)

    def response(self, status, hits=None, total=None):
        response = Mock(status_code=status, headers={})
        response.json.return_value = {"data": {"hits": hits or [], "total": total or 0}, "error": None}
        response.iter_content.side_effect = lambda **kwargs: iter([json.dumps(response.json.return_value).encode()])
        return response

    def test_retry_then_success(self):
        client = self.client([self.response(429), requests.Timeout(), self.response(200)])
        self.assertEqual(client.get("document/search")["hits"], [])
        self.assertEqual(client.sleep.call_count, 2)

    def test_forbidden_not_empty_result(self):
        client = self.client([self.response(403)])
        with self.assertRaises(VysionError):
            client.get("document/search")
        self.assertEqual(client.session.get.call_count, 1)

    def test_pagination_limit_visible(self):
        client = self.client([self.response(200, [{"id": "a"}], 2)])
        hits, truncated = client.search("x", page_size=1, max_pages=1)
        self.assertEqual(len(hits), 1)
        self.assertTrue(truncated)

    def test_invalid_schema(self):
        response = self.response(200)
        response.json.return_value = {"data": {"hits": "not-list"}}
        with self.assertRaises(VysionError):
            self.client([response]).get("x")

    def test_incomplete_pagination_fails(self):
        client = self.client([self.response(200, [{"id": "a"}], 2), self.response(200, [], 2)])
        with self.assertRaises(VysionError):
            client.search("x")

    def test_retry_exhaustion_and_safe_errors(self):
        client = self.client([self.response(503)] * 3)
        with self.assertRaises(VysionError):
            client.get("x")
        self.assertEqual(client.session.get.call_count, 3)
        self.assertEqual(client.session.get.call_args.kwargs["timeout"], (10, 45))
        self.assertFalse(client.session.get.call_args.kwargs["allow_redirects"])

    def test_redirect_rejected(self):
        client = self.client([self.response(302)])
        with self.assertRaises(VysionError):
            client.get("x")
        self.assertEqual(client.session.get.call_count, 1)


class ModelTests(unittest.TestCase):
    def test_notes_stable_and_not_indicators(self):
        hit = {"page": {"id": "doc1", "url": {"url": "example.onion", "networkProtocol": "http"}}}
        target = "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3"
        first = enrichment.VysionIE.make_evidence("documents", hit, target, [])
        second = enrichment.VysionIE.make_evidence("documents", hit, target, [])
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.type, "note")
        self.assertEqual(first.external_references[0].url, "https://app.vysion.ai/document/doc1")
        self.assertEqual(first.external_references[0].external_id, "doc1")
        self.assertEqual(first.external_references[1].url, "http://example.onion")
        self.assertIn("| Field | Value |", first.content)
        self.assertIn("https://app.vysion.ai/document/doc1", first.content)

    def test_same_title_different_pages_not_grouped(self):
        hits = [{"page": {"id": str(index), "pageTitle": "Same title", "url": {"url": url}}}
                for index, url in enumerate(["https://example.com/a", "https://example.com/b", "", ""])]
        self.assertEqual(len(enrichment.VysionIE.document_groups(hits)), 4)

    def test_leak_does_not_import_secrets(self):
        note = enrichment.VysionIE.make_evidence("leaks", {
            "id": "x", "content": "SECRET", "downloadUrl": "SECRET",
            "detectedInfo": "SECRET", "highlights": ["SECRET"],
            "password": "SECRET", "credentials": "SECRET",
        },
            "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3", [])
        self.assertNotIn("SECRET", note.serialize())

    def test_leak_link_encodes_id_and_highlight(self):
        note = enrichment.VysionIE.make_evidence("leaks", {"id": "id/?#"},
            "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3", [],
            matched_value="test+tag@example.com&other=1")
        url = "https://app.vysion.ai/leaks/id%2F%3F%23?highlight=test%2Btag%40example.com%26other%3D1"
        self.assertEqual(note.external_references[-1].url, url)
        self.assertIn(f"[Open leak in Vysion]({url})", note.content)

    def test_whitelist_no_request(self):
        connector = enrichment.VysionIE.__new__(enrichment.VysionIE)
        connector.client = Mock()
        result = connector._process_message({"enrichment_entity": {"standard_id": "x", "objectLabel": [{"value": "whitelist"}]}})
        self.assertIn("whitelisted", result)
        connector.client.search.assert_not_called()

    def connector(self, leaks=False):
        connector = enrichment.VysionIE.__new__(enrichment.VysionIE)
        connector.client = Mock()
        connector.client.search.return_value = ([], False)
        connector.leaks_enabled = leaks
        connector.im_enabled = True
        connector.max_tlp = "TLP:GREEN"
        connector.helper = Mock()
        connector.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
        return connector

    def test_every_marking_checked(self):
        connector = self.connector()
        entity = {"standard_id": "x", "objectMarking": [
            {"definition_type": "TLP", "definition": "TLP:RED"},
            {"definition_type": "TLP", "definition": "TLP:GREEN"},
        ]}
        with self.assertRaises(ValueError):
            connector._process_message({"enrichment_entity": entity})
        connector.client.search.assert_not_called()

    def test_leaks_opt_in(self):
        entity = {"entity_type": "IPv4-Addr", "observable_value": "192.0.2.1"}
        self.assertEqual(self.connector().queries(entity, {}), [])
        self.assertEqual(self.connector(True).queries(entity, {})[0][1], "leak/ip/192.0.2.1")

    def test_markings_propagated(self):
        marking = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        target = "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3"
        note = enrichment.VysionIE.make_evidence("leaks", {"id": "x"}, target, [marking])
        self.assertEqual(note.object_marking_refs, [marking])

    def test_source_error_no_false_success(self):
        connector = self.connector()
        connector.client.search.side_effect = VysionError("HTTP 403")
        entity = {"standard_id": "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3",
                  "entity_type": "Email-Addr", "observable_value": "user@example.com"}
        with self.assertRaises(VysionError):
            connector._process_message({"enrichment_entity": entity})
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_no_score_change(self):
        connector = self.connector()
        connector.client.search.side_effect = [([
            {"page": {"id": "doc1", "pageTitle": "Example", "url": {"url": "https://example.com"}}}
        ], False), ([], False)]
        connector.helper.api.note.read.return_value = None
        entity = {"standard_id": "email-addr--b689de09-1d7c-5dc8-8e36-198e019f45a3",
                  "entity_type": "Email-Addr", "observable_value": "user@example.com"}
        self.assertIn("score unchanged", connector._process_message({"enrichment_entity": entity}))
        connector.helper.send_stix2_bundle.assert_called_once()
        bundle = json.loads(connector.helper.send_stix2_bundle.call_args.args[0])
        self.assertNotIn(entity["standard_id"], {item["id"] for item in bundle["objects"]})
        notes = [item for item in bundle["objects"] if item["type"] == "note"]
        self.assertTrue(notes)
        self.assertTrue(all(item["created_by_ref"] == VYSION_AUTHOR.id for item in notes))
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_wallet_feed_truncated_does_not_checkpoint(self):
        connector = wallets.WalletFeed.__new__(wallets.WalletFeed)
        connector.platform = "darknet"
        connector.client = Mock()
        connector.client.search.return_value = ([], True)
        connector.helper = Mock()
        connector.helper.api.query.return_value = {"data": {"work": {"status": "complete", "completed_number": 1, "errors": []}}}
        connector.helper.get_state.return_value = {}
        with self.assertRaises(VysionError):
            connector.run_once()
        connector.helper.set_state.assert_not_called()
        connector.helper.send_stix2_bundle.assert_not_called()
        self.assertTrue(connector.helper.api.work.to_processed.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
