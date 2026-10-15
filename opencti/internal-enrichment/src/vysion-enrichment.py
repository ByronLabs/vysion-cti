import os
import html
import json
import re
import threading
from urllib.parse import quote, urlsplit

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from common.client import VysionClient
from common.evidence import evidence_note, evidence_bundle


CHAINS = {"BTC", "ETH", "XMR", "XRP", "ZEC", "DOT", "BNB", "DASH"}
ENRICHMENT_LOCK = threading.Lock()


def table_cell(value):
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    value = html.escape(str(value)[:2000]).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()!|])", r"\\\1", value)


class VysionIE:
    def __init__(self):
        config = {}
        path = os.path.join(os.path.dirname(__file__), "config.yml")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as stream:
                config = yaml.safe_load(stream) or {}
        self.client = VysionClient(
            get_config_variable("VYSION_API_URL", ["vysion", "api_url"], config),
            get_config_variable("VYSION_API_KEY", ["vysion", "api_key"], config),
        )
        self.max_tlp = os.getenv("VYSION_MAX_TLP", "TLP:GREEN")
        # Validate before registering, rather than failing on the first job.
        OpenCTIConnectorHelper.check_max_tlp("TLP:CLEAR", self.max_tlp)
        self.leaks_enabled = os.getenv("VYSION_ENABLE_LEAKS", "false").lower() == "true"
        self.im_enabled = os.getenv("VYSION_ENABLE_IM", "true").lower() == "true"
        self.helper = OpenCTIConnectorHelper(config)

    @staticmethod
    def wallet_chains(entity, stix_entity):
        # Address syntax is ambiguous (ETH vs BNB; BTC vs other Base58 chains).
        # Explicit chain labels take precedence; never guess the chain.
        labels = stix_entity.get("labels", []) + [
            item.get("value", "") for item in entity.get("objectLabel", [])
        ]
        chains = {label.split(":", 1)[1].upper() for label in labels
                  if isinstance(label, str) and label.lower().startswith("chain:")}
        if not chains or not chains.issubset(CHAINS):
            raise ValueError("Wallet requires explicit supported chain labels")
        return sorted(chains)

    @classmethod
    def wallet_chain(cls, entity, stix_entity):
        chains = cls.wallet_chains(entity, stix_entity)
        if len(chains) != 1:
            raise ValueError("Multiple chains supplied; use wallet_chains")
        return chains[0]

    def queries(self, entity, stix_entity):
        kind = entity["entity_type"]
        value = entity.get("observable_value") or stix_entity.get("value")
        if kind == "StixFile":
            hashes = stix_entity.get("hashes", {})
            value = hashes.get("SHA-256") or hashes.get("SHA-1") or hashes.get("MD5")
        if kind == "User-Account":
            value = stix_entity.get("account_login") or entity.get("account_login")
        if not value:
            raise ValueError("Observable has no supported value/hash/account_login")
        encoded = quote(str(value), safe="")
        queries = []
        if kind == "Url":
            queries.append(("documents", f"document/url/{encoded}", {}))
        elif kind in {"Domain-Name", "Hostname"}:
            # Phrase search, not an exact domain endpoint. Results are evidence
            # of mentions and do not prove domain ownership or maliciousness.
            escaped = str(value).replace('"', '\\"')
            queries.append(("documents", "document/search", {"q": f'"{escaped}"', "safe_search": "true"}))
        elif kind == "Email-Addr":
            queries.append(("documents", f"document/email/{encoded}", {}))
            if self.im_enabled:
                queries.append(("im", f"im/email/{encoded}", {}))
            if self.leaks_enabled:
                queries.append(("leaks", f"leak/email/{encoded}", {}))
        elif kind == "Cryptocurrency-Wallet":
            for chain in self.wallet_chains(entity, stix_entity):
                suffix = f"wallet/{chain}/{encoded}"
                queries.append(("documents", f"document/{suffix}", {}))
                if self.im_enabled:
                    queries.append(("im", f"im/{suffix}", {}))
                if self.leaks_enabled:
                    queries.append(("leaks", f"leak/{suffix}", {}))
        elif kind in {"IPv4-Addr", "IPv6-Addr"}:
            if self.leaks_enabled:
                queries.append(("leaks", f"leak/ip/{encoded}", {}))
        elif kind == "User-Account":
            if self.im_enabled:
                queries.append(("im", "im/search/profiles", {"q": str(value), "username": str(value)}))
            if self.leaks_enabled:
                queries.append(("leaks", f"leak/username/{encoded}", {}))
        elif kind == "StixFile":
            if self.leaks_enabled:
                queries.append(("leaks", f"leak/hash/{encoded}", {}))
        else:
            raise ValueError("Unsupported observable type")
        return queries

    @staticmethod
    def make_evidence(source, hit, target, markings, matched_value=None):
        rows = []
        app_url = "https://app.vysion.ai"
        source_url = None
        if source == "documents":
            page = hit.get("page") or {}
            record_id = page.get("id")
            url_data = page.get("url") or {}
            url = url_data.get("url", "") if isinstance(url_data, dict) else url_data
            if url and not urlsplit(url).scheme:
                protocol = url_data.get("networkProtocol", "http") if isinstance(url_data, dict) else "http"
                url = f"{protocol}://{url}"
            if not record_id:
                raise ValueError("Document result has no stable ID")
            title = "Vysion document mention"
            document_url = f"https://app.vysion.ai/document/{quote(str(record_id), safe='')}"
            content = f"Document: {page.get('pageTitle', '')}\nDetected: {page.get('detectionDate', '')}\nSource: {url}\nView document in Vysion: {document_url}\nA mention alone does not establish maliciousness."
            references = [{"source_name": "Vysion", "external_id": str(record_id), "url": document_url}]
            if url and urlsplit(url).scheme in {"http", "https"}:
                references.append({"source_name": "Original source", "url": url})
                source_url = url
            app_url = document_url
            title = f"Vysion · {page.get('pageTitle') or 'Document mention'}"
            rows = [
                ("Title", page.get("pageTitle")),
                ("Network", url_data.get("network") if isinstance(url_data, dict) else None),
                ("Source domain", url_data.get("domainName") if isinstance(url_data, dict) else None),
                ("Language", page.get("language")),
                ("Detected", page.get("detectionDate")),
                ("Ingested into Vysion", page.get("ingestionDate")),
                ("Document type", page.get("docType")),
                ("Document SHA-256", page.get("sha256sum")),
                ("Document SHA-1", page.get("sha1sum")),
                ("Vysion tags", [tag.get("value", "") if isinstance(tag, dict) else str(tag) for tag in (hit.get("tag") or [])]),
            ]
            content = "A mention does not establish malicious activity or domain ownership."
        elif source == "leaks":
            record_id = hit.get("id")
            app_url = f"https://app.vysion.ai/leaks/{quote(str(record_id), safe='')}"
            if matched_value:
                app_url += f"?highlight={quote(str(matched_value), safe='')}"
            title = "Vysion exposure evidence"
            # Intentionally exclude credentials, detectedInfo, highlights,
            # downloadable files and unrelated personal data.
            references = [{"source_name": "Vysion leak", "external_id": str(record_id)}]
            rows = [("Detected", hit.get("detectionDate")), ("Hash", hit.get("fileHash")),
                    ("File type", hit.get("fileType")), ("MIME", hit.get("detectedMimeType")),
                    ("Size (bytes)", hit.get("fileSize")), ("Language", hit.get("language"))]
            content = "Match found in the leak content indexed by Vysion. No credentials or leak content are imported into OpenCTI."
        else:
            record_id = f"{hit.get('platform', '')}:{hit.get('userId', '')}"
            if not hit.get("userId") or not hit.get("platform"):
                raise ValueError("IM profile result has no platform/user ID")
            title = "Vysion messaging profile association"
            content = f"Profile ID: {hit.get('userId')}\nPlatform: {hit.get('platform')}\nDetected: {hit.get('detectionDate', '')}\nAssociation is not proof of ownership or malicious activity."
            references = [{"source_name": "Vysion IM", "external_id": record_id}]
            rows = [("Platform", hit.get("platform")), ("Profile ID", hit.get("userId")),
                    ("Usernames", hit.get("usernames")), ("Detected", hit.get("detectionDate")),
                    ("Bot", hit.get("bot"))]
            content = ""
        if not record_id:
            raise ValueError("Evidence result has no stable ID")
        if source != "documents":
            references.append({"source_name": "Vysion App", "url": app_url})
        rows = [("Source", source), ("Vysion ID", record_id)] + rows
        table = "| Field | Value |\n| --- | --- |\n" + "\n".join(
            f"| {table_cell(key)} | {table_cell(value)} |" for key, value in rows
        )
        label = {"documents": "Open document in Vysion", "leaks": "Open leak in Vysion"}.get(source, "Open Vysion (home)")
        links = f"[{label}]({quote(app_url, safe=':/?=&%#')})"
        if source_url:
            links += f" · [Original source]({quote(source_url, safe=':/?=&%#')})"
        summary = content
        content = f"## Vysion evidence\n\n### {links}\n\n---\n\n### Evidence metadata\n\n{table}"
        if summary:
            content += f"\n\n---\n\n> {summary}"
        return evidence_note(source, str(record_id), target, title, content, markings, references)

    @staticmethod
    def document_source(hit):
        page = hit.get("page") or {}
        data = page.get("url") or {}
        url = data.get("url", "") if isinstance(data, dict) else data
        if url and not urlsplit(url).scheme:
            protocol = data.get("networkProtocol", "http") if isinstance(data, dict) else "http"
            url = f"{protocol}://{url}"
        return url

    @classmethod
    def document_groups(cls, hits):
        groups = {}
        for hit in hits:
            page = hit.get("page") or {}
            if not page.get("id"):
                raise ValueError("Document result has no stable ID")
            url = cls.document_source(hit)
            # Keep exact URLs (including query parameters) distinct. If a URL
            # is absent, never merge unrelated documents merely by title.
            key = (url or str(page["id"]), page.get("pageTitle") or "")
            groups.setdefault(key, []).append(hit)
        return list(groups.values())

    @classmethod
    def grouped_document_note(cls, hits, target, markings, previous_content=""):
        if len(previous_content.encode()) > 1_000_000:
            raise ValueError("Existing capture note exceeds retention byte limit")
        first = hits[0]
        page = first["page"]
        url = cls.document_source(first)
        key = json.dumps([url or str(page["id"]), page.get("pageTitle") or ""], ensure_ascii=True)
        section = "## Captures\n\n"
        header = "| Vysion ID | Detected | Language | SHA-256 | SHA-1 | Vysion document |"
        captures = {}
        # Retain previously collected captures even if a bounded search later
        # returns a different subset. Only parse our own generated table.
        if section in previous_content:
            table = previous_content.split(section, 1)[1].split("\n\n", 1)[0]
            for line in table.splitlines()[2:]:
                if line.startswith("| ") and line.endswith(" |"):
                    captures[line.split(" | ", 1)[0][2:]] = line
        references = []
        if url and urlsplit(url).scheme in {"http", "https"}:
            references.append({"source_name": "Original source", "url": url})
        for hit in hits:
            capture = hit["page"]
            record_id = str(capture["id"])
            app_url = f"https://app.vysion.ai/document/{quote(record_id, safe='')}"
            fields = [record_id, capture.get("detectionDate"), capture.get("language"),
                      capture.get("sha256sum"), capture.get("sha1sum")]
            captures[table_cell(record_id)] = "| " + " | ".join(table_cell(value) for value in fields) + f" | [Open capture]({app_url}) |"
            references.append({"source_name": "Vysion", "external_id": record_id, "url": app_url})
        if len(captures) > 1000:
            raise ValueError("Capture retention limit reached; existing note preserved")
        # Preserve legacy capture links too; do not depend on OpenCTI merge rules.
        existing_ids = {reference.get("external_id") for reference in references}
        for line in captures.values():
            match = re.search(r"\[Open capture\]\((https://app\.vysion\.ai/document/[^)]+)\)", line)
            if match:
                record_id = match[1].rsplit("/", 1)[1]
                if record_id not in existing_ids:
                    references.append({"source_name": "Vysion", "external_id": record_id, "url": match[1]})
        data = page.get("url") or {}
        rows = [("Title", page.get("pageTitle")), ("Source URL", url),
                ("Network", data.get("network") if isinstance(data, dict) else None),
                ("Document type", page.get("docType")), ("Collected captures", len(captures))]
        metadata = "| Field | Value |\n| --- | --- |\n" + "\n".join(
            f"| {table_cell(name)} | {table_cell(value)} |" for name, value in rows
        )
        content = "## Vysion evidence\n\n" + metadata + "\n\n" + section + header + "\n| --- | --- | --- | --- | --- | --- |\n" + "\n".join(captures[k] for k in sorted(captures))
        content += "\n\n> Captures collected from bounded search results; this is not necessarily the complete page history. A mention does not establish malicious activity or ownership."
        if len(content.encode()) > 1_000_000:
            raise ValueError("Capture note size limit reached; existing note preserved")
        return evidence_note("documents", "page-group:" + key, target,
                             f"Vysion · {page.get('pageTitle') or 'Document captures'}",
                             content, markings, references)

    def _process_message(self, data):
        # One writer per process; keep this connector ID exclusive to one instance.
        with ENRICHMENT_LOCK:
            return self._enrich(data)

    def _enrich(self, data):
        entity = data["enrichment_entity"]
        stix_entity = data.get("stix_entity") or next(
            (obj for obj in data.get("stix_objects", []) if obj.get("id") == entity["standard_id"]), {}
        )
        if any(item.get("value", "").lower() == "whitelist" for item in entity.get("objectLabel", [])):
            return "Skipped: observable is whitelisted"
        for marking in entity.get("objectMarking", []):
            if marking.get("definition_type", "").lower() == "tlp":
                if not self.helper.check_max_tlp(marking["definition"], self.max_tlp):
                    raise ValueError("Observable TLP exceeds VYSION_MAX_TLP; nothing sent to Vysion")
        markings = stix_entity.get("object_marking_refs", [])
        if entity.get("objectMarking") and not markings:
            raise ValueError("Cannot safely propagate observable markings")
        queries = self.queries(entity, stix_entity)
        if not queries:
            return "No enabled source supports this observable; enable leaks explicitly if needed"
        objects = {}
        truncated = []
        # Fail on source errors instead of reporting them as zero matches.
        # Collect first, then send one bundle tied to the listener's work.
        for source, endpoint, params in queries:
            hits, limited = self.client.search(endpoint, params, page_size=5 if source == "leaks" else None)
            if limited:
                truncated.append(source)
            if source == "documents":
                for group in self.document_groups(hits):
                    note = self.grouped_document_note(group, entity["standard_id"], markings)
                    cache = getattr(self, "note_cache", {})
                    previous = objects.get(note.id)
                    previous_content = previous.content if previous else cache.get(note.id)
                    if previous_content is None:
                        previous = self.helper.api.note.read(id=note.id, customAttributes="content")
                        previous_content = previous.get("content", "") if previous else ""
                    if previous_content:
                        note = self.grouped_document_note(
                            group, entity["standard_id"], markings, previous_content
                        )
                    objects[note.id] = note
            else:
                for hit in hits:
                    note = self.make_evidence(
                        source, hit, entity["standard_id"], markings,
                        matched_value=entity.get("observable_value"),
                    )
                    objects[note.id] = note
        if objects:
            bundle = evidence_bundle(objects.values())
            if len(bundle.encode()) > 2_000_000:
                raise ValueError("Enrichment bundle size limit exceeded")
            self.helper.send_stix2_bundle(
                bundle,
                update=True, work_id=self.helper.work_id,
            )
            cache = getattr(self, "note_cache", {})
            for key, note in objects.items():
                if "vysion:documents" in note.labels:
                    cache.pop(key, None)
                    cache[key] = note.content
            retained = {}
            size = 0
            for key, content in reversed(list(cache.items())):
                size += len(content.encode())
                if len(retained) >= 100 or size > 16_000_000:
                    break
                retained[key] = content
            self.note_cache = dict(reversed(list(retained.items())))
        # Preserve existing analyst scores: an indexed mention is not an IOC.
        return f"Submitted {len(objects)} evidence notes; score unchanged. Limited sources: {', '.join(truncated) or 'none'}"

    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    VysionIE().start()
