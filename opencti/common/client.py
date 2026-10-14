import os
import json
import hashlib
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import requests


class VysionError(RuntimeError):
    """Safe error that never includes API keys, query values or response bodies."""


class VysionClient:
    MAX_RESPONSE_BYTES = 2_000_000

    def __init__(self, base_url, api_key, sleep=time.sleep, session=None):
        parsed = urlsplit(base_url or "")
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("VYSION_API_URL must be an HTTPS base URL")
        if not api_key or api_key.startswith("CHANGE_ME"):
            raise ValueError("VYSION_API_KEY is missing")
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"Accept": "application/json", "x-api-key": api_key})
        self.sleep = sleep
        self.attempts = int(os.getenv("VYSION_HTTP_ATTEMPTS", "3"))
        self.max_pages = int(os.getenv("VYSION_MAX_PAGES", "5"))
        self.page_size = int(os.getenv("VYSION_PAGE_SIZE", "10"))
        if not 1 <= self.attempts <= 5 or not 1 <= self.max_pages <= 100:
            raise ValueError("Invalid Vysion retry/page limits")
        if not 1 <= self.page_size <= 100:
            raise ValueError("VYSION_PAGE_SIZE must be between 1 and 100")

    @staticmethod
    def retry_delay(response, attempt):
        header = response.headers.get("Retry-After", "") if response is not None else ""
        try:
            delay = float(header)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(header) - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                delay = 2 ** attempt
        return max(0, min(delay, 60))

    def get(self, endpoint, params=None):
        for attempt in range(self.attempts):
            response = None
            try:
                response = self.session.get(
                    f"{self.base_url}/api/v2/{endpoint.lstrip('/')}",
                    params=params or {}, timeout=(10, 45), allow_redirects=False, stream=True,
                )
            except (requests.Timeout, requests.ConnectionError):
                if attempt + 1 == self.attempts:
                    raise VysionError("Vysion network request failed after bounded retries") from None
                self.sleep(self.retry_delay(None, attempt))
                continue
            if response.status_code == 429 or response.status_code in (500, 502, 503, 504):
                response.close()
                if attempt + 1 == self.attempts:
                    raise VysionError(f"Vysion HTTP {response.status_code} after bounded retries")
                self.sleep(self.retry_delay(response, attempt))
                continue
            if response.status_code != 200:
                response.close()
                raise VysionError(f"Vysion HTTP {response.status_code}")
            try:
                body = bytearray()
                deadline = time.monotonic() + 60
                for chunk in response.iter_content(chunk_size=65536):
                    if time.monotonic() > deadline or len(body) + len(chunk) > self.MAX_RESPONSE_BYTES:
                        raise VysionError("Vysion response exceeds time or byte limit")
                    body.extend(chunk)
                payload = json.loads(body)
            except (ValueError, RecursionError):
                raise VysionError("Vysion returned invalid JSON") from None
            except (requests.RequestException, OSError):
                raise VysionError("Vysion response transfer failed") from None
            finally:
                response.close()
            self.validate_size(payload)
            if not isinstance(payload, dict) or payload.get("error"):
                raise VysionError("Vysion returned an API error or invalid payload")
            data = payload.get("data")
            if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
                raise VysionError("Vysion returned an unexpected result schema")
            if any(not isinstance(hit, dict) for hit in data["hits"]):
                raise VysionError("Vysion returned a non-object result")
            total = data.get("total")
            if isinstance(total, dict):
                total = total.get("value")
            if total is not None and (type(total) is not int or total < 0):
                raise VysionError("Vysion returned an invalid result count")
            return data
        raise VysionError("Vysion request could not be completed")

    @staticmethod
    def validate_size(payload):
        stack = [(payload, 0)]
        count = 0
        while stack:
            value, depth = stack.pop()
            count += 1
            if depth > 32 or count > 100000:
                raise VysionError("Vysion JSON complexity limit exceeded")
            if isinstance(value, str) and len(value) > 20000:
                raise VysionError("Vysion field size limit exceeded")
            if isinstance(value, dict):
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                if len(value) > 1000:
                    raise VysionError("Vysion array size limit exceeded")
                stack.extend((item, depth + 1) for item in value)

    def search(self, endpoint, params=None, page_size=None, max_pages=None):
        size = page_size or self.page_size
        pages = max_pages or self.max_pages
        if not 1 <= size <= 100 or not 1 <= pages <= 100:
            raise ValueError("Invalid Vysion search limits")
        hits = []
        total = None
        page_fingerprints = set()
        for page in range(1, pages + 1):
            data = self.get(endpoint, {**(params or {}), "page": page, "page_size": size})
            batch = data["hits"]
            if batch:
                fingerprint = hashlib.sha256(json.dumps(batch, sort_keys=True).encode()).digest()
                if fingerprint in page_fingerprints:
                    raise VysionError("Vysion repeated a result page; pagination incomplete")
                page_fingerprints.add(fingerprint)
            hits.extend(batch)
            if len(hits) > 5000:
                raise VysionError("Vysion search record limit exceeded")
            total = data.get("total")
            if isinstance(total, dict):
                total = total.get("value")
            if not batch and isinstance(total, int) and len(hits) < total:
                raise VysionError("Vysion pagination ended before the advertised result count")
            if (isinstance(total, int) and len(hits) >= total) or (total is None and len(batch) < size):
                return hits, False
        return hits, total is None or not isinstance(total, int) or len(hits) < total
