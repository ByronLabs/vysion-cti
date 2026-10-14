import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import requests


class VysionError(RuntimeError):
    """Safe error that never includes API keys, query values or response bodies."""


class VysionClient:
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
                    params=params or {}, timeout=(10, 45), allow_redirects=False,
                )
            except (requests.Timeout, requests.ConnectionError):
                if attempt + 1 == self.attempts:
                    raise VysionError("Vysion network request failed after bounded retries") from None
                self.sleep(self.retry_delay(None, attempt))
                continue
            if response.status_code == 429 or response.status_code in (500, 502, 503, 504):
                if attempt + 1 == self.attempts:
                    raise VysionError(f"Vysion HTTP {response.status_code} after bounded retries")
                self.sleep(self.retry_delay(response, attempt))
                continue
            if response.status_code != 200:
                raise VysionError(f"Vysion HTTP {response.status_code}")
            try:
                payload = response.json()
            except ValueError:
                raise VysionError("Vysion returned invalid JSON") from None
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

    def search(self, endpoint, params=None, page_size=None, max_pages=None):
        size = page_size or self.page_size
        pages = max_pages or self.max_pages
        if not 1 <= size <= 100 or not 1 <= pages <= 100:
            raise ValueError("Invalid Vysion search limits")
        hits = []
        total = None
        for page in range(1, pages + 1):
            data = self.get(endpoint, {**(params or {}), "page": page, "page_size": size})
            batch = data["hits"]
            hits.extend(batch)
            total = data.get("total")
            if isinstance(total, dict):
                total = total.get("value")
            if not batch and isinstance(total, int) and len(hits) < total:
                raise VysionError("Vysion pagination ended before the advertised result count")
            if (isinstance(total, int) and len(hits) >= total) or (total is None and len(batch) < size):
                return hits, False
        return hits, total is None or not isinstance(total, int) or len(hits) < total
