import re
import time
from datetime import datetime, timedelta, timezone

from stix2 import Bundle, ThreatActor, Relationship, Incident, Identity, Location
import os
import yaml
import requests
from pycti import OpenCTIConnectorHelper, get_config_variable


class VysionEI:
    """Vysion External Import Connector"""

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        self.vysion_api_url = get_config_variable(
            "VYSION_API_URL", ["vysion", "api_url"], config
        )
        self.vysion_api_key = get_config_variable(
            "VYSION_API_KEY", ["vysion", "api_key"], config
        )
        self.update_existing_data = (
            os.getenv("CONNECTOR_UPDATE_EXISTING_DATA", "true").lower() == "true"
        )
        self.interval_seconds = self._parse_interval(
            os.getenv("CONNECTOR_RUN_EVERY", "24h")
        )
        self.lookback_hours = int(os.getenv("VYSION_LOOKBACK_HOURS", "24"))
        if self.lookback_hours <= 0:
            raise ValueError("VYSION_LOOKBACK_HOURS must be greater than zero")

    @staticmethod
    def _parse_interval(value):
        match = re.fullmatch(r"(\d+)([dhms])", value.strip().lower())
        if not match:
            raise ValueError(
                "CONNECTOR_RUN_EVERY must use the format 7d, 12h, 10m or 30s"
            )
        amount, unit = match.groups()
        return int(amount) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]

    def call_vysion_api_feed(self, batch, page=1):
        try:
            response = requests.get(
                f"{self.vysion_api_url.rstrip('/')}/api/v2/feed/ransomware",
                params={"batch": batch, "page": page, "page_size": 100},
                headers={
                    "Accept": "application/json",
                    "x-api-key": self.vysion_api_key,
                },
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.helper.log_error(f"Error while calling Vysion API: {e}")
            raise RuntimeError("Vysion ransomware feed request failed") from e

    @staticmethod
    def event_key(event):
        """Use the immutable Vysion event ID, with a safe fallback for old feeds."""
        return str(
            event.get("id")
            or f"{event.get('ransomwareGroup', '')}:{event.get('companyName', '')}:"
            f"{event.get('detectionDate', '')}"
        )

    @staticmethod
    def event_datetime(event):
        value = str(event.get("detectionDate") or "")
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            return None

    def get_batch_events(self, batch):
        """Fetch every page for one UTC calendar day from the Vysion feed."""
        events = []
        page = 1
        while True:
            data = self.call_vysion_api_feed(batch, page).get("data", {})
            hits = data.get("hits", [])
            events.extend(hits)
            if not hits or len(events) >= int(data.get("total", len(events))):
                return events
            page += 1

    def get_feed_vysion(self, window_start, window_end):
        """Return Vysion events detected in a rolling UTC time window."""
        batches = []
        batch = window_start.date()
        while batch <= window_end.date():
            batches.append(batch.isoformat())
            batch += timedelta(days=1)

        events = []
        seen = set()
        for batch in batches:
            for event in self.get_batch_events(batch):
                key = self.event_key(event)
                detected_at = self.event_datetime(event)
                if (
                    key not in seen
                    and detected_at is not None
                    and window_start <= detected_at <= window_end
                ):
                    seen.add(key)
                    events.append(event)
        return events

    @staticmethod
    def normalize_event(event):
        """Extract the fields used by the STIX mapper from a Vysion event."""
        return {
            "event_id": VysionEI.event_key(event),
            "company": event.get("companyName", ""),
            "company_link": event.get("companyLink", ""),
            "link_post": event.get("url", ""),
            "ransomware_group": event.get("ransomwareGroup", ""),
            "date": event.get("detectionDate", ""),
            "info": event.get("text", ""),
            "victim_country": event.get("country", ""),
            "industry": event.get("industry", ""),
            "naics": event.get("naics", ""),
        }

    def get_legacy_imported_event_ids(self, state):
        """Migrate the former daily state so its last batch is not re-imported."""
        if state.get("imported_event_ids") or not state.get("last_batch"):
            return set(state.get("imported_event_ids", []))
        legacy_events = self.get_batch_events(state["last_batch"])
        return {self.event_key(event) for event in legacy_events}

    @staticmethod
    def event_to_stix(event):
        threat_actor = ThreatActor(
            name=event["ransomware_group"], labels=["ransomware"]
        )
        victim = Identity(
            name=event["company"],
            type="identity",
            identity_class="organization",
        )
        incident = Incident(
            name=(
                f"Vysion Feed: {event['ransomware_group']} Attack - {event['company']}"
            ),
            description=event["info"],
            labels=["ransomware"],
            external_references=[
                {
                    "source_name": (
                        f"Vysion - Ransomware Feed: "
                        f"{event['ransomware_group']} Attack"
                    ),
                    "url": event["link_post"],
                }
            ],
        )
        objects = [
            threat_actor,
            victim,
            incident,
            Relationship(
                source_ref=incident.id,
                target_ref=threat_actor.id,
                relationship_type="attributed-to",
                description="Attribution of the incident to the threat actor",
            ),
            Relationship(
                source_ref=incident.id,
                target_ref=victim.id,
                relationship_type="targets",
                description="Victim of the incident",
            ),
        ]

        # Vysion does not populate these fields for every victim. Create
        # geographic and sector context only where the feed explicitly has it.
        country = str(event.get("victim_country") or "").strip()
        if country:
            location_args = {"name": country}
            if len(country) == 2 and country.isalpha():
                location_args["country"] = country.upper()
            country_location = Location(**location_args)
            objects.extend(
                [
                    country_location,
                    Relationship(
                        source_ref=victim.id,
                        target_ref=country_location.id,
                        relationship_type="located-at",
                        description="Country reported by Vysion for this victim",
                    ),
                    Relationship(
                        source_ref=incident.id,
                        target_ref=country_location.id,
                        relationship_type="targets",
                    ),
                ]
            )

        industry = str(event.get("industry") or "").strip()
        if industry:
            naics = str(event.get("naics") or "").strip()
            labels = ["sector"] + ([f"naics:{naics}"] if naics else [])
            sector = Identity(
                name=industry,
                type="identity",
                identity_class="class",
                labels=labels,
            )
            objects.extend(
                [
                    sector,
                    Relationship(
                        source_ref=victim.id,
                        target_ref=sector.id,
                        relationship_type="related-to",
                        description="Industry reported by Vysion for this victim",
                    ),
                    Relationship(
                        source_ref=incident.id,
                        target_ref=sector.id,
                        relationship_type="targets",
                    ),
                ]
            )

        return objects

    def run_once(self, state):
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=self.lookback_hours)
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Vysion ransomware feed: {window_start.isoformat()} to {window_end.isoformat()}",
        )
        try:
            imported_event_ids = self.get_legacy_imported_event_ids(state)
            feed_events = self.get_feed_vysion(window_start, window_end)
            events = [
                self.normalize_event(event)
                for event in feed_events
                if self.event_key(event) not in imported_event_ids
            ]
            objects = [obj for event in events for obj in self.event_to_stix(event)]
            if objects:
                bundle = Bundle(objects=objects).serialize()
                self.helper.send_stix2_bundle(
                    bundle, update=self.update_existing_data, work_id=work_id
                )
            state = {
                "last_run": int(time.time()),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "events_imported": len(events),
                "events_seen": len(feed_events),
                "imported_event_ids": list(
                    (imported_event_ids | {event["event_id"] for event in events})
                )[-1000:],
            }
            self.helper.set_state(state)
            self.helper.api.work.to_processed(
                work_id,
                f"Imported {len(events)} new ransomware events from the last "
                f"{self.lookback_hours} hours ({len(feed_events)} seen)",
            )
            self.helper.log_info(f"Stored connector state: {state}")
        except Exception as error:
            self.helper.api.work.to_processed(work_id, f"Import failed: {error}")
            raise

    def run(self) -> None:

        self.helper.log_info(f"{self.helper.connect_name} connector is running...")

        while True:
            try:
                state = self.helper.get_state() or {}
                last_run = state.get("last_run")
                elapsed = int(time.time()) - last_run if last_run else None
                if elapsed is None or elapsed >= self.interval_seconds:
                    self.run_once(state)
                else:
                    remaining = self.interval_seconds - elapsed
                    self.helper.log_info(
                        f"Next Vysion ransomware feed run in {remaining} seconds"
                    )
            except Exception as e:
                self.helper.log_error(f"Error while running the connector: {e}")

            if self.helper.connect_run_and_terminate:
                return
            time.sleep(min(60, self.interval_seconds))

        return 0


if __name__ == "__main__":
    try:
        connector = VysionEI()
        connector.run()
    except Exception as e:
        print(f"Unable to start Vysion ransomware feed connector: {e}")
        time.sleep(10)
        raise
