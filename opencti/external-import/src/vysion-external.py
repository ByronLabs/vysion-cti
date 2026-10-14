import re
import time
from datetime import datetime, timedelta, timezone

from stix2 import Bundle, ThreatActor, Relationship, Incident, Identity, Location
import os
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from pycti import Identity as OpenCTIIdentity, ThreatActor as OpenCTIThreatActor, Location as OpenCTILocation

from common.client import VysionClient, VysionError
from common.evidence import stable_id, relation


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
        self.client = VysionClient(self.vysion_api_url, self.vysion_api_key)
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
        seconds = int(amount) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
        if seconds <= 0:
            raise ValueError("CONNECTOR_RUN_EVERY must be greater than zero")
        return seconds

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
        """Fetch a daily batch; never checkpoint an incomplete response."""
        events, truncated = self.client.search(
            "feed/ransomware", {"batch": batch}, page_size=100, max_pages=100
        )
        if truncated:
            raise VysionError("Ransomware feed page limit reached; checkpoint unchanged")
        for event in events:
            self.validate_event(event)
        return events

    @classmethod
    def validate_event(cls, event):
        if not isinstance(event, dict):
            raise VysionError("Ransomware feed entry must be an object")
        for field in ("companyName", "ransomwareGroup"):
            if not isinstance(event.get(field), str) or not event[field].strip():
                raise VysionError(f"Ransomware feed entry missing {field}")
        if cls.event_datetime(event) is None:
            raise VysionError("Ransomware feed entry has an invalid detectionDate")
        for field in ("country", "industry", "url", "text"):
            if event.get(field) is not None and not isinstance(event[field], str):
                raise VysionError(f"Ransomware feed entry has an invalid {field}")

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
            "company": event["companyName"].strip(),
            "company_link": event.get("companyLink", ""),
            "link_post": event.get("url", ""),
            "ransomware_group": event["ransomwareGroup"].strip(),
            "date": VysionEI.event_datetime(event).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "info": event.get("text") or "",
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
            id=OpenCTIThreatActor.generate_id(event["ransomware_group"], "Threat-Actor-Group"),
            name=event["ransomware_group"], labels=["ransomware"]
        )
        victim = Identity(
            id=OpenCTIIdentity.generate_id(event["company"], "organization"),
            name=event["company"],
            type="identity",
            identity_class="organization",
        )
        incident = Incident(
            id=stable_id("incident", f"ransomware:{event['event_id']}"),
            created=event["date"], modified=event["date"],
            name=(
                f"Vysion Feed: {event['ransomware_group']} Attack - {event['company']}"
            ),
            description=event["info"] or "Ransomware detection reported by Vysion",
            labels=["ransomware"],
            external_references=[
                {
                    "source_name": (
                        f"Vysion - Ransomware Feed: "
                        f"{event['ransomware_group']} Attack"
                    ),
                    "external_id": event["event_id"],
                    **({"url": event["link_post"]} if event.get("link_post") else {}),
                }
            ],
        )
        objects = [
            threat_actor,
            victim,
            incident,
            Relationship(
                id=relation(incident.id, threat_actor.id, "attributed-to").id,
                source_ref=incident.id,
                target_ref=threat_actor.id,
                relationship_type="attributed-to",
                description="Attribution of the incident to the threat actor",
            ),
            Relationship(
                id=relation(incident.id, victim.id, "targets").id,
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
            country = country.upper() if len(country) == 2 and country.isalpha() else country
            country_location = Location(
                id=OpenCTILocation.generate_id(country, "Country"),
                name=country, country=country, x_opencti_location_type="Country", allow_custom=True,
            )
            objects.extend(
                [
                    country_location,
                    Relationship(
                        id=relation(victim.id, country_location.id, "located-at").id,
                        source_ref=victim.id,
                        target_ref=country_location.id,
                        relationship_type="located-at",
                        description="Country reported by Vysion for this victim",
                    ),
                    Relationship(
                        id=relation(incident.id, country_location.id, "targets").id,
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
                id=OpenCTIIdentity.generate_id(industry, "class"),
                name=industry,
                type="identity",
                identity_class="class",
                labels=labels,
            )
            objects.extend(
                [
                    sector,
                    Relationship(
                        id=relation(victim.id, sector.id).id,
                        source_ref=victim.id,
                        target_ref=sector.id,
                        relationship_type="related-to",
                        description="Industry reported by Vysion for this victim",
                    ),
                    Relationship(
                        id=relation(incident.id, sector.id, "targets").id,
                        source_ref=incident.id,
                        target_ref=sector.id,
                        relationship_type="targets",
                    ),
                ]
            )

        return objects

    def run_once(self, state, window_start=None, window_end=None, checkpoint=True, max_events=None):
        if window_start is not None or window_end is not None:
            if checkpoint or window_start is None or window_end is None:
                raise ValueError("Historical test windows require both dates and checkpoint=False")
            if window_start.tzinfo is None or window_end.tzinfo is None or window_start >= window_end or window_end - window_start > timedelta(days=31):
                raise ValueError("Invalid historical ransomware test window")
        else:
            window_end = datetime.now(timezone.utc)
            window_start = window_end - timedelta(hours=self.lookback_hours)
        if max_events is not None and (checkpoint or max_events < 1):
            raise ValueError("Limited test imports require checkpoint=False and a positive limit")
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
            if max_events is not None:
                events = events[:max_events]
            objects = {obj.id: obj for event in events for obj in self.event_to_stix(event)}
            if objects:
                bundle = Bundle(objects=list(objects.values()), allow_custom=True).serialize()
                self.helper.send_stix2_bundle(
                    bundle, update=self.update_existing_data, work_id=work_id
                )
            state = {
                "last_run": int(time.time()),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "events_imported": len(events),
                "events_seen": len(feed_events),
                "imported_event_ids": list(dict.fromkeys(
                    list(state.get("imported_event_ids") or sorted(imported_event_ids))
                    + [event["event_id"] for event in events]
                ))[-1000:],
                "stix_id_scheme": "deterministic-v1",
            }
            self.helper.api.work.to_processed(
                work_id,
                f"Imported {len(events)} new ransomware events from the last "
                f"{self.lookback_hours} hours ({len(feed_events)} seen)",
            )
            if checkpoint:
                self.helper.set_state(state)
            self.helper.log_info(f"Submitted {len(events)} ransomware events")
            return {"work_id": work_id, "events": len(events), "object_ids": list(objects)}
        except Exception as error:
            self.helper.api.work.to_processed(work_id, f"Import failed: {type(error).__name__}; checkpoint unchanged", True)
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
