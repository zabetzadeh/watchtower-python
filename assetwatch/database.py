"""One SQLite source of truth. State changes and events commit together."""

import ipaddress
import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .monitor import dns_events, http_events
from .normalization import in_scope, ipv4_addresses, normalize_hostname
from .programs import format_program_messages

LOG = logging.getLogger(__name__)
SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS target_domains (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    domain TEXT NOT NULL, PRIMARY KEY(target_id, domain)
);
CREATE TABLE IF NOT EXISTS target_cidrs (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL, PRIMARY KEY(target_id, cidr)
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    dns_resolved INTEGER NOT NULL DEFAULT 0,
    ip_addresses TEXT NOT NULL DEFAULT '[]', dns_checked_at TEXT,
    dns_version INTEGER NOT NULL DEFAULT 0,
    http_available INTEGER NOT NULL DEFAULT 0, http_status INTEGER,
    previous_http_status INTEGER, http_ever_available INTEGER NOT NULL DEFAULT 0,
    http_checked_at TEXT, http_down_since TEXT, http_url TEXT,
    http_metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(target_id, hostname)
);
CREATE TABLE IF NOT EXISTS asset_sources (
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY(asset_id, source)
);
CREATE TABLE IF NOT EXISTS monitoring_jobs (
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, due_at REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(asset_id, watcher)
);
CREATE INDEX IF NOT EXISTS idx_monitoring_due ON monitoring_jobs(watcher, due_at, asset_id);
CREATE TABLE IF NOT EXISTS observation_confirmations (
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, state TEXT NOT NULL, samples INTEGER NOT NULL,
    PRIMARY KEY(asset_id, watcher)
);
CREATE TABLE IF NOT EXISTS asset_validations (
    asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL, state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, previous_state TEXT NOT NULL,
    new_state TEXT NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    attempted_at TEXT NOT NULL, success INTEGER NOT NULL,
    error TEXT, message_id TEXT
);
CREATE TABLE IF NOT EXISTS notification_suppressions (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    reason TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cdn_sources (
    source TEXT PRIMARY KEY, fetched_at REAL NOT NULL, ranges TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS watcher_runs (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, finished_at REAL NOT NULL, success INTEGER NOT NULL,
    PRIMARY KEY(target_id, watcher)
);
CREATE TABLE IF NOT EXISTS watcher_status (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, state TEXT NOT NULL, queued_at REAL, started_at REAL,
    finished_at REAL, detail TEXT NOT NULL DEFAULT '', last_error TEXT,
    results INTEGER NOT NULL DEFAULT 0, new_assets INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(target_id, watcher)
);
CREATE TABLE IF NOT EXISTS run_requests (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, PRIMARY KEY(target_id, watcher)
);
CREATE TABLE IF NOT EXISTS runtime_state (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS program_feeds (
    platform TEXT PRIMARY KEY, initialized_at TEXT,
    state TEXT NOT NULL DEFAULT 'never_run', started_at REAL, checked_at REAL,
    next_run_at REAL NOT NULL DEFAULT 0, last_error TEXT,
    program_count INTEGER NOT NULL DEFAULT 0, scope_count INTEGER NOT NULL DEFAULT 0,
    new_programs INTEGER NOT NULL DEFAULT 0, new_scopes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS programs (
    platform TEXT NOT NULL REFERENCES program_feeds(platform), program_key TEXT NOT NULL,
    name TEXT NOT NULL, url TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY(platform, program_key)
);
CREATE TABLE IF NOT EXISTS program_scopes (
    platform TEXT NOT NULL, program_key TEXT NOT NULL,
    identifier TEXT NOT NULL, type TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY(platform, program_key, identifier),
    FOREIGN KEY(platform, program_key) REFERENCES programs(platform, program_key)
);
CREATE TABLE IF NOT EXISTS program_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL, program_key TEXT NOT NULL,
    event_type TEXT NOT NULL, program_name TEXT NOT NULL, program_url TEXT NOT NULL,
    added_scope TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(platform, program_key) REFERENCES programs(platform, program_key)
);
CREATE TABLE IF NOT EXISTS program_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES program_events(id),
    part INTEGER NOT NULL, text TEXT NOT NULL,
    delivered_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, attempted_at TEXT,
    next_attempt_at REAL NOT NULL DEFAULT 0, last_error TEXT, message_id TEXT,
    UNIQUE(event_id, part)
);
CREATE INDEX IF NOT EXISTS idx_program_events_platform ON program_events(platform, id);
CREATE INDEX IF NOT EXISTS idx_program_messages_pending ON program_messages(next_attempt_at, id)
    WHERE delivered_at IS NULL;
CREATE TABLE IF NOT EXISTS dnsgen_progress (
    target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    last_asset_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dnsgen_candidates (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    domain TEXT NOT NULL, hostname TEXT NOT NULL,
    PRIMARY KEY(target_id, hostname)
);
CREATE INDEX IF NOT EXISTS idx_dnsgen_domain ON dnsgen_candidates(target_id, domain, hostname);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_dns ON assets(target_id, dns_resolved, id);
CREATE INDEX IF NOT EXISTS idx_assets_http ON assets(http_available);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(http_status);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_events_pending ON events(next_attempt_at, id)
    WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_id, id);
CREATE INDEX IF NOT EXISTS idx_notifications_event ON notifications(event_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def decode_asset(row) -> dict:
    result = dict(row)
    for field in ("ip_addresses", "known_ip_addresses", "cname_records", "http_metadata"):
        result[field] = json.loads(result[field])
    for field in ("dns_resolved", "http_available", "http_ever_available"):
        result[field] = bool(result[field])
    return result


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=10000")
        self.connection.executescript(SCHEMA)
        self.on_event = None
        self.migrate()

    def migrate(self):
        # Additive migration, serialized with other CLI/daemon connections.
        with self.transaction():
            columns = {row[1] for row in self.connection.execute("PRAGMA table_info(assets)")}
            for name, definition in (("known_ip_addresses", "TEXT NOT NULL DEFAULT '[]'"),
                                     ("cname_records", "TEXT NOT NULL DEFAULT '[]'"),
                                     ("cname_checked_at", "TEXT")):
                if name not in columns:
                    self.connection.execute(f"ALTER TABLE assets ADD COLUMN {name} {definition}")
            if "known_ip_addresses" not in columns:
                self.connection.execute("UPDATE assets SET known_ip_addresses=ip_addresses")
                # Recover earlier rotations from existing event history, one asset at a time.
                for row in self.connection.execute("SELECT id,ip_addresses FROM assets"):
                    known = set(json.loads(row["ip_addresses"]))
                    seen = set()
                    for event in self.connection.execute(
                            "SELECT * FROM events WHERE asset_id=? ORDER BY id", (row["id"],)):
                        seen.update(json.loads(event["previous_state"]).get("ip_addresses", []))
                        current = set(json.loads(event["new_state"]).get("ip_addresses", []))
                        if event["event_type"] == "dns_ip_changed" and current <= seen and not event["delivered_at"]:
                            self.suppress_notification(event["id"], "known_ip_rotation")
                        seen.update(current)
                    known.update(seen)
                    self.connection.execute("UPDATE assets SET known_ip_addresses=? WHERE id=?",
                                            (json.dumps(ipv4_addresses(known)), row["id"]))
            # A durable, deduplicated queue also upgrades old databases. Rows remain
            # scheduled after checks, so unresolved/old assets are never forgotten.
            self.connection.execute("INSERT OR IGNORE INTO monitoring_jobs(asset_id,watcher) "
                                    "SELECT id,'dns_resolution' FROM assets")
            self.connection.execute("INSERT OR IGNORE INTO monitoring_jobs(asset_id,watcher) "
                                    "SELECT id,'http_probe' FROM assets WHERE dns_resolved=1")
            # Recover the first proven live state without sending legacy raw findings.
            for row in self.connection.execute(
                    "SELECT * FROM assets a WHERE http_ever_available=1 "
                    "AND NOT EXISTS (SELECT 1 FROM asset_validations v WHERE v.asset_id=a.id)"):
                event = self.connection.execute(
                    "SELECT id,new_state FROM events WHERE asset_id=? "
                    "AND event_type IN ('http_service_appeared','http_service_returned') ORDER BY id LIMIT 1",
                    (row["id"],)).fetchone()
                state = json.loads(event["new_state"]) if event else decode_asset(row)
                if state.get("dns_resolved") and state.get("http_available"):
                    self._validate_asset(row["id"], state, event["id"] if event else 0)

    def close(self):
        self.connection.close()

    @contextmanager
    def transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def targets(self) -> list[dict]:
        result = []
        for row in self.connection.execute("SELECT * FROM targets ORDER BY name"):
            target = dict(row)
            target["domains"] = [r[0] for r in self.connection.execute(
                "SELECT domain FROM target_domains WHERE target_id=? ORDER BY domain", (row["id"],))]
            target["cidrs"] = [r[0] for r in self.connection.execute(
                "SELECT cidr FROM target_cidrs WHERE target_id=? ORDER BY cidr", (row["id"],))]
            result.append(target)
        return result

    def target(self, name: str) -> dict:
        for target in self.targets():
            if target["name"] == name:
                return target
        raise ValueError(f"Unknown target: {name}")

    def add_target(self, name: str, domains: list[str], cidrs: list[str]) -> dict:
        name = name.strip()
        if not name or len(name) > 200 or any(ord(c) < 32 for c in name):
            raise ValueError("Target name must contain 1–200 printable characters")
        normalized = [h for domain in domains if (h := normalize_hostname(domain))]
        if domains and len(normalized) != len(domains):
            raise ValueError("Provide valid root domain(s) (without a URL or port)")
        networks = sorted({str(ipaddress.ip_network(cidr, strict=True)) for cidr in cidrs})
        if not normalized and not networks:
            raise ValueError("Provide at least one valid root domain or CIDR")
        now = utcnow()
        with self.transaction():
            cursor = self.connection.execute("INSERT INTO targets(name,created_at) VALUES (?,?)", (name, now))
            target_id = cursor.lastrowid
            self.connection.executemany("INSERT INTO target_domains VALUES (?,?)",
                                        [(target_id, domain) for domain in sorted(set(normalized))])
            self.connection.executemany("INSERT INTO target_cidrs VALUES (?,?)",
                                        [(target_id, cidr) for cidr in networks])
        target = self.target(name)
        if target["domains"]:
            self.ingest(target_id, target["domains"], "target")
        return target

    def update_target(self, name: str, domains: list[str] | None = None, cidrs: list[str] | None = None) -> dict:
        target = self.target(name)
        target_id = target["id"]
        domains = domains or []
        cidrs = cidrs or []
        normalized = [h for domain in domains if (h := normalize_hostname(domain))]
        if domains and len(normalized) != len(domains):
            raise ValueError("Provide valid domain(s) (without a URL or port)")
        networks = sorted({str(ipaddress.ip_network(cidr, strict=True)) for cidr in cidrs})
        if not normalized and not networks:
            raise ValueError("Provide at least one valid domain or CIDR to update")
        with self.transaction():
            if normalized:
                self.connection.executemany("INSERT OR IGNORE INTO target_domains VALUES (?,?)",
                                            [(target_id, domain) for domain in sorted(set(normalized))])
            if networks:
                self.connection.executemany("INSERT OR IGNORE INTO target_cidrs VALUES (?,?)",
                                            [(target_id, cidr) for cidr in networks])
        if normalized:
            self.ingest(target_id, normalized, "target")
        return self.target(name)

    def remove_target(self, name: str):
        with self.transaction():
            if not self.connection.execute("DELETE FROM targets WHERE name=?", (name,)).rowcount:
                raise ValueError(f"Unknown target: {name}")

    def _event(self, asset_id: int, kind: str, before: dict, after: dict):
        self.connection.execute(
            "INSERT INTO events(asset_id,event_type,previous_state,new_state,created_at) VALUES (?,?,?,?,?)",
            (asset_id, kind, json.dumps(before), json.dumps(after), utcnow()))
        LOG.info("event=%s target_id=%s host=%s", kind, after.get("target_id"), after.get("hostname"))
        if self.on_event is not None:
            try:
                self.on_event()
            except Exception:
                pass

    def ingest(self, target_id: int, hostnames, source: str) -> int:
        new = 0
        with self.transaction():
            domains = [row[0] for row in self.connection.execute(
                "SELECT domain FROM target_domains WHERE target_id=?", (target_id,))]
            has_cidrs = bool(self.connection.execute(
                "SELECT 1 FROM target_cidrs WHERE target_id=?", (target_id,)).fetchone())
            if not domains and not has_cidrs:  # A target may have been removed while its tool was running.
                return 0
            now = utcnow()
            for raw in hostnames:
                hostname = normalize_hostname(raw)
                if not hostname:
                    continue
                if domains and not in_scope(hostname, domains):
                    continue
                cursor = self.connection.execute(
                    "INSERT OR IGNORE INTO assets(target_id,hostname,first_seen,last_seen) VALUES (?,?,?,?)",
                    (target_id, hostname, now, now))
                created = bool(cursor.rowcount)
                row = self.connection.execute(
                    "SELECT * FROM assets WHERE target_id=? AND hostname=?", (target_id, hostname)).fetchone()
                self.connection.execute("UPDATE assets SET last_seen=? WHERE id=?", (now, row["id"]))
                self.connection.execute(
                    "INSERT INTO asset_sources VALUES (?,?,?,?) ON CONFLICT(asset_id,source) "
                    "DO UPDATE SET last_seen=excluded.last_seen", (row["id"], source, now, now))
                if created:
                    self.connection.execute("INSERT INTO monitoring_jobs(asset_id,watcher) VALUES (?,'dns_resolution')",
                                            (row["id"],))
                    self._event(row["id"], "fresh_asset", {}, {**decode_asset(row), "source": source})
                    new += 1
        return new

    def assets(self, target_id=None, resolved=None, http=None, status=None, source=None, sources=None, limit=None, offset=None):
        clauses, params = [], []
        for column, value in (("target_id", target_id), ("dns_resolved", resolved),
                              ("http_available", http), ("http_status", status)):
            if value is not None:
                clauses.append(f"a.{column}=?")
                params.append(value)
        if source is not None:
            clauses.append("EXISTS (SELECT 1 FROM asset_sources s WHERE s.asset_id=a.id AND s.source=?)")
            params.append(source)
        if sources:
            placeholders = ",".join("?" for _ in sources)
            clauses.append(f"EXISTS (SELECT 1 FROM asset_sources s WHERE s.asset_id=a.id AND s.source IN ({placeholders}))")
            params.extend(sources)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        pagination = ""
        if limit is not None:
            pagination += f" LIMIT {int(limit)}"
            if offset is not None:
                pagination += f" OFFSET {int(offset)}"
        cursor = self.connection.execute(
            "SELECT a.*,t.name AS target FROM assets a JOIN targets t ON t.id=a.target_id"
            + where + " ORDER BY a.hostname,t.name" + pagination, params)
        for row in cursor:
            asset = decode_asset(row)
            asset["sources"] = [r[0] for r in self.connection.execute(
                "SELECT source FROM asset_sources WHERE asset_id=? ORDER BY source", (row["id"],))]
            yield asset

    def asset_batches(self, target_id: int, size: int, resolved_only=False, after_id=0, due_watcher=None):
        maximum = self.connection.execute(
            "SELECT COALESCE(MAX(id),0) FROM assets WHERE target_id=?", (target_id,)).fetchone()[0]
        last = after_id
        cutoff = time.time()
        while last < maximum:
            due = (" AND EXISTS (SELECT 1 FROM monitoring_jobs j WHERE j.asset_id=assets.id "
                   "AND j.watcher=? AND j.due_at<=?)") if due_watcher else ""
            rows = self.connection.execute(
                "SELECT * FROM assets WHERE target_id=? AND id>? AND id<=?"
                + (" AND dns_resolved=1" if resolved_only else "") + due + " ORDER BY id LIMIT ?",
                (target_id, last, maximum, *((due_watcher, cutoff) if due_watcher else ()), size)).fetchall()
            if not rows:
                break
            last = rows[-1]["id"]
            yield [decode_asset(row) for row in rows]

    def schedule_check(self, asset_id, watcher, delay):
        self.connection.execute("UPDATE monitoring_jobs SET due_at=? WHERE asset_id=? AND watcher=?",
                                (time.time() + delay, asset_id, watcher))

    def pending_dnsgen_batches(self, target_id: int, size: int):
        row = self.connection.execute(
            "SELECT last_asset_id FROM dnsgen_progress WHERE target_id=?", (target_id,)).fetchone()
        yield from self.asset_batches(target_id, size, after_id=row[0] if row else 0)

    def cache_dnsgen_candidates(self, target_id: int, names) -> int:
        with self.transaction():
            domains = [row[0] for row in self.connection.execute(
                "SELECT domain FROM target_domains WHERE target_id=? ORDER BY length(domain) DESC", (target_id,))]
            rows = []
            for raw in names:
                hostname = normalize_hostname(raw)
                if not hostname:
                    continue
                domain = next((root for root in domains if in_scope(hostname, [root])), None)
                if domain:
                    rows.append((target_id, domain, hostname))
            previous = self.connection.total_changes
            self.connection.executemany("INSERT OR IGNORE INTO dnsgen_candidates VALUES (?,?,?)", rows)
            return self.connection.total_changes - previous

    def finish_dnsgen_batch(self, target_id: int, last_asset_id: int):
        # Call only after the complete successful output has been cached. If interrupted
        # earlier, retry that seed batch; the candidate primary key deduplicates partial output.
        self.connection.execute(
            "INSERT INTO dnsgen_progress SELECT id,? FROM targets WHERE id=? "
            "ON CONFLICT(target_id) DO UPDATE SET last_asset_id=MAX(last_asset_id,excluded.last_asset_id)",
            (last_asset_id, target_id))

    def dnsgen_candidate_batches(self, target_id: int, domain: str, size: int):
        last = ""
        while True:
            rows = self.connection.execute(
                "SELECT hostname FROM dnsgen_candidates WHERE target_id=? AND domain=? AND hostname>? "
                "ORDER BY hostname LIMIT ?", (target_id, domain, last, size)).fetchall()
            if not rows:
                break
            last = rows[-1][0]
            yield [row[0] for row in rows]

    def reset_confirmation(self, asset_id: int, watcher: str):
        self.connection.execute("DELETE FROM observation_confirmations WHERE asset_id=? AND watcher=?",
                                (asset_id, watcher))

    def _confirm_observation(self, asset_id, watcher, state, required):
        # Called within the observation's transaction: pending evidence, accepted
        # state and events must never get out of sync after a crash.
        encoded = json.dumps(state, sort_keys=True)
        row = self.connection.execute(
            "SELECT state,samples FROM observation_confirmations WHERE asset_id=? AND watcher=?",
            (asset_id, watcher)).fetchone()
        samples = row["samples"] + 1 if row and row["state"] == encoded else 1
        if samples >= required:
            self.reset_confirmation(asset_id, watcher)
            return True
        self.connection.execute(
            "INSERT INTO observation_confirmations VALUES (?,?,?,?) "
            "ON CONFLICT(asset_id,watcher) DO UPDATE SET state=excluded.state,samples=excluded.samples",
            (asset_id, watcher, encoded, samples))
        LOG.info("asset_id=%s watcher=%s verification=pending samples=%s required=%s state=%s",
                 asset_id, watcher, samples, required, encoded)
        return False

    def observe_dns(self, asset_id: int, addresses: list[str], *, loss_confirmations=1):
        """Apply DNS evidence; return None while a loss awaits confirmation."""
        addresses = ipv4_addresses(addresses)
        with self.transaction():
            row = self.connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None:
                return False
            before = decode_asset(row)
            if not addresses and before["dns_resolved"]:
                if not self._confirm_observation(asset_id, "dns_resolution", [], loss_confirmations):
                    return None
            else:
                self.reset_confirmation(asset_id, "dns_resolution")
            now = utcnow()
            changed = before["ip_addresses"] != addresses
            if changed:
                self.reset_confirmation(asset_id, "http_probe")
            known = sorted(set(before["known_ip_addresses"]) | set(addresses))
            after = {**before, "dns_resolved": bool(addresses), "ip_addresses": addresses,
                     "known_ip_addresses": known,
                     "dns_checked_at": now, "dns_version": before["dns_version"] + int(changed)}
            kinds = dns_events(before, addresses)
            self.connection.execute(
                "UPDATE assets SET dns_resolved=?,ip_addresses=?,known_ip_addresses=?,dns_checked_at=?,"
                "dns_version=dns_version+? WHERE id=?",
                (bool(addresses), json.dumps(addresses), json.dumps(known), now, int(changed), asset_id))
            if not addresses and before["http_available"]:
                after.update(http_available=False, http_status=None, http_down_since=now,
                             previous_http_status=before["http_status"], http_metadata={"reason": "no_a_record"})
                self.connection.execute(
                    "UPDATE assets SET http_available=0,previous_http_status=http_status,http_status=NULL,"
                    "http_down_since=?,http_metadata=? WHERE id=?",
                    (now, json.dumps(after["http_metadata"]), asset_id))
                kinds.append("http_service_disappeared")
            if addresses:
                self.connection.execute(
                    "INSERT INTO monitoring_jobs VALUES (?,'http_probe',0) ON CONFLICT(asset_id,watcher) "
                    "DO UPDATE SET due_at=CASE WHEN ? THEN 0 ELSE due_at END", (asset_id, changed))
            else:
                self.connection.execute("DELETE FROM monitoring_jobs WHERE asset_id=? AND watcher='http_probe'",
                                        (asset_id,))
            for kind in kinds:
                self._event(asset_id, kind, before, after)
            return True

    def observe_cnames(self, asset_id: int, names: list[str]):
        records = sorted({name for raw in names if (name := normalize_hostname(raw))})
        with self.transaction():
            row = self.connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None:
                return
            before = decode_asset(row)
            now = utcnow()
            after = {**before, "cname_records": records, "cname_checked_at": now}
            self.connection.execute("UPDATE assets SET cname_records=?,cname_checked_at=? WHERE id=?",
                                    (json.dumps(records), now, asset_id))
            if before["cname_checked_at"] and before["cname_records"] != records:
                self._event(asset_id, "dns_cname_changed", before, after)

    def ip_batches(self, target_id: int, size: int):
        cursor = self.connection.execute(
            "SELECT DISTINCT j.value FROM assets a,json_each(a.ip_addresses) j "
            "WHERE a.target_id=? ORDER BY j.value", (target_id,))
        while rows := cursor.fetchmany(size):
            yield [row[0] for row in rows]

    def observe_http(self, asset_id: int, observation: dict | None, dns_version: int, *, confirmations=1):
        """Apply verified evidence; True=accepted, None=pending, False=stale.

        Direct callers may submit already verified evidence (one sample); the
        watcher supplies the configured confirmation threshold on every check.
        """
        with self.transaction():
            row = self.connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None or not row["dns_resolved"] or row["dns_version"] != dns_version:
                return False  # Discard results if DNS changed while HTTPX was in flight.
            before = decode_asset(row)
            status = observation["status_code"] if observation else None
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("Invalid HTTP status code")
            url = observation.get("url") if observation else before["http_url"]
            changed = (status != before["http_status"] or
                       (status is not None and url != before["http_url"]))
            if changed:
                state = {"status": status, "url": url, "dns_version": dns_version}
                if not self._confirm_observation(asset_id, "http_probe", state, confirmations):
                    return None
            else:
                self.reset_confirmation(asset_id, "http_probe")
            now = utcnow()
            previous_status = (before["http_status"] if before["http_status"] != status
                               and before["http_status"] is not None else before["previous_http_status"])
            down_since = None if status else before["http_down_since"]
            if status is None and before["http_available"]:
                down_since = now
            after = {**before, "http_available": status is not None, "http_status": status,
                     "previous_http_status": previous_status,
                     "http_ever_available": before["http_ever_available"] or status is not None,
                     "http_checked_at": now, "http_down_since": down_since,
                     "http_url": url,
                     "http_metadata": observation or {"reason": "probe_unavailable"}}
            self.connection.execute(
                "UPDATE assets SET http_available=?,http_status=?,previous_http_status=?,http_ever_available=?,"
                "http_checked_at=?,http_down_since=?,http_url=?,http_metadata=? WHERE id=?",
                (after["http_available"], status, previous_status, after["http_ever_available"], now,
                 down_since, after["http_url"], json.dumps(after["http_metadata"]), asset_id))
            for kind in http_events(before, status, url):
                self._event(asset_id, kind, before, after)
            if status is not None:
                event_id = self.connection.execute("SELECT COALESCE(MAX(id),0) FROM events WHERE asset_id=?",
                                                   (asset_id,)).fetchone()[0]
                self._validate_asset(asset_id, after, event_id)
            return True

    def _validate_asset(self, asset_id, state, event_id):
        created = self.connection.execute("INSERT OR IGNORE INTO asset_validations VALUES (?,?,?)",
                                          (asset_id, event_id, json.dumps(state))).rowcount
        if created:
            # Keep complete history; initial DNS/HTTP events are covered by one
            # validated fresh-asset message, not three notifications per finding.
            self.connection.execute(
                "INSERT OR IGNORE INTO notification_suppressions SELECT id,'initial_validation',? FROM events "
                "WHERE asset_id=? AND id<=? AND event_type!='fresh_asset' AND delivered_at IS NULL",
                (utcnow(), asset_id, event_id))

    def next_run_at(self, target_id: int, watcher: str, interval: float, retry_interval=None) -> float:
        if self.connection.execute("SELECT 1 FROM run_requests WHERE target_id=? AND watcher=?",
                                   (target_id, watcher)).fetchone():
            return 0
        if watcher in {"dns_resolution", "http_probe"}:
            row = self.connection.execute(
                "SELECT MIN(j.due_at) FROM monitoring_jobs j JOIN assets a ON a.id=j.asset_id "
                "WHERE a.target_id=? AND j.watcher=?", (target_id, watcher)).fetchone()
            return row[0] if row[0] is not None else float("inf")
        row = self.connection.execute(
            "SELECT finished_at,success FROM watcher_runs WHERE target_id=? AND watcher=?", (target_id, watcher)).fetchone()
        if watcher == "dns_bruteforce":
            # A failed/partial weekly run must not become a five-minute loop.
            # An interrupted attempt uses its durable start time, including after
            # a crash; merely waiting in the module queue does not count as a run.
            status = self.connection.execute(
                "SELECT started_at FROM watcher_status WHERE target_id=? AND watcher=?", (target_id, watcher)).fetchone()
            last_attempt = max(row["finished_at"] if row else 0, (status["started_at"] or 0) if status else 0)
            return last_attempt + interval if row or (status and status["started_at"] is not None) else 0
        if row and not row["success"] and retry_interval is not None:
            interval = min(interval, retry_interval)
        return row["finished_at"] + interval if row else 0

    def due(self, target_id: int, watcher: str, interval: float, retry_interval=None) -> bool:
        return self.next_run_at(target_id, watcher, interval, retry_interval) <= time.time()

    def finished(self, target_id: int, watcher: str, success: bool):
        self.connection.execute(
            "INSERT INTO watcher_runs SELECT id,?,?,? FROM targets WHERE id=? "
            "ON CONFLICT(target_id,watcher) DO UPDATE SET finished_at=excluded.finished_at,success=excluded.success",
            (watcher, time.time(), success, target_id))
        self.connection.execute(
            "UPDATE watcher_status SET state=CASE WHEN state='skipped' THEN state ELSE ? END,"
            "finished_at=? WHERE target_id=? AND watcher=?",
            ("success" if success else "failed", time.time(), target_id, watcher))

    def watcher_state(self, target_id: int, watcher: str, state: str, detail=""):
        now = time.time()
        if state == "queued":
            self.connection.execute(
                "INSERT INTO watcher_status(target_id,watcher,state,queued_at,detail) "
                "SELECT id,?,?,?,? FROM targets WHERE id=? ON CONFLICT(target_id,watcher) DO UPDATE SET "
                "state=excluded.state,queued_at=excluded.queued_at,started_at=NULL,finished_at=NULL,"
                "detail=excluded.detail,last_error=NULL,results=0,new_assets=0",
                (watcher, state, now, detail, target_id))
        else:
            self.connection.execute(
                "UPDATE watcher_status SET state=?,detail=?,started_at=CASE WHEN ?='running' "
                "THEN ? ELSE started_at END WHERE target_id=? AND watcher=?",
                (state, detail, state, now, target_id, watcher))

    def watcher_progress(self, target_id: int, watcher: str, detail: str, *, results=0, new_assets=0, error=None):
        self.connection.execute(
            "UPDATE watcher_status SET detail=?,results=results+?,new_assets=new_assets+?,"
            "last_error=COALESCE(?,last_error) WHERE target_id=? AND watcher=?",
            (detail[:1000], results, new_assets, error, target_id, watcher))

    def request_run(self, target_id: int, watcher: str):
        self.connection.execute("INSERT OR IGNORE INTO run_requests SELECT id,? FROM targets WHERE id=?",
                                (watcher, target_id))

    def consume_run_request(self, target_id: int, watcher: str):
        consumed = self.connection.execute("DELETE FROM run_requests WHERE target_id=? AND watcher=?",
                                            (target_id, watcher)).rowcount
        if consumed and watcher in {"dns_resolution", "http_probe"}:
            self.connection.execute("UPDATE monitoring_jobs SET due_at=0 WHERE watcher=? "
                                    "AND asset_id IN (SELECT id FROM assets WHERE target_id=?)", (watcher, target_id))

    def set_runtime(self, key: str, value):
        self.connection.execute("INSERT INTO runtime_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                (key, json.dumps(value)))

    def runtime(self, key: str, default=None):
        row = self.connection.execute("SELECT value FROM runtime_state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def program_feed_status(self, platform):
        row = self.connection.execute("SELECT * FROM program_feeds WHERE platform=?", (platform,)).fetchone()
        return dict(row) if row else None

    def start_program_check(self, platform):
        self.connection.execute(
            "INSERT INTO program_feeds(platform,state,started_at) VALUES (?,'running',?) "
            "ON CONFLICT(platform) DO UPDATE SET state='running',started_at=excluded.started_at,last_error=NULL",
            (platform, time.time()))

    def fail_program_check(self, platform, error, retry_after, state="failed"):
        self.connection.execute(
            "UPDATE program_feeds SET state=?,checked_at=?,next_run_at=?,last_error=? WHERE platform=?",
            (state, time.time(), time.time() + retry_after, error, platform))

    def observe_program_feed(self, platform, programs, interval):
        # The caller validates the entire feed before any baseline or seen-set changes.
        with self.transaction():
            self.connection.execute("INSERT OR IGNORE INTO program_feeds(platform) VALUES (?)", (platform,))
            baseline = self.program_feed_status(platform)["initialized_at"] is None
            now = utcnow()
            new_programs = new_scopes = scope_count = 0
            for program in programs:
                key = program["key"]
                created = bool(self.connection.execute(
                    "INSERT OR IGNORE INTO programs VALUES (?,?,?,?,?,?)",
                    (platform, key, program["name"], program["url"], now, now)).rowcount)
                self.connection.execute(
                    "UPDATE programs SET name=?,url=?,last_seen=? WHERE platform=? AND program_key=?",
                    (program["name"], program["url"], now, platform, key))
                added = []
                for item in program["scope"]:
                    inserted = self.connection.execute(
                        "INSERT OR IGNORE INTO program_scopes VALUES (?,?,?,?,?,?)",
                        (platform, key, item["identifier"], item["type"], now, now)).rowcount
                    self.connection.execute(
                        "UPDATE program_scopes SET type=?,last_seen=? WHERE platform=? AND program_key=? AND identifier=?",
                        (item["type"], now, platform, key, item["identifier"]))
                    if inserted:
                        added.append(item)
                scope_count += len(program["scope"])
                if not baseline and (created or added):
                    kind = "new_program" if created else "scope_added"
                    self._program_event(platform, program, kind, added, now)
                    new_programs += int(created)
                    new_scopes += len(added)
            self.connection.execute(
                "UPDATE program_feeds SET initialized_at=COALESCE(initialized_at,?),state=?,checked_at=?,"
                "next_run_at=?,last_error=NULL,program_count=?,scope_count=?,new_programs=?,new_scopes=? WHERE platform=?",
                (now, "baselined" if baseline else "success", time.time(), time.time() + interval,
                 len(programs), scope_count, new_programs, new_scopes, platform))
        return {"baseline": baseline, "new_programs": new_programs, "new_scopes": new_scopes}

    def _program_event(self, platform, program, kind, added, now):
        event_id = self.connection.execute(
            "INSERT INTO program_events(platform,program_key,event_type,program_name,program_url,added_scope,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (platform, program["key"], kind, program["name"], program["url"], json.dumps(added), now)).lastrowid
        event = {"id": event_id, "platform": platform, "event_type": kind, "program_name": program["name"],
                 "program_url": program["url"], "added_scope": added, "created_at": now}
        self.connection.executemany("INSERT INTO program_messages(event_id,part,text) VALUES (?,?,?)",
                                    [(event_id, number, text) for number, text in enumerate(format_program_messages(event), 1)])
        LOG.info("watcher=program_watch platform=%s program=%s event=%s event_id=P%s added_scopes=%s",
                 platform, program["key"], kind, event_id, len(added))

    def recent_program_events(self, platform=None, limit=10, offset=0):
        clause = " WHERE platform=?" if platform else ""
        params = (platform,) if platform else ()
        rows = []
        for row in self.connection.execute("SELECT * FROM program_events" + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
                                            (*params, limit, offset)):
            event = dict(row)
            event["added_scope"] = json.loads(event["added_scope"])
            rows.append(event)
        return rows

    def pending_program_messages(self, limit):
        return [dict(row) for row in self.connection.execute(
            "SELECT m.*,e.platform,e.program_name,e.program_url,e.created_at,e.event_type,'program' AS queue "
            "FROM program_messages m JOIN program_events e ON e.id=m.event_id "
            "WHERE m.delivered_at IS NULL AND m.next_attempt_at<=? AND NOT EXISTS ("
            "SELECT 1 FROM program_messages earlier WHERE earlier.event_id=m.event_id AND earlier.part<m.part "
            "AND earlier.delivered_at IS NULL AND earlier.next_attempt_at>?) ORDER BY m.id LIMIT ?",
            (time.time(), time.time(), limit))]

    def program_notification_result(self, notification_id, error=None, message_id=None, retry_after=0):
        now = utcnow()
        self.connection.execute(
            "UPDATE program_messages SET attempts=attempts+1,attempted_at=?,last_error=?,delivered_at=?,"
            "next_attempt_at=?,message_id=? WHERE id=? AND delivered_at IS NULL",
            (now, error, now if error is None else None, time.time() + retry_after,
             str(message_id) if message_id is not None else None, notification_id))

    def recent_events(self, target_id=None, kind=None, limit=10, offset=0):
        clauses, params = [], []
        if target_id is not None:
            clauses.append("a.target_id=?")
            params.append(target_id)
        if kind is not None:
            clauses.append("e.event_type=?")
            params.append(kind)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return [dict(row) for row in self.connection.execute(
            "SELECT e.*,a.hostname,t.name AS target FROM events e JOIN assets a ON a.id=e.asset_id "
            "JOIN targets t ON t.id=a.target_id" + where + " ORDER BY e.id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset))]

    def cname_assets(self, target_id=None, limit=20, offset=0):
        clause = " AND a.target_id=?" if target_id is not None else ""
        params = (target_id,) if target_id is not None else ()
        return [decode_asset(row) for row in self.connection.execute(
            "SELECT a.*,t.name AS target FROM assets a JOIN targets t ON t.id=a.target_id "
            "WHERE a.cname_records!='[]'" + clause + " ORDER BY a.hostname,a.id LIMIT ? OFFSET ?",
            (*params, limit, offset))]

    def pending_events(self, limit: int, *, exclude_types=(), validated_only=False):
        # Filter before LIMIT so muted IP churn cannot starve discovery alerts.
        exclusion = ""
        if exclude_types:
            exclusion = " AND e.event_type NOT IN (" + ",".join("?" for _ in exclude_types) + ")"
        if validated_only:
            exclusion += " AND EXISTS (SELECT 1 FROM asset_validations v WHERE v.asset_id=a.id)"
        rows = self.connection.execute(
            "SELECT e.*,a.hostname,t.name AS target FROM events e JOIN assets a ON a.id=e.asset_id "
            "JOIN targets t ON t.id=a.target_id WHERE e.delivered_at IS NULL AND e.next_attempt_at<=? "
            "AND NOT EXISTS (SELECT 1 FROM notification_suppressions s WHERE s.event_id=e.id)"
            + exclusion + " ORDER BY e.id LIMIT ?", (time.time(), *exclude_types, limit)).fetchall()
        events = [dict(row) for row in rows]
        if validated_only:
            for event in events:
                if event["event_type"] == "fresh_asset":
                    state = json.loads(self.connection.execute(
                        "SELECT state FROM asset_validations WHERE asset_id=?", (event["asset_id"],)).fetchone()[0])
                    state["source"] = json.loads(event["new_state"]).get("source", "unknown")
                    event["new_state"] = json.dumps(state)
                event["sources"] = [row[0] for row in self.connection.execute(
                    "SELECT source FROM asset_sources WHERE asset_id=? ORDER BY source", (event["asset_id"],))]
        return events

    def suppress_notification(self, event_id: int, reason: str):
        self.connection.execute(
            "INSERT OR IGNORE INTO notification_suppressions SELECT id,?,? FROM events WHERE id=?",
            (reason, utcnow(), event_id))

    def cdn_sources(self):
        return {row["source"]: {"fetched_at": row["fetched_at"], "ranges": json.loads(row["ranges"])}
                for row in self.connection.execute("SELECT * FROM cdn_sources")}

    def cache_cdn_source(self, source: str, ranges: dict, fetched_at: float):
        self.connection.execute(
            "INSERT INTO cdn_sources VALUES (?,?,?) ON CONFLICT(source) "
            "DO UPDATE SET fetched_at=excluded.fetched_at,ranges=excluded.ranges",
            (source, fetched_at, json.dumps(ranges)))

    def notification_result(self, event_id: int, error=None, message_id=None, retry_after=0):
        with self.transaction():
            if not self.connection.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                return
            now = utcnow()
            self.connection.execute(
                "INSERT INTO notifications(event_id,attempted_at,success,error,message_id) VALUES (?,?,?,?,?)",
                (event_id, now, error is None, error, str(message_id) if message_id is not None else None))
            self.connection.execute(
                "UPDATE events SET attempts=attempts+1,last_error=?,delivered_at=?,next_attempt_at=? WHERE id=?",
                (error, now if error is None else None, time.time() + retry_after, event_id))
