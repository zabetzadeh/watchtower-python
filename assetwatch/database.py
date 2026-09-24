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
CREATE TABLE IF NOT EXISTS watcher_runs (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    watcher TEXT NOT NULL, finished_at REAL NOT NULL, success INTEGER NOT NULL,
    PRIMARY KEY(target_id, watcher)
);
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
    for field in ("ip_addresses", "http_metadata"):
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
        normalized = [normalize_hostname(domain) for domain in domains]
        if not normalized or not all(normalized):
            raise ValueError("Provide at least one valid root domain (without a URL or port)")
        networks = sorted({str(ipaddress.ip_network(cidr, strict=True)) for cidr in cidrs})
        now = utcnow()
        with self.transaction():
            cursor = self.connection.execute("INSERT INTO targets(name,created_at) VALUES (?,?)", (name, now))
            target_id = cursor.lastrowid
            self.connection.executemany("INSERT INTO target_domains VALUES (?,?)",
                                        [(target_id, domain) for domain in sorted(set(normalized))])
            self.connection.executemany("INSERT INTO target_cidrs VALUES (?,?)",
                                        [(target_id, cidr) for cidr in networks])
        target = self.target(name)
        self.ingest(target_id, target["domains"], "target")
        return target

    def remove_target(self, name: str):
        with self.transaction():
            if not self.connection.execute("DELETE FROM targets WHERE name=?", (name,)).rowcount:
                raise ValueError(f"Unknown target: {name}")

    def _event(self, asset_id: int, kind: str, before: dict, after: dict):
        self.connection.execute(
            "INSERT INTO events(asset_id,event_type,previous_state,new_state,created_at) VALUES (?,?,?,?,?)",
            (asset_id, kind, json.dumps(before), json.dumps(after), utcnow()))
        LOG.info("event=%s target_id=%s host=%s", kind, after.get("target_id"), after.get("hostname"))

    def ingest(self, target_id: int, hostnames, source: str) -> int:
        new = 0
        with self.transaction():
            domains = [row[0] for row in self.connection.execute(
                "SELECT domain FROM target_domains WHERE target_id=?", (target_id,))]
            if not domains:  # A target may have been removed while its tool was running.
                return 0
            now = utcnow()
            for raw in hostnames:
                hostname = normalize_hostname(raw)
                if not hostname or not in_scope(hostname, domains):
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
                    self._event(row["id"], "fresh_asset", {}, {**decode_asset(row), "source": source})
                    new += 1
        return new

    def assets(self, target_id=None, resolved=None, http=None, status=None):
        clauses, params = [], []
        for column, value in (("target_id", target_id), ("dns_resolved", resolved),
                              ("http_available", http), ("http_status", status)):
            if value is not None:
                clauses.append(f"a.{column}=?")
                params.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = self.connection.execute(
            "SELECT a.*,t.name AS target FROM assets a JOIN targets t ON t.id=a.target_id"
            + where + " ORDER BY a.hostname,t.name", params)
        for row in cursor:
            asset = decode_asset(row)
            asset["sources"] = [r[0] for r in self.connection.execute(
                "SELECT source FROM asset_sources WHERE asset_id=? ORDER BY source", (row["id"],))]
            yield asset

    def asset_batches(self, target_id: int, size: int, resolved_only=False, after_id=0):
        maximum = self.connection.execute(
            "SELECT COALESCE(MAX(id),0) FROM assets WHERE target_id=?", (target_id,)).fetchone()[0]
        last = after_id
        while last < maximum:
            rows = self.connection.execute(
                "SELECT * FROM assets WHERE target_id=? AND id>? AND id<=?"
                + (" AND dns_resolved=1" if resolved_only else "") + " ORDER BY id LIMIT ?",
                (target_id, last, maximum, size)).fetchall()
            if not rows:
                break
            last = rows[-1]["id"]
            yield [decode_asset(row) for row in rows]

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

    def observe_dns(self, asset_id: int, addresses: list[str]):
        addresses = ipv4_addresses(addresses)
        with self.transaction():
            row = self.connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None:
                return
            before = decode_asset(row)
            now = utcnow()
            changed = before["ip_addresses"] != addresses
            after = {**before, "dns_resolved": bool(addresses), "ip_addresses": addresses,
                     "dns_checked_at": now, "dns_version": before["dns_version"] + int(changed)}
            kinds = dns_events(before, addresses)
            self.connection.execute(
                "UPDATE assets SET dns_resolved=?,ip_addresses=?,dns_checked_at=?,dns_version=dns_version+? WHERE id=?",
                (bool(addresses), json.dumps(addresses), now, int(changed), asset_id))
            if not addresses and before["http_available"]:
                after.update(http_available=False, http_status=None, http_down_since=now,
                             previous_http_status=before["http_status"], http_metadata={"reason": "no_a_record"})
                self.connection.execute(
                    "UPDATE assets SET http_available=0,previous_http_status=http_status,http_status=NULL,"
                    "http_down_since=?,http_metadata=? WHERE id=?",
                    (now, json.dumps(after["http_metadata"]), asset_id))
                kinds.append("http_service_disappeared")
            for kind in kinds:
                self._event(asset_id, kind, before, after)

    def observe_http(self, asset_id: int, observation: dict | None, dns_version: int):
        with self.transaction():
            row = self.connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None or not row["dns_resolved"] or row["dns_version"] != dns_version:
                return  # Discard results if DNS changed while HTTPX was in flight.
            before = decode_asset(row)
            status = observation["status_code"] if observation else None
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("Invalid HTTP status code")
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
                     "http_url": observation.get("url") if observation else before["http_url"],
                     "http_metadata": observation or {"reason": "probe_unavailable"}}
            self.connection.execute(
                "UPDATE assets SET http_available=?,http_status=?,previous_http_status=?,http_ever_available=?,"
                "http_checked_at=?,http_down_since=?,http_url=?,http_metadata=? WHERE id=?",
                (after["http_available"], status, previous_status, after["http_ever_available"], now,
                 down_since, after["http_url"], json.dumps(after["http_metadata"]), asset_id))
            for kind in http_events(before, status):
                self._event(asset_id, kind, before, after)

    def due(self, target_id: int, watcher: str, interval: float) -> bool:
        row = self.connection.execute(
            "SELECT finished_at FROM watcher_runs WHERE target_id=? AND watcher=?", (target_id, watcher)).fetchone()
        return row is None or row[0] + interval <= time.time()

    def finished(self, target_id: int, watcher: str, success: bool):
        self.connection.execute(
            "INSERT INTO watcher_runs SELECT id,?,?,? FROM targets WHERE id=? "
            "ON CONFLICT(target_id,watcher) DO UPDATE SET finished_at=excluded.finished_at,success=excluded.success",
            (watcher, time.time(), success, target_id))

    def pending_events(self, limit: int):
        rows = self.connection.execute(
            "SELECT e.*,a.hostname,t.name AS target FROM events e JOIN assets a ON a.id=e.asset_id "
            "JOIN targets t ON t.id=a.target_id WHERE e.delivered_at IS NULL AND e.next_attempt_at<=? "
            "ORDER BY e.id LIMIT ?", (time.time(), limit)).fetchall()
        return [dict(row) for row in rows]

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
