import asyncio
import copy
import io
import json
import logging
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

from assetwatch.cli import main
from assetwatch.config import Config, DEFAULTS, load_config
from assetwatch.database import Database
from assetwatch.logging_config import configure_logging
from assetwatch.normalization import in_scope, ipv4_addresses, normalize_hostname
from assetwatch.notifications import Notifier, format_event
from assetwatch.scheduler import Scheduler, daemon_lock


class DatabaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test", "example.org"], ["192.0.2.0/24"])

    def asset(self, hostname="example.test"):
        return next(asset for asset in self.db.assets(self.target["id"]) if asset["hostname"] == hostname)

    def kinds(self, hostname="example.test"):
        return [row[0] for row in self.db.connection.execute(
            "SELECT e.event_type FROM events e JOIN assets a ON a.id=e.asset_id WHERE a.hostname=? ORDER BY e.id", (hostname,))]

    def observe(self, status):
        asset = self.asset()
        observation = {"status_code": status, "url": "https://example.test"} if status else None
        self.db.observe_http(asset["id"], observation, asset["dns_version"])

    def test_normalized_dedup_sources_and_scope(self):
        names = [" API.Example.Test. ", "*.api.example.test", "api.example.test", "evil-example.test", "example.test.evil", "bad name.example.test"]
        self.assertEqual(self.db.ingest(self.target["id"], names, "subfinder"), 1)
        self.assertEqual(self.db.ingest(self.target["id"], names, "tlsx"), 0)
        asset = self.asset("api.example.test")
        self.assertEqual(asset["sources"], ["subfinder", "tlsx"])
        self.assertEqual(self.kinds("api.example.test"), ["fresh_asset"])
        other = self.db.add_target("two", ["other.test"], [])
        self.assertEqual(self.db.ingest(other["id"], ["api.example.test"], "tlsx"), 0)

    def test_full_http_lifecycle_and_repeated_real_transitions(self):
        asset = self.asset()
        self.observe(200)  # No A record: rejected even if a caller tries to submit it.
        self.assertFalse(self.asset()["http_available"])
        self.db.observe_dns(asset["id"], ["192.0.2.1"])
        for status in (None, 200, 200, 403, 200, 403, None, None, 200):
            self.observe(status)
        self.assertEqual(self.kinds(), ["fresh_asset", "fresh_subdomain", "http_service_appeared",
                                      "http_status_changed", "http_status_changed", "http_status_changed",
                                      "http_service_disappeared", "http_service_returned"])
        self.assertEqual(self.asset()["previous_http_status"], 403)
        self.assertTrue(self.asset()["http_ever_available"])
        self.assertIsNone(self.asset()["http_down_since"])
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.observe(200)
        self.assertEqual(len(self.kinds()), 8)

    def test_dns_loss_ip_changes_ipv4_and_stale_http_result(self):
        asset = self.asset()
        self.db.observe_dns(asset["id"], ["::1", "0.0.0.0", "224.0.0.1"])
        self.assertFalse(self.asset()["dns_resolved"])
        self.db.observe_dns(asset["id"], ["192.0.2.1"])
        self.observe(200)
        old = self.asset()
        self.db.observe_dns(asset["id"], ["192.0.2.2"])
        self.db.observe_http(asset["id"], {"status_code": 403, "url": "https://example.test"}, old["dns_version"])
        self.assertEqual(self.asset()["http_status"], 200)
        self.db.observe_dns(asset["id"], [])
        self.assertFalse(self.asset()["http_available"])
        self.assertIsNotNone(self.asset()["http_down_since"])
        self.db.observe_dns(asset["id"], ["192.0.2.2"])
        self.observe(200)
        self.assertEqual(self.kinds()[-4:], ["dns_unresolved", "http_service_disappeared", "fresh_subdomain", "http_service_returned"])

    def test_transaction_rolls_back_state_if_event_fails(self):
        with patch.object(self.db, "_event", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                self.db.observe_dns(self.asset()["id"], ["192.0.2.1"])
        self.assertFalse(self.asset()["dns_resolved"])
        self.assertEqual(self.kinds(), ["fresh_asset"])

    def test_removal_cascades_and_inflight_discovery_cannot_recreate_target(self):
        old_id = self.target["id"]
        self.db.finished(old_id, "tlsx", True)
        self.db.cache_dnsgen_candidates(old_id, ["generated.example.test"])
        self.db.finish_dnsgen_batch(old_id, self.asset()["id"])
        self.db.remove_target("one")
        self.assertEqual(self.db.ingest(old_id, ["api.example.test"], "tlsx"), 0)
        self.db.finished(old_id, "tlsx", True)
        self.assertEqual(self.db.cache_dnsgen_candidates(old_id, ["generated.example.test"]), 0)
        self.db.finish_dnsgen_batch(old_id, 100)
        for table in ("assets", "asset_sources", "events", "notifications", "watcher_runs", "dnsgen_candidates", "dnsgen_progress"):
            self.assertEqual(self.db.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
        self.assertNotEqual(self.db.add_target("one", ["example.test"], [])["id"], old_id)

    def test_inspection_filters_and_pagination(self):
        self.db.ingest(self.target["id"], [f"api{i}.example.test" for i in range(10)], "chaos")
        batches = list(self.db.asset_batches(self.target["id"], 3))
        ids = [asset["id"] for batch in batches for asset in batch]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 12)
        self.db.observe_dns(self.asset()["id"], ["192.0.2.1"])
        self.observe(403)
        self.assertEqual(len(list(self.db.assets(resolved=True, http=True, status=403))), 1)
        self.assertEqual(len(list(self.db.assets(resolved=False))), 11)

    def test_persistent_schedule_and_daemon_lock(self):
        self.assertTrue(self.db.due(self.target["id"], "dns_bruteforce", 604800))
        self.db.finished(self.target["id"], "dns_bruteforce", True)
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.assertFalse(self.db.due(self.target["id"], "dns_bruteforce", 604800))
        with daemon_lock(self.db.path):
            with self.assertRaises(ValueError):
                with daemon_lock(self.db.path):
                    self.fail("Second daemon acquired lock")
        with daemon_lock(self.db.path):
            pass

    def test_notification_retry_persistence_and_acknowledgement(self):
        self.config["telegram"].update(enabled=True, bot_token="secret-token", chat_id="123", send_delay=0.001)
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", side_effect=OSError("https://secret-token")):
            asyncio.run(notifier.flush())
        row = self.db.connection.execute("SELECT * FROM events ORDER BY id LIMIT 1").fetchone()
        self.assertIsNone(row["delivered_at"])
        self.assertNotIn("secret-token", row["last_error"])
        self.db.connection.execute("UPDATE events SET next_attempt_at=0")
        with patch("assetwatch.notifications.read_json", return_value={"ok": True, "result": {"message_id": 1}}) as send:
            asyncio.run(notifier.flush())
            self.assertEqual(send.call_count, 2)
            asyncio.run(notifier.flush())
            self.assertEqual(send.call_count, 2)
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM notifications").fetchone()[0], 3)
        self.assertEqual(self.db.pending_events(100), [])

    def test_telegram_disabled_preserves_backlog_and_source_title(self):
        self.db.ingest(self.target["id"], ["cert.example.test"], "tlsx")
        with patch("assetwatch.notifications.read_json") as send:
            asyncio.run(Notifier(self.config, self.db).flush())
            send.assert_not_called()
        event = self.db.pending_events(10)[-1]
        message = format_event(event)
        self.assertIn("Certificate-derived New Asset", message)
        self.assertIn("DNS: PENDING", message)

    def test_global_ip_mute_is_retained_without_blocking_bruteforce_and_outage_alerts(self):
        self.config["telegram"].update(enabled=True, bot_token="test-token", chat_id="123",
                                       batch_size=2, send_delay=0.001, notify_dns_ip_changes=False)
        self.config["cdn"]["enabled"] = False
        asset = self.asset()
        self.db.observe_dns(asset["id"], ["192.0.2.1"])
        self.observe(200)
        for event in self.db.pending_events(100):
            self.db.notification_result(event["id"])
        for number in range(2, 6):
            self.db.observe_dns(asset["id"], [f"192.0.2.{number}"])
        self.assertEqual(self.asset()["ip_addresses"], ["192.0.2.5"])
        self.assertEqual(self.kinds().count("dns_ip_changed"), 4)
        self.db.ingest(self.target["id"], ["new.example.test"], "dns_bruteforce")
        self.db.observe_dns(asset["id"], [])
        # Exercise a pre-existing outbox on restart, including more IP events than a batch.
        self.db.close()
        self.db = Database(self.path / "assets.db")
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            self.assertTrue(asyncio.run(notifier.flush()))
            self.assertFalse(asyncio.run(notifier.flush()))
            self.assertEqual(send.call_count, 3)
            messages = [call.args[2]["text"] for call in send.call_args_list]
            self.assertIn("DNS-Brute-Force New Asset", messages[0])
            self.assertIn("DNS Unresolved", messages[1])
            self.assertIn("HTTP Service Disappeared", messages[2])
            self.assertEqual({row["event_type"] for row in self.db.pending_events(100)}, {"dns_ip_changed"})
            self.assertFalse(asyncio.run(notifier.flush()))
            self.assertEqual(send.call_count, 3)
            self.config["telegram"]["notify_dns_ip_changes"] = True
            self.assertTrue(asyncio.run(notifier.flush()))
            self.assertTrue(asyncio.run(notifier.flush()))
            self.assertFalse(asyncio.run(notifier.flush()))
            self.assertEqual(send.call_count, 7)
        self.assertEqual(self.db.pending_events(100), [])


class NormalizationTests(unittest.TestCase):
    def test_hostnames(self):
        self.assertEqual(normalize_hostname(" *.API.Example.COM. "), "api.example.com")
        self.assertEqual(normalize_hostname("bücher.example"), "xn--bcher-kva.example")
        for invalid in (None, "https://example.com", "a.*.example.com", "a..example.com", "-a.example.com", "a_.example.com", "127.0.0.1", "example.com:443", "a b.example.com"):
            self.assertIsNone(normalize_hostname(invalid), invalid)
        self.assertFalse(in_scope("evil-example.com", ["example.com"]))
        self.assertTrue(in_scope("api.example.com", ["example.com"]))
        self.assertEqual(ipv4_addresses(["192.0.2.1", "192.0.2.1", "::1", "0.0.0.0", "invalid"]), ["192.0.2.1"])


class ConfigAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.filename = self.path / "config.yaml"
        self.filename.write_text("{}\n")

    def test_config_paths_environment_and_rejection(self):
        self.filename.write_text("telegram:\n  enabled: true\n  bot_token: '${TEST_TOKEN}'\n  chat_id: 123\ntools:\n  httpx: ./bin/httpx\n")
        with patch.dict(os.environ, {"TEST_TOKEN": "test-secret"}):
            config = load_config(self.filename)
        self.assertEqual(config["telegram"]["bot_token"], "test-secret")
        self.assertEqual(config["telegram"]["chat_id"], "123")
        self.assertEqual(config["tools"]["httpx"], str((self.path / "bin/httpx").resolve()))
        self.assertEqual(config.path(config["database"]["path"]), (self.path / "data/assets.db").resolve())
        for document in ({"intervals": {"tlsx": 0}}, {"runtime": {"threads": True}},
                         {"dns_bruteforce": {"shuffledns": {"threads": -1}}},
                         {"dns_bruteforce": {"dynamic": {"batch_size": 0}}},
                         {"dns_bruteforce": {"dynamic": {"batch_size": 1.5}}},
                         {"runtime": {"progress_interval": 0}}, {"chaos": {"api_key": 123}},
                         {"telegram": {"notify_dns_ip_changes": "false"}},
                         {"cdn": {"enabled": "true"}}, {"cdn": {"refresh_interval": 0}},
                         {"cdn": {"retry_interval": -1}}, {"cdn": {"max_age": 1}},
                         {"cdn": {"akamai_url": "file:///tmp/ips"}},
                         {"telegram": {"enabled": "false"}}, {"intervals": {"typo": 2}}):
            self.filename.write_text(yaml.safe_dump(document))
            with self.assertRaises(ValueError):
                load_config(self.filename)

    def test_chaos_key_from_yaml_literal_or_environment(self):
        for value in ("test-chaos-key", "${TEST_CHAOS_KEY}"):
            self.filename.write_text(yaml.safe_dump({"chaos": {"api_key": value}}))
            with patch.dict(os.environ, {"TEST_CHAOS_KEY": "test-chaos-key"}):
                self.assertEqual(load_config(self.filename)["chaos"]["api_key"], "test-chaos-key")

    def test_yaml_chaos_key_is_redacted_by_terminal_and_file_handlers(self):
        config = Config(copy.deepcopy(DEFAULTS), self.path)
        config["chaos"]["api_key"] = "yaml-test-secret"
        with patch("assetwatch.logging_config.logging.basicConfig") as setup:
            configure_logging(config)
        for handler in setup.call_args.kwargs["handlers"]:
            try:
                record = logging.LogRecord("tool", logging.WARNING, "", 0,
                                           "stderr: %s", ("yaml-test-secret",), None)
                handler.filter(record)
                self.assertNotIn("yaml-test-secret", record.getMessage())
                self.assertIn("[REDACTED]", record.getMessage())
            finally:
                handler.close()

    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = main(["--config", str(self.filename), *args])
        return result, out.getvalue(), err.getvalue()

    def test_cli_target_management_json_raw_dedup_and_errors(self):
        self.assertEqual(self.call("target", "add", "one",
                                   "--domain", " example.test, example.org ", "--domain", "example.test",
                                   "--cidr", "192.0.2.0/24, 2001:db8::/32",
                                   "--cidr", "198.51.100.0/24")[0], 0)
        target = json.loads(self.call("target", "show", "one", "--format", "json")[1])[0]
        self.assertEqual(target["domains"], ["example.org", "example.test"])
        self.assertEqual(target["cidrs"], ["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"])
        for flag, value in (("--domain", "example.test,"), ("--cidr", "192.0.2.0/24,,198.51.100.0/24")):
            with self.assertRaises(SystemExit) as error:
                self.call("target", "add", "invalid", "--domain", "example.test", flag, value)
            self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.call("target", "add", "two", "--domain", "example.test")[0], 0)
        code, out, _ = self.call("domains", "--all")
        self.assertEqual((code, out), (0, "example.org\nexample.test\n"))
        self.assertEqual(len(json.loads(self.call("assets", "--all", "--format", "json")[1])), 3)
        self.assertEqual(len(json.loads(self.call("targets", "--format", "json")[1])), 2)
        self.assertEqual(self.call("assets", "--target", "missing")[0], 2)
        self.assertEqual(self.call("target", "remove", "one")[0], 2)
        self.assertEqual(self.call("target", "remove", "one", "--yes")[0], 0)
        self.assertEqual(self.call("domains", "--all")[1], "example.test\n")


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_notification_batches_drain_without_poll_delay(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(copy.deepcopy(DEFAULTS), Path(directory))
            config["telegram"].update(enabled=True, bot_token="test-token", chat_id="123",
                                       batch_size=1, send_delay=0.001)
            config["intervals"]["monitoring"] = 12000
            db = Database(Path(directory) / "assets.db")
            self.addCleanup(db.close)
            target = db.add_target("one", ["example.test"], [])
            db.ingest(target["id"], ["new.example.test"], "dns_bruteforce")
            scheduler = Scheduler(config, db)
            with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
                task = asyncio.create_task(scheduler.monitoring())
                try:
                    async with asyncio.timeout(2):
                        while db.pending_events(10):
                            await asyncio.sleep(0.005)
                    self.assertEqual(send.call_count, 2)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    async def test_recurrence_failure_isolation_and_no_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(copy.deepcopy(DEFAULTS), Path(directory))
            config["program_watch"]["enabled"] = False
            config["runtime"]["poll_interval"] = 0.005
            config.values["intervals"] = {name: 0.015 for name in config["intervals"]}
            db = Database(Path(directory) / "test.db")
            self.addCleanup(db.close)
            db.add_target("one", ["one.test"], [])
            db.add_target("two", ["two.test"], [])
            counts, active, overlaps = {}, set(), []

            class FakeWatchers:
                def __getattr__(self, name):
                    async def run(target):
                        key = name, target["name"]
                        if key in active:
                            overlaps.append((key, "duplicate execution"))
                        if active and (name == "dns_bruteforce" or any(item[0] == "dns_bruteforce" for item in active)):
                            overlaps.append((key, set(active)))
                        active.add(key)
                        try:
                            counts[key] = counts.get(key, 0) + 1
                            if name == "tlsx" and target["name"] == "one":
                                raise RuntimeError("broken certificate tool")
                            if name == "dns_bruteforce" and target["name"] == "one" and counts[key] == 1:
                                raise RuntimeError("broken brute-force tool")
                            await asyncio.sleep(0.03 if name == "dns_bruteforce" else 0.001)
                            return True
                        finally:
                            active.remove(key)
                    return run

            class FakeNotifier:
                async def flush(self):
                    pass

            stop = asyncio.Event()
            task = asyncio.create_task(Scheduler(config, db, FakeWatchers(), FakeNotifier()).run(stop))

            async def wait_for_cycles():
                while not all(counts.get(key, 0) >= 3 for key in
                              (("dns_resolution", "one"), ("tlsx", "two"), ("http_probe", "two"))):
                    await asyncio.sleep(0.005)

            try:
                await asyncio.wait_for(wait_for_cycles(), 2)
            finally:
                stop.set()
                await asyncio.wait_for(task, 1)
            self.assertGreater(counts[("dns_resolution", "one")], 2)
            self.assertGreater(counts[("tlsx", "two")], 2)
            self.assertGreater(counts[("http_probe", "two")], 2)
            self.assertEqual(active, set())
            self.assertEqual(overlaps, [])
