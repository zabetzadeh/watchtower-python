import asyncio
import copy
import io
import json
import tempfile
import time
import unittest
import urllib.error
from contextlib import asynccontextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import AsyncMock, patch

from assetwatch.bot import Bot
from assetwatch.cli import main
from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.notifications import format_event
from assetwatch.reports import health_report, health_text, log_tail
from assetwatch.scheduler import Scheduler
from assetwatch.tools import ToolError, Tools
from assetwatch.watchers import Watchers


class Fixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test"], [])

    def asset(self):
        return next(self.db.assets(self.target["id"]))

    def reopen(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")


class StateTests(Fixture, unittest.TestCase):
    def test_ip_pool_is_durable_and_order_and_known_subsets_do_not_alert(self):
        asset_id = self.asset()["id"]
        self.db.observe_dns(asset_id, ["192.0.2.2", "192.0.2.1", "192.0.2.2"])
        initial = self.asset()
        self.assertEqual(initial["ip_addresses"], ["192.0.2.1", "192.0.2.2"])
        self.db.observe_dns(asset_id, ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(self.asset()["dns_version"], initial["dns_version"])
        for ips in (["192.0.2.2"], ["192.0.2.1"], ["192.0.2.2", "192.0.2.1"]):
            self.reopen()
            self.db.observe_dns(asset_id, ips)
        self.assertEqual(self.db.recent_events(kind="dns_ip_changed"), [])
        self.db.observe_dns(asset_id, ["192.0.2.3", "192.0.2.1"])
        self.assertEqual(len(self.db.recent_events(kind="dns_ip_changed")), 1)
        self.assertEqual(self.asset()["known_ip_addresses"], ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.db.observe_dns(asset_id, [])
        self.db.observe_dns(asset_id, ["192.0.2.2"])
        self.assertEqual(self.asset()["ip_addresses"], ["192.0.2.2"])
        self.assertEqual(len(self.db.recent_events(kind="dns_ip_changed")), 1)
        self.assertEqual(len(self.db.recent_events(kind="dns_unresolved")), 1)

    def test_existing_database_recovers_ip_history_and_cname_baseline(self):
        asset_id = self.asset()["id"]
        self.db.observe_dns(asset_id, ["192.0.2.1"])
        self.db.observe_dns(asset_id, ["192.0.2.2"])
        self.db.observe_dns(asset_id, [])
        count = len(self.db.recent_events())
        for column in ("known_ip_addresses", "cname_records", "cname_checked_at"):
            self.db.connection.execute(f"ALTER TABLE assets DROP COLUMN {column}")
        self.reopen()
        self.assertEqual(self.asset()["known_ip_addresses"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(self.asset()["ip_addresses"], [])
        self.assertIsNone(self.asset()["cname_checked_at"])
        self.assertEqual(len(self.db.recent_events()), count)
        self.reopen()
        self.assertEqual(self.asset()["known_ip_addresses"], ["192.0.2.1", "192.0.2.2"])

    def test_upgrade_suppresses_old_known_rotation_backlog_but_keeps_new_ip_alert(self):
        asset_id = self.asset()["id"]
        self.db.observe_dns(asset_id, ["192.0.2.1"])
        self.db.observe_dns(asset_id, ["192.0.2.2"])
        before = self.asset()
        after = {**before, "ip_addresses": ["192.0.2.1"]}
        # Simulate the previous version emitting another alert on the A -> B -> A rotation.
        self.db._event(asset_id, "dns_ip_changed", before, after)
        for column in ("known_ip_addresses", "cname_records", "cname_checked_at"):
            self.db.connection.execute(f"ALTER TABLE assets DROP COLUMN {column}")
        self.reopen()
        pending = [e for e in self.db.pending_events(100) if e["event_type"] == "dns_ip_changed"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0]["new_state"])["ip_addresses"], ["192.0.2.2"])
        self.assertEqual(self.db.connection.execute("SELECT reason FROM notification_suppressions").fetchone()[0], "known_ip_rotation")
        self.assertEqual(len(self.db.recent_events(kind="dns_ip_changed")), 2)

    def test_cname_baseline_changes_removal_reappearance_and_atomicity(self):
        asset_id = self.asset()["id"]
        self.db.observe_cnames(asset_id, ["A.vendor.test.", "b.vendor.test"])
        self.db.observe_cnames(asset_id, ["b.vendor.test", "a.vendor.test", "a.vendor.test"])
        self.assertEqual(self.db.recent_events(kind="dns_cname_changed"), [])
        self.reopen()
        for records in (["c.vendor.test"], [], ["c.vendor.test"]):
            self.db.observe_cnames(asset_id, records)
        events = self.db.recent_events(kind="dns_cname_changed")
        self.assertEqual(len(events), 3)
        self.assertIn("*Previous:* `(none)`", format_event(events[0]))
        self.assertIn("*Current:* `c.vendor.test`", format_event(events[0]))
        self.assertFalse(self.asset()["dns_resolved"])
        self.assertEqual(len(self.db.cname_assets(self.target["id"])), 1)
        before = self.asset()
        with patch.object(self.db, "_event", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                self.db.observe_cnames(asset_id, [])
        self.assertEqual(self.asset(), before)

    def test_failed_weekly_run_retry_and_manual_request_survive_restart(self):
        target_id = self.target["id"]
        with patch("assetwatch.database.time.time", return_value=1000):
            self.db.finished(target_id, "dns_bruteforce", False)
        self.assertEqual(self.db.next_run_at(target_id, "dns_bruteforce", 604800, 300), 1300)
        with patch("assetwatch.database.time.time", return_value=1300):
            self.assertTrue(self.db.due(target_id, "dns_bruteforce", 604800, 300))
        self.db.finished(target_id, "dns_bruteforce", True)
        self.assertFalse(self.db.due(target_id, "dns_bruteforce", 604800, 300))
        self.db.request_run(target_id, "dns_bruteforce")
        self.reopen()
        self.assertTrue(self.db.due(target_id, "dns_bruteforce", 604800, 300))
        self.db.consume_run_request(target_id, "dns_bruteforce")
        self.assertFalse(self.db.due(target_id, "dns_bruteforce", 604800, 300))

    def test_health_persisted_states_counts_and_stale_heartbeat(self):
        target_id = self.target["id"]
        self.db.watcher_state(target_id, "dns_bruteforce", "queued", "Waiting for scans")
        self.db.set_runtime("daemon", {"state": "running", "heartbeat_at": time.time()})
        self.assertIn("dns_bruteforce: queued", health_text(health_report(self.config, self.db)))
        self.db.watcher_state(target_id, "dns_bruteforce", "running", "Static")
        self.db.watcher_progress(target_id, "dns_bruteforce", "Partial result", results=10, new_assets=2, error="Missing executable")
        self.db.finished(target_id, "dns_bruteforce", False)
        self.reopen()
        report = health_report(self.config, self.db)
        row = next(row for row in report["modules"] if row["watcher"] == "dns_bruteforce")
        self.assertEqual((row["state"], row["results"], row["new_assets"]), ("failed", 10, 2))
        self.assertEqual(row["last_error"], "Missing executable")
        self.assertTrue(any("resolver file" in note for note in row["prerequisites"]))
        self.db.watcher_state(target_id, "tlsx", "queued")
        self.db.set_runtime("daemon", {"state": "running", "heartbeat_at": time.time() - 100})
        report = health_report(self.config, self.db)
        self.assertEqual(report["daemon"], "stopped or stale")
        self.assertEqual(next(row for row in report["modules"] if row["watcher"] == "tlsx")["state"], "interrupted/stale")

    def test_cli_reports_filters_queue_and_redacted_log_tail(self):
        self.config["telegram"]["bot_token"] = "fixture-secret"
        log = self.config.path(self.config["logging"]["file"])
        log.parent.mkdir()
        log.write_text("INFO target=one watcher=dns_bruteforce error=fixture-secret\nINFO target=two watcher=tlsx ok\n")
        self.assertNotIn("fixture-secret", log_tail(self.config, "dns_bruteforce", "one"))
        self.db.ingest(self.target["id"], ["ptr.example.test"], "ptr")
        self.db.observe_cnames(self.asset()["id"], ["a.vendor.test"])
        self.db.observe_cnames(self.asset()["id"], ["b.vendor.test"])
        with patch("assetwatch.cli.load_config", return_value=self.config), patch("assetwatch.cli.configure_logging"):
            # Point the CLI at the same temporary database.
            self.config["database"]["path"] = "assets.db"
            for args in (("health", "--format", "json"), ("changes", "--type", "dns_cname_changed"),
                         ("cnames", "--target", "one"), ("domains", "--all", "--source", "ptr"),
                         ("rerun", "tlsx", "--target", "one"), ("logs", "--module", "dns_bruteforce")):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(list(args)), 0)
                self.assertTrue(output.getvalue())
        self.assertTrue(self.db.due(self.target["id"], "tlsx", 3600))


class AsyncTests(Fixture, unittest.IsolatedAsyncioTestCase):
    def output(self, tools, rows):
        path = self.path / "output"
        path.write_text("\n".join(json.dumps(row) for row in rows))

        @asynccontextmanager
        async def run(*args, **kwargs):
            yield path

        return patch.object(tools.runner, "run", run)

    async def test_wrappers_merge_all_ips_and_preserve_unknown_cnames(self):
        tools = Tools(self.config)
        with self.output(tools, [{"host": "example.test", "status_code": "NOERROR", "a": ["192.0.2.1"]},
                                {"host": "EXAMPLE.TEST.", "status_code": "NOERROR", "a": ["192.0.2.2", "192.0.2.1"]}]):
            self.assertEqual(await tools.dns(["example.test"]), {"example.test": ["192.0.2.1", "192.0.2.2"]})
        with self.output(tools, [{"host": "example.test", "status_code": "NXDOMAIN", "cname": ["DANGLING.vendor.test."]}]):
            self.assertEqual(await tools.cnames(["example.test"]), {"example.test": ["dangling.vendor.test"]})
        for row in ({"host": "example.test", "status_code": "NOERROR", "cname": "bad"},
                    {"host": "example.test", "status_code": "NOERROR", "cname": ["bad hostname"]}):
            with self.output(tools, [row]):
                with self.assertRaises(ToolError):
                    await tools.cnames(["example.test"])
        self.db.observe_cnames(self.asset()["id"], ["keep.vendor.test"])
        before = self.asset()
        for rows in ([{"host": "example.test", "status_code": "SERVFAIL"}], []):
            with self.output(tools, rows):
                self.assertFalse(await Watchers(self.config, self.db, tools).dns_resolution(self.target))
            self.assertEqual(self.asset(), before)

    async def test_ptr_scoped_deduplication_and_normal_monitoring(self):
        tools = Tools(self.config)
        watchers = Watchers(self.config, self.db, tools)
        self.db.observe_dns(self.asset()["id"], ["192.0.2.1", "192.0.2.2"])
        self.db.ingest(self.target["id"], ["other.example.test"], "subfinder")
        other = next(a for a in self.db.assets() if a["hostname"] == "other.example.test")
        self.db.observe_dns(other["id"], ["192.0.2.1"])
        calls = []
        path = self.path / "ptr.txt"
        path.write_text(" PTR.EXAMPLE.TEST.\nptr.example.test\nneighbor.invalid\nother.example.test\n")

        @asynccontextmanager
        async def run(name, args, inputs, **kwargs):
            calls.append((name, args, inputs.read_text().splitlines()))
            yield path

        with patch.object(tools.runner, "run", run):
            self.assertTrue(await watchers.ptr_discovery(self.target))
            self.assertTrue(await watchers.ptr_discovery(self.target))
        self.assertEqual(calls[0][2], ["192.0.2.1", "192.0.2.2"])
        for flag in ("-ptr", "-resp-only", "-t", "-stream"):
            self.assertIn(flag, calls[0][1])
        found = list(self.db.assets(source="ptr"))
        self.assertEqual(len(found), 2)
        self.assertEqual(len([e for e in self.db.recent_events(kind="fresh_asset") if e["hostname"] == "ptr.example.test"]), 1)
        with patch.object(tools, "dns", AsyncMock(side_effect=lambda names: {n: ["192.0.2.3"] for n in names})), \
             patch.object(tools, "cnames", AsyncMock(side_effect=lambda names: {n: [] for n in names})), \
             patch.object(tools, "http", AsyncMock(side_effect=lambda names: {n: {"status_code": 200, "url": "https://" + n} for n in names})):
            await watchers.dns_resolution(self.target)
            await watchers.http_probe(self.target)
        self.assertTrue(all(a["http_available"] for a in self.db.assets(source="ptr")))
        second = self.db.add_target("two", ["other.test"], ["192.0.2.0/24"])
        with patch.object(tools.runner, "run", run):
            await watchers.ptr_discovery(second)
        self.assertEqual(list(self.db.assets(second["id"], source="ptr")), [])
        self.assertEqual(calls[-1][2], ["192.0.2.0/24"])

    async def test_missing_bruteforce_inputs_fail_before_dnsgen_and_tlsx_skip_visible(self):
        watchers = Watchers(self.config, self.db)
        self.db.watcher_state(self.target["id"], "dns_bruteforce", "queued")
        with patch.object(watchers, "dynamic_bruteforce", AsyncMock()) as dynamic:
            self.assertFalse(await watchers.dns_bruteforce(self.target))
            dynamic.assert_not_called()
        row = self.db.connection.execute("SELECT * FROM watcher_status").fetchone()
        self.assertIn("resolver file", row["last_error"])
        self.db.watcher_state(self.target["id"], "tlsx", "queued")
        self.assertTrue(await watchers.tlsx(self.target))
        self.db.finished(self.target["id"], "tlsx", True)
        row = self.db.connection.execute("SELECT * FROM watcher_status WHERE watcher='tlsx'").fetchone()
        self.assertEqual(row["state"], "skipped")
        self.assertIn("No CIDRs", row["detail"])

    async def test_bot_only_replies_to_authorized_chat_and_persists_offset(self):
        self.config["telegram"].update(chat_id="123", bot_token="fixture-secret", send_delay=0.001)
        bot = Bot(self.config, self.db)
        updates = [{"update_id": 1, "message": {"chat": {"id": 999}, "text": "/health"}},
                   {"update_id": 2, "message": {"chat": {"id": 123}, "text": "/start"}},
                   {"update_id": 3, "message": {"chat": {"id": 123}, "text": "/health missing"}},
                   {"update_id": 4, "message": {"chat": {"id": 123}, "text": "/new@another_bot"}}]
        calls = []

        async def api(method, payload):
            calls.append((method, payload))
            return updates if method == "getUpdates" else {"message_id": 1}

        bot.username = "our_bot"
        with patch.object(bot, "api", api):
            await bot.poll()
        sends = [payload for method, payload in calls if method == "sendMessage"]
        self.assertEqual(len(sends), 2)
        self.assertTrue(all(p["chat_id"] == "123" for p in sends))
        self.assertIn("keyboard", sends[0]["reply_markup"])
        self.assertIn("Unknown target", sends[1]["text"])
        self.reopen()
        bot = Bot(self.config, self.db)
        calls.clear()
        with patch.object(bot, "api", api):
            await bot.poll()
        self.assertEqual([name for name, _ in calls], ["getUpdates"])
        self.assertEqual(calls[0][1]["offset"], 5)

    async def test_bot_pagination_includes_all_cnames_and_new_asset_sources(self):
        self.db.ingest(self.target["id"], [f"h{i:02d}.example.test" for i in range(12)], "ptr")
        for asset in self.db.assets():
            self.db.observe_cnames(asset["id"], ["vendor.test"])
        bot = Bot(self.config, self.db)
        first = bot.response("/cnames one")
        second = bot.response("/cnames one 2")
        self.assertEqual(first.count("CNAME:"), 10)
        self.assertEqual(second.count("CNAME:"), 3)
        self.assertIn("Next: /cnames one 2", first)
        self.assertIn("ptr", bot.response("/new one"))
        self.assertIn("fresh_asset", bot.response("/updates one"))
        self.assertNotIn("fixture-secret", bot.response("/health one"))
        with self.assertRaises(ValueError):
            bot.response("/changes one 0")

    async def test_bot_api_errors_do_not_leak_tokens_and_honor_retry_delay(self):
        self.config["telegram"].update(enabled=True, chat_id="123", bot_token="fixture-secret")
        bot = Bot(self.config, self.db)
        error = urllib.error.HTTPError("https://api.telegram.org/botfixture-secret/getMe", 429,
                                       "Too many requests", {}, io.BytesIO(b'{"parameters":{"retry_after":15}}'))
        with patch("assetwatch.bot.read_json", side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                await bot.api("getMe", {})
        self.assertEqual(bot.retry_after, 15)
        failed = asyncio.Event()

        async def fail(method, payload):
            failed.set()
            raise OSError("fixture-secret")

        with patch.object(bot, "api", fail):
            task = asyncio.create_task(bot.run())
            try:
                await asyncio.wait_for(failed.wait(), 1)
                state = self.db.runtime("bot")
                self.assertEqual(state["state"], "failed")
                self.assertNotIn("fixture-secret", state["error"])
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_bot_splits_large_replies_without_losing_text(self):
        self.config["telegram"].update(chat_id="123", send_delay=0.001)
        bot = Bot(self.config, self.db)
        expected = "🆕" * 5000
        chunks = []

        async def api(method, payload):
            if method == "getUpdates":
                return [{"update_id": 1, "message": {"chat": {"id": 123}, "text": "/health"}}]
            chunks.append(payload["text"])
            return {"message_id": 1}

        with patch.object(bot, "api", api), patch.object(bot, "response", return_value=expected):
            await bot.poll()
        self.assertEqual("".join(chunks), expected)
        self.assertTrue(all(len(chunk.encode("utf-16-le")) // 2 <= 3800 for chunk in chunks))

    async def test_scheduler_failed_run_retries_without_weekly_delay_and_records_cancellation(self):
        self.config["runtime"].update(poll_interval=0.005, failure_retry_interval=0.01)
        started = asyncio.Event()

        class Failing:
            calls = 0

            async def dns_bruteforce(self, target):
                self.calls += 1
                if self.calls == 1:
                    raise ToolError("fixture failure")
                started.set()
                await asyncio.Event().wait()

        watcher = Failing()
        scheduler = Scheduler(self.config, self.db, watcher)
        task = asyncio.create_task(scheduler.watch("dns_bruteforce"))
        try:
            await asyncio.wait_for(started.wait(), 1)
            self.assertEqual(watcher.calls, 2)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        row = self.db.connection.execute("SELECT * FROM watcher_status").fetchone()
        self.assertEqual(row["state"], "interrupted")

    async def test_bot_all_button_commands_and_plain_text(self):
        # Ingest assets with various sources and states
        self.db.ingest(self.target["id"], ["live.example.test"], "dns_bruteforce")
        self.db.ingest(self.target["id"], ["passive.example.test"], "subfinder")
        self.db.ingest(self.target["id"], ["ptr.example.test"], "ptr")
        for asset in list(self.db.assets()):
            if asset["hostname"] == "live.example.test":
                self.db.observe_dns(asset["id"], ["192.0.2.1"])
                refreshed = [a for a in self.db.assets() if a["id"] == asset["id"]][0]
                self.db.observe_http(asset["id"], {"status_code": 200, "url": "https://live.example.test"}, refreshed["dns_version"])
            elif asset["hostname"] == "passive.example.test":
                self.db.observe_dns(asset["id"], ["192.0.2.2"])
            self.db.observe_cnames(asset["id"], ["alias.vendor.test"])

        bot = Bot(self.config, self.db)
        # Test plain button labels
        self.assertIn("CNAME:", bot.response("CNAME's"))
        self.assertIn("live.example.test", bot.response("Live's"))
        self.assertIn("live.example.test", bot.response("Resolved"))
        self.assertIn("live.example.test", bot.response("Brute force result"))
        self.assertIn("passive.example.test", bot.response("Passive"))
        self.assertIn("ptr.example.test", bot.response("PTR's"))
        self.assertIn("Assetwatch", bot.response("Help"))
        self.assertIn("example.test", bot.response("Targets"))
        self.assertIn("Daemon:", bot.response("Health"))
        self.assertIn("fresh_asset", bot.response("Changes"))
        self.assertIn("fresh_asset", bot.response("New"))

        # Test prompt responses for action buttons without args
        self.assertIn("➕ Add Target", bot.response("Add target"))
        self.assertIn("🔄 Update Target", bot.response("Update target"))
        self.assertIn("🗑️ Remove Target", bot.response("Remove target"))

    async def test_bot_target_management_add_update_remove(self):
        bot = Bot(self.config, self.db)
        # Add target with domain and CIDR
        res = bot.response("/add_target testcorp corp.test 10.0.0.0/24")
        self.assertIn("Target Added: testcorp", res)
        self.assertIn("corp.test", res)
        self.assertIn("10.0.0.0/24", res)

        # Add target with CIDR only
        res = bot.response("/add_target cidronly 192.168.1.0/24")
        self.assertIn("Target Added: cidronly", res)
        self.assertIn("192.168.1.0/24", res)

        # Update target
        res = bot.response("/update_target testcorp extra.test 10.1.0.0/24")
        self.assertIn("Target Updated: testcorp", res)
        self.assertIn("extra.test", res)
        self.assertIn("10.1.0.0/24", res)

        # Remove target
        res = bot.response("/remove_target testcorp")
        self.assertIn("Target Removed: testcorp", res)
        with self.assertRaises(ValueError):
            self.db.target("testcorp")

    async def test_bot_poll_handles_plain_button_text(self):
        self.config["telegram"].update(chat_id="123", bot_token="fixture-secret", send_delay=0.001)
        bot = Bot(self.config, self.db)
        updates = [{"update_id": 1, "message": {"chat": {"id": 123}, "text": "Live's"}},
                   {"update_id": 2, "message": {"chat": {"id": 123}, "text": "CNAME's"}},
                   {"update_id": 3, "message": {"chat": {"id": 123}, "text": "Brute force result"}}]
        calls = []

        async def api(method, payload):
            calls.append((method, payload))
            return updates if method == "getUpdates" else {"message_id": 1}

        with patch.object(bot, "api", api):
            await bot.poll()
        sends = [payload for method, payload in calls if method == "sendMessage"]
        self.assertEqual(len(sends), 3)
        self.assertTrue(all(p["reply_markup"]["keyboard"] for p in sends))

    async def test_automatic_notification_wake_on_event(self):
        self.config["telegram"].update(enabled=True, chat_id="123", bot_token="fixture-secret")
        notified = []

        class DummyNotifier:
            async def flush(self):
                notified.append(time.time())
                return False

        scheduler = Scheduler(self.config, self.db, notifier=DummyNotifier())
        self.assertEqual(len(notified), 0)

        # Ingesting a new asset triggers _event("fresh_asset"), which triggers db.on_event -> notify_wake.set()
        task = asyncio.create_task(scheduler.monitoring())
        try:
            await asyncio.sleep(0.02)
            self.assertGreaterEqual(len(notified), 1)
            count = len(notified)
            # Ingest asset - should instantly wake up monitoring task
            self.db.ingest(self.target["id"], ["instant.example.test"], "subfinder")
            await asyncio.sleep(0.05)
            self.assertGreater(len(notified), count)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
