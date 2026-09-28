"""Offline regressions for validation, bounded work and persistent monitoring."""

import asyncio
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from assetwatch.config import Config, DEFAULTS, load_config
from assetwatch.database import Database
from assetwatch.notifications import Notifier, format_event
from assetwatch.programs import utf16_length
from assetwatch.reports import health_report, health_text
from assetwatch.scheduler import Scheduler
from assetwatch.tools import ToolError
from assetwatch.watchers import Watchers


class Observations:
    def __init__(self):
        self.dns_calls, self.http_calls = [], []
        self.unresolved, self.no_http, self.inconclusive = set(), set(), set()
        self.technology = "nginx"

    async def dns(self, names):
        self.dns_calls.append(names)
        return {name: [] if name in self.unresolved else ["192.0.2.1"]
                for name in names if name not in self.inconclusive}

    async def cnames(self, names):
        return {name: [] for name in names}

    async def http(self, names):
        self.http_calls.append(names)
        return {name: None if name in self.no_http else {
            "status_code": 403, "url": "https://" + name,
            "title": "Admin [portal]", "tech": [self.technology], "webserver": "nginx/1.2"}
            for name in names}


class ValidationQueueTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["runtime"].update(batch_size=2, poll_interval=0.001)
        self.config["telegram"].update(enabled=True, bot_token="fixture", chat_id="123", send_delay=0.001)
        self.config["cdn"]["enabled"] = False
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test"], [])
        self.tools = Observations()
        self.watchers = Watchers(self.config, self.db, self.tools)

    def asset(self, name="example.test"):
        return next(a for a in self.db.assets() if a["hostname"] == name)

    def reopen(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.watchers = Watchers(self.config, self.db, self.tools)

    async def cycle(self):
        await self.watchers.dns_resolution(self.target, queued_only=True)
        await self.watchers.http_probe(self.target, queued_only=True)

    async def test_all_sources_are_stored_but_only_dns_and_http_validated_assets_alert(self):
        for source in ("dns_bruteforce", "subfinder", "tlsx", "ptr", "chaos", "crtsh"):
            await self.watchers.ingest(self.target, [source.replace("_", "-") + ".example.test"], source)
        self.tools.unresolved = {"subfinder.example.test"}
        self.tools.no_http = {"tlsx.example.test"}
        self.tools.inconclusive = {"ptr.example.test"}
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            await notifier.flush()
            send.assert_not_called()
            await self.watchers.dns_resolution(self.target, queued_only=True)
            await notifier.flush()
            send.assert_not_called()
            await self.watchers.http_probe(self.target, queued_only=True)
            await notifier.flush()
            self.assertEqual(send.call_count, 4)
            for call in send.call_args_list:
                payload = call.args[2]
                self.assertEqual(payload["parse_mode"], "MarkdownV2")
                for value in ("*DNS:* RESOLVED", "*HTTP:* LIVE", "`403`", "*Technology:* `nginx`"):
                    self.assertIn(value, payload["text"])
            self.assertEqual(len(list(self.db.assets())), 7)
            self.assertEqual(self.db.pending_events(100, validated_only=True), [])
            await self.watchers.dns_resolution(self.target)
            await self.watchers.http_probe(self.target)
            await notifier.flush()
            self.assertEqual(send.call_count, 4)
        self.assertTrue(all(len(batch) <= 2 for batch in self.tools.dns_calls + self.tools.http_calls))
        self.assertFalse(any("subfinder.example.test" in batch for batch in self.tools.http_calls))

    async def test_new_assets_do_not_wait_for_target_interval_and_schedules_survive_restart(self):
        await self.cycle()
        jobs = [tuple(row) for row in self.db.connection.execute("SELECT * FROM monitoring_jobs ORDER BY watcher")]
        self.reopen()
        self.assertEqual([tuple(row) for row in self.db.connection.execute("SELECT * FROM monitoring_jobs ORDER BY watcher")], jobs)
        await self.cycle()
        self.assertEqual(len(self.tools.dns_calls), 1)
        self.assertEqual(len(self.tools.http_calls), 1)
        await self.watchers.ingest(self.target, ["new.example.test"], "dns_bruteforce")
        await self.cycle()
        self.assertEqual(self.tools.dns_calls[-1], ["new.example.test"])
        self.assertEqual(self.tools.http_calls[-1], ["new.example.test"])
        self.assertEqual(len(list(self.db.assets(http=True))), 2)

    async def test_every_asset_is_rechecked_and_fingerprints_are_refreshed(self):
        self.tools.unresolved = {"example.test"}
        await self.cycle()
        self.assertEqual(self.tools.http_calls, [])
        self.reopen()
        self.tools.unresolved.clear()
        self.db.connection.execute("UPDATE monitoring_jobs SET due_at=0")
        await self.cycle()
        self.assertTrue(self.asset()["http_available"])
        self.tools.technology = "updated"
        self.db.connection.execute("UPDATE monitoring_jobs SET due_at=0")
        await self.cycle()
        self.assertEqual(self.asset()["http_metadata"]["tech"], ["updated"])
        self.assertEqual(len(self.tools.http_calls), 2)
        self.assertEqual(len(self.db.pending_events(100, validated_only=True)), 1)

    async def test_inconclusive_check_preserves_state_and_retries_earlier(self):
        await self.cycle()
        self.tools.inconclusive = {"example.test"}
        self.db.connection.execute("UPDATE monitoring_jobs SET due_at=0 WHERE watcher='dns_resolution'")
        self.assertFalse(await self.watchers.dns_resolution(self.target, queued_only=True))
        self.assertTrue(self.asset()["dns_resolved"])
        due = self.db.next_run_at(self.target["id"], "dns_resolution", 1800)
        self.assertLessEqual(due - time.time(), self.config["runtime"]["failure_retry_interval"])
        self.assertGreater(due, time.time())
        self.assertTrue(await self.watchers.dns_resolution(self.target, queued_only=True))
        self.assertEqual(len(self.tools.dns_calls), 2)

    async def test_cancelled_check_stays_due_after_restart(self):
        with patch.object(self.tools, "dns", side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await self.watchers.dns_resolution(self.target, queued_only=True)
        self.reopen()
        self.assertTrue(self.db.due(self.target["id"], "dns_resolution", 1800))
        await self.cycle()
        self.assertTrue(self.asset()["http_available"])

    async def test_http_result_for_an_old_dns_version_cannot_validate_or_count_as_success(self):
        await self.watchers.dns_resolution(self.target, queued_only=True)

        async def stale(names):
            self.db.observe_dns(self.asset()["id"], ["192.0.2.2"])
            return {name: {"status_code": 200} for name in names}

        with patch.object(self.tools, "http", stale):
            self.assertFalse(await self.watchers.http_probe(self.target, queued_only=True))
        self.assertFalse(self.asset()["http_available"])
        self.assertEqual(self.db.pending_events(100, validated_only=True), [])
        due = self.db.next_run_at(self.target["id"], "http_probe", 1800)
        self.assertLessEqual(due - time.time(), self.config["runtime"]["failure_retry_interval"])

    async def test_manual_rerun_during_an_active_check_is_not_lost(self):
        await self.cycle()
        self.db.request_run(self.target["id"], "http_probe")
        self.db.consume_run_request(self.target["id"], "http_probe")
        original = self.tools.http

        async def requested_again(names):
            self.db.request_run(self.target["id"], "http_probe")
            return await original(names)

        with patch.object(self.tools, "http", requested_again):
            await self.watchers.http_probe(self.target, queued_only=True)
        self.assertTrue(self.db.due(self.target["id"], "http_probe", 1800))
        self.db.consume_run_request(self.target["id"], "http_probe")
        await self.watchers.http_probe(self.target, queued_only=True)
        self.assertEqual(len(self.tools.http_calls), 3)

    async def test_invalid_backlog_cannot_starve_valid_alert_and_upgrade_keeps_validation(self):
        self.db.ingest(self.target["id"], [f"raw{i}.example.test" for i in range(100)], "dns_bruteforce")
        self.db.ingest(self.target["id"], ["valid.example.test"], "dns_bruteforce")
        valid = self.asset("valid.example.test")
        self.db.observe_dns(valid["id"], ["192.0.2.2"])
        self.db.observe_http(valid["id"], {"status_code": 500, "url": "https://valid.example.test"}, 1)
        events = self.db.pending_events(1, validated_only=True)
        self.assertEqual(events[0]["hostname"], "valid.example.test")
        self.assertEqual(json.loads(events[0]["new_state"])["http_status"], 500)
        # Simulate the pre-validation schema: reconstruct the first live snapshot.
        self.db.connection.execute("DROP TABLE asset_validations")
        self.db.connection.execute("DROP TABLE monitoring_jobs")
        self.reopen()
        self.assertEqual(self.db.pending_events(1, validated_only=True)[0]["id"], events[0]["id"])
        self.db.notification_result(events[0]["id"])
        self.reopen()
        self.assertEqual(self.db.pending_events(1, validated_only=True), [])
        self.assertEqual(len(list(self.db.assets())), 102)

    async def test_health_distinguishes_waiting_validation_from_deliverable_alerts(self):
        report = health_report(self.config, self.db)
        self.assertEqual(report["notification_backlog"], 0)
        self.assertEqual(report["awaiting_validation"], 1)
        self.assertEqual(report["due_checks"], {"dns_resolution": 1})
        self.assertIn("waiting for eligible assets", health_text(report))
        json.dumps(report, allow_nan=False)
        await self.cycle()
        report = health_report(self.config, self.db)
        self.assertEqual(report["notification_backlog"], 1)
        self.assertEqual(report["awaiting_validation"], 0)

    async def test_scheduler_picks_up_new_findings_and_returns_http_to_queue_after_dns_recovery(self):
        scheduler = Scheduler(self.config, self.db, watchers=self.watchers)
        tasks = [asyncio.create_task(scheduler.watch(name)) for name in ("dns_resolution", "http_probe")]
        try:
            async with asyncio.timeout(2):
                while not self.asset()["http_available"]:
                    await asyncio.sleep(0.005)
            self.db.observe_dns(self.asset()["id"], [])
            self.assertEqual(self.db.connection.execute("SELECT count(*) FROM monitoring_jobs WHERE watcher='http_probe'").fetchone()[0], 0)
            self.db.request_run(self.target["id"], "dns_resolution")
            async with asyncio.timeout(2):
                while not self.asset()["http_available"]:
                    await asyncio.sleep(0.005)
            self.assertEqual(len(self.tools.http_calls), 2)
            await self.watchers.ingest(self.target, ["new.example.test"], "dns_bruteforce")
            async with asyncio.timeout(2):
                while not self.asset("new.example.test")["http_available"]:
                    await asyncio.sleep(0.005)
            self.assertEqual(self.tools.http_calls[-1], ["new.example.test"])
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_markdown_survives_untrusted_fingerprints_and_long_unicode(self):
        await self.cycle()
        event = self.db.pending_events(1, validated_only=True)[0]
        state = json.loads(event["new_state"])
        state["http_metadata"] = {"title": "a`\\_*[x]\n" + "😀" * 9000, "tech": ["a`b", "c\\d"]}
        event.update(target="_*[]()~`>#+-=|{}.!\\", new_state=json.dumps(state))
        text = format_event(event)
        self.assertLessEqual(utf16_length(text), 3900)
        self.assertIn(r"a\`\\_*[x]", text)
        self.assertIn(r"a\`b, c\\d", text)
        # Code entities and bold labels must stay balanced after clipping.
        code = bold = False
        index = 0
        while index < len(text):
            char = text[index]
            if char == "\\":
                self.assertLess(index + 1, len(text))
                index += 2
                continue
            if char == "`":
                code = not code
            elif not code and char == "*":
                bold = not bold
            elif not code:
                self.assertNotIn(char, "_[]()~>#+-=|{}.!")
            index += 1
        self.assertFalse(code)
        self.assertFalse(bold)

    def test_invalid_resource_limits_are_rejected(self):
        for value in ("true", ".nan", ".inf", "-1"):
            config = self.path / "config.yaml"
            config.write_text(f"dns_bruteforce:\n  shuffledns:\n    cooldown: {value}\n")
            with self.assertRaises(ValueError):
                load_config(config)
        for key in ("dns_rate_limit", "http_rate_limit", "http_max_response_bytes"):
            config.write_text(f"runtime:\n  {key}: 0\n")
            with self.assertRaises(ValueError):
                load_config(config)
