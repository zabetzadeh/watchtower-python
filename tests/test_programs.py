import asyncio
import copy
import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

from assetwatch.bot import Bot
from assetwatch.cli import main
from assetwatch.config import Config, DEFAULTS, PROGRAM_FEEDS, load_config
from assetwatch.database import Database
from assetwatch.notifications import Notifier
from assetwatch.programs import ProgramWatcher, format_program_messages, parse_feed, program_next_run, utf16_length
from assetwatch.reports import health_report, health_text
from assetwatch.scheduler import Scheduler


def program(platform, key="example", names=("*.example.test",), name="Example [Bounty] (prod)!"):
    field = {"hackerone": "asset_identifier", "bugcrowd": "target", "intigriti": "endpoint"}[platform]
    type_field = "asset_type" if platform == "hackerone" else "type"
    row = {"name": name, "url": f"https://{platform}.com/{key}", "targets": {
        "in_scope": [{field: identifier, type_field: "wildcard"} for identifier in names], "out_of_scope": []}}
    if platform == "hackerone":
        row.update(id=0, handle=key, offers_bounties=True)
    if platform == "intigriti":
        row.update(id=key, handle=key, company_handle="example")
    return row


class Fixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["database"]["path"] = "assets.db"
        self.config["telegram"].update(enabled=True, bot_token="fixture-secret", chat_id="123", send_delay=0.001)
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())

    def observe(self, platform, rows):
        return self.db.observe_program_feed(platform, parse_feed(platform, rows), 3600)

    def reopen(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")


class ProgramTests(Fixture, unittest.TestCase):
    def test_three_platform_schemas_baseline_and_hackerone_zero_ids(self):
        for platform in PROGRAM_FEEDS:
            rows = [program(platform), program(platform, "second", ["api.example.test"])]
            if platform == "intigriti":
                rows[0]["targets"]["in_scope"][0]["type"] = None
            self.assertTrue(self.observe(platform, rows)["baseline"])
            status = self.db.program_feed_status(platform)
            self.assertEqual((status["program_count"], status["scope_count"]), (2, 2))
            self.assertIsNotNone(status["initialized_at"])
            self.assertFalse(self.observe(platform, list(reversed(rows)))["baseline"])
        self.assertEqual(self.db.recent_program_events(), [])
        self.assertEqual(self.db.pending_program_messages(100), [])
        self.assertEqual(self.db.targets(), [])
        self.assertEqual(list(self.db.assets()), [])

    def test_only_new_programs_and_in_scope_additions_not_metadata_removals_or_reappearance(self):
        for platform in PROGRAM_FEEDS:
            original = program(platform)
            removed = program(platform, "removed")
            self.observe(platform, [original, removed])
            changed = copy.deepcopy(original)
            changed["name"] = "Renamed Program"
            changed["max_payout"] = 99999
            entry = changed["targets"]["in_scope"][0]
            entry["instruction"] = "Policy was edited"
            entry["asset_type" if platform == "hackerone" else "type"] = "other"
            changed["targets"]["out_of_scope"] = [{"ignored": "out-of-scope.example.test"}]
            self.observe(platform, [changed])
            # All entries removed and then restored: remembered history remains intact.
            self.observe(platform, [program(platform, names=[])])
            self.observe(platform, [changed, removed])
            self.assertEqual(self.db.recent_program_events(platform), [])
            extended = program(platform, names=["*.example.test", "api.example.test", "api.example.test"])
            result = self.observe(platform, [extended, program(platform, "brand-new", names=[])])
            self.assertEqual((result["new_programs"], result["new_scopes"]), (1, 1))
            events = self.db.recent_program_events(platform)
            self.assertEqual([e["event_type"] for e in events], ["new_program", "scope_added"])
            self.assertEqual(events[0]["added_scope"], [])
            self.assertEqual([s["identifier"] for s in events[1]["added_scope"]], ["api.example.test"])
            self.reopen()
            self.observe(platform, [extended, program(platform, "brand-new", names=[])])
            self.assertEqual(len(self.db.recent_program_events(platform)), 2)

    def test_scope_moving_from_out_to_in_alerts_and_new_program_has_one_combined_event(self):
        row = program("hackerone")
        row["targets"]["out_of_scope"] = [{"asset_identifier": "api.example.test", "asset_type": "URL"}]
        self.observe("hackerone", [row])
        row["targets"]["in_scope"] += row["targets"]["out_of_scope"]
        row["targets"]["out_of_scope"] = []
        self.observe("hackerone", [row, program("hackerone", "new", ["a.test", "b.test"])])
        events = self.db.recent_program_events("hackerone")
        self.assertEqual(len(events), 2)
        self.assertEqual(len(events[0]["added_scope"]), 2)
        self.assertEqual(events[1]["added_scope"][0]["identifier"], "api.example.test")

    def test_normalization_preserves_wildcard_and_url_path_identity(self):
        row = program("hackerone", names=["*.EXAMPLE.TEST.", "*.example.test", "example.test",
                                         "https://EXAMPLE.test/Case", "https://example.test/case"])
        values = [s["identifier"] for s in parse_feed("hackerone", [row])[0]["scope"]]
        self.assertEqual(values, ["*.example.test", "example.test", "https://example.test/Case", "https://example.test/case"])

    def test_malformed_or_partial_schema_is_rejected_before_state_changes(self):
        good = program("hackerone")
        for data in ([], {}, [None], [good, good], [{**good, "targets": {}}],
                     [{**good, "handle": ""}], [{**good, "url": "javascript:alert(1)"}],
                     [{**good, "targets": {"in_scope": [{"asset_identifier": ""}]}}]):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    parse_feed("hackerone", data)
        with self.assertRaises(ValueError):
            parse_feed("unknown", [good])

    def test_seen_sets_and_event_pages_roll_back_together_if_queue_write_fails(self):
        self.observe("bugcrowd", [program("bugcrowd")])
        before = self.db.program_feed_status("bugcrowd")
        changed = program("bugcrowd", names=["*.example.test", "new.test"])
        with patch("assetwatch.database.format_program_messages", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                self.observe("bugcrowd", [changed])
        self.assertEqual(self.db.program_feed_status("bugcrowd"), before)
        self.assertEqual(self.db.recent_program_events(), [])
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM program_scopes").fetchone()[0], 1)
        self.assertEqual(self.observe("bugcrowd", [changed])["new_scopes"], 1)

    def test_markdown_escapes_untrusted_text_and_splits_every_asset_without_truncation(self):
        identifiers = [f"https://example.test/{i}/[test]_x*`\\!" for i in range(200)] + ["🆕`\\" * 1500]
        event = {"id": 42, "platform": "hackerone", "event_type": "scope_added",
                 "program_name": "Acme_[x](link)! ~`>#+-=|{}.\\",
                 "created_at": "2026-09-27T10:30:00+00:00",
                 "added_scope": [{"identifier": name, "type": "url_[test]"} for name in identifiers]}
        pages = format_program_messages(event)
        self.assertGreater(len(pages), 2)
        self.assertTrue(all(utf16_length(page) <= 3800 for page in pages))
        self.assertTrue(all(page.startswith("🎯 *Scope Expanded*") for page in pages))
        self.assertIn(r"*Acme\_\[x\]\(link\)\!", pages[0])
        self.assertIn("`2026-09-27 10:30 UTC`", pages[0])
        self.assertIn(f"Part {len(pages)}/{len(pages)}", pages[-1])
        combined = "\n".join(pages)
        for i in range(200):
            self.assertIn(f"https://example.test/{i}/", combined)
        self.assertEqual(combined.count("🆕"), 1500)
        self.assertIn(r"\`\\", combined)

    def test_health_cli_and_bot_surface_program_changes_without_scan_targets(self):
        self.observe("intigriti", [program("intigriti")])
        self.observe("intigriti", [program("intigriti", names=["*.example.test", "new.test"])])
        report = health_report(self.config, self.db)
        self.assertEqual(report["program_notification_backlog"], 1)
        self.assertIn("Intigriti: success", health_text(report))
        self.assertIn("Scope expanded", Bot(self.config, self.db).response("/programs intigriti"))
        self.assertIn("No program additions", Bot(self.config, self.db).response("/programs hackerone"))
        with self.assertRaises(ValueError):
            Bot(self.config, self.db).response("/programs nope")
        with patch("assetwatch.cli.load_config", return_value=self.config), patch("assetwatch.cli.configure_logging"), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["program-changes", "--platform", "intigriti", "--format", "json"]), 0)
        event = json.loads(out.getvalue())[0]
        self.assertEqual(event["added_scope"][0]["identifier"], "new.test")

    def test_config_rejects_invalid_program_settings(self):
        path = self.path / "config.yaml"
        for value in ({"program_watch": {"enabled": "yes"}}, {"program_watch": {"max_feed_bytes": 0}},
                      {"program_watch": {"max_feed_bytes": 2.5}}, {"intervals": {"program_watch": -1}}):
            path.write_text(yaml.safe_dump(value))
            with self.assertRaises(ValueError):
                load_config(path)

    def test_changed_interval_applies_to_persisted_schedule_and_failures_retry_earlier(self):
        status = {"state": "success", "checked_at": 100, "next_run_at": 3700}
        self.config["intervals"]["program_watch"] = 60
        self.assertEqual(program_next_run(self.config, status), 160)
        self.config["intervals"]["program_watch"] = 3600
        status["state"] = "failed"
        self.assertEqual(program_next_run(self.config, status), 400)
        status["state"] = "interrupted"
        self.assertEqual(program_next_run(self.config, status), 0)


class ProgramAsyncTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def test_failed_first_fetch_never_baselines_and_one_platform_cannot_break_others(self):
        watcher = ProgramWatcher(self.config, self.db)
        with patch("assetwatch.programs.read_json", side_effect=OSError("fixture-secret")):
            self.assertFalse(await watcher.check("hackerone"))
        failed = self.db.program_feed_status("hackerone")
        self.assertIsNone(failed["initialized_at"])
        self.assertNotIn("fixture-secret", failed["last_error"])
        self.assertGreater(failed["next_run_at"], time.time())
        for platform in PROGRAM_FEEDS:
            with patch("assetwatch.programs.read_json", return_value=[program(platform)]):
                self.assertTrue(await watcher.check(platform))
        self.assertEqual(self.db.recent_program_events(), [])
        before = self.db.program_feed_status("hackerone")["initialized_at"]
        for value in ([], [{"name": "partial download"}]):
            with patch("assetwatch.programs.read_json", return_value=value):
                self.assertFalse(await watcher.check("hackerone"))
        self.assertEqual(self.db.program_feed_status("hackerone")["initialized_at"], before)

    async def test_scheduler_watches_all_feeds_with_no_targets_and_during_scan_lock(self):
        self.config["telegram"]["enabled"] = False
        self.config["runtime"]["poll_interval"] = 0.002
        self.config["intervals"]["program_watch"] = 0.01
        calls = {name: 0 for name in PROGRAM_FEEDS}

        def fetch(url, *args, **kwargs):
            platform = next(name for name, value in PROGRAM_FEEDS.items() if value == url)
            calls[platform] += 1
            return [program(platform)]

        scheduler = Scheduler(self.config, self.db)
        stop = asyncio.Event()
        with patch("assetwatch.programs.read_json", side_effect=fetch):
            async with scheduler.scans.slot(exclusive=True):
                task = asyncio.create_task(scheduler.run(stop))
                try:
                    async with asyncio.timeout(2):
                        while min(calls.values()) < 2:
                            await asyncio.sleep(0.005)
                finally:
                    stop.set()
                    await asyncio.wait_for(task, 1)
        self.assertEqual(self.db.targets(), [])
        self.assertTrue(all(self.db.program_feed_status(name)["initialized_at"] for name in PROGRAM_FEEDS))

    async def test_schedule_survives_restart_and_disabled_watcher_never_fetches(self):
        self.observe("hackerone", [program("hackerone")])
        self.reopen()
        watcher = ProgramWatcher(self.config, self.db)
        with patch("assetwatch.programs.read_json") as fetch:
            task = asyncio.create_task(watcher.watch("hackerone"))
            try:
                await asyncio.sleep(0.02)
                fetch.assert_not_called()
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self.config["program_watch"]["enabled"] = False
            await watcher.watch("bugcrowd")
            fetch.assert_not_called()

    async def test_markdown_alert_delivery_is_durable_and_interleaves_with_asset_backlog(self):
        self.config["telegram"]["batch_size"] = 2
        target = self.db.add_target("example", ["example.test"], [])
        self.db.ingest(target["id"], ["a.example.test", "b.example.test"], "subfinder")
        self.observe("hackerone", [program("hackerone")])
        self.observe("hackerone", [program("hackerone"), program("hackerone", "new", ["new.test"])])
        with patch("assetwatch.notifications.read_json", return_value={"ok": True, "result": {"message_id": 12}}) as send:
            self.assertTrue(await Notifier(self.config, self.db).flush())
            self.assertEqual(send.call_count, 2)
            message = send.call_args_list[1].args[2]
            self.assertEqual(message["parse_mode"], "MarkdownV2")
            self.assertIn("🆕 *New Program*", message["text"])
            self.assertEqual(message["reply_markup"]["inline_keyboard"][0][0]["url"], "https://hackerone.com/new")
        self.reopen()
        self.assertEqual(self.db.pending_program_messages(10), [])
        self.assertEqual(self.db.connection.execute("SELECT message_id FROM program_messages").fetchone()[0], "12")

    async def test_single_message_batches_alternate_queues_without_exceeding_limit(self):
        self.config["telegram"]["batch_size"] = 1
        self.db.add_target("example", ["a.test", "b.test", "c.test"], [])
        self.observe("hackerone", [program("hackerone")])
        self.observe("hackerone", [program("hackerone"), program("hackerone", "new")])
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            self.assertTrue(await notifier.flush())
            self.assertEqual(send.call_count, 1)
            self.assertTrue(await notifier.flush())
            self.assertEqual(send.call_count, 2)
            self.assertIn("*New Program*", send.call_args_list[1].args[2]["text"])

    async def test_large_alert_retries_only_unacknowledged_parts_in_order_after_restart(self):
        self.observe("hackerone", [program("hackerone")])
        names = [f"https://example.test/{i}/" + "x" * 100 for i in range(100)]
        self.observe("hackerone", [program("hackerone", names=names)])
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", side_effect=[{"ok": True}, OSError("fixture-secret")]) as send:
            self.assertFalse(await notifier.flush())
            self.assertEqual(send.call_count, 2)
        self.reopen()
        self.assertEqual(self.db.pending_program_messages(100), [])  # Later parts wait for failed part 2.
        self.db.connection.execute("UPDATE program_messages SET next_attempt_at=0")
        remaining = self.db.pending_program_messages(100)
        self.assertGreater(len(remaining), 1)
        self.assertEqual(remaining[0]["part"], 2)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            await Notifier(self.config, self.db).flush()
            self.assertEqual(send.call_count, len(remaining))
            self.assertNotIn("fixture-secret", json.dumps([dict(r) for r in self.db.connection.execute("SELECT * FROM program_messages")]))
        self.assertEqual(self.db.pending_program_messages(100), [])
        self.observe("hackerone", [program("hackerone", names=names)])
        self.assertEqual(len(self.db.recent_program_events()), 1)

    async def test_telegram_disabled_keeps_program_outbox(self):
        self.observe("bugcrowd", [program("bugcrowd")])
        self.observe("bugcrowd", [program("bugcrowd"), program("bugcrowd", "new")])
        self.config["telegram"]["enabled"] = False
        with patch("assetwatch.notifications.read_json") as send:
            self.assertFalse(await Notifier(self.config, self.db).flush())
            send.assert_not_called()
        self.assertEqual(len(self.db.pending_program_messages(10)), 1)


if __name__ == "__main__":
    unittest.main()
