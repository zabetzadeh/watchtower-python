import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assetwatch.cdn import CdnRanges, download_ranges, parse_ranges
from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.notifications import Notifier


FEED = {
    "cdn": {"arvancloud": ["192.0.2.0/25"], "fastly": ["198.51.100.0/25"]},
    "waf": {"cloudflare": ["203.0.113.0/25"], "arvancloud": ["192.0.2.0/25"]},
    "cloud": {"hosting": ["192.0.2.128/25"]},
    "common": {"akamai": ["example.invalid"]},
}
AKAMAI = "198.51.100.128/25\n"


class CdnTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["telegram"].update(enabled=True, bot_token="test-token", chat_id="123",
                                       batch_size=2, send_delay=0.001)
        self.config["cdn"].update(refresh_interval=100, retry_interval=10, max_age=300)
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.clock = patch("assetwatch.cdn.time.time", return_value=1000)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.json_patch = patch("assetwatch.cdn.read_json", return_value=copy.deepcopy(FEED))
        self.get_json = self.json_patch.start()
        self.addCleanup(self.json_patch.stop)
        self.text_patch = patch("assetwatch.cdn.read_text", return_value=AKAMAI)
        self.get_text = self.text_patch.start()
        self.addCleanup(self.text_patch.stop)
        self.ranges = CdnRanges(self.config, self.db)
        await self.ranges.refresh()

    async def test_provider_rotation_origin_changes_and_mixed_answers(self):
        rotation = self.ranges.rotation_providers
        for first, second, provider in (("192.0.2.1", "192.0.2.2", "arvancloud"),
                                         ("203.0.113.1", "203.0.113.2", "cloudflare"),
                                         ("198.51.100.129", "198.51.100.130", "akamai")):
            self.assertEqual(rotation([first], [second]), {provider})
        self.assertEqual(rotation(["192.0.2.1"], ["203.0.113.1"]), set())  # Provider changed.
        self.assertEqual(rotation(["192.0.2.1"], ["192.0.2.129"]), set())  # Left the CDN.
        self.assertEqual(rotation(["192.0.2.129"], ["192.0.2.1"]), set())  # Entered the CDN.
        self.assertEqual(rotation(["192.0.2.129"], ["192.0.2.130"]), set())  # Cloud is not CDN.
        self.assertEqual(rotation([], ["192.0.2.1"]), set())
        self.assertEqual(rotation(["192.0.2.1"], []), set())
        self.assertEqual(rotation(["bad"], ["192.0.2.1"]), set())
        self.assertEqual(rotation(["192.0.2.1"], ["192.0.2.1", "192.0.2.2"]), {"arvancloud"})
        self.assertEqual(rotation(["192.0.2.1", "192.0.2.129"],
                                  ["192.0.2.2", "192.0.2.129"]), {"arvancloud"})
        self.assertEqual(rotation(["192.0.2.1", "192.0.2.129"],
                                  ["192.0.2.2", "192.0.2.130"]), set())

    async def test_cache_survives_restart_and_refreshes_on_interval(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")
        restarted = CdnRanges(self.config, self.db)
        await restarted.refresh()
        self.assertEqual(self.get_json.call_count, 1)
        self.assertEqual(self.get_text.call_count, 1)
        self.assertEqual(restarted.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), {"arvancloud"})
        self.now.return_value = 1100
        await restarted.refresh()
        self.assertEqual(self.get_json.call_count, 2)
        self.assertEqual(self.get_text.call_count, 2)

    async def test_failed_or_invalid_refresh_keeps_cache_then_expires_and_recovers(self):
        self.get_json.side_effect = OSError("offline")
        self.get_text.return_value = "<html>not a CIDR list</html>"
        self.now.return_value = 1100
        await self.ranges.refresh()
        saved = self.db.cdn_sources()
        self.assertTrue(all(row["fetched_at"] == 1000 for row in saved.values()))
        self.assertEqual(self.ranges.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), {"arvancloud"})
        self.now.return_value = 1101
        await self.ranges.refresh()
        self.assertEqual(self.get_json.call_count, 2)  # Failed sources obey retry delay.
        self.now.return_value = 1301
        await self.ranges.refresh()
        self.assertEqual(self.ranges.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), set())
        self.get_json.side_effect = None
        self.get_json.return_value = {"cdn": {"arvancloud": ["192.0.2.128/25"]}, "waf": {}}
        self.get_text.return_value = AKAMAI
        self.now.return_value = 1311
        await self.ranges.refresh()
        self.assertEqual(self.ranges.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), set())
        self.assertEqual(self.ranges.rotation_providers(["192.0.2.129"], ["192.0.2.130"]), {"arvancloud"})

    async def test_failed_first_download_does_not_suppress_unknown_changes(self):
        self.db.connection.execute("DELETE FROM cdn_sources")
        self.get_json.side_effect = OSError("offline")
        self.get_text.side_effect = OSError("offline")
        empty = CdnRanges(self.config, self.db)
        await empty.refresh()
        self.assertEqual(empty.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), set())

    async def test_disabled_filter_skips_download_and_never_suppresses(self):
        self.config["cdn"]["enabled"] = False
        self.now.return_value = 1100
        await self.ranges.refresh()
        self.assertEqual(self.get_json.call_count, 1)
        self.assertEqual(self.ranges.rotation_providers(["192.0.2.1"], ["192.0.2.2"]), set())

    async def test_suppression_is_persistent_and_never_marked_as_telegram_delivery(self):
        self.db.add_target("one", ["example.test"], [])
        asset = next(self.db.assets())
        self.db.observe_dns(asset["id"], ["192.0.2.1"])
        for event in self.db.pending_events(100):
            self.db.notification_result(event["id"])
        for number in (2, 3, 4):
            self.db.observe_dns(asset["id"], [f"192.0.2.{number}"])
        self.db.observe_dns(asset["id"], ["203.0.113.1"])
        self.db.observe_dns(asset["id"], [])
        self.db.observe_dns(asset["id"], ["203.0.113.2"])
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            while await notifier.flush():
                pass
            self.assertEqual(send.call_count, 3)  # Migration, DNS loss, DNS return.
            suppressed = self.db.connection.execute(
                "SELECT e.*,s.reason FROM events e JOIN notification_suppressions s ON s.event_id=e.id").fetchall()
            self.assertEqual(len(suppressed), 3)
            for row in suppressed:
                self.assertIsNone(row["delivered_at"])
                self.assertEqual(row["attempts"], 0)
                self.assertEqual(row["reason"], "cdn_ip_rotation:arvancloud")
                self.assertIn("ip_addresses", json.loads(row["new_state"]))
            self.db.close()
            self.db = Database(self.path / "assets.db")
            self.assertFalse(await Notifier(self.config, self.db).flush())
            self.assertEqual(send.call_count, 3)
        self.assertEqual(next(self.db.assets())["ip_addresses"], ["203.0.113.2"])
        self.assertEqual(self.db.pending_events(100), [])
        self.db.remove_target("one")
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM notification_suppressions").fetchone()[0], 0)

    def test_rejects_malformed_empty_and_catchall_feeds(self):
        for data in ({}, {"cdn": "not a list"}, {"cdn": []}, {"cdn": ["0.0.0.0/0"]},
                     {"cdn": ["bad"]}, {"cdn": [123]}):
            with self.assertRaises(ValueError):
                parse_ranges(data)
        for data in ([], {"cloud": {"provider": ["192.0.2.0/24"]}}, {"cdn": {}, "waf": {}}):
            self.get_json.return_value = data
            with self.assertRaises(ValueError):
                download_ranges("projectdiscovery", "https://example.invalid", 1)
