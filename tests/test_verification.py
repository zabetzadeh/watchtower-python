"""Offline monitoring regressions using the default confirmation policy."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from assetwatch.config import Config, DEFAULTS, load_config
from assetwatch.database import Database
from assetwatch.notifications import format_event
from assetwatch.programs import utf16_length
from assetwatch.tools import ToolError
from assetwatch.watchers import Watchers


class VerificationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test"], [])
        self.watchers = Watchers(self.config, self.db)
        self.db.observe_dns(self.asset()["id"], ["192.0.2.1"])

    def asset(self):
        return next(self.db.assets(self.target["id"]))

    def reopen(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.watchers = Watchers(self.config, self.db)

    async def http(self, status, *, url="https://example.test", queued_only=False):
        observation = {"status_code": status, "url": url} if status is not None else None
        with patch.object(self.watchers.tools, "http", return_value={"example.test": observation}):
            self.assertTrue(await self.watchers.http_probe(self.target, queued_only=queued_only))

    async def stable(self, status):
        for _ in range(self.config["verification"]["http_confirmations"]):
            await self.http(status)

    async def dns(self, addresses):
        with patch.object(self.watchers.tools, "dns", return_value={"example.test": addresses}), \
                patch.object(self.watchers.tools, "cnames", return_value={"example.test": []}):
            self.assertTrue(await self.watchers.dns_resolution(self.target))

    def events(self, kind):
        return self.db.recent_events(kind=kind)

    async def test_initial_stray_200_never_becomes_a_baseline_and_candidates_survive_restart(self):
        await self.http(200)
        await self.http(403)
        await self.http(403)
        self.assertIsNone(self.asset()["http_status"])
        self.assertIsNone(self.asset()["http_checked_at"])
        self.assertEqual(self.db.pending_events(100, validated_only=True), [])
        self.reopen()
        await self.http(403)
        self.assertEqual(self.asset()["http_status"], 403)
        self.assertEqual(self.events("http_status_changed"), [])
        pending = self.db.pending_events(100, validated_only=True)
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0]["new_state"])["http_status"], 403)

    async def test_transient_disappearance_preserves_state_and_real_outage_and_return_alert_once(self):
        await self.stable(403)
        before = self.asset()
        for _ in range(2):
            await self.http(None)
            self.assertEqual(self.asset(), before)
            self.assertEqual(self.events("http_service_disappeared"), [])
        await self.http(403)  # Recovery cancels the pending loss.
        await self.http(None)
        self.reopen()
        await self.http(None)
        self.assertTrue(self.asset()["http_available"])
        await self.http(None)
        self.assertFalse(self.asset()["http_available"])
        self.assertIsNotNone(self.asset()["http_down_since"])
        await self.http(None)
        self.assertEqual(len(self.events("http_service_disappeared")), 1)
        await self.http(403)
        await self.http(None)  # A stray recovery must not announce a return.
        self.assertEqual(self.events("http_service_returned"), [])
        await self.stable(403)
        await self.http(403)
        self.assertEqual(len(self.events("http_service_returned")), 1)
        self.assertIsNone(self.asset()["http_down_since"])

    async def test_status_noise_resets_and_genuine_repeated_transitions_keep_previous_status(self):
        await self.stable(403)
        for status in (200, 200, 403, 200, 500, 200, 403):
            await self.http(status)
            self.assertEqual(self.asset()["http_status"], 403)
        self.assertEqual(self.events("http_status_changed"), [])
        for status in (200, 403, 200):
            await self.stable(status)
        changes = self.events("http_status_changed")
        self.assertEqual(len(changes), 3)
        self.assertEqual(json.loads(changes[0]["previous_state"])["http_status"], 403)
        self.assertEqual(json.loads(changes[0]["new_state"])["http_status"], 200)

    async def test_failed_and_missing_results_break_consecutive_confirmation(self):
        await self.stable(403)
        for result in ({}, ToolError("malformed output")):
            await self.http(None)
            await self.http(None)
            mock = AsyncMock(side_effect=result) if isinstance(result, Exception) else AsyncMock(return_value=result)
            with patch.object(self.watchers.tools, "http", mock):
                self.assertFalse(await self.watchers.http_probe(self.target))
            await self.http(None)
            await self.http(None)
            self.assertTrue(self.asset()["http_available"])
            await self.http(403)
        self.assertEqual(self.events("http_service_disappeared"), [])

    async def test_url_switches_require_matching_samples_without_cross_service_status_alert(self):
        await self.http(200, url="http://example.test")
        await self.http(200)
        await self.http(200)
        self.assertFalse(self.asset()["http_available"])
        await self.http(200)
        for _ in range(3):
            await self.http(403, url="http://example.test")
        self.assertEqual(self.asset()["http_url"], "http://example.test")
        self.assertEqual(self.asset()["http_status"], 403)
        self.assertEqual(self.events("http_status_changed"), [])
        for _ in range(3):
            await self.http(200, url="http://example.test")
        self.assertEqual(len(self.events("http_status_changed")), 1)

    async def test_dns_loss_cannot_bypass_http_verification(self):
        await self.stable(403)
        for _ in range(2):
            await self.dns([])
            self.assertTrue(self.asset()["http_available"])
            self.assertTrue(self.asset()["dns_resolved"])
        await self.dns(["192.0.2.1"])
        await self.dns([])
        self.reopen()
        await self.dns([])
        self.assertTrue(self.asset()["http_available"])
        await self.dns([])
        self.assertFalse(self.asset()["dns_resolved"])
        self.assertFalse(self.asset()["http_available"])
        self.assertEqual(len(self.events("dns_unresolved")), 1)
        self.assertEqual(len(self.events("http_service_disappeared")), 1)
        self.assertEqual(self.db.connection.execute(
            "SELECT count(*) FROM monitoring_jobs WHERE watcher='http_probe'").fetchone()[0], 0)
        await self.dns(["192.0.2.1"])
        await self.stable(403)
        self.assertEqual(len(self.events("http_service_returned")), 1)

    async def test_dns_missing_result_breaks_loss_confirmation_and_ip_changes_clear_http_evidence(self):
        await self.stable(403)
        await self.dns([])
        await self.dns([])
        with patch.object(self.watchers.tools, "dns", return_value={}), \
                patch.object(self.watchers.tools, "cnames", return_value={"example.test": []}):
            self.assertFalse(await self.watchers.dns_resolution(self.target))
        await self.dns([])
        self.assertTrue(self.asset()["dns_resolved"])
        await self.dns(["192.0.2.1"])
        await self.http(200)
        await self.http(200)
        old_version = self.asset()["dns_version"]
        await self.dns(["192.0.2.2"])
        self.assertFalse(self.db.observe_http(self.asset()["id"], None, old_version, confirmations=3))
        await self.http(200)
        self.assertEqual(self.asset()["http_status"], 403)

    async def test_only_pending_assets_retry_early_with_durable_deadlines(self):
        await self.stable(403)
        self.db.ingest(self.target["id"], ["other.example.test"], "subfinder")
        other = next(a for a in self.db.assets() if a["hostname"] == "other.example.test")
        self.db.observe_dns(other["id"], ["192.0.2.2"])
        self.db.observe_http(other["id"], {"status_code": 403, "url": "https://other.example.test"}, 1)
        rows = {"example.test": None,
                "other.example.test": {"status_code": 403, "url": "https://other.example.test"}}
        with patch("assetwatch.database.time.time", return_value=1000), \
                patch.object(self.watchers.tools, "http", return_value=rows):
            await self.watchers.http_probe(self.target)
        self.reopen()
        with patch("assetwatch.database.time.time", return_value=1029), \
                patch.object(self.watchers.tools, "http") as probe:
            await self.watchers.http_probe(self.target, queued_only=True)
            probe.assert_not_called()
        with patch("assetwatch.database.time.time", return_value=1030), \
                patch.object(self.watchers.tools, "http", return_value={"example.test": None}) as probe:
            await self.watchers.http_probe(self.target, queued_only=True)
            probe.assert_awaited_once_with(["example.test"])
        self.assertTrue(self.asset()["http_available"])

    async def test_failed_commit_rolls_back_confirmation_and_asset_removal_cleans_candidates(self):
        await self.stable(403)
        await self.http(200)
        await self.http(200)
        asset = self.asset()
        with patch.object(self.db, "_event", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                self.db.observe_http(asset["id"], {"status_code": 200, "url": asset["http_url"]},
                                     asset["dns_version"], confirmations=3)
        self.assertEqual(self.asset()["http_status"], 403)
        self.reopen()
        await self.http(200)
        self.assertEqual(len(self.events("http_status_changed")), 1)
        await self.http(None)
        self.db.remove_target("one")
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM observation_confirmations").fetchone()[0], 0)

    async def test_dns_alert_shows_previous_current_and_new_without_known_pool_noise(self):
        pool = [f"192.0.2.{i}" for i in range(1, 51)]
        await self.dns(pool)
        count = len(self.events("dns_ip_changed"))
        for addresses in (pool[::-1], pool[:10], pool[10:20], pool):
            await self.dns(addresses)
            self.assertEqual(len(self.events("dns_ip_changed")), count)
        await self.dns([pool[0], "198.51.100.1"])
        message = format_event(self.events("dns_ip_changed")[0])
        for field in ("*Previous IPs:* `192.0.2.1,", "*Current IPs:* `192.0.2.1, 198.51.100.1`",
                      "*New IPs:* `198.51.100.1`"):
            self.assertIn(field, message)
        self.assertLessEqual(utf16_length(message), 3900)
        self.reopen()
        await self.dns(pool)
        self.assertEqual(len(self.events("dns_ip_changed")), count + 1)

    def test_upgrade_adds_confirmation_table_without_changing_existing_state_or_history(self):
        before, events = self.asset(), self.db.recent_events()
        self.db.connection.execute("DROP TABLE observation_confirmations")
        self.reopen()
        self.assertEqual(self.asset(), before)
        self.assertEqual(self.db.recent_events(), events)
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM observation_confirmations").fetchone()[0], 0)

    def test_verification_configuration_validation(self):
        filename = self.path / "config.yaml"
        filename.write_text("{}")
        self.assertEqual(load_config(filename)["verification"],
                         {"http_confirmations": 3, "dns_loss_confirmations": 3, "retry_interval": 30})
        for name in ("http_confirmations", "dns_loss_confirmations", "retry_interval"):
            for value in (0, -1, True, "3", float("nan"), float("inf")):
                filename.write_text(yaml.safe_dump({"verification": {name: value}}))
                with self.assertRaises(ValueError):
                    load_config(filename)
        for name in ("http_confirmations", "dns_loss_confirmations"):
            filename.write_text(yaml.safe_dump({"verification": {name: 1.5}}))
            with self.assertRaises(ValueError):
                load_config(filename)
