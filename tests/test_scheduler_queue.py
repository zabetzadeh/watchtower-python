import asyncio
import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.reports import health_report
from assetwatch.scheduler import Scheduler


class SchedulerQueueTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["runtime"].update(poll_interval=0.002, failure_retry_interval=0.005)
        self.config["program_watch"]["enabled"] = False
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test"], [])
        self.tasks = []

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def start(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        return task

    async def wait_until(self, condition):
        async with asyncio.timeout(2):
            while not condition():
                await asyncio.sleep(0.001)

    def status(self, watcher):
        return self.db.connection.execute(
            "SELECT * FROM watcher_status WHERE target_id=? AND watcher=?",
            (self.target["id"], watcher)).fetchone()

    async def test_whole_modules_are_fifo_and_health_distinguishes_waiters(self):
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        class Watchers:
            def __getattr__(self, name):
                async def run(target, **options):
                    calls.append((name, "start"))
                    if name == "passive_discovery":
                        entered.set()
                        await release.wait()
                    # Simulate separate tool calls, ingestion and cooldowns.
                    for number in range(3):
                        await asyncio.sleep(0)
                        calls.append((name, number))
                    calls.append((name, "finish"))
                    return True
                return run

        scheduler = Scheduler(self.config, self.db, watchers=Watchers())
        names = ("passive_discovery", "tlsx", "dns_bruteforce")
        self.start(scheduler.watch(names[0]))
        await asyncio.wait_for(entered.wait(), 1)
        for name in names[1:]:
            self.start(scheduler.watch(name))
        await self.wait_until(lambda: all(self.status(name) is not None for name in names))
        self.db.set_runtime("daemon", {"state": "running", "heartbeat_at": time.time()})
        report = health_report(self.config, self.db)
        self.assertEqual([row["watcher"] for row in report["modules"] if row["state"] == "running"], [names[0]])
        for name in names[1:]:
            self.assertEqual(self.status(name)["state"], "queued")
            self.assertIsNone(self.status(name)["started_at"])
        release.set()
        await self.wait_until(lambda: self.status(names[-1])["state"] == "success")
        self.assertEqual(calls, [(name, step) for name in names for step in ("start", 0, 1, 2, "finish")])

    async def test_failed_weekly_run_only_repeats_on_explicit_request(self):
        resumed = asyncio.Event()

        class Watchers:
            calls = 0

            async def dns_bruteforce(self, target):
                self.calls += 1
                if self.calls == 1:
                    return False  # Partial failures must use the weekly deadline too.
                resumed.set()
                await asyncio.Event().wait()

        watchers = Watchers()
        scheduler = Scheduler(self.config, self.db, watchers=watchers)
        task = self.start(scheduler.watch("dns_bruteforce"))
        await self.wait_until(lambda: self.status("dns_bruteforce") is not None
                              and self.status("dns_bruteforce")["state"] == "failed")
        await asyncio.sleep(0.04)  # Several failure-retry periods pass.
        self.assertEqual(watchers.calls, 1)
        for _ in range(2):
            self.db.request_run(self.target["id"], "dns_bruteforce")
        await asyncio.wait_for(resumed.wait(), 1)
        self.assertEqual(watchers.calls, 2)
        started = self.status("dns_bruteforce")["started_at"]
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.status("dns_bruteforce")["state"], "interrupted")
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.assertEqual(self.db.next_run_at(self.target["id"], "dns_bruteforce", 604800, 300), started + 604800)

    async def test_restart_respects_started_bruteforce_but_runs_waiting_work(self):
        target_id = self.target["id"]
        self.db.watcher_state(target_id, "dns_bruteforce", "queued")
        self.db.watcher_state(target_id, "dns_bruteforce", "running")
        started = self.status("dns_bruteforce")["started_at"]
        self.db.watcher_state(target_id, "tlsx", "queued")
        self.db.close()  # Simulate a crash, without Scheduler's cancellation handler.
        self.db = Database(self.path / "assets.db")
        calls = []

        class Watchers:
            def __getattr__(self, name):
                async def run(target, **options):
                    calls.append(name)
                    return True
                return run

        stop = asyncio.Event()
        scheduler = Scheduler(self.config, self.db, watchers=Watchers())
        task = self.start(scheduler.run(stop))
        await self.wait_until(lambda: "ptr_discovery" in calls)
        stop.set()
        await asyncio.wait_for(task, 1)
        self.assertIn("tlsx", calls)
        self.assertNotIn("dns_bruteforce", calls)
        self.assertEqual(self.db.next_run_at(target_id, "dns_bruteforce", 604800, 300), started + 604800)
        with patch("assetwatch.database.time.time", return_value=started + 604800):
            self.assertTrue(self.db.due(target_id, "dns_bruteforce", 604800, 300))

    async def test_cancelled_queued_bruteforce_does_not_consume_weekly_turn(self):
        scheduler = Scheduler(self.config, self.db)
        async with scheduler.scan_slot:
            task = self.start(scheduler.watch("dns_bruteforce"))
            await self.wait_until(lambda: self.status("dns_bruteforce") is not None)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertIsNone(self.status("dns_bruteforce")["started_at"])
        self.assertTrue(self.db.due(self.target["id"], "dns_bruteforce", 604800, 300))
        self.assertIsNone(self.db.connection.execute("SELECT * FROM watcher_runs").fetchone())

    async def test_queued_target_scope_is_refreshed_or_removed_before_execution(self):
        calls = []

        class Watchers:
            async def tlsx(self, target):
                calls.append(target)
                return True

        scheduler = Scheduler(self.config, self.db, watchers=Watchers())
        async with scheduler.scan_slot:
            self.start(scheduler.watch("tlsx"))
            await self.wait_until(lambda: self.status("tlsx") is not None)
            self.db.update_target("one", cidrs=["192.0.2.0/24"])
        await self.wait_until(lambda: bool(calls))
        self.assertEqual(calls[0]["cidrs"], ["192.0.2.0/24"])
        async with scheduler.scan_slot:
            self.db.request_run(self.target["id"], "tlsx")
            await self.wait_until(lambda: self.status("tlsx")["state"] == "queued")
            self.db.remove_target("one")
        await asyncio.sleep(0.01)
        self.assertEqual(len(calls), 1)
