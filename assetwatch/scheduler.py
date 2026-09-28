"""FIFO module runs with independent deadlines; one daemon owns the database."""

import asyncio
import logging
import math
import signal
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from .notifications import Notifier
from .bot import Bot
from .config import PROGRAM_FEEDS, WATCHERS
from .programs import ProgramWatcher
from .logging_config import redact
from .watchers import Watchers

LOG = logging.getLogger(__name__)


@contextmanager
def daemon_lock(path):
    import fcntl

    # macOS unifies flock and SQLite's byte-range locks, so use an empty sidecar.
    # Never unlink it: an open daemon must keep locking the same inode.
    with open(str(path) + ".lock", "a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another assetwatch daemon already owns this database") from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


class Scheduler:
    def __init__(self, config, database, watchers=None, notifier=None):
        self.config, self.db = config, database
        self.notify_wake = asyncio.Event()
        self.db.on_event = self.notify_wake.set
        self.watchers = watchers or Watchers(config, database)
        self.notifier = notifier or Notifier(config, database)
        self.programs = ProgramWatcher(config, database)
        # Keep whole modules together, including ingestion and tool cooldowns.
        # Each watcher can queue one target at a time; Lock waiters are FIFO.
        self.scan_slot = asyncio.Lock()

    async def watch(self, name):
        interval = self.config["intervals"][name]
        retry_interval = self.config["runtime"]["failure_retry_interval"]
        announced = set()
        while True:
            try:
                for target in self.db.targets():
                    if not self.db.due(target["id"], name, interval, retry_interval):
                        if target["id"] not in announced:
                            next_run = self.db.next_run_at(target["id"], name, interval, retry_interval)
                            LOG.info("watcher=%s target=%s state=scheduled next_run=%s",
                                     name, target["name"], self.display_time(next_run))
                            announced.add(target["id"])
                        continue
                    LOG.info("watcher=%s target=%s state=queued", name, target["name"])
                    self.db.watcher_state(target["id"], name, "queued",
                                          "Waiting for the FIFO module queue")
                    async with self.scan_slot:
                        # Target scope can change while another module is running.
                        current = next((item for item in self.db.targets() if item["id"] == target["id"]), None)
                        if current is None:
                            continue
                        await self.execute(name, current, interval, retry_interval)
                    announced.add(target["id"])
            except Exception as error:
                LOG.error("watcher=%s scheduler_error=%s", name, error)
            await asyncio.sleep(self.config["runtime"]["poll_interval"])

    async def execute(self, name, target, interval, retry_interval):
        success = False
        try:
            with self.db.transaction():
                self.db.consume_run_request(target["id"], name)
                self.db.watcher_state(target["id"], name, "running", "Started; owns the module queue")
            LOG.info("watcher=%s target=%s state=started", name, target["name"])
            options = {"queued_only": True} if name in {"dns_resolution", "http_probe"} else {}
            success = await getattr(self.watchers, name)(target, **options)
        except asyncio.CancelledError:
            detail = ("Daemon stopped; next attempt follows the configured interval"
                      if name == "dns_bruteforce" else "Daemon stopped; run will be retried")
            self.db.watcher_state(target["id"], name, "interrupted", detail)
            if name not in {"dns_resolution", "http_probe", "dns_bruteforce"}:
                self.db.request_run(target["id"], name)
            raise
        except Exception as error:
            reason = redact(self.config, str(error))[:1000]
            self.db.watcher_progress(target["id"], name, reason, error=reason)
            LOG.error("watcher=%s target=%s state=failed error=%s", name, target["name"], error)
        self.db.finished(target["id"], name, bool(success))
        next_run = self.db.next_run_at(target["id"], name, interval, retry_interval)
        LOG.info("watcher=%s target=%s state=finished success=%s next_run=%s",
                 name, target["name"], success, self.display_time(next_run))

    @staticmethod
    def display_time(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if math.isfinite(timestamp) else "waiting_for_assets"

    async def monitoring(self):
        while True:
            try:
                if await self.notifier.flush():
                    await asyncio.sleep(0)
                    continue
            except Exception as error:
                LOG.error("watcher=monitoring error=%s", error)
                self.db.set_runtime("delivery", {"state": "failed", "error": type(error).__name__, "checked_at": time.time()})
            try:
                await asyncio.wait_for(self.notify_wake.wait(), timeout=self.config["intervals"]["monitoring"])
                self.notify_wake.clear()
            except TimeoutError:
                pass

    async def heartbeat(self):
        while True:
            try:
                self.db.set_runtime("daemon", {"state": "running", "heartbeat_at": time.time()})
            except Exception as error:
                LOG.error("daemon=heartbeat_failed error=%s", error)
            await asyncio.sleep(self.config["runtime"]["poll_interval"])

    async def run(self, stop: asyncio.Event | None = None):
        own_signals = stop is None
        stop = stop or asyncio.Event()
        loop = asyncio.get_running_loop()
        for row in self.db.connection.execute("SELECT target_id,watcher FROM watcher_status WHERE state IN ('running','queued','interrupted')"):
            if row["watcher"] not in {"dns_resolution", "http_probe", "dns_bruteforce"}:
                self.db.request_run(row["target_id"], row["watcher"])
            detail = ("Previous run interrupted; next attempt follows the configured interval"
                      if row["watcher"] == "dns_bruteforce" else "Previous run interrupted; retry queued")
            self.db.watcher_state(row["target_id"], row["watcher"], "interrupted", detail)
        if own_signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
        tasks = [asyncio.create_task(self.watch(name), name=name) for name in WATCHERS]
        tasks += [asyncio.create_task(self.programs.watch(platform), name="program_watch:" + platform)
                  for platform in PROGRAM_FEEDS]
        tasks.append(asyncio.create_task(self.monitoring(), name="monitoring"))
        tasks.append(asyncio.create_task(Bot(self.config, self.db).run(), name="telegram_commands"))
        tasks.append(asyncio.create_task(self.heartbeat(), name="heartbeat"))
        LOG.info("daemon=started targets=%s watchers=%s", len(self.db.targets()), len(tasks))
        if not self.config["telegram"]["enabled"]:
            LOG.warning("telegram=disabled events_are_stored=true enable=telegram.enabled")
        else:
            LOG.info("telegram=enabled poll_interval=%s notify_dns_ip_changes=%s",
                     self.config["intervals"]["monitoring"], self.config["telegram"]["notify_dns_ip_changes"])
        try:
            await stop.wait()
        finally:
            LOG.info("daemon=stopping")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.db.set_runtime("daemon", {"state": "stopped", "heartbeat_at": time.time()})
            if own_signals:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.remove_signal_handler(sig)
            LOG.info("daemon=stopped")
