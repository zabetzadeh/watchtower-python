"""Independent bounded watcher tasks; one daemon may own a database."""

import asyncio
import logging
import signal
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone

from .notifications import Notifier
from .watchers import Watchers

LOG = logging.getLogger(__name__)
WATCHERS = ("passive_discovery", "tlsx", "dns_resolution", "http_probe", "dns_bruteforce")


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


class ScanGate:
    """Ordinary scans may overlap; brute force waits for exclusive access."""

    def __init__(self):
        self.condition = asyncio.Condition()
        self.active = 0
        self.exclusive = False
        self.waiting_exclusive = 0

    @asynccontextmanager
    async def slot(self, exclusive=False):
        async with self.condition:
            if exclusive:
                self.waiting_exclusive += 1
                try:
                    await self.condition.wait_for(lambda: not self.exclusive and self.active == 0)
                finally:
                    self.waiting_exclusive -= 1
                    self.condition.notify_all()
                self.exclusive = True
            else:
                # Once brute force is queued, let existing scans drain before admitting more.
                await self.condition.wait_for(lambda: not self.exclusive and self.waiting_exclusive == 0)
                self.active += 1
        try:
            yield
        finally:
            async with self.condition:
                if exclusive:
                    self.exclusive = False
                else:
                    self.active -= 1
                self.condition.notify_all()


class Scheduler:
    def __init__(self, config, database, watchers=None, notifier=None):
        self.config, self.db = config, database
        self.watchers = watchers or Watchers(config, database)
        self.notifier = notifier or Notifier(config, database)
        self.scans = ScanGate()

    async def watch(self, name):
        interval = self.config["intervals"][name]
        announced = set()
        while True:
            try:
                for target in self.db.targets():
                    if not self.db.due(target["id"], name, interval):
                        if target["id"] not in announced:
                            next_run = self.db.next_run_at(target["id"], name, interval)
                            LOG.info("watcher=%s target=%s state=scheduled next_run=%s",
                                     name, target["name"], datetime.fromtimestamp(next_run, timezone.utc).isoformat())
                            announced.add(target["id"])
                        continue
                    LOG.info("watcher=%s target=%s state=queued", name, target["name"])
                    success = False
                    try:
                        async with self.scans.slot(exclusive=name == "dns_bruteforce"):
                            LOG.info("watcher=%s target=%s state=started", name, target["name"])
                            success = await getattr(self.watchers, name)(target)
                    except Exception as error:
                        LOG.error("watcher=%s target=%s state=failed error=%s", name, target["name"], error)
                    self.db.finished(target["id"], name, bool(success))
                    next_run = self.db.next_run_at(target["id"], name, interval)
                    LOG.info("watcher=%s target=%s state=finished success=%s next_run=%s",
                             name, target["name"], success, datetime.fromtimestamp(next_run, timezone.utc).isoformat())
                    announced.add(target["id"])
            except Exception as error:
                LOG.error("watcher=%s scheduler_error=%s", name, error)
            await asyncio.sleep(self.config["runtime"]["poll_interval"])

    async def monitoring(self):
        while True:
            try:
                if await self.notifier.flush():
                    await asyncio.sleep(0)
                    continue
            except Exception as error:
                LOG.error("watcher=monitoring error=%s", error)
            await asyncio.sleep(self.config["intervals"]["monitoring"])

    async def run(self, stop: asyncio.Event | None = None):
        own_signals = stop is None
        stop = stop or asyncio.Event()
        loop = asyncio.get_running_loop()
        if own_signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
        tasks = [asyncio.create_task(self.watch(name), name=name) for name in WATCHERS]
        tasks.append(asyncio.create_task(self.monitoring(), name="monitoring"))
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
            if own_signals:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.remove_signal_handler(sig)
            LOG.info("daemon=stopped")
