import asyncio
import copy
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.tools import ToolRunner


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_cli_signals_and_concurrent_inspection(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as directory:
                directory = Path(directory)
                config = directory / "config.yaml"
                config.write_text(yaml.safe_dump({"runtime": {"poll_interval": 0.01}, "program_watch": {"enabled": False}}))
                command = [sys.executable, "-m", "assetwatch", "--config", str(config)]
                process = await asyncio.create_subprocess_exec(*command, "run", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    logfile = directory / "logs/assetwatch.log"
                    for _ in range(200):
                        if logfile.exists() and "daemon=started" in logfile.read_text():
                            break
                        await asyncio.sleep(0.01)
                    self.assertIn("daemon=started", logfile.read_text())
                    inspector = await asyncio.create_subprocess_exec(*command, "targets", "--format", "json", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    output, errors = await asyncio.wait_for(inspector.communicate(), 5)
                    self.assertEqual(inspector.returncode, 0, errors)
                    self.assertEqual(output.strip(), b"[]")
                    second = await asyncio.create_subprocess_exec(*command, "run", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    _, errors = await asyncio.wait_for(second.communicate(), 5)
                    self.assertEqual(second.returncode, 2)
                    self.assertIn(b"already owns", errors)
                    process.send_signal(sig)
                    _, errors = await asyncio.wait_for(process.communicate(), 5)
                    self.assertEqual(process.returncode, 0, errors)
                    self.assertIn("daemon=stopped", logfile.read_text())
                    db = Database(directory / "data/assets.db")
                    try:
                        self.assertEqual(db.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    finally:
                        db.close()
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()

    async def test_help_capture_supports_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(copy.deepcopy(DEFAULTS), Path(directory))
            config["tools"]["massdns"] = sys.executable
            async with ToolRunner(config).run("massdns", ["-c", "import sys; print('--resolvers', file=sys.stderr)"], merge_stderr=True) as output:
                self.assertIn("--resolvers", output.read_text())

    async def test_unchanged_dns_allows_inflight_http_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "assets.db")
            try:
                db.add_target("one", ["example.test"], [])
                asset = next(db.assets())
                db.observe_dns(asset["id"], ["192.0.2.1"])
                version = next(db.assets())["dns_version"]
                db.observe_dns(asset["id"], ["192.0.2.1"])
                db.observe_http(asset["id"], {"status_code": 200, "url": "https://example.test"}, version)
                self.assertTrue(next(db.assets())["http_available"])
            finally:
                db.close()
