import asyncio
import copy
import json
import os
import shutil
import signal
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.tools import ToolError, ToolRunner, Tools
from assetwatch.watchers import Watchers


class WrapperTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.tools = Tools(self.config)

    def output(self, rows):
        path = self.path / "output.jsonl"
        path.write_text("\n".join(json.dumps(row) if not isinstance(row, str) else row for row in rows) + "\n")

        @asynccontextmanager
        async def run(*args, **kwargs):
            yield path

        return patch.object(self.tools.runner, "run", run)

    async def test_dns_explicit_negatives_and_inconclusive_errors(self):
        with self.output([
            {"host": "yes.example.test", "status_code": "NOERROR", "a": ["192.0.2.1", "::1"]},
            {"host": "no.example.test", "status_code": "NXDOMAIN"},
            {"host": "empty.example.test", "status_code": "NOERROR", "a": []},
            {"host": "error.example.test", "status_code": "SERVFAIL"},
        ]):
            observed = await self.tools.dns(["yes.example.test", "no.example.test", "empty.example.test", "error.example.test", "timeout.example.test"])
        self.assertEqual(observed, {"yes.example.test": ["192.0.2.1"], "no.example.test": [], "empty.example.test": []})

    async def test_malformed_and_wrong_host_results_reject_batch(self):
        for rows in (["not JSON"], [{"host": "outside.test", "status_code": "NOERROR"}], [{"host": "example.test", "a": []}]):
            with self.output(rows):
                with self.assertRaises(ToolError):
                    await self.tools.dns(["example.test"])

    async def test_http_success_explicit_failure_and_missing(self):
        with self.output([
            {"input": "up.example.test", "url": "http://up.example.test", "status_code": 200},
            {"input": "up.example.test", "url": "https://up.example.test", "status_code": 403},
            {"input": "down.example.test", "url": "https://down.example.test", "failed": True},
        ]):
            results = await self.tools.http(["up.example.test", "down.example.test", "missing.example.test"])
        self.assertEqual(results["up.example.test"]["status_code"], 403)
        self.assertIsNone(results["down.example.test"])
        self.assertNotIn("missing.example.test", results)

    async def test_http_malformed_does_not_become_unavailable(self):
        with self.output([{"input": "example.test", "url": "https://example.test", "status_code": "200"}]):
            with self.assertRaises(ToolError):
                await self.tools.http(["example.test"])

    async def test_crtsh_multiline_names_and_encoded_query(self):
        with patch("assetwatch.tools.read_json", return_value=[{"name_value": "*.example.test\napi.example.test"}]) as get:
            async with self.tools.passive("crtsh", "example.test") as names:
                self.assertEqual(list(names), ["*.example.test", "api.example.test"])
        self.assertIn("q=%25.example.test", get.call_args.args[0])

    async def test_runner_nonzero_stderr_timeout_and_literal_arguments(self):
        self.config["tools"]["dnsx"] = sys.executable
        runner = ToolRunner(self.config)
        with self.assertRaises(ToolError):
            async with runner.run("dnsx", ["-c", "import sys; print('failed', file=sys.stderr); sys.exit(7)"]):
                self.fail("Nonzero exit yielded output")
        literal = "$(touch should-not-exist); echo secret"
        async with runner.run("dnsx", ["-c", "import sys; print(sys.argv[1])", literal]) as output:
            self.assertEqual(output.read_text().strip(), literal)
            temporary_output = output
        self.assertFalse(temporary_output.exists())
        self.config["runtime"]["tool_timeout"] = 0.05
        with self.assertRaises(ToolError):
            async with runner.run("dnsx", ["-c", "import time; time.sleep(30)"]):
                self.fail("Timed out tool yielded output")

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    async def test_cancellation_terminates_child_process_group(self):
        self.config["tools"]["dnsx"] = sys.executable
        pidfile = self.path / "pids"
        script = ("import os, subprocess, sys, time; "
                  "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                  "open(sys.argv[1], 'w').write(str(os.getpid()) + ' ' + str(p.pid)); time.sleep(30)")

        async def run():
            async with ToolRunner(self.config).run("dnsx", ["-c", script, str(pidfile)]):
                pass

        task = asyncio.create_task(run())
        for _ in range(100):
            if pidfile.exists() and pidfile.read_text():
                break
            await asyncio.sleep(0.01)
        self.assertTrue(pidfile.exists())
        parent, child = map(int, pidfile.read_text().split())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(ProcessLookupError):
            os.kill(parent, 0)
        # Grandchildren can briefly remain zombies awaiting the OS reaper.
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        process = await asyncio.create_subprocess_exec("ps", "-o", "stat=", "-p", str(child), stdout=asyncio.subprocess.PIPE)
        output, _ = await process.communicate()
        self.assertTrue(not output.strip() or output.strip().startswith(b"Z"), output)


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["runtime"]["batch_size"] = 3
        self.phase, self.calls = self.path / "phase", self.path / "calls.jsonl"
        self.phase.write_text("0")
        environment = patch.dict(os.environ, {"ASSETWATCH_TEST_PHASE": str(self.phase), "ASSETWATCH_TEST_CALLS": str(self.calls)})
        environment.start()
        self.addCleanup(environment.stop)
        for name in self.config["tools"]:
            destination = self.path / name
            shutil.copyfile(Path(__file__).with_name("fake_tool.py"), destination)
            destination.chmod(0o755)
            self.config["tools"][name] = str(destination)
        wordlists = self.path / "wordlists"
        wordlists.mkdir()
        (wordlists / "small.txt").write_text("api\ndev\n")
        (self.path / "resolvers.txt").write_text("192.0.2.53\n")
        self.db = Database(self.path / "assets.db")
        self.addCleanup(self.db.close)
        self.target = self.db.add_target("one", ["example.test", "example.org"], ["192.0.2.0/24"])
        self.watchers = Watchers(self.config, self.db)

    async def test_all_discovery_sources_feed_continuous_dns_http(self):
        with patch("assetwatch.tools.read_json", return_value=[{"name_value": "crt.example.test\nunresolved.example.test"}]):
            self.assertFalse(await self.watchers.passive_discovery(self.target))  # Chaos fails; other sources succeed.
        await self.watchers.tlsx(self.target)
        self.assertTrue(await self.watchers.dns_bruteforce(self.target))
        assets = {asset["hostname"]: asset for asset in self.db.assets()}
        for name in ("api.example.test", "crt.example.test", "cert.example.test", "static.example.test", "generated.example.test", "generated.example.org"):
            self.assertIn(name, assets)
        self.assertNotIn("outside.invalid", assets)
        self.assertNotIn("wrong-cidr.example.test", assets)
        await self.watchers.dns_resolution(self.target)
        await self.watchers.http_probe(self.target)
        self.assertTrue(next(asset for asset in self.db.assets() if asset["hostname"] == "generated.example.test")["http_available"])
        for phase in (1, 2, 0):
            self.phase.write_text(str(phase))
            await self.watchers.http_probe(self.target)
        generated = next(asset for asset in self.db.assets() if asset["hostname"] == "generated.example.test")
        kinds = [row[0] for row in self.db.connection.execute("SELECT event_type FROM events WHERE asset_id=? ORDER BY id", (generated["id"],))]
        self.assertEqual(kinds, ["fresh_asset", "fresh_subdomain", "http_service_appeared", "http_status_changed", "http_service_disappeared", "http_service_returned"])
        records = [json.loads(line) for line in self.calls.read_text().splitlines()]
        http_inputs = [host for record in records if record["tool"] == "httpx" for host in record["input"]]
        self.assertNotIn("unresolved.example.test", http_inputs)
        dnsgen_input = next(record["input"] for record in records if record["tool"] == "dnsgen")
        self.assertIn("unresolved.example.test", dnsgen_input)
        self.assertIn("api.example.org", dnsgen_input)
        for record in records:
            if record["tool"] == "shuffledns":
                args = record["args"]
                self.assertEqual(args[args.index("-t") + 1], "10")
                self.assertEqual(args[args.index("-wt") + 1], "10")
                self.assertEqual(args[args.index("-m") + 1], self.config["tools"]["massdns"])
                self.assertNotIn("outside.invalid", record.get("input", []))

    async def test_failed_dns_batch_preserves_state_and_other_batches_continue(self):
        await self.watchers.dns_resolution(self.target)
        await self.watchers.http_probe(self.target)
        before = list(self.db.assets())
        with patch.object(self.watchers.tools, "dns", side_effect=ToolError("dnsx failed")):
            self.assertFalse(await self.watchers.dns_resolution(self.target))
        self.assertEqual(list(self.db.assets()), before)


if __name__ == "__main__":
    unittest.main()
