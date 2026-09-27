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
from assetwatch.notifications import Notifier
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

    async def test_yaml_chaos_key_overrides_only_child_environment(self):
        script = self.path / "chaos"
        script.write_text(f"#!{sys.executable}\n"
                          "import os, sys\n"
                          "assert os.environ['PDCP_API_KEY'] == os.environ['EXPECTED_KEY']\n"
                          "assert os.environ['EXPECTED_KEY'] not in sys.argv\n"
                          "print('api.example.test')\n")
        script.chmod(0o755)
        self.config["tools"]["chaos"] = str(script)
        for key, expected in (("yaml-test-key", "yaml-test-key"), ("", "inherited-test-key")):
            self.config["chaos"]["api_key"] = key
            with patch.dict(os.environ, {"PDCP_API_KEY": "inherited-test-key", "EXPECTED_KEY": expected}):
                async with self.tools.passive("chaos", "example.test") as names:
                    self.assertEqual([name.strip() for name in names], ["api.example.test"])
                self.assertEqual(os.environ["PDCP_API_KEY"], "inherited-test-key")

    async def test_tool_progress_is_logged_before_process_finishes(self):
        self.config["tools"]["dnsgen"] = sys.executable
        self.config["runtime"]["progress_interval"] = 0.01
        release = self.path / "release"
        script = ("import pathlib, sys, time\n"
                  "print('candidate.example.test', flush=True)\n"
                  "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(0.01)\n")

        async def run():
            async with ToolRunner(self.config).run("dnsgen", ["-c", script, str(release)]) as output:
                self.assertEqual(output.read_text().strip(), "candidate.example.test")

        with self.assertLogs("assetwatch.tools", level="INFO") as logs:
            task = asyncio.create_task(run())
            try:
                async with asyncio.timeout(2):
                    while not any("state=running" in line for line in logs.output):
                        await asyncio.sleep(0.005)
                self.assertFalse(task.done())
                release.touch()
                await asyncio.wait_for(task, 2)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(any("output_bytes=" in line for line in logs.output))

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
        await self.watchers.ptr_discovery(self.target)
        self.assertTrue(await self.watchers.dns_bruteforce(self.target))
        assets = {asset["hostname"]: asset for asset in self.db.assets()}
        for name in ("api.example.test", "crt.example.test", "cert.example.test", "ptr.example.test", "static.example.test", "generated.example.test", "generated.example.org"):
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
            if record["tool"] == "dnsx" and "-ptr" in record["args"]:
                self.assertIn("-resp-only", record["args"])
            if record["tool"] == "subfinder":
                self.assertIn("-recursive", record["args"])
            if record["tool"] == "chaos":
                self.assertNotIn("-recursive", record["args"])
            if record["tool"] == "httpx":
                self.assertIn("-auto-referer", record["args"])
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
        # Successful independent CNAME checks still advance their observation timestamp.
        after = list(self.db.assets())
        for asset in before + after:
            asset.pop("cname_checked_at")
        self.assertEqual(after, before)

    async def test_cname_alerts_include_unresolved_assets_and_ignore_ip_notification_mute(self):
        self.db.ingest(self.target["id"], ["unresolved.example.test"], "subfinder")
        await self.watchers.dns_resolution(self.target)
        for event in self.db.pending_events(100):
            self.db.notification_result(event["id"])
        self.config["telegram"].update(enabled=True, bot_token="fixture-token", chat_id="123",
                                       send_delay=0.001, notify_dns_ip_changes=False)
        self.phase.write_text("4")
        await self.watchers.dns_resolution(self.target)
        cname_events = self.db.recent_events(kind="dns_cname_changed")
        self.assertEqual(len(cname_events), 3)
        unresolved = next(a for a in self.db.assets() if a["hostname"] == "unresolved.example.test")
        self.assertFalse(unresolved["dns_resolved"])
        self.assertEqual(unresolved["cname_records"], ["service.vendor.test"])
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            await notifier.flush()
            self.assertEqual(send.call_count, 3)
            self.assertTrue(all("DNS CNAME Changed" in call.args[2]["text"] for call in send.call_args_list))
            await self.watchers.dns_resolution(self.target)
            await notifier.flush()
            self.assertEqual(send.call_count, 3)

    async def test_bruteforce_logs_progress_and_delivers_each_new_asset_once(self):
        for event in self.db.pending_events(100):
            self.db.notification_result(event["id"])
        self.config["telegram"].update(enabled=True, bot_token="test-token", chat_id="123", send_delay=0.001)
        with self.assertLogs("assetwatch.watchers", level="INFO") as logs:
            self.assertTrue(await self.watchers.dns_bruteforce(self.target))
        for marker in ("mode=static", "tool=dnsgen batch=1", "mode=dynamic", "new_asset_events=", "state=complete success=True"):
            self.assertTrue(any(marker in line for line in logs.output), marker)
        notifier = Notifier(self.config, self.db)
        with patch("assetwatch.notifications.read_json", return_value={"ok": True}) as send:
            await notifier.flush()
            self.assertGreater(send.call_count, 0)
            self.assertTrue(all("DNS-Brute-Force New Asset" in call.args[2]["text"] for call in send.call_args_list))
            sent = send.call_count
            self.assertTrue(await self.watchers.dns_bruteforce(self.target))
            await notifier.flush()
            self.assertEqual(send.call_count, sent)
        self.assertEqual(self.db.pending_events(100), [])


if __name__ == "__main__":
    unittest.main()
