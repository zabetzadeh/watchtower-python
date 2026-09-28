import asyncio
import copy
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from assetwatch.config import Config, DEFAULTS
from assetwatch.database import Database
from assetwatch.tools import ToolError, ToolRunner
from assetwatch.watchers import Watchers


class DynamicTools:
    def __init__(self):
        self.generated = []
        self.resolved = []
        self.fail_generation = None
        self.fail_resolution = False

    @asynccontextmanager
    async def dnsgen(self, inputs):
        seeds = inputs.read_text().splitlines()
        self.generated.append(seeds)
        if len(self.generated) == self.fail_generation:
            raise ToolError("generation failed")
        names = ["dev." + seed for seed in seeds]
        yield iter(names + ["*." + name.upper() + "." for name in names] + ["outside.invalid"])

    @asynccontextmanager
    async def shuffledns(self, domain, *, candidates=None, wordlist=None):
        if candidates is not None:
            self.resolved.append((domain, candidates.read_text().splitlines()))
        if wordlist is not None:
            words = wordlist.read_text().splitlines()
            self.resolved.append((domain, words))
            yield iter([w + "." + domain for w in words])
            return
        if self.fail_resolution:
            raise ToolError("resolution failed")
        yield iter(())  # Cached candidates remain unresolved and must be retried.


class IncrementalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.config = Config(copy.deepcopy(DEFAULTS), self.path)
        self.config["runtime"]["batch_size"] = 2
        self.config["dns_bruteforce"]["dynamic"]["batch_size"] = 2
        self.db = Database(self.path / "assets.db")
        self.addCleanup(lambda: self.db.close())
        self.target = self.db.add_target("one", ["example.test", "example.org"], [])
        self.tools = DynamicTools()
        self.watchers = Watchers(self.config, self.db, self.tools)

    def reopen(self):
        self.db.close()
        self.db = Database(self.path / "assets.db")
        self.watchers = Watchers(self.config, self.db, self.tools)

    def candidates(self):
        return [row[0] for row in self.db.connection.execute(
            "SELECT hostname FROM dnsgen_candidates WHERE target_id=? ORDER BY hostname", (self.target["id"],))]

    async def test_batches_cache_reuse_new_findings_and_restart(self):
        self.db.ingest(self.target["id"], ["api.example.test", "unresolved.example.test", "api.example.org"], "subfinder")
        other = self.db.add_target("two", ["example.test"], [])
        self.db.ingest(other["id"], ["private.example.test"], "tlsx")
        expected = {asset["hostname"] for asset in self.db.assets(self.target["id"])}

        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual([len(batch) for batch in self.tools.generated], [2, 2, 1])
        self.assertEqual({host for batch in self.tools.generated for host in batch}, expected)
        self.assertEqual(set(self.candidates()), {"dev." + host for host in expected})
        first_resolution = self.tools.resolved[:]
        for domain, names in first_resolution:
            self.assertEqual(len(names), len(set(names)))
            self.assertTrue(all(name.endswith("." + domain) for name in names))

        self.reopen()
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.tools.generated), 3)
        self.assertEqual(self.tools.resolved[2:], first_resolution)

        self.db.ingest(self.target["id"], ["new.example.test", "api.example.test"], "tlsx")
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(self.tools.generated[3:], [["new.example.test"]])
        self.assertEqual(set(self.candidates()), {"dev." + host for host in expected | {"new.example.test"}})
        self.assertNotIn("dev.private.example.test", self.candidates())

    async def test_failed_generation_retries_only_unfinished_batches(self):
        self.db.ingest(self.target["id"], ["api.example.test", "api.example.org"], "subfinder")
        self.tools.fail_generation = 2
        with self.assertRaises(RuntimeError):
            await self.watchers.dynamic_bruteforce(self.target)
        completed, failed = self.tools.generated
        self.assertEqual(len(self.candidates()), 2)
        self.assertTrue(self.tools.resolved)  # Still resolve the cache from completed batches.
        self.reopen()
        self.tools.fail_generation = None
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(self.tools.generated, [completed, failed, failed])
        self.assertEqual(len(self.candidates()), 4)

    async def test_failed_resolution_does_not_regenerate_cached_candidates(self):
        self.tools.fail_resolution = True
        with self.assertRaises(RuntimeError):
            await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.tools.generated), 1)
        self.assertEqual(len(self.candidates()), 2)
        self.reopen()
        self.tools.fail_resolution = False
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.tools.generated), 1)
        self.assertEqual(self.tools.resolved[:2], self.tools.resolved[2:])

    async def test_cancelled_cache_append_retries_without_duplicates(self):
        self.config["runtime"]["batch_size"] = 1

        @asynccontextmanager
        async def interrupted(inputs):
            def output():
                yield "dev." + inputs.read_text().splitlines()[0]
                raise asyncio.CancelledError
            yield output()

        with patch.object(self.tools, "dnsgen", interrupted):
            with self.assertRaises(asyncio.CancelledError):
                await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.candidates()), 1)
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM dnsgen_progress").fetchone()[0], 0)
        self.reopen()
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.candidates()), 2)
        self.assertEqual(len(self.tools.generated), 1)

    async def test_existing_database_gains_cache_without_losing_assets(self):
        # Simulate a database made before the cache tables existed.
        self.db.connection.execute("DROP TABLE dnsgen_candidates")
        self.db.connection.execute("DROP TABLE dnsgen_progress")
        before = list(self.db.assets())
        self.reopen()
        self.assertEqual(list(self.db.assets()), before)
        await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(len(self.candidates()), 2)

    async def test_static_bruteforce_wordlist_chunking(self):
        wordlist_dir = self.path / "wordlists"
        wordlist_dir.mkdir(parents=True, exist_ok=True)
        wordlist_file = wordlist_dir / "test.txt"
        # Write 7 words
        wordlist_file.write_text("\n".join(f"sub{i}" for i in range(7)) + "\n")
        resolvers_file = self.path / "resolvers.txt"
        resolvers_file.write_text("1.1.1.1\n")

        self.config["dns_bruteforce"]["static"]["wordlist_dir"] = str(wordlist_dir)
        self.config["dns_bruteforce"]["static"]["chunk_size"] = 3
        self.config["dns_bruteforce"]["shuffledns"]["resolvers"] = str(resolvers_file)
        self.config["dns_bruteforce"]["shuffledns"]["cooldown"] = 0.001
        self.config["dns_bruteforce"]["dynamic"]["enabled"] = False

        self.tools.resolved.clear()
        success = await self.watchers.dns_bruteforce(self.target)
        self.assertTrue(success)

        # 2 domains * (3 chunks of size 3, 3, 1) = 6 resolved calls
        chunk_calls = [c for c in self.tools.resolved if c[0] == "example.test"]
        self.assertEqual(len(chunk_calls), 3)
        self.assertEqual(len(chunk_calls[0][1]), 3)
        self.assertEqual(len(chunk_calls[1][1]), 3)
        self.assertEqual(len(chunk_calls[2][1]), 1)

        # Check all 7 subdomains ingested
        assets = [a["hostname"] for a in self.db.assets(self.target["id"])]
        for i in range(7):
            self.assertIn(f"sub{i}.example.test", assets)

    async def test_static_wordlist_is_consumed_lazily_before_first_tool_call(self):
        directory = self.path / "wordlists"
        directory.mkdir()
        wordlist = directory / "words.txt"
        wordlist.write_text("placeholder")
        (self.path / "resolvers.txt").write_text("192.0.2.53\n")
        self.config["dns_bruteforce"]["static"]["chunk_size"] = 3
        self.config["dns_bruteforce"]["dynamic"]["enabled"] = False
        consumed = []

        class Stream:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def __iter__(self):
                for number in range(10):
                    consumed.append(number)
                    if number > 2:
                        raise AssertionError("Read ahead beyond the current chunk")
                    yield f"sub{number}\n"

        original_open = Path.open

        def open_file(path, *args, **kwargs):
            return Stream() if path.resolve() == wordlist.resolve() else original_open(path, *args, **kwargs)

        @asynccontextmanager
        async def shuffledns(*args, **kwargs):
            self.assertEqual(consumed, [0, 1, 2])
            raise asyncio.CancelledError
            yield  # Make this an async context manager without executing any tool.

        with patch.object(Path, "open", open_file), patch.object(self.tools, "shuffledns", shuffledns):
            with self.assertRaises(asyncio.CancelledError):
                await self.watchers.dns_bruteforce(self.target)

    async def test_dynamic_chunk_size_limits_tools_and_failed_chunk_does_not_drop_the_rest(self):
        self.config["dns_bruteforce"]["dynamic"]["chunk_size"] = 2
        self.config["dns_bruteforce"]["shuffledns"]["cooldown"] = 0
        self.db.ingest(self.target["id"], [f"sub{i}.example.test" for i in range(6)], "subfinder")
        calls = []

        @asynccontextmanager
        async def shuffledns(domain, *, candidates):
            names = candidates.read_text().splitlines()
            calls.append(names)
            self.assertLessEqual(len(names), 2)
            if len(calls) == 1:
                raise ToolError("failed first chunk")
            yield names

        with patch.object(self.tools, "shuffledns", shuffledns):
            with self.assertRaises(RuntimeError):
                await self.watchers.dynamic_bruteforce(self.target)
        self.assertEqual(sum(map(len, calls)), 8)
        self.assertEqual(len(list(self.db.assets(source="dns_bruteforce"))), 7)
        self.assertEqual(self.db.pending_events(100, validated_only=True), [])

    async def test_target_management_cidr_and_domain(self):
        # Target with only CIDR
        cidr_target = self.db.add_target("cidr_only", [], ["10.0.0.0/24"])
        self.assertEqual(cidr_target["domains"], [])
        self.assertEqual(cidr_target["cidrs"], ["10.0.0.0/24"])

        # Passive discovery and brute force gracefully skip without domain
        self.assertTrue(await self.watchers.passive_discovery(cidr_target))
        self.assertTrue(await self.watchers.dns_bruteforce(cidr_target))

        # Update target with new domain and CIDR
        updated = self.db.update_target("cidr_only", ["mycorp.test"], ["10.1.0.0/24"])
        self.assertEqual(updated["domains"], ["mycorp.test"])
        self.assertEqual(sorted(updated["cidrs"]), ["10.0.0.0/24", "10.1.0.0/24"])


class ToolQueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_fifo_queue_yields_between_bruteforce_chunks(self):
        runner = ToolRunner(None)
        calls = []
        first_started, release = asyncio.Event(), asyncio.Event()

        @asynccontextmanager
        async def execute(name, *args, **kwargs):
            calls.append(name)
            if len(calls) == 1:
                first_started.set()
                await release.wait()
            yield Path("unused")

        async def chunks():
            for _ in range(2):
                async with runner.run("shuffledns", []):
                    pass

        async def dns():
            async with runner.run("dnsx", []):
                pass

        with patch.object(runner, "execute", execute):
            brute = asyncio.create_task(chunks())
            await first_started.wait()
            normal = asyncio.create_task(dns())
            await asyncio.sleep(0)
            self.assertEqual(calls, ["shuffledns"])
            release.set()
            await asyncio.wait_for(asyncio.gather(brute, normal), 1)
        self.assertEqual(calls, ["shuffledns", "dnsx", "shuffledns"])

    async def test_cancelled_waiter_never_executes_and_releases_queue(self):
        runner = ToolRunner(None)
        calls = []

        @asynccontextmanager
        async def execute(name, *args, **kwargs):
            calls.append(name)
            yield Path("unused")

        async def run(name):
            async with runner.run(name, []):
                pass

        with patch.object(runner, "execute", execute):
            async with runner.slot:
                cancelled = asyncio.create_task(run("shuffledns"))
                normal = asyncio.create_task(run("httpx"))
                await asyncio.sleep(0)
                cancelled.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await cancelled
                self.assertEqual(calls, [])
            await asyncio.wait_for(normal, 1)
        self.assertEqual(calls, ["httpx"])
