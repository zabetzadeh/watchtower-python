"""Discovery feeds one table; DNS and HTTP revisit every stored asset."""

import asyncio
import logging
import tempfile
from itertools import islice
from pathlib import Path

from .tools import Tools

LOG = logging.getLogger(__name__)


class Watchers:
    def __init__(self, config, database, tools=None):
        self.config = config
        self.db = database
        self.tools = tools or Tools(config)

    async def ingest(self, target, names, source):
        iterator = iter(names)
        total = new = 0
        while batch := list(islice(iterator, self.config["runtime"]["batch_size"])):
            total += len(batch)
            new += self.db.ingest(target["id"], batch, source)
            await asyncio.sleep(0)
        LOG.info("target=%s source=%s results=%s new_assets=%s", target["name"], source, total, new)

    async def passive_discovery(self, target):
        success = True
        for domain in target["domains"]:
            for source in ("subfinder", "chaos", "crtsh"):
                try:
                    async with self.tools.passive(source, domain) as names:
                        await self.ingest(target, names, source)
                except Exception as error:
                    success = False
                    LOG.error("target=%s domain=%s tool=%s error=%s", target["name"], domain, source, error)
        return success

    async def tlsx(self, target):
        if target["cidrs"]:
            async with self.tools.certificates(target["cidrs"]) as names:
                await self.ingest(target, names, "tlsx")
        return True

    async def dns_resolution(self, target):
        success = True
        for batch in self.db.asset_batches(target["id"], self.config["runtime"]["batch_size"]):
            try:
                observations = await self.tools.dns([asset["hostname"] for asset in batch])
                for asset in batch:
                    if asset["hostname"] in observations:
                        self.db.observe_dns(asset["id"], observations[asset["hostname"]])
                LOG.info("target=%s watcher=dns_resolution checked=%s resolved=%s inconclusive=%s",
                         target["name"], len(batch), sum(bool(ips) for ips in observations.values()),
                         len(batch) - len(observations))
            except Exception as error:
                success = False
                LOG.error("target=%s watcher=dns_resolution error=%s state_preserved=true", target["name"], error)
        return success

    async def http_probe(self, target):
        success = True
        for batch in self.db.asset_batches(target["id"], self.config["runtime"]["batch_size"], resolved_only=True):
            try:
                observations = await self.tools.http([asset["hostname"] for asset in batch])
                for asset in batch:
                    if asset["hostname"] in observations:
                        self.db.observe_http(asset["id"], observations[asset["hostname"]], asset["dns_version"])
                LOG.info("target=%s watcher=http_probe checked=%s available=%s inconclusive=%s",
                         target["name"], len(batch), sum(value is not None for value in observations.values()),
                         len(batch) - len(observations))
            except Exception as error:
                success = False
                LOG.error("target=%s watcher=http_probe error=%s state_preserved=true", target["name"], error)
        return success

    async def dns_bruteforce(self, target):
        settings = self.config["dns_bruteforce"]
        success = True
        if settings["static"]["enabled"]:
            directory = self.config.path(settings["static"]["wordlist_dir"])
            wordlists = sorted(path for path in directory.glob("*.txt") if path.is_file())
            if not wordlists:
                success = False
                LOG.warning("target=%s watcher=dns_bruteforce no_wordlists=%s", target["name"], directory)
            for domain in target["domains"]:
                for wordlist in wordlists:
                    try:
                        async with self.tools.shuffledns(domain, wordlist=wordlist) as names:
                            await self.ingest(target, names, "dns_bruteforce")
                    except Exception as error:
                        success = False
                        LOG.error("target=%s domain=%s wordlist=%s error=%s", target["name"], domain, wordlist, error)
        if settings["dynamic"]["enabled"]:
            try:
                await self.dynamic_bruteforce(target)
            except Exception as error:
                success = False
                LOG.error("target=%s watcher=dynamic_bruteforce error=%s", target["name"], error)
        return success

    async def dynamic_bruteforce(self, target):
        with tempfile.TemporaryDirectory(prefix="assetwatch-brute-") as directory:
            directory = Path(directory)
            inputs = directory / "new-hostnames.txt"
            batch_size = self.config["runtime"]["batch_size"]
            seed_batch_size = self.config["dns_bruteforce"]["dynamic"]["batch_size"]
            failures = []
            seeds = new_candidates = 0
            try:
                for batch in self.db.pending_dnsgen_batches(target["id"], seed_batch_size):
                    inputs.write_text("".join(asset["hostname"] + "\n" for asset in batch), encoding="utf-8")
                    async with self.tools.dnsgen(inputs) as names:
                        iterator = iter(names)
                        while candidates := list(islice(iterator, batch_size)):
                            new_candidates += self.db.cache_dnsgen_candidates(target["id"], candidates)
                            await asyncio.sleep(0)
                    self.db.finish_dnsgen_batch(target["id"], batch[-1]["id"])
                    seeds += len(batch)
            except Exception as error:
                LOG.error("target=%s tool=dnsgen error=%s checkpoint_preserved=true", target["name"], error)
                failures.append("dnsgen")
            LOG.info("target=%s tool=dnsgen new_seeds=%s new_candidates=%s", target["name"], seeds, new_candidates)

            # Reuse the full cache, including previously unresolved candidates. Only
            # one domain's input is exported at a time, in bounded database batches.
            path = directory / "candidates.txt"
            for domain in target["domains"]:
                count = 0
                with path.open("w", encoding="utf-8") as stream:
                    for batch in self.db.dnsgen_candidate_batches(target["id"], domain, batch_size):
                        stream.writelines(hostname + "\n" for hostname in batch)
                        count += len(batch)
                        await asyncio.sleep(0)
                if path.stat().st_size:
                    LOG.info("target=%s domain=%s mode=dynamic cached_candidates=%s", target["name"], domain, count)
                    try:
                        async with self.tools.shuffledns(domain, candidates=path) as names:
                            await self.ingest(target, names, "dns_bruteforce")
                    except Exception as error:
                        LOG.error("target=%s domain=%s mode=dynamic error=%s", target["name"], domain, error)
                        failures.append(domain)
            if failures:
                raise RuntimeError("Dynamic brute force failed for: " + ", ".join(failures))
