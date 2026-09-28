"""Discovery feeds one table; DNS and HTTP revisit every stored asset."""

import asyncio
import ipaddress
import logging
import tempfile
from itertools import islice
from pathlib import Path

from .tools import Tools
from .logging_config import redact

LOG = logging.getLogger(__name__)


class Watchers:
    def __init__(self, config, database, tools=None):
        self.config = config
        self.db = database
        self.tools = tools or Tools(config)

    def error(self, target, watcher, error):
        reason = redact(self.config, str(error))[:1000]
        self.db.watcher_progress(target["id"], watcher, reason, error=reason)

    async def ingest(self, target, names, source):
        iterator = iter(names)
        total = new = 0
        while batch := list(islice(iterator, self.config["runtime"]["batch_size"])):
            total += len(batch)
            new += self.db.ingest(target["id"], batch, source)
            await asyncio.sleep(0)
        LOG.info("target=%s source=%s results=%s new_assets=%s", target["name"], source, total, new)
        watcher = {"subfinder": "passive_discovery", "chaos": "passive_discovery", "crtsh": "passive_discovery",
                   "ptr": "ptr_discovery"}.get(source, source)
        self.db.watcher_progress(target["id"], watcher, f"{source}: results={total} new_assets={new}",
                                 results=total, new_assets=new)
        return new

    async def passive_discovery(self, target):
        if not target["domains"]:
            self.db.watcher_state(target["id"], "passive_discovery", "skipped", "No domains configured for this target")
            LOG.info("target=%s watcher=passive_discovery state=skipped reason=no_domains", target["name"])
            return True
        success = True
        for domain in target["domains"]:
            for source in ("subfinder", "chaos", "crtsh"):
                try:
                    async with self.tools.passive(source, domain) as names:
                        await self.ingest(target, names, source)
                except Exception as error:
                    success = False
                    self.error(target, "passive_discovery", error)
                    LOG.error("target=%s domain=%s tool=%s error=%s", target["name"], domain, source, error)
        return success

    async def tlsx(self, target):
        if target["cidrs"]:
            self.db.watcher_progress(target["id"], "tlsx", f"Scanning {len(target['cidrs'])} configured CIDRs")
            async with self.tools.certificates(target["cidrs"]) as names:
                await self.ingest(target, names, "tlsx")
        else:
            self.db.watcher_state(target["id"], "tlsx", "skipped", "No CIDRs configured for this target")
            LOG.info("target=%s watcher=tlsx state=skipped reason=no_configured_cidrs", target["name"])
        return True

    async def ptr_discovery(self, target):
        success = True
        networks = [ipaddress.ip_network(cidr) for cidr in target["cidrs"]]

        def inputs():
            # Let dnsx stream CIDR expansion; never materialize networks in Python.
            for cidr in target["cidrs"]:
                yield [cidr]
            for batch in self.db.ip_batches(target["id"], self.config["runtime"]["batch_size"]):
                remaining = [ip for ip in batch if not any(ipaddress.ip_address(ip) in net for net in networks)]
                if remaining:
                    yield remaining

        checked = False
        for batch in inputs():
            checked = True
            try:
                self.db.watcher_progress(target["id"], "ptr_discovery", f"Querying PTR for {len(batch)} IP/CIDR inputs")
                async with self.tools.ptr(batch) as names:
                    await self.ingest(target, names, "ptr")
            except Exception as error:
                success = False
                self.error(target, "ptr_discovery", error)
                LOG.error("target=%s watcher=ptr_discovery error=%s", target["name"], error)
        if not checked:
            self.db.watcher_state(target["id"], "ptr_discovery", "skipped", "No observed A records or configured CIDRs yet")
            LOG.info("target=%s watcher=ptr_discovery state=skipped reason=no_ip_inputs", target["name"])
        return success

    async def dns_resolution(self, target, *, queued_only=False):
        success = True
        for batch in self.db.asset_batches(target["id"], self.config["runtime"]["batch_size"],
                                          due_watcher="dns_resolution" if queued_only else None):
            observations, cnames = {}, {}
            try:
                observations = await self.tools.dns([asset["hostname"] for asset in batch])
                for asset in batch:
                    if asset["hostname"] in observations:
                        self.db.observe_dns(asset["id"], observations[asset["hostname"]])
                LOG.info("target=%s watcher=dns_resolution checked=%s resolved=%s inconclusive=%s",
                         target["name"], len(batch), sum(bool(ips) for ips in observations.values()),
                         len(batch) - len(observations))
                self.db.watcher_progress(target["id"], "dns_resolution", f"A records: checked={len(batch)}",
                                         results=len(observations))
                if len(observations) < len(batch):
                    success = False
                    self.error(target, "dns_resolution", "Inconclusive A responses; previous state preserved")
            except Exception as error:
                success = False
                self.error(target, "dns_resolution", error)
                LOG.error("target=%s watcher=dns_resolution error=%s state_preserved=true", target["name"], error)
            try:
                cnames = await self.tools.cnames([asset["hostname"] for asset in batch])
                for asset in batch:
                    if asset["hostname"] in cnames:
                        self.db.observe_cnames(asset["id"], cnames[asset["hostname"]])
                LOG.info("target=%s watcher=dns_resolution record=cname checked=%s inconclusive=%s",
                         target["name"], len(batch), len(batch) - len(cnames))
                if len(cnames) < len(batch):
                    success = False
                    self.error(target, "dns_resolution", "Inconclusive CNAME responses; previous state preserved")
            except Exception as error:
                success = False
                self.error(target, "dns_resolution", error)
                LOG.error("target=%s watcher=dns_resolution record=cname error=%s state_preserved=true", target["name"], error)
            for asset in batch:
                delay = self.config["intervals"]["dns_resolution"]
                if asset["hostname"] not in observations or asset["hostname"] not in cnames:
                    delay = min(delay, self.config["runtime"]["failure_retry_interval"])
                self.db.schedule_check(asset["id"], "dns_resolution", delay)
        return success

    async def http_probe(self, target, *, queued_only=False):
        success = True
        for batch in self.db.asset_batches(target["id"], self.config["runtime"]["batch_size"], resolved_only=True,
                                          due_watcher="http_probe" if queued_only else None):
            observed = set()
            try:
                observations = await self.tools.http([asset["hostname"] for asset in batch])
                for asset in batch:
                    if asset["hostname"] in observations:
                        if self.db.observe_http(asset["id"], observations[asset["hostname"]], asset["dns_version"]):
                            observed.add(asset["id"])
                LOG.info("target=%s watcher=http_probe checked=%s available=%s inconclusive=%s",
                         target["name"], len(batch), sum(asset["id"] in observed and observations[asset["hostname"]] is not None
                                                        for asset in batch), len(batch) - len(observed))
                self.db.watcher_progress(target["id"], "http_probe", f"HTTP checked={len(batch)}", results=len(observed))
                if len(observed) < len(batch):
                    success = False
                    self.error(target, "http_probe", "Inconclusive or stale HTTP responses; previous state preserved")
            except Exception as error:
                success = False
                self.error(target, "http_probe", error)
                LOG.error("target=%s watcher=http_probe error=%s state_preserved=true", target["name"], error)
            for asset in batch:
                delay = self.config["intervals"]["http_probe"]
                if asset["id"] not in observed:
                    delay = min(delay, self.config["runtime"]["failure_retry_interval"])
                self.db.schedule_check(asset["id"], "http_probe", delay)
        return success

    async def dns_bruteforce(self, target):
        settings = self.config["dns_bruteforce"]
        success = True
        if not settings["static"]["enabled"] and not settings["dynamic"]["enabled"]:
            self.db.watcher_state(target["id"], "dns_bruteforce", "skipped", "Static and dynamic modes are disabled")
            LOG.info("target=%s watcher=dns_bruteforce state=skipped reason=both_modes_disabled", target["name"])
            return True
        if not target["domains"]:
            self.db.watcher_state(target["id"], "dns_bruteforce", "skipped", "No domains configured for this target")
            LOG.info("target=%s watcher=dns_bruteforce state=skipped reason=no_domains", target["name"])
            return True
        LOG.info("target=%s watcher=dns_bruteforce static_enabled=%s dynamic_enabled=%s threads=%s",
                 target["name"], settings["static"]["enabled"], settings["dynamic"]["enabled"],
                 settings["shuffledns"]["threads"])
        resolvers = self.config.path(settings["shuffledns"]["resolvers"])
        if not resolvers.is_file() or not resolvers.stat().st_size:
            reason = f"ShuffleDNS requires a nonempty resolver file: {resolvers}"
            self.error(target, "dns_bruteforce", reason)
            LOG.error("target=%s watcher=dns_bruteforce error=%s", target["name"], reason)
            return False
        if settings["static"]["enabled"]:
            directory = self.config.path(settings["static"]["wordlist_dir"])
            wordlists = sorted(path for path in directory.glob("*.txt") if path.is_file() and path.stat().st_size)
            if not wordlists:
                success = False
                self.error(target, "dns_bruteforce", f"No nonempty .txt wordlists in {directory}")
                LOG.warning("target=%s watcher=dns_bruteforce no_wordlists=%s", target["name"], directory)
            chunk_size = settings["static"].get("chunk_size", 5000)
            cooldown = settings["shuffledns"].get("cooldown", 1.0)
            for domain in target["domains"]:
                for number, wordlist in enumerate(wordlists, 1):
                    LOG.info("target=%s domain=%s mode=static wordlist=%s wordlist_number=%s wordlists=%s state=started",
                             target["name"], domain, wordlist.name, number, len(wordlists))
                    try:
                        with wordlist.open(encoding="utf-8", errors="replace") as stream, \
                                tempfile.TemporaryDirectory(prefix="assetwatch-brute-chunk-") as tmpdir:
                            chunk_file = Path(tmpdir) / "chunk.txt"
                            words_iter = (word for line in stream if (word := line.strip()) and not word.startswith("#"))
                            chunk_num = 0
                            while words := list(islice(words_iter, chunk_size)):
                                chunk_num += 1
                                if chunk_num > 1:
                                    await asyncio.sleep(cooldown)
                                chunk_file.write_text("\n".join(words) + "\n", encoding="utf-8")
                                self.db.watcher_progress(
                                    target["id"], "dns_bruteforce",
                                    f"Static: {domain}, wordlist {number}/{len(wordlists)} ({wordlist.name}) chunk {chunk_num} ({len(words)} words)")
                                try:
                                    async with self.tools.shuffledns(domain, wordlist=chunk_file) as names:
                                        new = await self.ingest(target, names, "dns_bruteforce")
                                    LOG.info("target=%s domain=%s mode=static wordlist=%s chunk=%s words=%s state=finished new_assets=%s validation=queued",
                                             target["name"], domain, wordlist.name, chunk_num, len(words), new)
                                except Exception as error:
                                    success = False
                                    self.error(target, "dns_bruteforce", error)
                                    LOG.error("target=%s domain=%s wordlist=%s chunk=%s error=%s",
                                              target["name"], domain, wordlist.name, chunk_num, error)
                    except Exception as error:
                        success = False
                        self.error(target, "dns_bruteforce", error)
                        LOG.error("target=%s domain=%s wordlist=%s error=%s", target["name"], domain, wordlist.name, error)
        if settings["dynamic"]["enabled"]:
            try:
                await self.dynamic_bruteforce(target)
            except Exception as error:
                success = False
                self.error(target, "dns_bruteforce", error)
                LOG.error("target=%s watcher=dynamic_bruteforce error=%s", target["name"], error)
        LOG.info("target=%s watcher=dns_bruteforce state=complete success=%s", target["name"], success)
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
                for number, batch in enumerate(self.db.pending_dnsgen_batches(target["id"], seed_batch_size), 1):
                    self.db.watcher_progress(target["id"], "dns_bruteforce", f"DNSGen batch={number} seeds={len(batch)}")
                    LOG.info("target=%s mode=dynamic tool=dnsgen batch=%s seeds=%s state=started",
                             target["name"], number, len(batch))
                    inputs.write_text("".join(asset["hostname"] + "\n" for asset in batch), encoding="utf-8")
                    async with self.tools.dnsgen(inputs) as names:
                        iterator = iter(names)
                        while candidates := list(islice(iterator, batch_size)):
                            new_candidates += self.db.cache_dnsgen_candidates(target["id"], candidates)
                            await asyncio.sleep(0)
                    self.db.finish_dnsgen_batch(target["id"], batch[-1]["id"])
                    seeds += len(batch)
                    LOG.info("target=%s mode=dynamic tool=dnsgen batch=%s state=finished seeds_processed=%s new_candidates=%s",
                             target["name"], number, seeds, new_candidates)
            except Exception as error:
                self.error(target, "dns_bruteforce", error)
                LOG.error("target=%s tool=dnsgen error=%s checkpoint_preserved=true", target["name"], error)
                failures.append("dnsgen")
            LOG.info("target=%s tool=dnsgen new_seeds=%s new_candidates=%s", target["name"], seeds, new_candidates)

            # Each cached chunk takes one tool slot. Monitoring gets a turn between
            # chunks, and ShuffleDNS never loads an entire target's cache at once.
            path = directory / "candidates.txt"
            chunk_size = self.config["dns_bruteforce"]["dynamic"]["chunk_size"]
            cooldown = self.config["dns_bruteforce"]["shuffledns"]["cooldown"]
            for domain in target["domains"]:
                count = 0
                failed = False
                for number, batch in enumerate(self.db.dnsgen_candidate_batches(target["id"], domain, chunk_size), 1):
                    if number > 1:
                        await asyncio.sleep(cooldown)
                    path.write_text("".join(hostname + "\n" for hostname in batch), encoding="utf-8")
                    count += len(batch)
                    self.db.watcher_progress(target["id"], "dns_bruteforce", f"Dynamic: {domain}, cached_candidates={count}")
                    LOG.info("target=%s domain=%s mode=dynamic cached_candidates=%s state=started", target["name"], domain, count)
                    try:
                        async with self.tools.shuffledns(domain, candidates=path) as names:
                            new = await self.ingest(target, names, "dns_bruteforce")
                        LOG.info("target=%s domain=%s mode=dynamic chunk=%s state=finished new_assets=%s validation=queued",
                                 target["name"], domain, number, new)
                    except Exception as error:
                        LOG.error("target=%s domain=%s mode=dynamic error=%s", target["name"], domain, error)
                        failed = True
                if failed:
                    failures.append(domain)
                if not count:
                    LOG.info("target=%s domain=%s mode=dynamic state=skipped reason=no_cached_candidates",
                             target["name"], domain)
            if failures:
                raise RuntimeError("Dynamic brute force failed for: " + ", ".join(failures))
