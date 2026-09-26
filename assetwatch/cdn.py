"""Refresh public CDN CIDRs and identify address rotation within a provider."""

import asyncio
import ipaddress
import logging
import time

from .tools import read_json, read_text

LOG = logging.getLogger(__name__)
SOURCES = ("projectdiscovery", "akamai")


def parse_ranges(data):
    if not isinstance(data, dict) or not data:
        raise ValueError("Expected a nonempty provider-to-CIDR mapping")
    result = {}
    for provider, cidrs in data.items():
        if not isinstance(provider, str) or not provider or not isinstance(cidrs, list):
            raise ValueError("Invalid CDN provider entry")
        networks = set()
        for cidr in cidrs:
            if not isinstance(cidr, str):
                raise ValueError("CDN CIDRs must be strings")
            network = ipaddress.ip_network(cidr)
            if network.prefixlen == 0:
                raise ValueError("A CDN range cannot cover the entire address space")
            networks.add(network)
        if networks:
            result[provider] = networks
    if not result:
        raise ValueError("CDN source contains no ranges")
    return result


def download_ranges(source, url, timeout):
    if source == "akamai":
        return parse_ranges({"akamai": read_text(url, timeout).split()})
    data = read_json(url, timeout)
    if not isinstance(data, dict):
        raise ValueError("Invalid ProjectDiscovery CDN data")
    providers = {}
    # Cloud-hosting networks and CNAME suffixes are not CDN IP evidence.
    for category in ("cdn", "waf"):
        group = data.get(category)
        if not isinstance(group, dict):
            raise ValueError(f"Missing CDN data category: {category}")
        for provider, networks in group.items():
            if not isinstance(networks, list):
                raise ValueError("Invalid CDN range list")
            if provider != "akamai":  # Use Akamai's own published list for this provider.
                providers.setdefault(provider, []).extend(networks)
    return parse_ranges(providers)


class CdnRanges:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.sources, self.retry_at = {}, {}
        for url, entry in database.cdn_sources().items():
            try:
                self.sources[url] = (entry["fetched_at"], parse_ranges(entry["ranges"]))
            except ValueError:
                LOG.warning("cdn_cache=invalid action=refresh")

    async def refresh(self):
        settings = self.config["cdn"]
        if not settings["enabled"]:
            return
        for source in SOURCES:
            url = settings[source + "_url"]
            now = time.time()
            cached = self.sources.get(url)
            if cached and now - cached[0] < settings["refresh_interval"]:
                continue
            if now < self.retry_at.get(url, 0):
                continue
            self.retry_at[url] = now + settings["retry_interval"]
            try:
                networks = await asyncio.to_thread(
                    download_ranges, source, url, self.config["runtime"]["request_timeout"])
                fetched_at = time.time()
                serialized = {provider: sorted(str(net) for net in ranges)
                              for provider, ranges in networks.items()}
                self.db.cache_cdn_source(url, serialized, fetched_at)
                self.sources[url] = (fetched_at, networks)
                LOG.info("cdn_source=%s state=refreshed providers=%s ranges=%s", source,
                         len(networks), sum(len(ranges) for ranges in networks.values()))
            except Exception as error:
                LOG.warning("cdn_source=%s state=refresh_failed error=%s cause=%s usable_cache=%s",
                            source, type(error).__name__, type(getattr(error, "reason", error)).__name__,
                            bool(cached and now - cached[0] <= settings["max_age"]))

    def rotation_providers(self, previous, current):
        """Return providers only if every changed IP is known and ownership stays the same."""
        settings = self.config["cdn"]
        if not settings["enabled"] or not previous or not current or set(previous) == set(current):
            return set()
        now = time.time()
        active = [self.sources[settings[source + "_url"]][1] for source in SOURCES
                  if settings[source + "_url"] in self.sources
                  and now - self.sources[settings[source + "_url"]][0] <= settings["max_age"]]
        owners = {}
        for value in set(previous) | set(current):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return set()
            providers = {provider for ranges in active for provider, networks in ranges.items()
                         if any(address in network for network in networks)}
            owners[value] = {("cdn", name) for name in providers} or {("ip", value)}
        changed = set(previous) ^ set(current)
        if any(kind == "ip" for value in changed for kind, _ in owners[value]):
            return set()
        before = set().union(*(owners[value] for value in previous))
        after = set().union(*(owners[value] for value in current))
        if before != after:
            return set()
        return {name for value in changed for _, name in owners[value]}
