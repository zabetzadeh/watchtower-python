"""Normalization and scope checks shared by every discovery source."""

import ipaddress
import re

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_hostname(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    if not all(LABEL.fullmatch(label) for label in value.split(".")):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return None


def in_scope(hostname: str, domains: list[str]) -> bool:
    return any(hostname == root or hostname.endswith("." + root) for root in domains)


def ipv4_addresses(values) -> list[str]:
    addresses = set()
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            continue
        if ip.version == 4 and not ip.is_unspecified and not ip.is_multicast:
            addresses.add(str(ip))
    return sorted(addresses)
