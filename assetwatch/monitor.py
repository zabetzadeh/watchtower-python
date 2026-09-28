"""Explicit state transitions, independent of discovery source."""


def dns_events(previous: dict, addresses: list[str]) -> list[str]:
    if addresses and not previous["dns_resolved"]:
        return ["fresh_subdomain"]
    if not addresses and previous["dns_resolved"]:
        return ["dns_unresolved"]
    # Round-robin DNS can return different subsets of an established address pool.
    # Keep current observations separately; alert only on previously unseen IPs.
    if set(addresses) - set(previous.get("known_ip_addresses", previous["ip_addresses"])):
        return ["dns_ip_changed"]
    return []


def http_events(previous: dict, status: int | None, url: str | None = None) -> list[str]:
    if status is not None and not previous["http_available"]:
        return ["http_service_returned" if previous["http_ever_available"]
                else "http_service_appeared"]
    if status is None and previous["http_available"]:
        return ["http_service_disappeared"]
    if status is not None and status != previous["http_status"]:
        # HTTPX may fall back between HTTP and HTTPS. They are different
        # services, so comparing their status codes creates misleading alerts.
        previous_url = previous.get("http_url")
        if previous_url and url and previous_url.rstrip("/") != url.rstrip("/"):
            return []
        return ["http_status_changed"]
    return []
