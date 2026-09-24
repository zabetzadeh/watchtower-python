"""Explicit state transitions, independent of discovery source."""


def dns_events(previous: dict, addresses: list[str]) -> list[str]:
    if addresses and not previous["dns_resolved"]:
        return ["fresh_subdomain"]
    if not addresses and previous["dns_resolved"]:
        return ["dns_unresolved"]
    if addresses != previous["ip_addresses"]:
        return ["dns_ip_changed"]
    return []


def http_events(previous: dict, status: int | None) -> list[str]:
    if status is not None and not previous["http_available"]:
        return ["http_service_returned" if previous["http_ever_available"]
                else "http_service_appeared"]
    if status is None and previous["http_available"]:
        return ["http_service_disappeared"]
    if status is not None and status != previous["http_status"]:
        return ["http_status_changed"]
    return []
