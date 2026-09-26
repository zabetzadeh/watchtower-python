"""Persistent Telegram outbox. Acknowledged events are never resent."""

import asyncio
import json
import logging
import urllib.error

from .cdn import CdnRanges
from .tools import read_json

LOG = logging.getLogger(__name__)
TITLES = {
    "fresh_asset": "🆕 Fresh Asset",
    "fresh_subdomain": "🆕 Fresh Subdomain",
    "dns_unresolved": "🔴 DNS Unresolved",
    "dns_ip_changed": "🔄 DNS IP Changed",
    "http_service_appeared": "🟢 HTTP Service Appeared",
    "http_service_disappeared": "🔴 HTTP Service Disappeared",
    "http_service_returned": "🟢 HTTP Service Returned",
    "http_status_changed": "🔄 HTTP Status Changed",
}


def format_event(event: dict) -> str:
    before, after = json.loads(event["previous_state"]), json.loads(event["new_state"])
    title = TITLES.get(event["event_type"], event["event_type"])
    if event["event_type"] == "fresh_asset":
        title = {"tlsx": "🆕 Certificate-derived New Asset",
                 "dns_bruteforce": "🆕 DNS-Brute-Force New Asset"}.get(after.get("source"), title)
    lines = [title, "", f"Target: {event['target']}", f"Subdomain: {event['hostname']}"]
    if after.get("source"):
        lines.append(f"Source: {after['source']}")
    if event["event_type"] == "http_status_changed":
        lines.append(f"{before.get('http_status')} → {after.get('http_status')}")
    else:
        dns = "RESOLVED" if after.get("dns_resolved") else "UNRESOLVED"
        if not after.get("dns_checked_at"):
            dns = "PENDING"
        http = "YES" if after.get("http_available") else "NO"
        if not after.get("http_checked_at"):
            http = "PENDING"
        lines += [f"DNS: {dns}", "IP: " + (", ".join(after.get("ip_addresses", [])) or "-"),
                  f"HTTP: {http}", f"Status: {after.get('http_status') or '-'}"]
    if after.get("http_url"):
        lines.append(f"URL: {after['http_url']}")
    lines += [f"Time: {event['created_at']}", f"Event: {event['id']}"]
    return "\n".join(lines)[:4000]


class Notifier:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.cdn = CdnRanges(config, database)

    async def flush(self):
        settings = self.config["telegram"]
        if not settings["enabled"]:
            return False
        excluded = () if settings["notify_dns_ip_changes"] else ("dns_ip_changed",)
        events = self.db.pending_events(settings["batch_size"], exclude_types=excluded)
        if any(event["event_type"] == "dns_ip_changed" for event in events):
            await self.cdn.refresh()
        if events:
            LOG.info("telegram=sending batch_events=%s oldest_event_at=%s",
                     len(events), events[0]["created_at"])
        for event in events:
            if event["event_type"] == "dns_ip_changed":
                before, after = json.loads(event["previous_state"]), json.loads(event["new_state"])
                providers = self.cdn.rotation_providers(before["ip_addresses"], after["ip_addresses"])
                if providers:
                    reason = "cdn_ip_rotation:" + ",".join(sorted(providers))
                    self.db.suppress_notification(event["id"], reason)
                    LOG.info("telegram=suppressed event_id=%s target=%s host=%s reason=%s",
                             event["id"], event["target"], event["hostname"], reason)
                    continue
            retry_after = self.config["intervals"]["monitoring"]
            try:
                result = await asyncio.to_thread(
                    read_json, f"https://api.telegram.org/bot{settings['bot_token']}/sendMessage",
                    self.config["runtime"]["request_timeout"],
                    {"chat_id": settings["chat_id"], "text": format_event(event),
                     "link_preview_options": {"is_disabled": True}})
                if not isinstance(result, dict) or result.get("ok") is not True:
                    if isinstance(result, dict):
                        retry_after = max(retry_after, float(result.get("parameters", {}).get("retry_after", 0)))
                    raise ValueError("Telegram rejected the message")
                self.db.notification_result(event["id"], message_id=result.get("result", {}).get("message_id"))
                LOG.info("telegram=delivered event_id=%s event=%s target=%s host=%s",
                         event["id"], event["event_type"], event["target"], event["hostname"])
            except Exception as error:
                if isinstance(error, urllib.error.HTTPError):
                    try:
                        details = json.loads(error.read(8192))
                        retry_after = max(retry_after, float(details.get("parameters", {}).get("retry_after", 0)))
                    except (OSError, ValueError, TypeError, AttributeError):
                        pass
                # Exception text can contain a URL with the bot token; never persist it.
                reason = f"Telegram delivery failed ({type(error).__name__})"
                self.db.notification_result(event["id"], error=reason, retry_after=retry_after)
                LOG.error("telegram=failed event_id=%s reason=%s retry_after=%s", event["id"], reason, retry_after)
                return False
            await asyncio.sleep(settings["send_delay"])
        # Drain a full successful batch without another monitoring-interval delay.
        return len(events) == settings["batch_size"]
