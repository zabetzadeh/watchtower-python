"""Persistent Telegram outbox. Acknowledged events are never resent."""

import asyncio
import json
import logging
import time
import urllib.error
from itertools import zip_longest

from .cdn import CdnRanges
from .tools import read_json

LOG = logging.getLogger(__name__)
TITLES = {
    "fresh_asset": "🆕 Fresh Asset",
    "fresh_subdomain": "🆕 Fresh Subdomain",
    "dns_unresolved": "🔴 DNS Unresolved",
    "dns_ip_changed": "🔄 DNS IP Changed",
    "dns_cname_changed": "🔄 DNS CNAME Changed",
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
                 "ptr": "🆕 PTR-derived New Asset",
                 "dns_bruteforce": "🆕 DNS-Brute-Force New Asset"}.get(after.get("source"), title)
    lines = [title, "", f"Target: {event['target']}", f"Subdomain: {event['hostname']}"]
    if after.get("source"):
        lines.append(f"Source: {after['source']}")
    if event["event_type"] == "dns_cname_changed":
        lines += ["Previous: " + (", ".join(before.get("cname_records", [])) or "(none)"),
                  "Current: " + (", ".join(after.get("cname_records", [])) or "(none)"),
                  "Review the CNAME change; this is not proof of takeover."]
    elif event["event_type"] == "http_status_changed":
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
        if event["event_type"] == "dns_ip_changed":
            new_ips = sorted(set(after.get("ip_addresses", [])) -
                             set(before.get("known_ip_addresses", before.get("ip_addresses", []))))
            lines.append("New IPs: " + ", ".join(new_ips))
            lines.append("Known IP pool: " + ", ".join(after.get("known_ip_addresses", after.get("ip_addresses", []))))
    if after.get("http_url"):
        lines.append(f"URL: {after['http_url']}")
    lines += [f"Time: {event['created_at']}", f"Event: {event['id']}"]
    return "\n".join(lines)[:4000]


class Notifier:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.cdn = CdnRanges(config, database)
        self.program_first = False

    async def flush(self):
        settings = self.config["telegram"]
        if not settings["enabled"]:
            self.db.set_runtime("delivery", {"state": "disabled", "checked_at": time.time()})
            return False
        excluded = () if settings["notify_dns_ip_changes"] else ("dns_ip_changed",)
        asset_events = self.db.pending_events(settings["batch_size"], exclude_types=excluded)
        program_messages = self.db.pending_program_messages(settings["batch_size"])
        # Alternate queues so a large asset backlog cannot hide program additions.
        queues = (program_messages, asset_events) if self.program_first else (asset_events, program_messages)
        events = [event for pair in zip_longest(*queues) for event in pair if event is not None][:settings["batch_size"]]
        self.program_first = not self.program_first
        if any(event["event_type"] == "dns_ip_changed" for event in events):
            await self.cdn.refresh()
        if events:
            LOG.info("telegram=sending batch_events=%s oldest_event_at=%s",
                     len(events), events[0]["created_at"])
        for event in events:
            program = event.get("queue") == "program"
            record_result = self.db.program_notification_result if program else self.db.notification_result
            target = event["platform"] if program else event["target"]
            host = event["program_name"] if program else event["hostname"]
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
                payload = {"chat_id": settings["chat_id"], "text": event["text"] if program else format_event(event),
                           "link_preview_options": {"is_disabled": True}}
                if program:
                    payload.update(parse_mode="MarkdownV2", reply_markup={"inline_keyboard": [[
                        {"text": "Open program ↗", "url": event["program_url"]}]]})
                result = await asyncio.to_thread(
                    read_json, f"https://api.telegram.org/bot{settings['bot_token']}/sendMessage",
                    self.config["runtime"]["request_timeout"], payload)
                if not isinstance(result, dict) or result.get("ok") is not True:
                    if isinstance(result, dict):
                        retry_after = max(retry_after, float(result.get("parameters", {}).get("retry_after", 0)))
                    raise ValueError("Telegram rejected the message")
                record_result(event["id"], message_id=result.get("result", {}).get("message_id"))
                self.db.set_runtime("delivery", {"state": "delivered", "queue": event.get("queue", "asset"),
                                                 "event_id": event["id"], "checked_at": time.time()})
                LOG.info("telegram=delivered queue=%s event_id=%s event=%s target=%s host=%r",
                         event.get("queue", "asset"), event["id"], event["event_type"], target, host)
            except Exception as error:
                if isinstance(error, urllib.error.HTTPError):
                    try:
                        details = json.loads(error.read(8192))
                        retry_after = max(retry_after, float(details.get("parameters", {}).get("retry_after", 0)))
                    except (OSError, ValueError, TypeError, AttributeError):
                        pass
                # Exception text can contain a URL with the bot token; never persist it.
                reason = f"Telegram delivery failed ({type(error).__name__})"
                record_result(event["id"], error=reason, retry_after=retry_after)
                self.db.set_runtime("delivery", {"state": "failed", "queue": event.get("queue", "asset"),
                                                 "error": reason, "checked_at": time.time()})
                LOG.error("telegram=failed queue=%s event_id=%s reason=%s retry_after=%s",
                          event.get("queue", "asset"), event["id"], reason, retry_after)
                return False
            await asyncio.sleep(settings["send_delay"])
        # Drain a full successful batch without another monitoring-interval delay.
        return len(events) == settings["batch_size"]
