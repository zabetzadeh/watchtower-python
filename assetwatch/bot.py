"""Telegram commands and button UI, restricted to the configured chat."""

import asyncio
import hashlib
import ipaddress
import json
import logging
import shlex
import time
import urllib.error

from .config import PROGRAM_FEEDS
from .normalization import normalize_hostname
from .reports import event_summary, health_report, health_text, program_event_summary
from .tools import read_json

LOG = logging.getLogger(__name__)

HELP = """Assetwatch Bot

Dashboard & Monitoring:
• Health — module state, errors, results, and next scheduled runs
• Changes — latest DNS, HTTP, and discovery state changes
• New — newest discovered assets and sources

Asset Inspection:
• Live's — assets with active HTTP service
• Resolved — assets with resolved DNS records
• CNAME's — current CNAME records
• Brute force result — assets discovered via DNS brute force
• Passive — assets discovered via subfinder, chaos, crt.sh
• PTR's — assets discovered via reverse DNS / PTR records

Target Management:
• Targets — list all targets and scope
• Add target — add target (accepts domain, CIDR, or both)
• Update target — add domains/CIDRs to existing target
• Remove target — delete target and its assets

Bounty Programs:
• /programs [platform] [page] — new bounty programs and scope additions

Syntax:
• Tap any button or send slash commands (/health, /cnames, /lives)
• Filter by target: /lives example
• Paginate: /cnames example 2
• Add target: /add_target <name> <domains_or_cidrs...>
• Update target: /update_target <name> <domains_or_cidrs...>
• Remove target: /remove_target <name>
"""

MENU = {
    "keyboard": [
        ["Health", "Changes", "New"],
        ["Live's", "Resolved", "CNAME's"],
        ["Brute force result", "Passive", "PTR's"],
        ["Targets", "Add target", "Update target"],
        ["Remove target", "Help"],
    ],
    "resize_keyboard": True,
}


def classify_target_inputs(parts: list[str]) -> tuple[list[str], list[str]]:
    domains, cidrs = [], []
    for part in parts:
        for item in part.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
                cidrs.append(str(net))
                continue
            except ValueError:
                pass
            normalized = normalize_hostname(item)
            if normalized:
                domains.append(normalized)
            else:
                raise ValueError(f"Invalid domain or CIDR: {item}")
    return domains, cidrs


def parse_command(text: str) -> tuple[str, list[str]]:
    text = text.strip()
    lower = text.lower()
    for prefix, mapped in (
        ("brute force result", "/bruteforce"),
        ("brute force results", "/bruteforce"),
        ("brute force", "/bruteforce"),
        ("add target", "/add_target"),
        ("update target", "/update_target"),
        ("remove target", "/remove_target"),
        ("cname's", "/cnames"),
        ("live's", "/lives"),
        ("ptr's", "/ptrs"),
    ):
        if lower == prefix or lower.startswith(prefix + " "):
            remainder = text[len(prefix):].strip()
            if not remainder:
                return mapped, []
            try:
                return mapped, shlex.split(remainder)
            except ValueError:
                return mapped, remainder.split()

    try:
        parts = shlex.split(text)
    except ValueError:
        parts = text.split()
    if not parts:
        return "/help", []
    cmd = parts.pop(0).split("@", 1)[0].lower()
    alias_map = {
        "health": "/health",
        "/health": "/health",
        "/status": "/health",
        "changes": "/changes",
        "/changes": "/changes",
        "/updates": "/changes",
        "new": "/new",
        "/new": "/new",
        "live's": "/lives",
        "lives": "/lives",
        "live": "/lives",
        "/lives": "/lives",
        "/live": "/lives",
        "resolved": "/resolved",
        "/resolved": "/resolved",
        "cname's": "/cnames",
        "cnames": "/cnames",
        "cname": "/cnames",
        "/cnames": "/cnames",
        "/cname": "/cnames",
        "passive": "/passive",
        "/passive": "/passive",
        "ptr's": "/ptrs",
        "ptrs": "/ptrs",
        "ptr": "/ptrs",
        "/ptrs": "/ptrs",
        "/ptr": "/ptrs",
        "targets": "/targets",
        "target": "/targets",
        "/targets": "/targets",
        "/target": "/targets",
        "programs": "/programs",
        "/programs": "/programs",
        "help": "/help",
        "/help": "/help",
        "/start": "/help",
        "add_target": "/add_target",
        "/add_target": "/add_target",
        "/add": "/add_target",
        "update_target": "/update_target",
        "/update_target": "/update_target",
        "/update": "/update_target",
        "remove_target": "/remove_target",
        "/remove_target": "/remove_target",
        "/remove": "/remove_target",
        "bruteforce": "/bruteforce",
        "/bruteforce": "/bruteforce",
        "/brute": "/bruteforce",
    }
    return alias_map.get(cmd, cmd), parts


class Bot:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.username = None
        self.retry_after = 0
        token_id = hashlib.sha256(config["telegram"]["bot_token"].encode()).hexdigest()[:16]
        self.offset_key = "telegram_offset:" + token_id

    async def api(self, method, payload):
        try:
            result = await asyncio.to_thread(
                read_json, f"https://api.telegram.org/bot{self.config['telegram']['bot_token']}/{method}",
                self.config["runtime"]["request_timeout"], payload)
        except urllib.error.HTTPError as error:
            try:
                details = json.loads(error.read(8192))
                self.retry_after = max(0, float(details.get("parameters", {}).get("retry_after", 0)))
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            raise
        if not isinstance(result, dict) or result.get("ok") is not True:
            if isinstance(result, dict):
                self.retry_after = max(0, float(result.get("parameters", {}).get("retry_after", 0)))
            raise ValueError("Telegram API request rejected")
        return result.get("result")

    def response(self, text):
        command, parts = parse_command(text)
        if command == "/help":
            return HELP

        if command == "/add_target":
            if not parts:
                return ("➕ Add Target\n\n"
                        "Accepts root domain(s), CIDR(s), or both.\n\n"
                        "Usage:\n/add_target <name> <domain_or_cidr> [more...]\n\n"
                        "Examples:\n"
                        "• Domain only:\n  /add_target mytarget example.com\n"
                        "• CIDR only:\n  /add_target cloud 192.168.1.0/24\n"
                        "• Both:\n  /add_target corp corp.com,corp.net 10.0.0.0/8")
            name = parts.pop(0)
            if not parts:
                raise ValueError("Provide at least one domain or CIDR for the target")
            domains, cidrs = classify_target_inputs(parts)
            target = self.db.add_target(name, domains, cidrs)
            return (f"✅ Target Added: {target['name']}\n"
                    f"Domains: {', '.join(target['domains']) or '-'}\n"
                    f"CIDRs: {', '.join(target['cidrs']) or '-'}")

        if command == "/update_target":
            if not parts:
                return ("🔄 Update Target\n\n"
                        "Add new domains or CIDRs to an existing target.\n\n"
                        "Usage:\n/update_target <name> <domain_or_cidr> [more...]\n\n"
                        "Example:\n/update_target example api.example.org 10.1.0.0/16")
            name = parts.pop(0)
            if not parts:
                raise ValueError("Provide at least one domain or CIDR to add/update")
            domains, cidrs = classify_target_inputs(parts)
            target = self.db.update_target(name, domains, cidrs)
            return (f"✅ Target Updated: {target['name']}\n"
                    f"Domains: {', '.join(target['domains']) or '-'}\n"
                    f"CIDRs: {', '.join(target['cidrs']) or '-'}")

        if command == "/remove_target":
            if not parts:
                return ("🗑️ Remove Target\n\n"
                        "Delete target, its assets and history.\n\n"
                        "Usage:\n/remove_target <name>\n\n"
                        "Example:\n/remove_target example")
            name = parts.pop(0)
            self.db.remove_target(name)
            return f"🗑️ Target Removed: {name}\nAll assets and events for this target have been deleted."

        if command not in {"/health", "/changes", "/new", "/cnames", "/targets", "/programs",
                           "/lives", "/resolved", "/bruteforce", "/passive", "/ptrs"}:
            return "Unknown command. Use /help or tap Help."

        page = 1
        if parts and parts[-1].isdigit():
            page = int(parts.pop())
        if page < 1 or page > 100000:
            raise ValueError("Page must be between 1 and 100000")
        if len(parts) > 1 or (command == "/targets" and parts):
            raise ValueError("Use /help for command syntax; quote target names containing spaces")
        platform = None
        if command == "/programs":
            platform = parts[0].lower() if parts and parts[0] != "*" else None
            if platform and platform not in PROGRAM_FEEDS:
                raise ValueError("Platform must be hackerone, bugcrowd or intigriti")
        target_id = self.db.target(parts[0])["id"] if command != "/programs" and parts and parts[0] != "*" else None
        size = 6 if command == "/health" else 10
        offset = (page - 1) * size

        if command == "/programs":
            rows = self.db.recent_program_events(platform, size + 1, offset)
            body = "\n\n".join(program_event_summary(row) for row in rows[:size])
            if not rows:
                body = "No program additions recorded yet. The first successful fetch establishes a silent baseline; see /health."
            more = len(rows) > size
        elif command == "/health":
            report = health_report(self.config, self.db, target_id)
            total = len(report["modules"])
            report["modules"] = report["modules"][offset:offset + size]
            body = health_text(report)
            more = offset + size < total
        elif command == "/targets":
            rows = self.db.targets()[offset:offset + size + 1]
            body = "\n\n".join(f"{row['name']}\nDomains: {', '.join(row['domains']) or '-'}\nCIDRs: {', '.join(row['cidrs']) or '-'}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/cnames":
            rows = self.db.cname_assets(target_id, size + 1, offset)
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nCNAME: {', '.join(row['cname_records'])}\nChecked: {row['cname_checked_at']}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/lives":
            rows = list(self.db.assets(target_id=target_id, http=True, limit=size + 1, offset=offset))
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nStatus: {row['http_status'] or '-'}\nURL: {row['http_url'] or '-'}\nIP: {', '.join(row['ip_addresses']) or '-'}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/resolved":
            rows = list(self.db.assets(target_id=target_id, resolved=True, limit=size + 1, offset=offset))
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nIP: {', '.join(row['ip_addresses']) or '-'}\nHTTP: {'YES (' + str(row['http_status']) + ')' if row['http_available'] else 'NO'}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/bruteforce":
            rows = list(self.db.assets(target_id=target_id, source="dns_bruteforce", limit=size + 1, offset=offset))
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nDNS: {'RESOLVED (' + ', '.join(row['ip_addresses']) + ')' if row['dns_resolved'] else 'UNRESOLVED'}\nHTTP: {str(row['http_status']) if row['http_available'] else 'NO'}\nSeen: {row['last_seen'][:19]}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/passive":
            rows = list(self.db.assets(target_id=target_id, sources=["subfinder", "chaos", "crtsh"], limit=size + 1, offset=offset))
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nSources: {', '.join(s for s in row['sources'] if s in {'subfinder', 'chaos', 'crtsh'}) or ', '.join(row['sources'])}\nDNS: {'RESOLVED (' + ', '.join(row['ip_addresses']) + ')' if row['dns_resolved'] else 'UNRESOLVED'}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/ptrs":
            rows = list(self.db.assets(target_id=target_id, source="ptr", limit=size + 1, offset=offset))
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nIP: {', '.join(row['ip_addresses']) or '-'}\nDNS: {'RESOLVED' if row['dns_resolved'] else 'UNRESOLVED'}\nSeen: {row['last_seen'][:19]}"
                                for row in rows[:size])
            more = len(rows) > size
        else:
            rows = self.db.recent_events(target_id, "fresh_asset" if command == "/new" else None, size + 1, offset)
            body = "\n\n".join(event_summary(row) for row in rows[:size])
            more = len(rows) > size

        scope = " " + shlex.quote(parts[0]) if parts else ""
        footer = f"\n\nPage {page}." + (f" Next: {command}{scope} {page + 1}" if more else " End.")
        return (body or "No entries.") + footer

    async def poll(self):
        updates = await self.api("getUpdates", {"offset": self.db.runtime(self.offset_key, 0),
                                                "timeout": 0, "limit": 20, "allowed_updates": ["message"]})
        if not isinstance(updates, list):
            raise ValueError("Invalid Telegram updates")
        for update in updates:
            if not isinstance(update, dict) or type(update.get("update_id")) is not int:
                raise ValueError("Invalid Telegram update")
            if update["update_id"] < self.db.runtime(self.offset_key, 0):
                continue
            message = update.get("message", {})
            text = message.get("text", "")
            allowed = str(message.get("chat", {}).get("id", "")) == self.config["telegram"]["chat_id"]
            if allowed and isinstance(text, str) and text.strip():
                if text.startswith("/"):
                    addressed = text.split()[0].partition("@")[2]
                    if addressed and self.username and addressed.lower() != self.username.lower():
                        self.db.set_runtime(self.offset_key, update["update_id"] + 1)
                        continue
                try:
                    reply = self.response(text)
                except ValueError as error:
                    reply = str(error) + "\nUse /help."
                # Limit each message by UTF-16 length too (Telegram counts astral emoji as two).
                chunks, chunk, units = [], "", 0
                for char in reply:
                    width = 2 if ord(char) > 0xffff else 1
                    if units + width > 3800:
                        chunks.append(chunk)
                        chunk, units = "", 0
                    chunk += char
                    units += width
                if chunk:
                    chunks.append(chunk)
                for chunk in chunks:
                    payload = {"chat_id": self.config["telegram"]["chat_id"], "text": chunk,
                               "reply_markup": MENU, "link_preview_options": {"is_disabled": True}}
                    if message.get("message_thread_id"):
                        payload["message_thread_id"] = message["message_thread_id"]
                    await self.api("sendMessage", payload)
                    await asyncio.sleep(self.config["telegram"]["send_delay"])
            # Unauthorized updates are acknowledged without replying or exposing data.
            self.db.set_runtime(self.offset_key, update["update_id"] + 1)

    async def run(self):
        settings = self.config["telegram"]
        if not settings["enabled"] or not settings["commands_enabled"]:
            self.db.set_runtime("bot", {"state": "disabled"})
            return
        if not settings["chat_id"].lstrip("-").isdigit():
            self.db.set_runtime("bot", {"state": "failed", "error": "Commands require a numeric telegram.chat_id"})
            LOG.error("telegram_commands=disabled reason=numeric_chat_id_required")
            return
        while True:
            try:
                if self.username is None:
                    identity = await self.api("getMe", {})
                    self.username = identity["username"]
                await self.poll()
                self.db.set_runtime("bot", {"state": "polling", "checked_at": time.time()})
            except Exception as error:
                # API exceptions can include the token in a URL; never store their text.
                reason = f"Telegram commands failed ({type(error).__name__}); check connectivity, webhook, or another getUpdates consumer"
                self.db.set_runtime("bot", {"state": "failed", "error": reason, "checked_at": time.time()})
                LOG.error("telegram_commands=failed reason=%s", reason)
            await asyncio.sleep(max(settings["command_poll_interval"], self.retry_after))
            self.retry_after = 0
