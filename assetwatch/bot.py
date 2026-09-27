"""Read-only Telegram commands, restricted to the configured chat."""

import asyncio
import hashlib
import json
import logging
import shlex
import time
import urllib.error

from .config import PROGRAM_FEEDS
from .reports import event_summary, health_report, health_text, program_event_summary
from .tools import read_json

LOG = logging.getLogger(__name__)
HELP = """Assetwatch
/health [target] [page] — module state, errors, results and next runs
/changes [target] [page] — latest DNS/HTTP/discovery events
/new [target] [page] — newest assets and discovery sources
/cnames [target] [page] — current CNAME records
/targets [page] — target names and scope
/programs [platform] [page] — new bounty programs and scope additions
/help — this menu

Omit target (or use *) for all targets. Quote names containing spaces.
Pages contain 10 entries (health: 6 modules). Times are UTC.
CNAME changes are investigation signals, not proof of takeover.
"""
MENU = {"keyboard": [["/health", "/changes"], ["/new", "/targets"], ["/programs"], ["/cnames", "/help"]],
        "resize_keyboard": True}


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
        parts = shlex.split(text)
        command = parts.pop(0).split("@", 1)[0].lower()
        command = {"/start": "/help", "/status": "/health", "/updates": "/changes"}.get(command, command)
        if command == "/help":
            return HELP
        if command not in {"/health", "/changes", "/new", "/cnames", "/targets", "/programs"}:
            return "Unknown command. Use /help."
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
            body = "\n\n".join(f"{row['name']}\nDomains: {', '.join(row['domains'])}\nCIDRs: {', '.join(row['cidrs']) or '-'}"
                                for row in rows[:size])
            more = len(rows) > size
        elif command == "/cnames":
            rows = self.db.cname_assets(target_id, size + 1, offset)
            body = "\n\n".join(f"{row['target']}: {row['hostname']}\nCNAME: {', '.join(row['cname_records'])}\nChecked: {row['cname_checked_at']}"
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
            if allowed and isinstance(text, str) and text.startswith("/"):
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
            # Unauthorized/non-command updates are acknowledged without replying or exposing data.
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
