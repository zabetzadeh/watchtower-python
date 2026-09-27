"""Public program feed monitoring. This never adds targets to the scanning pipeline."""

import asyncio
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from .config import PROGRAM_FEEDS
from .tools import read_json

LOG = logging.getLogger(__name__)
PLATFORMS = {"hackerone": "HackerOne", "bugcrowd": "Bugcrowd", "intigriti": "Intigriti"}


def required_text(value, label, maximum=8192):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Missing or invalid {label}")
    return value.strip()


def program_url(value):
    value = required_text(value, "program URL", 2048)
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or
            parsed.password or any(char.isspace() or ord(char) < 32 for char in value)):
        raise ValueError("Invalid program URL")
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))


def scope_identifier(value, kind):
    value = required_text(value, "scope identifier")
    if kind.lower() in {"url", "website", "wildcard", "domain", "api"}:
        if re.fullmatch(r"(?:\*\.)?[a-zA-Z0-9_.-]+", value) and "." in value:
            return value.lower().rstrip(".")
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            # URL paths and queries remain case-sensitive; host/scheme are not.
            return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(),
                               parsed.path if parsed.path != "/" else "", parsed.query, parsed.fragment))
    return value


def parse_feed(platform, data):
    if platform not in PROGRAM_FEEDS:
        raise ValueError("Unknown program platform")
    if not isinstance(data, list) or not data:
        raise ValueError("Expected a nonempty program feed; previous baseline preserved")
    result, seen = [], set()
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("Expected a program object")
        name = required_text(row.get("name"), "program name", 500)
        url = program_url(row.get("url"))
        # HackerOne currently exports id=0 for every program; the handle is stable.
        key = (required_text(row.get("handle"), "HackerOne handle", 500).lower() if platform == "hackerone" else
               required_text(row.get("id"), "Intigriti ID", 500).lower() if platform == "intigriti" else url)
        if key in seen:
            raise ValueError("Duplicate program identity in feed")
        seen.add(key)
        targets = row.get("targets")
        if not isinstance(targets, dict) or not isinstance(targets.get("in_scope"), list):
            raise ValueError("Missing or invalid in_scope list")
        scope = {}
        field = {"hackerone": "asset_identifier", "bugcrowd": "target", "intigriti": "endpoint"}[platform]
        for entry in targets["in_scope"]:
            if not isinstance(entry, dict):
                raise ValueError("Expected a scope object")
            # Some Intigriti asset categories are represented by null in the feed.
            kind = entry.get("asset_type" if platform == "hackerone" else "type")
            kind = "other" if kind is None else required_text(kind, "scope type", 100).lower()
            identifier = scope_identifier(entry.get(field), kind)
            scope[identifier] = {"identifier": identifier, "type": kind}
        result.append({"key": key, "name": name, "url": url,
                       "scope": [scope[key] for key in sorted(scope)]})
    return result


def markdown(value):
    return re.sub(r"([\\_*\[\]()~`>#+\-=|{}.!])", r"\\\1", str(value))


def utf16_length(value):
    return len(value.encode("utf-16-le")) // 2


def code_parts(value, maximum=1000):
    # Escape before packing; never split an escape or cut off a long scope entry.
    part, size = "", 0
    for char in value.replace("\r", "").replace("\n", " ⏎ "):
        escaped = "\\" + char if char in "\\`" else char
        length = utf16_length(escaped)
        if size + length > maximum:
            yield part
            part, size = "", 0
        part += escaped
        size += length
    if part:
        yield part


def format_program_messages(event):
    added = event["added_scope"]
    title = "🆕 *New Program*" if event["event_type"] == "new_program" else "🎯 *Scope Expanded*"
    header = (f"{title}\n\n*{markdown(event['program_name'])}*\n"
              f"Platform: *{PLATFORMS[event['platform']]}*\n"
              f"New in\\-scope entries: *{len(added)}*\n\n")
    # Reserve room for timestamp, event reference, and part numbering.
    budget = 3800 - utf16_length(header) - 160
    bodies, body = [], ""
    for item in added:
        for number, piece in enumerate(code_parts(item["identifier"])):
            line = (f"• `{piece}`" + (f" _{markdown(item['type'])}_" if number == 0 else " _continued_") + "\n")
            if body and utf16_length(body + line) > budget:
                bodies.append(body)
                body = ""
            body += line
    bodies.append(body or r"No in\-scope entries listed yet\." + "\n")
    observed = datetime.fromisoformat(event["created_at"]).strftime("%Y-%m-%d %H:%M UTC")
    return [header + body + f"\n🕒 `{observed}`\n"
            f"Event: `P{event['id']}` • Part {part}/{len(bodies)}"
            for part, body in enumerate(bodies, 1)]


def program_next_run(config, status):
    if not status or status["state"] in {"running", "interrupted"} or status["checked_at"] is None:
        return 0
    delay = config["intervals"]["program_watch"]
    if status["state"] == "failed":
        delay = min(delay, config["runtime"]["failure_retry_interval"])
    return status["checked_at"] + delay


class ProgramWatcher:
    def __init__(self, config, database):
        self.config, self.db = config, database

    async def check(self, platform):
        self.db.start_program_check(platform)
        LOG.info("watcher=program_watch platform=%s state=started", platform)
        try:
            data = await asyncio.to_thread(read_json, PROGRAM_FEEDS[platform],
                                           self.config["runtime"]["request_timeout"],
                                           max_bytes=self.config["program_watch"]["max_feed_bytes"])
            programs = parse_feed(platform, data)
            result = self.db.observe_program_feed(platform, programs, self.config["intervals"]["program_watch"])
            LOG.info("watcher=program_watch platform=%s state=success baseline=%s programs=%s new_programs=%s new_scopes=%s",
                     platform, result["baseline"], len(programs), result["new_programs"], result["new_scopes"])
            return True
        except asyncio.CancelledError:
            self.db.fail_program_check(platform, "Run interrupted; retry on restart", 0, state="interrupted")
            raise
        except Exception as error:
            # Do not copy a potentially large/untrusted feed value or URL into health/logs.
            reason = f"Feed fetch/validation failed ({type(error).__name__}); previous baseline preserved"
            delay = min(self.config["intervals"]["program_watch"], self.config["runtime"]["failure_retry_interval"])
            self.db.fail_program_check(platform, reason, delay)
            LOG.error("watcher=program_watch platform=%s state=failed error=%s", platform, reason)
            return False

    async def watch(self, platform):
        if not self.config["program_watch"]["enabled"]:
            return
        while True:
            try:
                row = self.db.program_feed_status(platform)
                if program_next_run(self.config, row) <= time.time():
                    await self.check(platform)
            except Exception as error:
                LOG.error("watcher=program_watch platform=%s scheduler_error=%s", platform, type(error).__name__)
            await asyncio.sleep(self.config["runtime"]["poll_interval"])
