"""Read-only reports shared by the terminal and Telegram commands."""

import json
import shutil
import time
from collections import deque
from datetime import datetime, timezone

from .config import PROGRAM_FEEDS, WATCHERS
from .programs import PLATFORMS, program_next_run
from .logging_config import redact


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds") if value else "-"


def prerequisites(config, target, watcher):
    required = {
        "passive_discovery": ["subfinder", "chaos"], "tlsx": ["tlsx"],
        "dns_resolution": ["dnsx"], "ptr_discovery": ["dnsx"], "http_probe": ["httpx"],
        "dns_bruteforce": [],
    }[watcher][:]
    notes = []
    if watcher == "tlsx" and not target["cidrs"]:
        return ["No CIDRs configured; TLSX will be skipped"]
    if watcher == "dns_bruteforce":
        brute = config["dns_bruteforce"]
        if not brute["static"]["enabled"] and not brute["dynamic"]["enabled"]:
            return ["Static and dynamic brute force are disabled"]
        required += ["shuffledns", "massdns"]
        if brute["dynamic"]["enabled"]:
            required.append("dnsgen")
        if brute["static"]["enabled"]:
            directory = config.path(brute["static"]["wordlist_dir"])
            if not any(path.is_file() and path.stat().st_size for path in directory.glob("*.txt")):
                notes.append(f"No nonempty .txt wordlists: {directory}")
        resolvers = config.path(brute["shuffledns"]["resolvers"])
        if not resolvers.is_file() or not resolvers.stat().st_size:
            notes.append(f"Missing/empty resolver file: {resolvers}")
    for tool in required:
        if not shutil.which(config["tools"][tool]):
            notes.append(f"Executable not found: {tool} ({config['tools'][tool]})")
    return notes


def health_report(config, db, target_id=None):
    daemon = db.runtime("daemon", {})
    now = time.time()
    live = (daemon.get("state") == "running" and
            now - daemon.get("heartbeat_at", 0) < max(15, config["runtime"]["poll_interval"] * 3))
    modules = []
    for target in db.targets():
        if target_id is not None and target["id"] != target_id:
            continue
        for watcher in WATCHERS:
            row = db.connection.execute("SELECT * FROM watcher_status WHERE target_id=? AND watcher=?",
                                         (target["id"], watcher)).fetchone()
            legacy = db.connection.execute("SELECT * FROM watcher_runs WHERE target_id=? AND watcher=?",
                                            (target["id"], watcher)).fetchone()
            status = dict(row) if row else {"state": ("success" if legacy["success"] else "failed") if legacy else "never_run",
                                           "finished_at": legacy["finished_at"] if legacy else None,
                                           "results": 0, "new_assets": 0, "detail": "", "last_error": None}
            if not live and status["state"] in {"running", "queued"}:
                status["state"] = "interrupted/stale"
            status.update(target=target["name"], watcher=watcher,
                          next_run_at=db.next_run_at(target["id"], watcher, config["intervals"][watcher],
                                                     config["runtime"]["failure_retry_interval"]),
                          prerequisites=prerequisites(config, target, watcher))
            if status["state"] in {"running", "queued"}:
                status["next_run_at"] = None
            modules.append(status)
    counts = dict(db.connection.execute(
        "SELECT event_type,count(*) FROM events e WHERE delivered_at IS NULL "
        "AND NOT EXISTS (SELECT 1 FROM notification_suppressions s WHERE s.event_id=e.id) GROUP BY event_type"))
    muted = 0 if config["telegram"]["notify_dns_ip_changes"] else counts.pop("dns_ip_changed", 0)
    feeds = []
    for platform in PROGRAM_FEEDS:
        feed = db.program_feed_status(platform) or {"state": "never_run", "platform": platform,
                                                   "initialized_at": None, "checked_at": None, "next_run_at": 0,
                                                   "program_count": 0, "scope_count": 0, "new_programs": 0,
                                                   "new_scopes": 0, "last_error": None}
        feed["next_run_at"] = program_next_run(config, feed)
        if not config["program_watch"]["enabled"]:
            feed["state"] = "disabled"
        elif not live and feed["state"] == "running":
            feed["state"] = "interrupted/stale"
        feeds.append(feed)
    program_backlog = db.connection.execute("SELECT count(*) FROM program_messages WHERE delivered_at IS NULL").fetchone()[0]
    return {"daemon": "running" if live else "stopped or stale", "heartbeat_at": daemon.get("heartbeat_at"),
            "telegram_enabled": config["telegram"]["enabled"],
            "commands_enabled": config["telegram"]["commands_enabled"],
            "notification_backlog": sum(counts.values()) + program_backlog, "muted_ip_events": muted,
            "program_notification_backlog": program_backlog, "program_feeds": feeds,
            "delivery": db.runtime("delivery", {}), "bot": db.runtime("bot", {}),
            "log_file": str(config.path(config["logging"]["file"])), "modules": modules}


def health_text(report):
    lines = [f"Daemon: {report['daemon']}", f"Heartbeat: {timestamp(report['heartbeat_at'])}",
             f"Telegram: {'enabled' if report['telegram_enabled'] else 'disabled'}; "
             f"commands={'enabled' if report['commands_enabled'] else 'disabled'}; "
             f"pending={report['notification_backlog']}; muted IP events={report['muted_ip_events']}"]
    for name in ("delivery", "bot"):
        if report[name]:
            lines.append(f"{name}: {report[name].get('state')} {report[name].get('error', '')}")
    lines.append("\nProgram scope watch:")
    for feed in report["program_feeds"]:
        next_run = "running" if feed["state"] == "running" else timestamp(feed["next_run_at"]) if feed["next_run_at"] else "due"
        lines += [f"{PLATFORMS[feed['platform']]}: {feed['state']} | programs={feed['program_count']} scopes={feed['scope_count']}",
                  f"Checked: {timestamp(feed['checked_at'])}; next: {next_run}; "
                  f"new programs={feed['new_programs']} new scopes={feed['new_scopes']}"]
        if feed["last_error"]:
            lines.append("Last error: " + feed["last_error"])
    for row in report["modules"]:
        next_run = ("after this run completes" if row["state"] == "running" else
                    "waiting for scan access" if row["state"] == "queued" else
                    timestamp(row["next_run_at"]) if row["next_run_at"] else "due / requested")
        lines += ["", f"{row['target']} / {row['watcher']}: {row['state']}",
                  f"Started: {timestamp(row.get('started_at'))}; finished: {timestamp(row.get('finished_at'))}",
                  f"Next: {next_run}; "
                  f"results={row['results']} new_assets={row['new_assets']}"]
        if row["detail"]:
            lines.append(row["detail"])
        if row["last_error"]:
            lines.append("Last error: " + row["last_error"])
        lines += ["Check: " + note for note in row["prerequisites"]]
    lines.append("\nLog: " + report["log_file"])
    return "\n".join(lines)


def event_summary(event):
    before, after = json.loads(event["previous_state"]), json.loads(event["new_state"])
    kind = event["event_type"]
    if kind == "dns_cname_changed":
        detail = f"{', '.join(before.get('cname_records', [])) or '(none)'} → {', '.join(after.get('cname_records', [])) or '(none)'}"
    elif kind == "dns_ip_changed":
        detail = "New IPs: " + ", ".join(sorted(set(after.get("ip_addresses", [])) -
                                               set(before.get("known_ip_addresses", before.get("ip_addresses", [])))))
    elif kind.startswith("http_"):
        detail = f"{before.get('http_status') or '-'} → {after.get('http_status') or '-'}"
    else:
        detail = after.get("source", "")
    return f"#{event['id']} {event['created_at']} {event['target']}\n{kind}: {event['hostname']}\n{detail}"


def program_event_summary(event):
    title = "New program" if event["event_type"] == "new_program" else "Scope expanded"
    scope = event["added_scope"]
    preview = "\n".join("• " + item["identifier"][:200] for item in scope[:5])
    if len(scope) > 5:
        preview += f"\n… and {len(scope) - 5} more (full entries in the alert / CLI JSON)."
    return (f"P{event['id']} | {event['created_at']} | {PLATFORMS[event['platform']]}\n"
            f"{title}: {event['program_name']}\n{len(scope)} added scope entries\n{preview}\n{event['program_url']}")


def log_tail(config, module=None, target=None, lines=50):
    markers = {
        "passive_discovery": ("watcher=passive_discovery", "tool=subfinder", "tool=chaos", "tool=crtsh"),
        "tlsx": ("watcher=tlsx", "tool=tlsx", "source=tlsx"),
        "dns_resolution": ("watcher=dns_resolution", "tool=dnsx"),
        "ptr_discovery": ("watcher=ptr_discovery", "record=ptr", "source=ptr"),
        "http_probe": ("watcher=http_probe", "tool=httpx"),
        "dns_bruteforce": ("watcher=dns_bruteforce", "tool=dnsgen", "tool=shuffledns", "mode=static", "mode=dynamic", "source=dns_bruteforce"),
        "program_watch": ("watcher=program_watch", "queue=program"),
    }
    path = config.path(config["logging"]["file"])
    if not path.is_file():
        return f"No log file yet: {path}"
    with path.open(encoding="utf-8", errors="replace") as stream:
        selected = deque((redact(config, line.rstrip()) for line in stream
                          if (not module or any(marker in line for marker in markers[module]))
                          and (not target or f"target={target} " in line)), maxlen=lines)
    return "\n".join(selected) or "No matching entries in the current log file."
