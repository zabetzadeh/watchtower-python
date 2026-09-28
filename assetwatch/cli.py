"""Terminal target management, inspection, raw export and continuous mode."""

import argparse
import asyncio
import json
import shutil
import sqlite3
import sys

import yaml

from . import __version__
from .config import load_config
from .config import PROGRAM_FEEDS, WATCHERS
from .database import Database
from .logging_config import configure_logging
from .scheduler import Scheduler, daemon_lock
from .tools import ToolRunner
from .reports import event_summary, health_report, health_text, log_tail, program_event_summary


def comma_separated(value: str) -> list[str]:
    items = [item.strip() for item in value.split(",")]
    if not all(items):
        raise argparse.ArgumentTypeError("Comma-separated lists must not contain empty values")
    return items


def parser():
    root = argparse.ArgumentParser(prog="assetwatch", description="Continuous authorized asset discovery and monitoring")
    root.add_argument("--config", default="config.yaml", help="YAML config (default: config.yaml)")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="Run all watchers until Ctrl+C or SIGTERM")
    commands.add_parser("doctor", help="Check executables and brute-force inputs without scanning")
    program_changes = commands.add_parser("program-changes", help="New programs and in-scope additions from bounty feeds")
    program_changes.add_argument("--platform", choices=PROGRAM_FEEDS)
    program_changes.add_argument("--limit", type=int, default=20)
    program_changes.add_argument("--offset", type=int, default=0)
    program_changes.add_argument("--format", choices=("text", "json"), default="text")
    for name in ("health", "changes", "cnames"):
        command = commands.add_parser(name, help={"health": "Module status, failures and next runs",
                                                  "changes": "Recent persisted events", "cnames": "Current CNAME records"}[name])
        scope = command.add_mutually_exclusive_group()
        scope.add_argument("--target")
        scope.add_argument("--all", action="store_true")
        command.add_argument("--format", choices=("text", "json"), default="text")
        if name != "health":
            command.add_argument("--limit", type=int, default=20)
            command.add_argument("--offset", type=int, default=0)
        if name == "changes":
            command.add_argument("--type", dest="event_type", help="For example fresh_asset or dns_cname_changed")
    logs = commands.add_parser("logs", help="Tail matching entries in the current log file")
    logs.add_argument("--module", choices=(*WATCHERS, "program_watch"))
    logs.add_argument("--target")
    logs.add_argument("--lines", type=int, default=50)
    rerun = commands.add_parser("rerun", help="Queue a module for the running daemon; respects scan concurrency")
    rerun.add_argument("module", choices=WATCHERS)
    rerun.add_argument("--target", required=True)
    targets = commands.add_parser("targets", help="List targets")
    targets.add_argument("--format", choices=("text", "json"), default="text")
    target = commands.add_parser("target", help="Manage configured targets")
    actions = target.add_subparsers(dest="action", required=True)
    add = actions.add_parser("add")
    add.add_argument("name")
    add.add_argument("--domain", action="extend", type=comma_separated, default=[],
                     help="Root domains, comma-separated; flag may also be repeated")
    add.add_argument("--cidr", action="extend", type=comma_separated, default=[],
                     help="Authorized CIDRs, comma-separated; flag may also be repeated")
    update = actions.add_parser("update")
    update.add_argument("name")
    update.add_argument("--domain", action="extend", type=comma_separated, default=[],
                        help="Root domains, comma-separated; flag may also be repeated")
    update.add_argument("--cidr", action="extend", type=comma_separated, default=[],
                        help="Authorized CIDRs, comma-separated; flag may also be repeated")
    listing = actions.add_parser("list")
    listing.add_argument("--format", choices=("text", "json"), default="text")
    show = actions.add_parser("show")
    show.add_argument("name")
    show.add_argument("--format", choices=("text", "json"), default="text")
    remove = actions.add_parser("remove")
    remove.add_argument("name")
    remove.add_argument("--yes", action="store_true", help="Confirm deletion of target, assets and history")
    for name in ("assets", "domains"):
        command = commands.add_parser(name, help="Inspect asset state" if name == "assets" else "Export unique hostnames")
        scope = command.add_mutually_exclusive_group(required=True)
        scope.add_argument("--target")
        scope.add_argument("--all", action="store_true")
        command.add_argument("--format", choices=("text", "json"), default="text")
        dns = command.add_mutually_exclusive_group()
        dns.add_argument("--resolved", dest="resolved", action="store_const", const=True, default=None)
        dns.add_argument("--unresolved", dest="resolved", action="store_const", const=False)
        http = command.add_mutually_exclusive_group()
        http.add_argument("--http", dest="http", action="store_const", const=True, default=None)
        http.add_argument("--no-http", dest="http", action="store_const", const=False)
        command.add_argument("--status", type=int, choices=range(100, 600), metavar="100..599")
        command.add_argument("--source", help="Filter discovery source, e.g. dns_bruteforce, tlsx, ptr")
    return root


def print_json(items):
    print("[", end="")
    separator = ""
    for item in items:
        print(separator + json.dumps(item, ensure_ascii=False), end="")
        separator = ",\n"
    print("]")


def print_targets(items, output_format):
    if output_format == "json":
        print_json(items)
        return
    for target in items:
        print(f"TARGET: {target['name']}")
        print("Domains: " + ", ".join(target["domains"]))
        print("CIDRs: " + (", ".join(target["cidrs"]) or "-"))


def unique_domains(assets):
    previous = None
    for asset in assets:  # Database orders by hostname, then target.
        if asset["hostname"] != previous:
            yield asset["hostname"]
            previous = asset["hostname"]


async def doctor(config):
    ok = True
    runner = ToolRunner(config)
    markers = {"subfinder": "-d", "chaos": "-d", "dnsx": "-rcode", "httpx": "-status-code",
               "tlsx": "-san", "shuffledns": "-mode", "dnsgen": "wordlen", "massdns": "resolvers"}
    brute = config["dns_bruteforce"]
    required = {"subfinder", "chaos", "dnsx", "httpx", "tlsx"}
    if brute["static"]["enabled"] or brute["dynamic"]["enabled"]:
        required.update(("shuffledns", "massdns"))
    if brute["dynamic"]["enabled"]:
        required.add("dnsgen")
    for name in sorted(required):
        executable = shutil.which(config["tools"][name])
        if not executable:
            ok = False
            print(f"ERROR {name}: executable not found: {config['tools'][name]}")
            continue
        try:
            flag = "--help" if name in {"dnsgen", "massdns"} else "-h"
            async with runner.run(name, [flag], merge_stderr=True) as output:
                help_text = output.read_text(encoding="utf-8", errors="replace")
                required_flags = [markers[name]]
                if name == "subfinder":
                    required_flags.append("-recursive")
                if name == "httpx":
                    required_flags += ["-auto-referer", "-tech-detect", "-rate-limit", "-response-size-to-read"]
                if name == "dnsx":
                    required_flags += ["-ptr", "-resp-only", "-cname", "-stream", "-rate-limit"]
                if name == "shuffledns":
                    required_flags += ["-strict-wildcard", "-wt"]
                missing = [flag for flag in required_flags if flag not in help_text]
                if missing:
                    raise ValueError("Missing flags: " + ", ".join(missing) + "; check/update the configured executable")
            print(f"OK    {name}: {executable}")
        except Exception as error:
            ok = False
            print(f"ERROR {name}: {error}")
            if name == "httpx":
                print("      Configure tools.httpx with the ProjectDiscovery binary, not Python's httpx client.")
    if brute["static"]["enabled"]:
        directory = config.path(brute["static"]["wordlist_dir"])
        if not any(path.is_file() and path.stat().st_size for path in directory.glob("*.txt")):
            print(f"ERROR no static .txt wordlists in {directory}")
            ok = False
    if brute["static"]["enabled"] or brute["dynamic"]["enabled"]:
        resolvers = config.path(brute["shuffledns"]["resolvers"])
        if not resolvers.is_file() or not resolvers.stat().st_size:
            print(f"ERROR supply DNS resolver IPs, one per line: {resolvers}")
            ok = False
    print("Telegram: " + ("enabled (delivery not tested)" if config["telegram"]["enabled"] else "disabled; events remain queued"))
    return 0 if ok else 1


def main(argv=None):
    arguments = parser().parse_args(argv)
    database = None
    try:
        config = load_config(arguments.config)
        configure_logging(config)
        if arguments.command == "doctor":
            return asyncio.run(doctor(config))
        if arguments.command == "logs":
            if not 1 <= arguments.lines <= 10000:
                raise ValueError("--lines must be between 1 and 10000")
            print(log_tail(config, arguments.module, arguments.target, arguments.lines))
            return 0
        database = Database(config.path(config["database"]["path"]))
        if arguments.command == "run":
            with daemon_lock(database.path):
                asyncio.run(Scheduler(config, database).run())
        elif arguments.command == "rerun":
            target = database.target(arguments.target)
            database.request_run(target["id"], arguments.module)
            print(f"Queued {arguments.module} for {target['name']}. The assetwatch run daemon executes it when scan access is available.")
        elif arguments.command == "program-changes":
            if not 1 <= arguments.limit <= 10000 or arguments.offset < 0:
                raise ValueError("--limit must be 1..10000 and --offset must be nonnegative")
            events = database.recent_program_events(arguments.platform, arguments.limit, arguments.offset)
            if arguments.format == "json":
                print_json(events)
            else:
                for event in events:
                    print(program_event_summary(event))
        elif arguments.command in {"health", "changes", "cnames"}:
            target_id = database.target(arguments.target)["id"] if arguments.target else None
            if arguments.command == "health":
                report = health_report(config, database, target_id)
                print(json.dumps(report, ensure_ascii=False, indent=2) if arguments.format == "json" else health_text(report))
            else:
                if not 1 <= arguments.limit <= 10000 or arguments.offset < 0:
                    raise ValueError("--limit must be 1..10000 and --offset must be nonnegative")
                if arguments.command == "changes":
                    rows = database.recent_events(target_id, arguments.event_type, arguments.limit, arguments.offset)
                else:
                    rows = database.cname_assets(target_id, arguments.limit, arguments.offset)
                if arguments.format == "json":
                    print_json(rows)
                else:
                    for row in rows:
                        print(event_summary(row) if arguments.command == "changes" else
                              f"{row['target']}\t{row['hostname']}\t{','.join(row['cname_records'])}\t{row['cname_checked_at']}")
        elif arguments.command == "targets" or (arguments.command == "target" and arguments.action == "list"):
            print_targets(database.targets(), arguments.format)
        elif arguments.command == "target":
            if arguments.action == "add":
                if not arguments.domain and not arguments.cidr:
                    raise ValueError("Provide at least one --domain or --cidr")
                print_targets([database.add_target(arguments.name, arguments.domain, arguments.cidr)], "text")
            elif arguments.action == "update":
                if not arguments.domain and not arguments.cidr:
                    raise ValueError("Provide at least one --domain or --cidr to update")
                print_targets([database.update_target(arguments.name, arguments.domain, arguments.cidr)], "text")
            elif arguments.action == "show":
                print_targets([database.target(arguments.name)], arguments.format)
            elif arguments.action == "remove":
                if not arguments.yes:
                    raise ValueError("Removal deletes the target, its assets and history. Repeat with --yes to confirm.")
                database.remove_target(arguments.name)
                print(f"Removed {arguments.name}, its assets and history. Restore from a backup to recover them.")
        else:
            target_id = database.target(arguments.target)["id"] if arguments.target else None
            assets = database.assets(target_id, arguments.resolved, arguments.http, arguments.status, arguments.source)
            if arguments.command == "domains":
                names = unique_domains(assets)
                if arguments.format == "json":
                    print_json(names)
                else:
                    for name in names:
                        print(name)
            elif arguments.format == "json":
                print_json(assets)
            else:
                print("TARGET\tHOSTNAME\tDNS\tIP\tHTTP\tSTATUS\tCNAME\tKNOWN_IPS")
                for asset in assets:
                    dns = ("YES" if asset["dns_resolved"] else "NO") if asset["dns_checked_at"] else "PENDING"
                    http = ("YES" if asset["http_available"] else "NO") if asset["http_checked_at"] else "PENDING"
                    print("\t".join((asset["target"], asset["hostname"], dns,
                                     ",".join(asset["ip_addresses"]) or "-", http,
                                     str(asset["http_status"] or "-"), ",".join(asset["cname_records"]) or "-",
                                     ",".join(asset["known_ip_addresses"]) or "-")))
        return 0
    except (OSError, ValueError, sqlite3.Error, yaml.YAMLError) as error:
        print(f"assetwatch: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if database:
            database.close()
