"""Small validated YAML configuration; relative paths follow the config file."""

import copy
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

WATCHERS = ("passive_discovery", "tlsx", "dns_resolution", "http_probe", "dns_bruteforce", "ptr_discovery")
PROGRAM_FEEDS = {
    platform: f"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{platform}_data.json"
    for platform in ("hackerone", "bugcrowd", "intigriti")
}

DEFAULTS = {
    "database": {"path": "./data/assets.db"},
    "intervals": {"passive_discovery": 3600, "tlsx": 3600,
                  "dns_resolution": 1800, "http_probe": 1800,
                  "monitoring": 300, "dns_bruteforce": 604800, "ptr_discovery": 3600,
                  "program_watch": 3600},
    "program_watch": {"enabled": True, "max_feed_bytes": 32 * 1024 * 1024},
    "runtime": {"batch_size": 500, "tool_timeout": 1800,
                "request_timeout": 30, "threads": 10, "poll_interval": 1,
                "progress_interval": 30, "failure_retry_interval": 300},
    "chaos": {"api_key": ""},
    "cdn": {"enabled": True, "refresh_interval": 86400, "retry_interval": 3600,
            "max_age": 604800,
            "projectdiscovery_url": "https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/sources_data.json",
            "akamai_url": "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt"},
    "dns_bruteforce": {"static": {"enabled": True, "wordlist_dir": "./wordlists", "chunk_size": 5000},
                       "dynamic": {"enabled": True, "batch_size": 100, "chunk_size": 5000},
                       "shuffledns": {"threads": 10, "resolvers": "./resolvers.txt", "cooldown": 1.0}},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": "",
                 "batch_size": 50, "send_delay": 1.1, "notify_dns_ip_changes": True,
                 "commands_enabled": True, "command_poll_interval": 3},
    "logging": {"file": "./logs/assetwatch.log", "level": "INFO",
                "max_bytes": 10485760, "backup_count": 5},
    "tools": {name: name for name in
              ("subfinder", "chaos", "dnsx", "httpx", "tlsx", "massdns", "shuffledns", "dnsgen")},
}


def merge(base: dict, override: dict, prefix: str = "") -> None:
    for key, value in override.items():
        if key not in base:
            raise ValueError(f"Unknown configuration key: {prefix}{key}")
        if isinstance(base[key], dict):
            if not isinstance(value, dict):
                raise ValueError(f"{prefix}{key} must be a mapping")
            merge(base[key], value, f"{prefix}{key}.")
        else:
            base[key] = value


def positive(value, name: str, integer: bool = False) -> None:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0
            or (integer and not isinstance(value, int))):
        raise ValueError(f"{name} must be a positive {'integer' if integer else 'number'}")


@dataclass
class Config:
    values: dict
    base: Path

    def __getitem__(self, key):
        return self.values[key]

    def path(self, value: str) -> Path:
        path = Path(value).expanduser()
        return (self.base / path).resolve()


def load_config(filename: str | Path = "config.yaml") -> Config:
    filename = Path(filename).resolve()
    with filename.open(encoding="utf-8") as stream:
        supplied = yaml.safe_load(stream)
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, dict):
        raise ValueError("Configuration must be a YAML mapping")
    values = copy.deepcopy(DEFAULTS)
    merge(values, supplied)

    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, str):
            return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                          lambda match: os.environ.get(match[1], ""), value)
        return value

    values = expand(values)
    for name, value in values["intervals"].items():
        positive(value, f"intervals.{name}")
    for name, value in values["runtime"].items():
        positive(value, f"runtime.{name}", name in {"batch_size", "threads"})
    for section in (values["telegram"], values["cdn"], values["program_watch"], values["dns_bruteforce"]["static"],
                    values["dns_bruteforce"]["dynamic"]):
        if not isinstance(section["enabled"], bool):
            raise ValueError("enabled values must be YAML true or false")
    positive(values["program_watch"]["max_feed_bytes"], "program_watch.max_feed_bytes", True)
    if not isinstance(values["telegram"]["notify_dns_ip_changes"], bool):
        raise ValueError("telegram.notify_dns_ip_changes must be YAML true or false")
    if not isinstance(values["telegram"]["commands_enabled"], bool):
        raise ValueError("telegram.commands_enabled must be YAML true or false")
    positive(values["telegram"]["command_poll_interval"], "telegram.command_poll_interval")
    for key in ("refresh_interval", "retry_interval", "max_age"):
        positive(values["cdn"][key], f"cdn.{key}")
    if values["cdn"]["max_age"] < values["cdn"]["refresh_interval"]:
        raise ValueError("cdn.max_age must be at least cdn.refresh_interval")
    for key in ("projectdiscovery_url", "akamai_url"):
        value = values["cdn"][key]
        if not isinstance(value, str) or urlsplit(value).scheme != "https" or not urlsplit(value).netloc:
            raise ValueError(f"cdn.{key} must be an HTTPS URL")
    if not isinstance(values["chaos"]["api_key"], str):
        raise ValueError("chaos.api_key must be a string")
    values["chaos"]["api_key"] = values["chaos"]["api_key"].strip()
    positive(values["dns_bruteforce"]["shuffledns"]["threads"], "shuffledns.threads", True)
    positive(values["dns_bruteforce"]["dynamic"]["batch_size"], "dns_bruteforce.dynamic.batch_size", True)
    positive(values["dns_bruteforce"]["static"]["chunk_size"], "dns_bruteforce.static.chunk_size", True)
    positive(values["dns_bruteforce"]["dynamic"]["chunk_size"], "dns_bruteforce.dynamic.chunk_size", True)
    if not isinstance(values["dns_bruteforce"]["shuffledns"]["cooldown"], (int, float)) or values["dns_bruteforce"]["shuffledns"]["cooldown"] < 0:
        raise ValueError("dns_bruteforce.shuffledns.cooldown must be a non-negative number")
    positive(values["telegram"]["batch_size"], "telegram.batch_size", True)
    positive(values["telegram"]["send_delay"], "telegram.send_delay")
    for key in ("max_bytes", "backup_count"):
        positive(values["logging"][key], f"logging.{key}", True)
    if not isinstance(values["logging"]["level"], str) or values["logging"]["level"] not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ValueError("logging.level must be DEBUG, INFO, WARNING or ERROR")
    if not isinstance(values["telegram"]["bot_token"], str):
        raise ValueError("telegram.bot_token must be a string")
    if type(values["telegram"]["chat_id"]) not in (str, int):
        raise ValueError("telegram.chat_id must be a string or integer")
    for key in ("bot_token", "chat_id"):
        values["telegram"][key] = str(values["telegram"][key] or "")
        if values["telegram"]["enabled"] and not values["telegram"][key]:
            raise ValueError(f"telegram.{key} is required when Telegram is enabled")
    for name, value in values["tools"].items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"tools.{name} must be an executable path or name")
        if "/" in value:
            values["tools"][name] = str((filename.parent / Path(value).expanduser()).resolve())
    for section, key in (("database", "path"), ("logging", "file")):
        if not isinstance(values[section][key], str) or not values[section][key]:
            raise ValueError(f"{section}.{key} must be a nonempty path")
    for section, key in (("static", "wordlist_dir"), ("shuffledns", "resolvers")):
        if not isinstance(values["dns_bruteforce"][section][key], str) or not values["dns_bruteforce"][section][key]:
            raise ValueError(f"dns_bruteforce.{section}.{key} must be a nonempty path")
    return Config(values, filename.parent)
