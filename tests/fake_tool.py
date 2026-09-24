#!/usr/bin/env python3
"""Offline executable fixture for end-to-end wrapper tests."""

import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
phase = int(Path(os.environ["ASSETWATCH_TEST_PHASE"]).read_text())
record = {"tool": name, "args": args}
hosts = []
if name in {"dnsx", "httpx", "tlsx"}:
    hosts = sys.stdin.read().splitlines()
    record["input"] = hosts
if name == "dnsgen":
    record["input"] = Path(args[0]).read_text().splitlines()
if name == "shuffledns" and "-l" in args:
    record["input"] = Path(args[args.index("-l") + 1]).read_text().splitlines()
with open(os.environ["ASSETWATCH_TEST_CALLS"], "a") as stream:
    stream.write(json.dumps(record) + "\n")

if name == "subfinder":
    domain = args[args.index("-d") + 1]
    print(" API." + domain.upper() + ". ")
    print("api." + domain)
    print("outside.invalid")
elif name == "chaos":
    print("chaos unavailable", file=sys.stderr)
    sys.exit(1)
elif name == "tlsx":
    print(json.dumps({"ip": "192.0.2.1", "subject_cn": "cert.example.test", "subject_an": ["*.cert.example.test", "outside.invalid"]}))
    print(json.dumps({"ip": "198.51.100.1", "subject_cn": "wrong-cidr.example.test"}))
elif name == "dnsx":
    for host in hosts:
        if host.startswith("unresolved.") or phase == 3:
            print(json.dumps({"host": host, "status_code": "NXDOMAIN"}))
        else:
            print(json.dumps({"host": host, "status_code": "NOERROR", "a": ["192.0.2.1"]}))
elif name == "httpx":
    for host in hosts:
        print(json.dumps({"input": host, "url": "https://" + host,
                          "failed": phase == 2, "status_code": 0 if phase == 2 else (403 if phase == 1 else 200),
                          "title": "Fixture", "webserver": "fixture"}))
elif name == "dnsgen":
    print("generated.example.test")
    print("generated.example.org")
    print("outside.invalid")
elif name == "shuffledns":
    domain = args[args.index("-d") + 1]
    print(("static." if "-w" in args else "generated.") + domain)
    print("outside.invalid")
