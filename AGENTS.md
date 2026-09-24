# AGENTS.md

# Continuous Asset Watcher

## 1. Mission

Build a small, readable, Python-based CLI application for **continuous authorized attack-surface asset discovery and monitoring**.

The application receives explicitly configured targets.

Each target may contain:

* company/target name
* one or more root domains
* zero or more CIDR ranges

The application continuously discovers assets, resolves them, probes HTTP services, monitors state changes, discovers certificate-based assets, and periodically performs DNS brute-force discovery.

All discovered assets must eventually enter one common monitoring pipeline.

The application must be intentionally simple.

---

# 2. Core Philosophy

The application is a **continuous watcher**, not a one-shot scanner.

Nothing should be implemented as:

```text
run once → finish → exit
```

when that component is supposed to be monitored continuously.

Instead:

```text
run
 ↓
execute task
 ↓
process results
 ↓
compare state
 ↓
notify changes
 ↓
wait for configured interval
 ↓
execute again
 ↓
repeat forever
```

Every major component has its own configurable interval.

---

# 3. Components

The application consists of these continuous components:

```text
1. Passive Subdomain Discovery
2. Certificate Discovery / TLSX
3. DNS Resolution / DNSX
4. HTTP Probing / HTTPX
5. State Monitoring
6. Telegram Notifications
7. DNS Brute Force
```

DNS brute-force is also continuous, but intentionally has a much longer configurable interval.

For example:

```text
Passive discovery: every 1 hour
TLSX: every 1 hour
DNS resolution: every 1 hour
HTTP probing: every 30 minutes
Monitoring: continuous through state comparison
DNS brute force: every 7 days
```

These are only examples.

All intervals must be configurable.

---

# 4. External Tools

Use external security tools rather than reimplementing their functionality.

Primary tools:

```text
subfinder
chaos
crt.sh
dnsx
httpx
tlsx
massdns
shuffledns
dnsgen
```

Most tools are from the ProjectDiscovery ecosystem.

The application must invoke them as external executables.

Tool paths must be configurable.

---

# 5. Target Model

A target has:

```text
Target
├── name
├── domains
└── cidrs
```

Example:

```yaml
name: example

domains:
  - example.com
  - example.org

cidrs:
  - 1.2.3.0/24
  - 5.6.7.0/24
```

CIDRs are optional.

A target may have multiple domains and multiple CIDRs.

---

# 6. Configuration

Use:

```text
config.yaml
```

Example:

```yaml
database:
  path: "./data/assets.db"

intervals:

  passive_discovery: 3600

  tlsx: 3600

  dns_resolution: 1800

  http_probe: 1800

  monitoring: 300

  dns_bruteforce: 604800

dns_bruteforce:

  static:
    enabled: true
    wordlist_dir: "./wordlists"

  dynamic:
    enabled: true

  shuffledns:
    threads: 10

telegram:
  enabled: true
  bot_token: "${TELEGRAM_BOT_TOKEN}"
  chat_id: "${TELEGRAM_CHAT_ID}"

tools:

  subfinder: "subfinder"
  chaos: "chaos"
  dnsx: "dnsx"
  httpx: "httpx"
  tlsx: "tlsx"
  massdns: "massdns"
  shuffledns: "shuffledns"
  dnsgen: "dnsgen"
```

Do not hard-code intervals.

Do not hard-code secrets.

---

# 7. Single Database

Use exactly one database.

Default:

```text
SQLite
```

All state must be stored in this database.

Do not introduce:

* Redis
* PostgreSQL
* MongoDB
* Elasticsearch
* separate databases per target

unless explicitly requested later.

---

# 8. Database Responsibilities

The database is the source of truth for:

* targets
* target domains
* target CIDRs
* discovered hostnames
* discovery sources
* first/last seen
* DNS state
* IP addresses
* HTTP state
* HTTP status
* HTTP metadata
* state transitions
* notification history

---

# 9. Asset Identity

An asset must be unique per target.

Conceptually:

```text
UNIQUE(target_id, hostname)
```

If:

```text
api.example.com
```

is found by:

```text
subfinder
chaos
crt.sh
tlsx
dns brute force
```

there must still be only one asset.

Its discovery sources may be recorded as:

```text
subfinder
chaos
crtsh
tlsx
dns_bruteforce
```

---

# 10. Normalization

Before database insertion:

```text
API.Example.COM.
```

becomes:

```text
api.example.com
```

Normalization happens before deduplication.

At minimum:

* lowercase
* remove trailing dot
* remove whitespace
* normalize wildcard output
* validate hostname format

---

# 11. Continuous Passive Discovery

For every target, continuously run:

```text
subfinder
chaos
crt.sh
```

against configured domains.

Pipeline:

```text
Target
  ↓
Domains
  ↓
subfinder
chaos
crt.sh
  ↓
normalize
  ↓
deduplicate
  ↓
database
  ↓
state/event detection
  ↓
Telegram
```

This process does not terminate after one execution.

After the configured interval:

```text
repeat
```

---

# 12. Continuous TLSX Discovery

For targets with CIDRs:

```text
CIDR
 ↓
TLSX
 ↓
certificate names
 ↓
normalize
 ↓
deduplicate
 ↓
database
```

TLSX is also a continuous watcher.

It must not run only once.

After:

```text
intervals.tlsx
```

it runs again.

New certificate-derived hostnames enter the same asset database.

They then enter the same:

```text
DNSX
 ↓
HTTPX
 ↓
monitoring
```

pipeline.

---

# 13. TLSX Scope Isolation

CIDR-based certificate discovery must respect target scope.

For example:

```text
Target A
  ├── domains
  └── CIDRs

Target B
  ├── domains
  └── CIDRs
```

TLSX results from Target A must be associated with Target A.

Do not mix target ownership.

---

# 14. Continuous DNS Resolution

DNS resolution is not a one-time operation.

Use:

```text
dnsx
```

continuously.

The resolution watcher periodically processes assets from the database.

Conceptually:

```text
Database assets
       ↓
DNSX
       ↓
current DNS state
       ↓
database
```

The application must detect:

```text
unresolved → resolved
resolved → unresolved
```

and track IP changes where useful.

---

# 15. A Record Requirement

For HTTP probing:

```text
hostname
   ↓
DNSX
   ↓
A record?
```

If there is no usable A record:

```text
do not HTTP probe
```

If an A record exists:

```text
run HTTPX
```

---

# 16. Continuous HTTPX

HTTP probing must also be continuous.

Use:

```text
httpx
```

against currently DNS-resolvable assets.

Do not probe only newly discovered assets.

Previously discovered assets must continue to be monitored.

Example:

```text
api.example.com
```

can be checked repeatedly:

```text
Day 1 → 200
Day 2 → 200
Day 3 → 403
Day 4 → 200
```

The state transitions must be detected.

---

# 17. HTTP State

At minimum store:

```text
HTTP available/unavailable
HTTP status code
last HTTP observation
previous HTTP status
```

The system must distinguish:

```text
never had HTTP service
```

from:

```text
had HTTP service → disappeared
```

and:

```text
disappeared → returned
```

---

# 18. Events

The monitoring engine must detect the following events.

## 18.1 Fresh Asset

Hostname was never present in the database.

```text
NOT FOUND
   ↓
FOUND
```

Event:

```text
fresh_asset
```

---

## 18.2 Fresh Subdomain

Hostname already existed but previously did not resolve.

```text
DNS unresolved
      ↓
DNS resolved
```

Event:

```text
fresh_subdomain
```

---

## 18.3 HTTP Service Appeared

Previously:

```text
DNS resolved
HTTP unavailable
```

Now:

```text
DNS resolved
HTTP available
```

Generate event.

---

## 18.4 HTTP Service Returned

Previously:

```text
HTTP available
```

then:

```text
HTTP unavailable
```

for some period, then:

```text
HTTP available
```

again.

This must generate a separate event from the first HTTP appearance.

---

## 18.5 HTTP Status Changed

Example:

```text
200 → 403
```

or:

```text
403 → 200
```

Generate notification.

Do not generate notifications when:

```text
200 → 200
```

---

# 19. Event State Machine

State transitions should be explicit.

Conceptually:

```text
                ┌──────────────┐
                │   NEW ASSET  │
                └──────┬───────┘
                       ↓
                ┌──────────────┐
                │ DNS RESOLVED │
                └──────┬───────┘
                       ↓
              ┌───────────────────┐
              │ HTTP AVAILABLE?   │
              └───────┬───────────┘
                  YES  │  NO
                       │
          ┌────────────┘
          ↓
    HTTP SERVICE ACTIVE
          │
          ↓
    STATUS MONITORING
          │
          ├── status changed
          │
          ├── service disappeared
          │
          └── service returned
```

The exact implementation may differ, but the state transitions must remain distinguishable.

---

# 20. DNS Brute Force

DNS brute force is a separate discovery module.

It has two modes:

```text
static
dynamic
```

Unlike the other watchers, it normally runs with a long interval.

Example:

```text
every 7 days
```

but this value must be configurable.

---

# 21. Static DNS Brute Force

The user provides static wordlists in a configured directory.

Example:

```text
wordlists/
├── common.txt
├── production.txt
├── cloud.txt
└── custom.txt
```

For each target domain:

```text
domain
 +
static wordlist
 ↓
ShuffleDNS
 ↓
MassDNS
 ↓
resolved hostnames
```

The application must support configurable wordlist directories.

Do not embed huge wordlists inside the application.

---

# 22. Dynamic DNS Brute Force

Dynamic mode uses:

```text
dnsgen
```

The input is the complete set of subdomains already discovered for the target.

Conceptually:

```text
Existing target subdomains
          ↓
        DNSGen
          ↓
generated candidate names
          ↓
      ShuffleDNS
          ↓
       MassDNS
          ↓
      discovered hosts
```

The DNSGen input must come from the existing database.

It should consider all relevant subdomains belonging to that target.

---

# 23. ShuffleDNS / MassDNS

DNS brute-force must use:

```text
shuffledns
massdns
```

The exact invocation should be isolated inside the DNS brute-force tool wrapper.

Do not implement DNS resolution manually in Python.

---

# 24. ShuffleDNS Thread Control

Thread/concurrency configuration is required.

Example:

```yaml
dns_bruteforce:
  shuffledns:
    threads: 10
```

The goal is to prevent excessive load against DNS infrastructure and keep the scan controlled.

The implementation must:

* respect configured concurrency
* never silently create unlimited threads
* avoid spawning a thread per hostname
* handle failures cleanly

Use a bounded worker/concurrency model.

The configured value must directly control the amount of parallel work.

---

# 25. DNS Brute Force Output

This is extremely important.

DNS brute-force output must NOT remain isolated inside the brute-force module.

Any newly discovered hostname must enter the main asset database.

Example:

```text
DNS brute force
      ↓
api-dev.example.com
      ↓
assets table
      ↓
DNS monitoring
      ↓
HTTP monitoring
```

Therefore a brute-force-discovered hostname becomes a normal asset.

It must subsequently receive continuous monitoring.

---

# 26. Common Asset Pipeline

Every discovery mechanism must feed the same pipeline.

Sources:

```text
subfinder
chaos
crt.sh
tlsx
dns brute force
```

all eventually become:

```text
             ┌───────────────┐
             │ normalize     │
             └───────┬───────┘
                     ↓
             ┌───────────────┐
             │ deduplicate   │
             └───────┬───────┘
                     ↓
             ┌───────────────┐
             │ Asset Database│
             └───────┬───────┘
                     ↓
                  DNSX
                     ↓
              DNS state
                     ↓
                  HTTPX
                     ↓
              HTTP state
                     ↓
             State comparison
                     ↓
                Telegram
```

Do not implement separate monitoring logic for each discovery source.

---

# 27. Continuous Watcher Architecture

Each watcher has its own loop and interval.

Conceptually:

```text
Application
│
├── Passive Discovery Watcher
│      └── every N seconds
│
├── TLSX Watcher
│      └── every N seconds
│
├── DNS Resolution Watcher
│      └── every N seconds
│
├── HTTPX Watcher
│      └── every N seconds
│
└── DNS Brute Force Watcher
       └── every N seconds
```

The application may implement this with a simple scheduler.

Do not introduce Celery, RabbitMQ, Redis, Kubernetes, or distributed workers.

A single-process implementation is preferred.

---

# 28. Scheduler Requirements

The scheduler must:

* run indefinitely
* respect individual intervals
* avoid unnecessary duplicate execution
* survive tool failures
* log execution
* continue processing other targets
* not terminate because one watcher fails

Example:

```text
21:00 Passive discovery started
21:02 Passive discovery finished
21:30 HTTPX started
21:31 HTTPX finished
22:00 Passive discovery started
```

If TLSX fails:

```text
TLSX failed for target X
```

the other watchers must continue.

---

# 29. Terminal Visibility

Everything important must be visible in the terminal.

Use structured logging.

At minimum:

```text
INFO
WARNING
ERROR
```

The user must be able to leave the program running overnight and understand what happened later.

Example:

```text
2026-09-24 21:00:01 INFO  Passive discovery started: example
2026-09-24 21:00:08 INFO  subfinder: 143 results
2026-09-24 21:00:09 INFO  chaos: 27 results
2026-09-24 21:00:10 INFO  crt.sh: 31 results
2026-09-24 21:00:10 INFO  New assets: 4

2026-09-24 21:05:01 INFO  DNS resolution started
2026-09-24 21:05:08 INFO  Resolved: 173
2026-09-24 21:05:08 INFO  Fresh subdomains: 2

2026-09-24 21:10:01 INFO  HTTP probing started
2026-09-24 21:10:15 INFO  HTTP services: 121
2026-09-24 21:10:15 INFO  Status changes: 3
```

---

# 30. Persistent Logging

Logs should be available after the process has been running for a long time.

Support a log file configured by the application.

Example:

```text
logs/assetwatch.log
```

The user should be able to return the next day and determine:

* what ran
* when it ran
* which target was processed
* which tool failed
* what new assets appeared
* what monitoring events happened

---

# 31. Terminal Asset Inspection

The user must have direct control over discovered assets from the terminal.

Provide commands such as:

```bash
assetwatch targets
```

```bash
assetwatch assets --target example
```

```bash
assetwatch assets --all
```

The output should provide useful asset state.

For example:

```text
TARGET: example

HOSTNAME                 DNS       IP          HTTP      STATUS
api.example.com          YES       1.2.3.4     YES       200
admin.example.com        YES       1.2.3.5     YES       403
old.example.com          NO        -           NO        -
dev.example.com          YES       1.2.3.6     NO        -
```

The user must be able to inspect all known assets.

---

# 32. Raw Subdomain Output

The CLI must also provide raw hostname output.

Example:

```bash
assetwatch domains --target example
```

Output:

```text
api.example.com
admin.example.com
dev.example.com
...
```

For all targets:

```bash
assetwatch domains --all
```

No duplicates.

Machine-readable formats should be supported where practical:

```text
--format text
--format json
```

---

# 33. Asset Filtering

Terminal inspection should allow basic filtering.

For example:

```bash
assetwatch assets --target example --resolved
```

```bash
assetwatch assets --target example --http
```

```bash
assetwatch assets --target example --status 200
```

```bash
assetwatch assets --target example --unresolved
```

```bash
assetwatch assets --target example --no-http
```

Keep filters simple.

Do not build a complex query language.

---

# 34. Telegram

All meaningful events must be sent to the configured Telegram bot.

Telegram is a notification layer, not the source of truth.

The database remains authoritative.

Notifications include events such as:

```text
Fresh Asset
Fresh Subdomain
HTTP Service Appeared
HTTP Service Returned
HTTP Status Changed
Certificate-derived New Asset
DNS-Brute-Force New Asset
```

---

# 35. Telegram Deduplication

Never repeatedly notify unchanged state.

For example:

```text
api.example.com → 200
```

observed every 30 minutes must NOT produce:

```text
30-minute notification
30-minute notification
30-minute notification
...
```

Only meaningful state transitions generate notifications.

The database must preserve enough information to guarantee notification deduplication.

---

# 36. Event Identity

An event should be identifiable using information such as:

```text
target
hostname
event_type
previous_state
new_state
```

Example:

```text
example
api.example.com
http_status_changed
200
403
```

is a distinct event from:

```text
example
api.example.com
http_status_changed
403
200
```

---

# 37. Telegram Example

Example notification:

```text
🆕 Fresh Asset

Target: example
Host: api-dev.example.com
Source: dns_bruteforce

DNS: RESOLVED
IP: 1.2.3.4
HTTP: YES
Status: 200
```

Status change:

```text
🔄 HTTP Status Changed

Target: example
Host: api.example.com

200 → 403

URL: https://api.example.com
```

HTTP return:

```text
🟢 HTTP Service Returned

Target: example
Host: api.example.com

HTTP service was unavailable.
It is available again.

Status: 200
```

Keep notifications concise.

---

# 38. Error Handling

External tools may fail.

For every external tool:

* capture stdout
* capture stderr
* capture exit code
* log failures
* do not crash the entire application
* continue other targets
* continue other watchers

Example:

```text
ERROR subfinder failed for target example
ERROR stderr: ...
```

The scheduler continues.

---

# 39. External Tool Wrappers

Keep subprocess execution isolated.

Suggested:

```text
tools/
├── subfinder.py
├── chaos.py
├── crtsh.py
├── dnsx.py
├── httpx.py
├── tlsx.py
├── dnsgen.py
├── shuffledns.py
└── massdns.py
```

Each wrapper should have a simple responsibility:

```text
build command
run command
parse output
return normalized result
```

Do not scatter `subprocess.run()` throughout the project.

---

# 40. Project Structure

Prefer a simple structure:

```text
assetwatch/
│
├── main.py
├── cli.py
├── config.py
├── database.py
├── models.py
├── scheduler.py
├── monitor.py
├── notifications.py
├── normalization.py
├── logging_config.py
│
├── discovery/
│   ├── passive.py
│   ├── certificates.py
│   └── dns_bruteforce.py
│
├── resolution/
│   └── dns.py
│
├── probing/
│   └── http.py
│
└── tools/
    ├── subfinder.py
    ├── chaos.py
    ├── crtsh.py
    ├── dnsx.py
    ├── httpx.py
    ├── tlsx.py
    ├── dnsgen.py
    ├── shuffledns.py
    └── massdns.py
```

The exact structure may be simplified further if appropriate.

Do not create unnecessary modules.

---

# 41. No Duplicate Processing

Deduplication applies everywhere:

```text
discovery
database
DNS processing
HTTP processing
notifications
terminal output
```

Example:

If 3 tools return:

```text
api.example.com
api.example.com
api.example.com
```

the asset pipeline processes it as one hostname.

---

# 42. Monitoring Newly Discovered Assets

This is a critical requirement.

A new hostname discovered today must automatically enter continuous monitoring.

Example:

```text
Day 1
DNS brute force discovers:

new-api.example.com

↓
database

↓
DNSX

↓
HTTPX

↓
continuous monitoring
```

The user must NOT need to manually add it to another list.

---

# 43. Monitoring Must Not Depend on Discovery Source

The monitoring system should not care whether the asset came from:

```text
subfinder
chaos
crt.sh
TLSX
DNS brute force
```

Once stored:

```text
asset
```

is monitored identically.

---

# 44. Target Ownership

Every asset must belong to exactly one logical target.

Do not allow accidental cross-target mixing.

When processing results, the application must know:

```text
which target produced this result
```

and preserve that relationship.

---

# 45. CLI Target Management

Provide simple target commands.

Conceptually:

```bash
assetwatch target add
assetwatch target list
assetwatch target show NAME
assetwatch target remove NAME
```

Adding a target should allow:

```text
name
domains
CIDRs (optional)
```

---

# 46. Main Command

The main continuous mode should be something like:

```bash
assetwatch run
```

Once started:

```text
Application starts
        ↓
load configuration
        ↓
load database
        ↓
start continuous watchers
        ↓
continue indefinitely
```

The process should be suitable for:

```text
systemd
tmux
screen
Docker
```

but Docker is not required.

---

# 47. Graceful Shutdown

Support:

```text
Ctrl+C
```

without corrupting the database.

The application should shut down cleanly.

---

# 48. Performance

The project is intended to run on one machine.

Do not optimize prematurely.

However:

* avoid loading enormous datasets unnecessarily
* use database indexes
* batch database writes where useful
* avoid duplicate processing
* use bounded concurrency
* keep ShuffleDNS threads configurable
* do not create unlimited threads

---

# 49. Database Indexes

Useful indexes should exist for:

```text
target_id
hostname
target_id + hostname
DNS state
HTTP state
HTTP status
last_seen
```

Use the simplest schema that satisfies the requirements.

---

# 50. Security

This tool is for authorized asset discovery and monitoring.

Only process targets explicitly configured by the user.

Do not add:

* exploitation
* credential attacks
* authentication brute force
* automatic vulnerability exploitation
* destructive testing
* intrusive payload execution

The application is an:

```text
Asset Discovery + DNS + HTTP Monitoring
```

system.

---

# 51. Implementation Order

Implement incrementally.

## Phase 1

```text
Configuration
CLI
SQLite database
Target management
```

## Phase 2

```text
Normalization
Asset model
Deduplication
```

## Phase 3

```text
subfinder
chaos
crt.sh
```

## Phase 4

```text
Continuous passive watcher
```

## Phase 5

```text
dnsx
```

## Phase 6

```text
httpx
```

## Phase 7

```text
State transition engine
```

## Phase 8

```text
Telegram notifications
```

## Phase 9

```text
TLSX continuous watcher
```

## Phase 10

```text
DNS brute force
static mode
dynamic mode
```

## Phase 11

```text
CLI asset inspection
filters
raw export
```

## Phase 12

```text
logging
error recovery
graceful shutdown
systemd compatibility
```

---

# 52. Acceptance Criteria

The application is complete when:

* [ ] Python CLI works.
* [ ] YAML configuration works.
* [ ] Multiple targets are supported.
* [ ] Multiple domains per target are supported.
* [ ] Optional CIDRs are supported.
* [ ] One SQLite database is used.
* [ ] Target ownership is preserved.
* [ ] Duplicate assets cannot exist.
* [ ] subfinder runs continuously.
* [ ] chaos runs continuously.
* [ ] crt.sh discovery runs continuously.
* [ ] TLSX runs continuously.
* [ ] DNSX runs continuously.
* [ ] HTTPX runs continuously.
* [ ] DNS brute force runs continuously with its own longer interval.
* [ ] Static DNS brute force uses configured wordlists.
* [ ] Dynamic DNS brute force uses DNSGen.
* [ ] ShuffleDNS/MassDNS are used for DNS brute force.
* [ ] ShuffleDNS concurrency is configurable.
* [ ] DNS brute-force results enter the main asset database.
* [ ] Every newly discovered hostname enters continuous monitoring automatically.
* [ ] Fresh assets are detected.
* [ ] Fresh subdomains are detected.
* [ ] HTTP service appearance is detected.
* [ ] HTTP service return is detected.
* [ ] HTTP status changes are detected.
* [ ] Notifications are deduplicated.
* [ ] Telegram notifications work.
* [ ] Logs are visible in terminal.
* [ ] Logs are persisted.
* [ ] Tool errors do not terminate the application.
* [ ] Raw subdomains can be listed.
* [ ] Assets can be listed per target.
* [ ] All targets can be listed.
* [ ] DNS/HTTP state can be inspected from terminal.
* [ ] Basic filters work.
* [ ] Graceful shutdown works.

---

# 53. Final Architecture

The final mental model must be:

```text
                         TARGETS
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
        SUBFINDER         CHAOS          CRT.SH
             │              │              │
             └──────────────┼──────────────┘
                            │
                            ▼
                       NORMALIZE
                            │
                            ▼
                       DEDUPLICATE
                            │
                            ▼
                      ┌────────────┐
                      │  DATABASE  │◄──────────────┐
                      └─────┬──────┘               │
                            │                      │
             ┌──────────────┼──────────────┐       │
             │              │              │       │
             ▼              ▼              ▼       │
           DNSX           HTTPX          TLSX      │
             │              │              │       │
             │              │              ▼       │
             │              │          CERT ASSETS │
             │              │              │       │
             │              └──────────────┘       │
             │                                     │
             ▼                                     │
        DNS STATE                                   │
             │                                     │
             ▼                                     │
        HTTP STATE                                  │
             │                                     │
             ▼                                     │
       STATE CHANGES                                │
             │                                     │
             ▼                                     │
         TELEGRAM                                  │
                                                   │
                                                   │
       DNS BRUTE FORCE                             │
              │                                    │
       ┌──────┴──────┐                             │
       │             │                             │
     STATIC       DYNAMIC                          │
       │             │                             │
   WORDLIST       DNSGEN                           │
       │             │                             │
       └──────┬──────┘                             │
              ▼                                    │
         SHUFFLEDNS                                │
              │                                    │
           MASSDNS                                 │
              │                                    │
              ▼                                    │
        NEW HOSTNAMES ─────────────────────────────┘
```

The most important rule is:

```text
DISCOVERY ≠ MONITORING
```

Discovery finds assets.

The database remembers assets.

Monitoring continuously checks the current state of every known asset.

Therefore a hostname discovered **once**, even months ago, remains in the monitoring system until explicitly removed.

The application should behave like a small continuous asset-watch daemon rather than a collection of one-shot recon scripts.

---

# 54. Code Quality Rule

When choosing between:

```text
50 lines of clever abstraction
```

and:

```text
20 lines of obvious Python
```

choose the obvious Python.

The project should be understandable by opening the repository and reading it from top to bottom.

Do not add functionality merely because it might be useful.

Implement exactly the required behavior.
