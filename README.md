# Assetwatch

A small Python CLI that continuously discovers and monitors explicitly configured
targets. One SQLite database remembers each hostname, its sources, DNS/HTTP state,
transitions, delivery history, watcher schedules and the DNSGen candidate cache.
Python 3.11+ on Linux or macOS.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/assetwatch --help
```

Install the external executables separately and put them on PATH, or set absolute
paths in `config.yaml`:

| Tool | Upstream |
| --- | --- |
| subfinder | https://github.com/projectdiscovery/subfinder |
| chaos | https://github.com/projectdiscovery/chaos-client |
| dnsx | https://github.com/projectdiscovery/dnsx |
| httpx | https://github.com/projectdiscovery/httpx |
| tlsx | https://github.com/projectdiscovery/tlsx |
| shuffledns | https://github.com/projectdiscovery/shuffledns |
| massdns | https://github.com/blechschmidt/massdns |
| dnsgen | https://github.com/AlephNullSK/dnsgen |

`httpx` must be the **ProjectDiscovery executable**. A Python HTTP client uses the
same name; an explicit path such as `/home/you/go/bin/httpx` avoids that collision.
The supplied config selects `${HOME}/go/bin/httpx`, matching this workspace's
installed ProjectDiscovery binary; change it if your installation is elsewhere.
crt.sh is queried through its JSON API; it has no required executable.
Configure other passive provider credentials using the tools' own configuration.
Set the Chaos key in YAML (a literal string or an environment reference):

```yaml
chaos:
  api_key: "${PDCP_API_KEY}"  # Or your actual Chaos key
```

`chaos.api_key` overrides inherited credentials for the Chaos subprocess only.
An empty value preserves the tool's environment/configuration behavior. The key is
passed through the child environment (`PDCP_API_KEY`, plus `CHAOS_KEY` for older
clients), never command arguments, and is redacted from application logs.
Current Chaos clients document `PDCP_API_KEY` in their
[authentication guide](https://chaos.projectdiscovery.io/docs/api-key).

Put your static wordlists (`*.txt`, one word per line) in `wordlists/`. Supply your
chosen DNS resolver IPs, one per line, in `resolvers.txt`. Both paths are configurable.
If a brute-force mode is unwanted, set its `enabled` value to `false`.
No wordlist or resolver service is silently downloaded or selected.

```sh
.venv/bin/assetwatch doctor
```

This validates executables and required input files without discovering or probing
any targets. API credentials and network delivery still require a live run to verify.

## Targets and continuous operation

Use only domains and CIDRs you are authorized to monitor. The names below are
examples; no target is preconfigured or scanned by installation.

```sh
.venv/bin/assetwatch target add example --domain example.com,example.org
# Optionally append --cidr 192.0.2.0/24,198.51.100.0/24 to an add command.
.venv/bin/assetwatch targets
.venv/bin/assetwatch target show example
.venv/bin/assetwatch run
```

Both `--domain` and `--cidr` accept comma-separated lists and repeated flags,
including a mixture of both. Quote lists containing spaces; surrounding spaces
are trimmed. Duplicate entries are deduplicated, and empty list entries are rejected.

`python -m assetwatch` and `python watchtower.py` are equivalent entry points.
Use `assetwatch --config /path/to/config.yaml ...` for another configuration.
Relative database, log, executable and wordlist paths follow the YAML file's
directory. Bare executable names are resolved through PATH.

Six independent asynchronous tasks run passive discovery, TLSX, DNSX (A and CNAME),
HTTPX, DNS brute force and PTR discovery. Another task polls notifications at `intervals.monitoring`, draining
full successful batches without waiting for another interval; state
comparison happens immediately when observations are committed. Each task processes
targets sequentially. All scan tools share **one FIFO execution slot** across all
targets, with bounded tool threads and a configurable overall timeout. DNSGen seed
batches and static/dynamic ShuffleDNS chunks release that slot between invocations,
so DNS and HTTP monitoring can run during a long brute-force cycle. Waiting work is
bounded by the watcher count; no task/thread is created per hostname. Telegram delivery,
program feeds and CLI inspection remain available. Subfinder, Chaos and crt.sh run each passive
cycle, with failures isolated by source and domain.
Subfinder receives `-recursive`, selecting sources that support recursive
subdomain queries; this flag alone does not repeatedly enumerate every discovered
hostname. HTTPX receives `-auto-referer`, setting the Referer header to the request
URL. `doctor` checks that the installed executables support both required flags.

Discovery intervals are seconds **after the previous run finishes**, persisted per
target and watcher across restarts. DNS/HTTP deadlines are persisted **per asset**
in a deduplicated SQLite queue. Every new finding queues an immediate DNS check;
a usable A record queues HTTP fingerprinting. Completed checks reschedule themselves
at their own intervals. Unresolved names keep their DNS jobs; resolved hosts without
HTTP keep both jobs. Successful batches survive restarts without repeating the whole
target, and interrupted batches remain due. New findings do not wait for the target's
next full discovery cycle. Newly added targets are picked up without restarting.
Failed or partially inconclusive runs retry after the smaller of their normal interval
and `runtime.failure_retry_interval` (default 300 seconds). This also applies to
previously failed runs stored before upgrading, so a missing resolver file no longer
postpones another attempt for a week. Interrupted runs are retried on restart.
Use `assetwatch rerun dns_bruteforce --target example` to queue a run immediately;
it still waits for scan access and requires the daemon to be running. Repeated
requests deduplicate; a request made during a run schedules one additional run.
Configuration changes require a restart.

All discovery sources normalize and insert into the same asset table. Root domains
are seeded on target creation. Every known hostname remains eligible for periodic
DNS checks, including unresolved and months-old assets. HTTPX checks only hosts
with a usable IPv4 A record. Certificate names must belong to a configured domain
of the target whose CIDR produced them; shared-certificate neighbors are discarded.
TLSX requires configured CIDRs; targets without them show `skipped` with a reason.
PTR discovery runs every `intervals.ptr_discovery` (default 3600 seconds), using
`dnsx -ptr -resp-only` on each target's configured CIDRs and distinct currently
observed A-record IPs. CIDR expansion is streamed by dnsx, with bounded tool threads
and the usual tool timeout. PTR names outside the target's root domains are discarded.
Accepted names use source `ptr` and automatically receive the same DNS/HTTP monitoring.
[DNSX documents the PTR, CNAME and response-only flags here](https://docs.projectdiscovery.io/opensource/dnsx/usage).
Dynamic DNSGen processes only hostnames added since its last successful seed batch,
including unresolved findings from every source. Generated candidates are normalized,
scope-filtered, deduplicated and appended to a per-target cache in the same SQLite
database. Every dynamic resolution cycle reuses the cache, so unresolved candidates
are checked again without regenerating their permutations. No new findings means
no DNSGen process. Previously processed seeds are not regenerated for a new source
tag or a last-seen update.

`dns_bruteforce.dynamic.batch_size` limits new input hostnames per DNSGen invocation
(default 100). The first run processes existing assets in these small batches; later
runs only append new candidates. DNSGen learns words within each batch, so its
permutations may differ from generating against all historical names at once.
The cache and generation checkpoint survive restarts. Failed or interrupted seed
batches are retried, with partial cached output deduplicated; completed batches
are skipped. A ShuffleDNS failure does not discard the cache or regenerate seeds.
Candidate export and output ingestion use bounded batches and temporary files.
`dns_bruteforce.static.chunk_size` bounds words read from disk at once;
`dns_bruteforce.dynamic.chunk_size` bounds cached names sent to each ShuffleDNS run
(both default to 5000). The wordlist is streamed, not accumulated as a list of chunks.
`dns_bruteforce.shuffledns.cooldown` pauses between chunks (default one second).
Failed chunks are logged and other chunks continue; failed cycles retry on the failure
interval. A retry may revisit successful brute-force chunks, with findings deduplicated.
The cache grows on disk as findings accumulate; removing a target also removes its
candidate cache and checkpoint. Existing databases gain these tables automatically.

ShuffleDNS receives both `-t` and `-wt` from `dns_bruteforce.shuffledns.threads`,
and invokes the configured MassDNS executable. It also receives `-sw` to check every
result for wildcard DNS, including small chunks below its usual IP-count threshold
([ShuffleDNS options](https://github.com/projectdiscovery/shuffledns#usage)). Static and dynamic runs feed the
same monitoring pipeline as passive and certificate discoveries.

Brute-force logs show each domain/wordlist, DNSGen seed batch, cached candidate
count and `new_assets` with `validation=queued`. A stored finding is not yet an alert.
Tool heartbeats show elapsed
time and output sizes every `runtime.progress_interval` seconds (default 30), even
when a tool is silent. These are activity indicators, not a percentage of completed
DNS queries. Output is ingested after each tool completes successfully. The scheduler
logs queued/started jobs and the next run time, including persisted weekly schedules
after a restart. `tool=... state=queued` means that tool is waiting for its execution slot.

Ctrl+C and SIGTERM cancel watcher tasks, terminate tool process groups (including
MassDNS children), and close the database. One daemon can own a database at a time;
inspection and target management commands can run alongside it. An empty `.lock`
sidecar holds the daemon's OS lock; do not remove it while the daemon runs. SQLite
WAL sidecars are part of the same database. Keep the database on a local
filesystem. Back up using SQLite's backup API, or stop the daemon before copying.

## Bug bounty program scope watch

`assetwatch run` also watches the public program feeds from bounty-targets-data:

* [HackerOne](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/hackerone_data.json)
* [Bugcrowd](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/bugcrowd_data.json)
* [Intigriti](https://github.com/arkadiyt/bounty-targets-data/blob/main/data/intigriti_data.json)

The watcher downloads the raw JSON versions of those files. It is enabled by default
and runs once per hour, independently for each feed, even with no configured scan
targets or while a brute-force tool is running. Set these values in your YAML to
change its interval or disable it:

```yaml
program_watch:
  enabled: true
  max_feed_bytes: 33554432  # Maximum download size per feed (32 MiB)
intervals:
  program_watch: 3600      # Seconds after each source's completed check
```

**The first successful fetch of each platform establishes a silent baseline.**
Subsequent checks generate exactly two kinds of events:

* `new_program`: a program identity not seen before on that platform, with its
  initial in-scope entries in the same alert.
* `scope_added`: newly seen in-scope entries for an existing program. The alert
  contains only the added entries.

Program removals, removed scope entries, out-of-scope changes, policy/description
edits, bounty amount changes, display-name changes and asset-type-only edits do not alert.
Previously seen programs/scopes stay remembered, so removal followed by reappearance
does not alert again. A scope entry moving from out-of-scope to in-scope alerts if
it has not previously been seen in-scope. Scope comparison preserves URL path case
and distinguishes wildcard scope from a bare domain.

All asset categories in the feeds are supported: domains, URLs, CIDRs, apps, source
code, hardware and other entries. Programs without monetary rewards are included
when present in these feeds. Only the feeds' structured `targets.in_scope` entries
are compared; policy prose is not interpreted as additional scope. Review the linked
program's current policy when deciding what to test. Feed changes never create
scan targets or put third-party assets into DNS/HTTP/brute-force monitoring.

The program catalog, ever-seen scope, source baselines, events and Telegram delivery
progress all use the existing SQLite database. Identity uses the HackerOne handle,
Bugcrowd program URL and Intigriti ID, qualified by platform. The HackerOne export's
numeric ID is not used because it can be zero for every program. Empty, malformed
or failed downloads preserve the last baseline and retry after
`runtime.failure_retry_interval` (capped by the normal interval). Each source fails
independently. Downloads use `runtime.request_timeout`; the configured size limit
prevents unbounded feed reads. Restarting preserves baselines and schedules.

Alerts use Telegram [MarkdownV2](https://core.telegram.org/bots/api#markdownv2-style)
with a bold title/program name, platform, added-entry count, code-formatted scope,
UTC timestamp, event reference and an **Open program ↗** button. Dynamic text is
escaped so wildcards, underscores and other feed content cannot break formatting.
Large changes are split into numbered messages without dropping entries. Each part
is acknowledged separately in SQLite; retries resume with the undelivered parts.
Program and asset notifications alternate so an existing asset backlog does not
hide new program additions. Telegram settings and delivery retries are shared.

Example of a scope-addition alert as it appears in Telegram:

> 🎯 **Scope Expanded**
>
> **Example Program**
> Platform: **HackerOne**
> New in-scope entries: **2**
>
> • `*.new.example.com` _wildcard_
> • `https://api.example.com/v2` _url_
>
> 🕒 `2026-09-27 10:30 UTC`
> Event: `P42` • Part 1/1
>
> **Open program ↗**

Inspect feed health, errors, schedules and history with:

```sh
assetwatch health
assetwatch logs --module program_watch --lines 100
assetwatch program-changes
assetwatch program-changes --platform hackerone --limit 20 --offset 0 --format json
```

In Telegram, `/programs` shows recent additions across all platforms, and
`/programs bugcrowd 2` shows the second page for Bugcrowd. History summaries preview
up to five scope entries; alerts and CLI JSON retain every added entry. `/health`
shows each feed's baseline/check status, counts, last error and next check.
If Telegram is disabled, additions are still recorded and queued for later delivery.

## Inspect and export

```sh
assetwatch assets --target example
assetwatch assets --all --resolved
assetwatch assets --target example --http --status 200
assetwatch assets --all --unresolved
assetwatch assets --all --no-http --format json
assetwatch domains --target example
assetwatch domains --all --format json
assetwatch domains --target example --source ptr
assetwatch assets --target example --source dns_bruteforce
assetwatch assets --target example --source tlsx
assetwatch cnames --target example --limit 100 --offset 0
assetwatch changes --target example --type dns_cname_changed
assetwatch changes --target example --type fresh_asset
assetwatch health --target example
assetwatch health --format json
assetwatch logs --module dns_bruteforce --lines 100
assetwatch logs --module tlsx --lines 100
assetwatch rerun dns_bruteforce --target example
assetwatch target remove example --yes
```

Text asset output is tab-separated. JSON includes sources, timestamps, current and
previous status, availability history and HTTP metadata. `ip_addresses` contains
the latest complete observed A-record set; `known_ip_addresses` contains all IPs
ever observed for that asset. `cname_records` holds all returned CNAME names, and
`cname_checked_at` distinguishes an empty observation from no observation yet. `PENDING` means no
conclusive observation yet; `--unresolved`/`--no-http` also include pending assets.
Raw domain output has no headers or duplicates, even across explicitly overlapping
targets. A target removal deletes its assets, events and notification history.
Ownership and uniqueness are per `(target_id, hostname)`; explicitly configuring
the same domain under two targets gives each its own independent state.

## State and notifications

Events: `fresh_asset`, `fresh_subdomain`, `dns_unresolved`, `dns_ip_changed`, `dns_cname_changed`,
`http_service_appeared`, `http_service_disappeared`, `http_service_returned`, and
`http_status_changed`. Fresh-asset messages identify certificate/brute-force/PTR sources.
**Asset alerts require a usable IPv4 A record and a confirmed HTTP response.**
Any HTTP status from 100 through 599 qualifies, including 403/500; success does not
mean only status 200. Raw discovery, DNS-only findings, timeouts and failed probes
stay silent. All accepted hostnames remain visible in `assets --all` and target
exports, including those that have never qualified for an alert.

The first confirmed live response releases **one** fresh-asset alert containing its
DNS/HTTP state, source, URL, page title, server and detected technologies. Initial
DNS resolution/HTTP appearance events remain in history with `initial_validation`
suppression, avoiding three alerts for one finding. If a name becomes live later,
it qualifies then. Subsequent DNS changes, HTTP status changes, outages and returns
for previously validated assets retain their alerts. Pending unvalidated findings
cannot block eligible notifications. Validation and delivery survive restarts, and
old databases recover validation from their first recorded live HTTP observation.

Unchanged observations generate no new event. A later repeat of a real transition
(200 → 403 → 200 → 403) creates a new event for each occurrence.

A-record observations are normalized, deduplicated and compared as sets; multiple
DNSX rows for the same hostname are merged. The database remembers all previously
seen IPs per asset across restarts. **A newly seen IP can notify; rotation among
known IPs, response reordering, and a nonempty subset of a known pool do not.**
Removing only part of a pool updates current state without an IP alert; a completely
empty conclusive A response still generates the normal DNS-loss event. Historical
IPs are never used to authorize an HTTP probe when the current A set is empty.

New-IP events **notify by default, except known CDN address rotation**. The filter compares the old and new IP sets against downloaded provider
CIDRs. It skips an alert only when every added/removed address is a known CDN IP
and the set of providers stays the same. An unchanged origin IP alongside rotating
CDN IPs is fine; an origin IP change, unknown IP, provider migration, or move onto/off
a CDN still alerts. DNS resolution/loss and HTTP changes always retain their normal
notification behavior.

The public range sources are ProjectDiscovery's
[CDN/WAF dataset](https://github.com/projectdiscovery/cdncheck/blob/main/sources_data.json)
and [Akamai's published IPv4 CIDRs](https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt).
They cover ArvanCloud, Cloudflare, Akamai, Fastly, CloudFront and other listed
providers. Cloud-hosting ranges and CNAME suffixes in the ProjectDiscovery dataset
are excluded. Coverage depends on those feeds; an unmatched IP remains eligible for
alerts. No target hostnames or IPs are sent to the range feeds.

Ranges are fetched when an IP-change notification needs classification, cached in
the same SQLite database, and refreshed after `cdn.refresh_interval` (default one
day). Failed or malformed downloads preserve each source's last good cache and retry
after `cdn.retry_interval`. Once a source exceeds `cdn.max_age` (default seven days),
its ranges cannot suppress alerts. Updates replace the old ranges, so removed CIDRs
stop matching. Both URLs are configurable as `cdn.projectdiscovery_url` and
`cdn.akamai_url`, using the same JSON/text formats as the default feeds.
Downloads verify HTTPS certificates. If a Python installation lacks its CA bundle
(`cause=SSLCertVerificationError` in the log), configure its trust store. On this
macOS workspace, the existing system bundle works with
`SSL_CERT_FILE=/etc/ssl/cert.pem`; set it in the daemon's environment before startup.

Suppressed events retain their full state history and a durable suppression reason;
they are logged as `telegram=suppressed` and are never marked as delivered. They do
not re-enter the queue after restart. Set `cdn.enabled: false` to notify on all future
new-IP events, or `telegram.notify_dns_ip_changes: false` to mute all IP-only alerts.
If upgrading from the previous global mute, set `notify_dns_ip_changes: true` in
your existing YAML: its undelivered backlog will then pass through the CDN filter.

CNAME monitoring covers every asset, including unresolved hosts. It makes a separate
DNSX CNAME request so an A-record failure cannot erase valid CNAME state. External
alias destinations are stored as record data, without adding them to scan scope.
The first conclusive CNAME observation establishes a silent baseline. Later
additions, removals and replacements generate `dns_cname_changed` events with both
old and new sets, independent of IP/CDN notification filtering. Telegram delivery
requires that the asset has qualified through DNS + HTTP validation; changes for
never-valid names remain inspectable in CLI history. Identical normalized
sets stay quiet. These alerts are investigation signals, not proof of a takeover;
no takeover probing or exploitation is performed. `cnames` and `/cnames` list current
records; `changes --type dns_cname_changed` provides their history.

Existing databases are migrated automatically without removing assets or history.
The migration seeds known IP pools from current state and historical event snapshots,
and suppresses undelivered historical `dns_ip_changed` events that merely revisited
IPs already seen at that point (`known_ip_rotation`). Truly new-IP events remain
queued. Back up and stop the old daemon before upgrading, then restart the new code.

DNSX uses explicit NOERROR/NXDOMAIN observations. SERVFAIL, REFUSED, omitted results,
failed executables, timeouts and malformed output preserve previous state. HTTPX
uses explicit probe failures to mark a service unavailable; missing rows are
inconclusive. DNS loss marks any active HTTP service down without probing. Results
from an HTTP batch are discarded if its DNS state or IP set changed in flight.
HTTPX uses its default HTTPS-first/HTTP-fallback behavior, does not follow redirects,
and records one representative HTTP service per hostname (not every port/scheme).
Every HTTP check includes `-tech-detect` and refreshes the stored fingerprint, even
when the status stays unchanged. `runtime.dns_rate_limit` (default 50) caps DNSX
queries/second and `runtime.http_rate_limit` (default 10) caps HTTPX requests/second.
`runtime.http_max_response_bytes` (default 1048576) bounds each HTTP response read;
fingerprints may be incomplete for pages larger than that cap. Tool concurrency
still follows `runtime.threads`. ShuffleDNS uses its own bounded threads, chunks
and cooldown; its thread setting is not a requests-per-second limit.
These are the tools' documented [DNSX rate limit](https://docs.projectdiscovery.io/opensource/dnsx/usage)
and [HTTPX fingerprint/rate/response-size options](https://docs.projectdiscovery.io/opensource/httpx/usage).

Telegram is disabled initially. The supplied config reads credentials from environment
variables; no literal bot credentials are needed in YAML. To enable it:

```sh
export TELEGRAM_BOT_TOKEN='your-token'
export TELEGRAM_CHAT_ID='your-chat-id'
# Set telegram.enabled: true in config.yaml, then start assetwatch run.
```

Useful settings for timely alerts and visible brute-force activity:

```yaml
intervals:
  monitoring: 30          # Telegram polling only; separate from DNS/HTTP scans
runtime:
  progress_interval: 30   # Seconds between running-tool heartbeats
  failure_retry_interval: 300
  dns_rate_limit: 50
  http_rate_limit: 10
  http_max_response_bytes: 1048576
telegram:
  notify_dns_ip_changes: true
  commands_enabled: true
  command_poll_interval: 3
cdn:
  enabled: true
  refresh_interval: 86400
  retry_interval: 3600
  max_age: 604800
```

Brute-force results enter the normal validation queue. Rediscovering an existing
hostname records its source without another fresh-asset alert. Check `new_assets`
and `validation=queued` in the logs, then `health` for assets awaiting validation,
due DNS/HTTP checks and the deliverable notification backlog. A successful delivery
logs its event type and ID. Delivery requires `telegram.enabled: true` and valid
credentials. New events wake the outbox immediately; `intervals.monitoring` is its
fallback polling/retry interval. Eligible backlogs drain in bounded batches,
respecting `telegram.send_delay` and server retry delays.

### Bot menu and module diagnostics

With the daemon running and Telegram enabled, send `/start` or `/help` to the bot.
It replies with a button menu and these read-only commands:

| Command | What it shows |
| --- | --- |
| `/health [target] [page]` | Module state, start/finish/next times, last error, result and new-asset counts, missing prerequisites, daemon heartbeat, delivery backlog |
| `/changes [target] [page]` | Latest persisted discovery, DNS, CNAME and HTTP changes |
| `/new [target] [page]` | Newly discovered assets and their source |
| `/cnames [target] [page]` | Current CNAME records, including aliases on unresolved hosts |
| `/targets [page]` | Target names, domains and CIDRs |
| `/programs [platform] [page]` | New bounty programs and added scope from HackerOne, Bugcrowd and Intigriti |

`/status` aliases `/health`; `/updates` aliases `/changes`. Omit a target or use `*`
for all targets. Quote target names containing spaces, for example
`/changes "Example Company" 2`. Follow the next-page command to inspect all results.
Commands only reply to the numeric chat ID in `telegram.chat_id`; other chats are
ignored. Everyone in that configured group can read the reports. No target changes
or scans can be initiated through the bot. Set `telegram.commands_enabled: false`
to keep notifications only. Updates use persisted offsets, independent of notification
backlogs and the scan-tool queue. Telegram's `getUpdates` requires that the bot has no active
webhook or other polling consumer; failures appear in terminal/CLI health reports.

`assetwatch health` works even while the daemon is stopped. It distinguishes
`never_run`, `queued`, `running`, `success`, `failed`, `skipped` and interrupted/stale
work. A heartbeat confirms whether the daemon is active; saved successful runs are
historical information, not a claim that the daemon is still running. `results` counts
raw discovered names (before scope filtering/deduplication) for discovery modules,
and conclusive observations for DNS/HTTP; `new_assets` counts actual inserted assets.
Progress updates identify the current wordlist, DNSGen seed batch or candidate count.
Failed runs can have partial results. Health checks local prerequisites without
making network requests; `doctor` also checks executable help/flag compatibility.

For brute-force or TLSX troubleshooting:

1. Run `assetwatch health --target example` and `assetwatch doctor`.
2. Supply nonempty static `.txt` wordlists, a nonempty resolver file, and the configured
   executables. Missing resolvers now fail before expensive DNSGen generation.
   TLSX skips targets with no CIDRs; inspect their scope with `target show`.
3. Read `assetwatch logs --module dns_bruteforce --lines 100` or
   `assetwatch logs --module tlsx --lines 100`. Logs show errors and running-tool
   heartbeats. This reads the current configured log file; older logs remain in its
   rotated siblings. Add `--target example` for target-tagged entries (tool-only
   heartbeat/stderr lines may have no target tag).
4. After fixing inputs, queue `assetwatch rerun dns_bruteforce --target example`
   or `assetwatch rerun tlsx --target example`. `queued` can mean another scan still
   owns the scan resources; inspect the other modules in health.
5. Inspect results with `assetwatch domains --target example --source dns_bruteforce`
   or `--source tlsx`. A successful run can find zero new assets and send no alerts.

State and its event commit atomically. Events queue while Telegram is disabled or
unreachable and are delivered after it is enabled, including the existing backlog,
subject to DNS + HTTP validation, the configured IP-alert policy and CDN filter.
Acknowledged events are not resent; failed attempts and server retry delays are
stored. Asset alerts use Telegram MarkdownV2 with bold labels and code-formatted
hostnames, IPs, URLs and fingerprints. Dynamic text is escaped, and long fields
are shortened without cutting Markdown entities. Full fingerprints remain in the
database and CLI JSON. Fresh alerts show the first validated snapshot and its
observation time, even if delivery was delayed while Telegram was offline.

Telegram offers no idempotency key for sendMessage: if Telegram accepts a message
but its response is lost (or the process stops before recording the acknowledgement),
a retry can duplicate that delivery. Durable event deduplication prevents repeated
alerts for unchanged observations; it cannot guarantee exactly-once network delivery.

Logs include timestamp, level, watcher, target, tool failures and state events, on
stderr and in the rotating file configured by `logging.file`. Bot/API secrets are
redacted from logs; Telegram exceptions containing token URLs are not persisted.

## systemd

Edit `deploy/assetwatch.service` for your user, repository path and tool PATH.
Keep any environment file outside the repository with permissions `0600`, then
install the unit under `/etc/systemd/system/` and enable it with systemctl. No
service or live scanner is installed or started automatically.

## Tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use temporary SQLite databases, fake executable output and mocked network
responses; they do not scan public targets or send Telegram messages.
