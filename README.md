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

Five independent asynchronous tasks run passive discovery, TLSX, DNSX, HTTPX and
DNS brute force. A sixth polls notifications at `intervals.monitoring`, draining
full successful batches without waiting for another interval; state
comparison happens immediately when observations are committed. Each task processes
targets sequentially. Tools have bounded concurrency and a configurable overall
timeout. Brute force has exclusive access to scan resources: it waits for active
passive/TLSX/DNSX/HTTPX jobs to finish, then runs DNSGen and ShuffleDNS/MassDNS
sequentially while other scan jobs wait. This applies across all targets. Queued
jobs resume afterward; their intervals still run from completion. Telegram delivery
and CLI inspection remain available. Subfinder, Chaos and crt.sh run each passive
cycle, with failures isolated by source and domain.
Subfinder receives `-recursive`, selecting sources that support recursive
subdomain queries; this flag alone does not repeatedly enumerate every discovered
hostname. HTTPX receives `-auto-referer`, setting the Referer header to the request
URL. `doctor` checks that the installed executables support both required flags.

Intervals are seconds **after the previous run finishes**, persisted per target
and watcher across restarts. Newly added targets are picked up without restarting.
Failed runs retry on their normal interval. For a failed weekly brute-force run,
fix the issue and temporarily lower `intervals.dns_bruteforce` before restarting
if you need an earlier retry. Configuration changes require a restart.

All discovery sources normalize and insert into the same asset table. Root domains
are seeded on target creation. Every known hostname remains eligible for periodic
DNS checks, including unresolved and months-old assets. HTTPX checks only hosts
with a usable IPv4 A record. Certificate names must belong to a configured domain
of the target whose CIDR produced them; shared-certificate neighbors are discarded.
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
The cache grows on disk as findings accumulate; removing a target also removes its
candidate cache and checkpoint. Existing databases gain these tables automatically.

ShuffleDNS receives both `-t` and `-wt` from `dns_bruteforce.shuffledns.threads`,
and invokes the configured MassDNS executable. Static and dynamic runs feed the
same monitoring pipeline as passive and certificate discoveries.

Brute-force logs show each domain/wordlist, DNSGen seed batch, cached candidate
count and `new_asset_events` queued for notification. Tool heartbeats show elapsed
time and output sizes every `runtime.progress_interval` seconds (default 30), even
when a tool is silent. These are activity indicators, not a percentage of completed
DNS queries. Output is ingested after each tool completes successfully. The scheduler
logs queued/started jobs and the next run time, including persisted weekly schedules
after a restart. `state=queued` means the watcher is waiting for scan resources.

Ctrl+C and SIGTERM cancel watcher tasks, terminate tool process groups (including
MassDNS children), and close the database. One daemon can own a database at a time;
inspection and target management commands can run alongside it. An empty `.lock`
sidecar holds the daemon's OS lock; do not remove it while the daemon runs. SQLite
WAL sidecars are part of the same database. Keep the database on a local
filesystem. Back up using SQLite's backup API, or stop the daemon before copying.

## Inspect and export

```sh
assetwatch assets --target example
assetwatch assets --all --resolved
assetwatch assets --target example --http --status 200
assetwatch assets --all --unresolved
assetwatch assets --all --no-http --format json
assetwatch domains --target example
assetwatch domains --all --format json
assetwatch target remove example --yes
```

Text asset output is tab-separated. JSON includes sources, timestamps, current and
previous status, availability history and HTTP metadata. `PENDING` means no
conclusive observation yet; `--unresolved`/`--no-http` also include pending assets.
Raw domain output has no headers or duplicates, even across explicitly overlapping
targets. A target removal deletes its assets, events and notification history.
Ownership and uniqueness are per `(target_id, hostname)`; explicitly configuring
the same domain under two targets gives each its own independent state.

## State and notifications

Events: `fresh_asset`, `fresh_subdomain`, `dns_unresolved`, `dns_ip_changed`,
`http_service_appeared`, `http_service_disappeared`, `http_service_returned`, and
`http_status_changed`. Fresh-asset messages identify certificate/brute-force sources.
Unchanged observations generate no new event. A later repeat of a real transition
(200 → 403 → 200 → 403) creates a new event for each occurrence.

IP changes are kept in SQLite and **notify by default, except known CDN address
rotation**. The filter compares the old and new IP sets against downloaded provider
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
IP changes, or `telegram.notify_dns_ip_changes: false` to mute all IP-only alerts.
If upgrading from the previous global mute, set `notify_dns_ip_changes: true` in
your existing YAML: its undelivered backlog will then pass through the CDN filter.

DNSX uses explicit NOERROR/NXDOMAIN observations. SERVFAIL, REFUSED, omitted results,
failed executables, timeouts and malformed output preserve previous state. HTTPX
uses explicit probe failures to mark a service unavailable; missing rows are
inconclusive. DNS loss marks any active HTTP service down without probing. Results
from an HTTP batch are discarded if its DNS state or IP set changed in flight.
HTTPX uses its default HTTPS-first/HTTP-fallback behavior, does not follow redirects,
and records one representative HTTP service per hostname (not every port/scheme).

Telegram is disabled initially. To enable it:

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
telegram:
  notify_dns_ip_changes: true
cdn:
  enabled: true
  refresh_interval: 86400
  retry_interval: 3600
  max_age: 604800
```

Brute force sends a fresh-asset alert only for a hostname newly inserted into the
target's asset table. Rediscovering an existing hostname records its source without
another fresh-asset alert; zero new findings means zero such alerts. Check
`new_asset_events` in the logs, `telegram=disabled`/`telegram=failed`, and the scheduled
next run when diagnosing missing messages. A successful delivery logs its event
type and ID. Delivery requires `telegram.enabled: true` and valid credentials.
The outbox interval controls how soon new events are picked up: 12000 means up to
3 hours 20 minutes even before any delivery backlog. Existing eligible backlogs
now drain continuously in bounded batches, respecting `telegram.send_delay` and
server retry delays.

State and its event commit atomically. Events queue while Telegram is disabled or
unreachable and are delivered after it is enabled, including the existing backlog,
subject to the configured IP-alert policy and CDN filter.
Acknowledged events are not resent; failed attempts and server retry delays are
stored. Plain-text messages avoid Markdown injection. Fresh assets may show
DNS/HTTP `PENDING`; later transitions arrive separately.

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
