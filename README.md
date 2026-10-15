# Watchpost

Watchpost is a self-hosted SOC investigation and threat detection platform. It ingests
security logs, normalises them into a common schema, runs detection rules mapped to
MITRE ATT&CK, raises alerts, and gives analysts a web interface to investigate and manage
cases.

It is a defensive tool only: it reads and analyses logs and never scans, probes or
modifies other systems.

## Features

- **Log ingestion**: Linux `auth.log`/`secure`, Apache and Nginx access logs, Windows
  Security and Sysmon events exported as JSON (Winlogbeat, EVTX converters, NXLog,
  PowerShell), and any JSON lines. Formats are detected automatically; files can be plain,
  UTF-16 or gzip. Upload from the browser with a progress bar or drop files into a watched
  folder. Every event is deduplicated by hash and malformed lines are reported, not lost.
- **One schema for everything**: an ECS-style normalised event with indexed columns for the
  fields rules and searches use, plus the untouched original record.
- **Detection engine**: Sigma-style YAML rules with match, threshold, sequence and new-value
  logic, run automatically on every upload and on demand over any time range. 21 built-in
  rules mapped to MITRE ATT&CK, each with a [write-up](docs/README.md). Rules can be edited,
  validated and tested against pasted log lines in the browser.
- **Threat intelligence**: a local indicator store fed by CSV or text feeds, matched against
  every event during ingestion and against stored events when new indicators arrive.
  Optional AbuseIPDB and VirusTotal lookups enrich alerts, with caching and rate limits;
  private addresses are never sent anywhere.
- **Investigation**: an alert queue with filters and bulk triage, a timeline around each
  alert, cases with notes, pinned evidence and full history, Markdown and PDF reports, an
  event search language, entity pages for hosts, users and addresses, and an ATT&CK matrix
  of what fired.
- **Dashboard**: alerts over time, by severity, top attacking addresses, targeted users and
  noisiest rules, ingestion rate and time to resolve.
- **Access control and audit**: sign-in with Argon2id passwords and short-lived sessions,
  viewer, analyst and admin roles, CSRF protection, login throttling, strict security
  headers and an audit log of every analyst action.
- **Realistic test data and a benchmark**: a generator that writes logs for a fictional
  company with six attacks hidden in normal activity, and a benchmark that times ingestion,
  detection and search on a million events.

## Screenshots

| | |
| --- | --- |
| ![Dashboard](docs/screenshots/overview.png) | ![Alert queue](docs/screenshots/alerts.png) |
| **Overview**: a week of generated data with the planted attacks | **Alert queue**: filters, owners and bulk triage |
| ![Alert](docs/screenshots/alert.png) | ![Case](docs/screenshots/case.png) |
| **Alert**: rule notes, threat intel and the timeline around it | **Case**: linked alerts, evidence, notes and history |
| ![Event search](docs/screenshots/events.png) | ![ATT&CK matrix](docs/screenshots/mitre.png) |
| **Event search**: hunting for the attacker's address and tools | **ATT&CK matrix**: techniques with alerts in the period |
| ![Rule editor](docs/screenshots/rule.png) | ![Threat intel](docs/screenshots/intel.png) |
| **Rule**: edit, validate and test against sample lines | **Threat intel**: indicator store and matches |

## Architecture

```mermaid
flowchart LR
    subgraph Browser
        UI[React + TypeScript UI]
    end
    subgraph Docker Compose
        NGINX[frontend<br/>nginx: static UI + /api proxy]
        API[api<br/>FastAPI]
        WORKER[worker<br/>arq]
        REDIS[(redis<br/>job queue, login throttle)]
        DB[(PostgreSQL<br/>events, alerts, cases)]
        MIGRATE[migrate<br/>schema + built-in rules]
    end
    TI[AbuseIPDB / VirusTotal<br/>optional, HTTPS]
    UI --> NGINX --> API
    API --> DB
    API -- enqueue jobs --> REDIS
    REDIS --> WORKER
    WORKER --> DB
    MIGRATE --> DB
    API -. public indicators only .-> TI
    WORKER -. public indicators only .-> TI
```

- **api**: FastAPI on async SQLAlchemy 2 (asyncpg). Serves the REST API under `/api`
  (OpenAPI docs at `/api/docs`).
- **worker**: an [arq](https://arq-docs.helpmanual.io/) worker that runs ingestion,
  detection, indicator sweep and enrichment jobs off a Redis queue. Every five minutes it
  also re-queues any job still marked as queued, so work recorded during a Redis outage is
  not lost.
- **migrate**: a one-shot container that applies Alembic migrations and loads the
  built-in detection rules before the api and worker start.
- **frontend**: the production UI build served by nginx, which also proxies `/api` so the
  browser only ever talks to one origin.

## Quick start

Requires Docker with Compose v2.

```bash
cp .env.example .env        # optional for local use; required for anything shared
docker compose up --build
```

| Service    | URL                                |
| ---------- | ---------------------------------- |
| UI         | http://localhost:3000              |
| API docs   | http://localhost:8000/api/docs     |
| Readiness  | http://localhost:8000/api/health/ready |

All ports bind to `127.0.0.1` only. Set `WATCHPOST_ENV=production` and a real
`WATCHPOST_SECRET_KEY` before exposing the stack anywhere.

Every page needs a sign-in. Create the first admin account (you are asked for the
password twice; it must be at least 12 characters):

```bash
docker compose exec api watchpost create-user admin --role admin --full-name "Admin"
```

Then sign in at http://localhost:3000 and add everyone else from **Users**.

To see it work on something realistic, generate a week of logs with attacks hidden in
them and load them (details in [Sample data](#sample-data-and-attack-scenarios)):

```bash
docker compose exec api watchpost generate-logs --output /tmp/demo --events 200000
docker compose cp api:/tmp/demo ./demo
cp demo/*.log demo/*.jsonl watch/     # the worker ingests anything dropped into ./watch
```

Import `demo/iocs.csv` on the **Threat intel** page, and the alerts appear within a minute
or two.

## Normalised event schema

Every parser maps its input onto one flat schema inspired by the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html). Rules and
searches use the dotted names; each one is a real, indexable column in the `events`
table. The original record is kept in `raw_event` (JSONB).

| Field | Type | Field | Type |
| --- | --- | --- | --- |
| `@timestamp` | datetime (UTC) | `process.name` | keyword |
| `log_source` | keyword | `process.pid` | integer |
| `host.name` | keyword | `process.executable` | text |
| `source.ip` / `source.port` | ip / integer | `process.command_line` | text |
| `destination.ip` / `destination.port` | ip / integer | `process.parent.name` / `.pid` | keyword / integer |
| `user.name` | keyword | `url.original` | text |
| `event.category` | keyword (ECS values) | `http.request.method` | keyword |
| `event.action` | keyword | `http.response.status_code` | integer |
| `event.outcome` | success / failure / unknown | `user_agent.original` | text |
| `event.code` | keyword | `message` | text |

The live list is available from `GET /api/meta/fields` and on the **Event schema** page.

## Log ingestion

### Supported formats

| Parser | Input | Notes |
| --- | --- | --- |
| `linux_auth` | `/var/log/auth.log`, `/var/log/secure` | Classic and RFC 3339 syslog headers. Maps SSH logins (password/key, invalid users, max attempts, scanner noise), sudo (including failures), su, PAM sessions and auth failures, and account changes (useradd, usermod, gpasswd, userdel, passwd). Other lines are kept as generic events. |
| `web_access` | Apache / Nginx access logs | Common, Combined and `vhost_combined`. Keeps a URL-decoded copy of the request target so rules can match encoded attacks. |
| `windows` | Windows event logs exported as JSON | Security, System and Sysmon channels, in any of the common shapes: Winlogbeat/Elastic Agent, EVTX converted to JSON (`evtx_dump`, xmltodict), NXLog, or PowerShell. Sysmon records get `log_source = sysmon`, everything else `windows_security`. |
| `json` | Any JSON lines (or a JSON array) | Maps ECS field names (nested or dotted) and common aliases such as `src_ip`, `username`, `status_code` or epoch timestamps. |

The format is detected automatically from the start of each file; an explicit parser can
be chosen when uploading. Files may be plain text, UTF-16 (PowerShell's default), or
gzip-compressed. Binary files, archives and raw `.evtx` files are rejected with a message
saying what to do instead.

### Getting logs in

- **Upload** from the **Ingest** page, or `POST /api/ingest/uploads` (multipart: `file`,
  optional `parser` and `host_name`). Uploads are capped at 512 MiB by default
  (`WATCHPOST_MAX_UPLOAD_BYTES`).
- **Watched folder**: copy files into `./watch`. The worker scans it every 10 seconds,
  waits until a file has stopped changing, and ingests each new version of a file once.
  It never modifies the folder, which is mounted read-only. To force a parser, use a
  subfolder named after it, e.g. `watch/web_access/frontend.log`.

The `samples/` folder has small example logs for each format, including a short attack
story in each; see [samples/README.md](samples/README.md).

### How a file is processed

1. The worker streams the file line by line (or record by record for JSON documents), so
   memory use does not grow with file size.
2. Each record is parsed into a normalised event. Records that cannot be parsed are
   counted, and the first 100 are kept with their line number and the reason.
3. Each batch is checked against the threat intel indicators (see
   [Threat intelligence](#threat-intelligence)), and matching events are flagged.
4. Events are inserted in batches with `ON CONFLICT (event_hash) DO NOTHING`. The hash
   covers the log source and the raw line (for JSON, the record with its keys sorted), so
   ingesting the same data twice stores it once and reports exact duplicate counts.
5. Progress counters are committed with every batch, so the **Ingest** page shows live
   progress and the totals always match the database.
6. Once the file is done, a detection run over its new events is queued.

### Exporting Windows events

Watchpost reads JSON, not binary `.evtx`. This PowerShell snippet exports the Security
log with named event data fields (use `-LogName 'Microsoft-Windows-Sysmon/Operational'`
for Sysmon):

```powershell
Get-WinEvent -LogName Security -MaxEvents 5000 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
    [pscustomobject]@{
        EventID     = $_.Id
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        Computer    = $_.MachineName
        Channel     = $_.LogName
        Provider    = $_.ProviderName
        Keywords    = $_.KeywordsDisplayNames
        EventData   = $data
    } | ConvertTo-Json -Compress -Depth 4
} | Set-Content -Encoding utf8 security.jsonl
```

Year-less syslog timestamps (`Oct 12 09:02:13`) are resolved against the upload time, or
the file's modification time for watched files, and are assumed to be UTC.

## Detection

### How it works

Rules are YAML files in [`backend/rules/`](backend/rules). When the stack starts, the
`migrate` container runs `watchpost sync-rules`, which loads them into the database:
new files are added, changed files update their rule (keeping whether you enabled or
disabled it), and rules you edited in the UI are never overwritten.

Every time an ingestion job stores new events, the worker queues a **detection run** over
exactly those events. You can also scan stored events again from the **Rules** page,
for example after enabling or writing a rule.

- **Match** rules look at one event at a time.
- **Threshold** and **sequence** rules also read the events around the new ones (one
  shared pass per log source), so a brute force split across two uploads is still caught.
- **New value** rules compare each event with the entity's history over a lookback period.

Those extra reads are narrowed in SQL first: when a rule requires plain values on indexed
columns (`event.action: ssh_login`, `event.code: '4625'`), only matching rows are fetched,
and new-value rules that only use normalised fields skip the raw record entirely. Python
still evaluates every rule in full, so this can only skip rows that could never match.

Hits become alerts grouped by rule and entity (`group_by`, e.g. the source IP). A partial
unique index allows one *open* alert per group, so further hits update that alert's last
seen time and event count instead of creating new alerts. Running detection twice over
the same events changes nothing. Once an alert is closed, new activity opens a new one.

### Writing a rule

Rules use a subset of [Sigma](https://sigmahq.io/): named selections, field modifiers and
a condition. Fields are the normalised names (`source.ip`, `process.command_line`, ...),
paths into the raw event (`details.url_decoded`), or, Sigma style, Windows event data
fields such as `TargetImage`.

```yaml
id: custom-root-ssh-login            # lowercase letters, digits and dashes
title: Successful root login over SSH
description: Root should never log in directly over SSH on our servers.
severity: high                        # informational, low, medium, high, critical (Sigma: level)
mitre:
  tactics: [TA0001]
  techniques: [T1078]
logsource:
  source: linux_auth                  # linux_auth, web_access, windows_security, sysmon, json
detection:
  login:
    event.action: ssh_login
    event.outcome: success
    user.name: root
  trusted_network:
    source.ip|cidr: 10.0.0.0/8
  condition: login and not trusted_network
group_by: [host.name]                 # one open alert per host
falsepositives:
  - Break-glass access during an outage
```

Matching is case-insensitive. A list of values means "any of them"; `*` and `?` are
wildcards. Modifiers:

| Modifier | Meaning |
| --- | --- |
| `contains`, `startswith`, `endswith` | substring tests |
| `re` (+ `i`, `m`, `s` flags) | regular expression search |
| `all` | every listed value must match |
| `cidr` | IP address within a network |
| `gt`, `gte`, `lt`, `lte` | numeric comparisons |
| `exists` | the field is present (`true`) or absent (`false`) |

Conditions support `and`, `or`, `not`, parentheses, `1 of selection_*` and `all of them`.
Three keys extend Sigma for stateful detections:

```yaml
type: threshold                       # N events (or N distinct values) in a window
group_by: [source.ip]
threshold: {count: 10, timeframe: 5m, distinct: user.name}

type: sequence                        # ordered steps by the same entity
group_by: [source.ip]
sequence:
  maxspan: 15m
  steps:
    - {name: failures, count: 5, detection: {...}}
    - {name: success, detection: {...}}

type: new_value                       # a value not seen for this entity before
group_by: [user.name]
new_value: {field: source.ip, lookback: 30d}
```

Open a rule in the UI to edit its YAML, validate it, and **test it against pasted log
lines**: the result shows which lines would fire, without storing anything.

### Built-in rules

| Rule | Type | Severity | ATT&CK |
| --- | --- | --- | --- |
| [SSH brute force](docs/rules/ssh-brute-force.md) | threshold | medium | T1110.001 |
| [SSH password spraying](docs/rules/ssh-password-spraying.md) | threshold | medium | T1110.003 |
| [SSH brute force followed by a successful login](docs/rules/ssh-brute-force-then-success.md) | sequence | high | T1110.001, T1078 |
| [Login from a new source address](docs/rules/login-from-new-source-ip.md) | new value | medium | T1078 |
| [Local user account created on Linux](docs/rules/linux-user-created.md) | match | low | T1136.001 |
| [User added to a Linux admin group](docs/rules/linux-user-added-to-admin-group.md) | match | high | T1098 |
| [Password hash file read with sudo](docs/rules/linux-shadow-file-access.md) | match | high | T1003.008 |
| [Windows logon brute force](docs/rules/windows-logon-brute-force.md) | threshold | medium | T1110 |
| [PowerShell with an encoded command](docs/rules/windows-encoded-powershell.md) | match | high | T1059.001, T1027 |
| [Windows event log cleared](docs/rules/windows-audit-log-cleared.md) | match | high | T1070.001 |
| [Scheduled task created](docs/rules/windows-scheduled-task-created.md) | match | medium | T1053.005 |
| [Windows user account created](docs/rules/windows-user-account-created.md) | match | low | T1136.001 |
| [Account added to a privileged Windows group](docs/rules/windows-user-added-to-admin-group.md) | match | high | T1098 |
| [LSASS process memory accessed](docs/rules/sysmon-lsass-memory-access.md) | match | critical | T1003.001 |
| [Office application started a shell or script host](docs/rules/office-app-spawns-shell.md) | match | high | T1566.001, T1204.002 |
| [Registry Run key persistence](docs/rules/sysmon-registry-run-key.md) | match | medium | T1547.001 |
| [Web directory and file scanning](docs/rules/web-directory-scanning.md) | threshold | low | T1595.003 |
| [SQL injection attempt in a web request](docs/rules/web-sql-injection.md) | match | high | T1190 |
| [Path traversal attempt in a web request](docs/rules/web-path-traversal.md) | match | high | T1190, T1083 |
| [Known attack tool user agent](docs/rules/web-scanner-user-agent.md) | match | medium | T1595.002 |
| [Threat intel indicator match](docs/rules/threat-intel-indicator-match.md) | match | high | (depends on the indicator) |

Each rule has a [write-up](docs/README.md) explaining the attack, the log evidence and
the detection logic, and is tested against a matching and a non-matching example built
from real log lines. All 21 fire on the logs in `samples/` and on the
[generated data set](#sample-data-and-attack-scenarios) (the indicator match once the
accompanying `iocs.csv` has been imported).

### MITRE ATT&CK coverage

| Tactic | Technique | Rules |
| --- | --- | --- |
| Reconnaissance (TA0043) | T1595.002 Vulnerability Scanning | [Known attack tool user agent](docs/rules/web-scanner-user-agent.md) |
| | T1595.003 Wordlist Scanning | [Web directory and file scanning](docs/rules/web-directory-scanning.md) |
| Initial Access (TA0001) | T1190 Exploit Public-Facing Application | [SQL injection](docs/rules/web-sql-injection.md), [path traversal](docs/rules/web-path-traversal.md) |
| | T1078 Valid Accounts | [SSH brute force then login](docs/rules/ssh-brute-force-then-success.md), [login from a new address](docs/rules/login-from-new-source-ip.md) |
| | T1566.001 Spearphishing Attachment | [Office application started a shell](docs/rules/office-app-spawns-shell.md) |
| Execution (TA0002) | T1059.001 PowerShell | [Encoded PowerShell](docs/rules/windows-encoded-powershell.md) |
| | T1204.002 Malicious File | [Office application started a shell](docs/rules/office-app-spawns-shell.md) |
| | T1053.005 Scheduled Task | [Scheduled task created](docs/rules/windows-scheduled-task-created.md) |
| Persistence (TA0003) | T1136.001 Local Account | [Linux user created](docs/rules/linux-user-created.md), [Windows user created](docs/rules/windows-user-account-created.md) |
| | T1098 Account Manipulation | [Linux admin group](docs/rules/linux-user-added-to-admin-group.md), [Windows privileged group](docs/rules/windows-user-added-to-admin-group.md) |
| | T1053.005 Scheduled Task | [Scheduled task created](docs/rules/windows-scheduled-task-created.md) |
| | T1547.001 Registry Run Keys | [Registry Run key persistence](docs/rules/sysmon-registry-run-key.md) |
| Privilege Escalation (TA0004) | T1098 Account Manipulation | [Linux admin group](docs/rules/linux-user-added-to-admin-group.md), [Windows privileged group](docs/rules/windows-user-added-to-admin-group.md) |
| | T1053.005 Scheduled Task | [Scheduled task created](docs/rules/windows-scheduled-task-created.md) |
| | T1547.001 Registry Run Keys | [Registry Run key persistence](docs/rules/sysmon-registry-run-key.md) |
| Defense Evasion (TA0005) | T1027 Obfuscated Files or Information | [Encoded PowerShell](docs/rules/windows-encoded-powershell.md) |
| | T1070.001 Clear Windows Event Logs | [Windows event log cleared](docs/rules/windows-audit-log-cleared.md) |
| Credential Access (TA0006) | T1110 Brute Force | [Windows logon brute force](docs/rules/windows-logon-brute-force.md) |
| | T1110.001 Password Guessing | [SSH brute force](docs/rules/ssh-brute-force.md), [SSH brute force then login](docs/rules/ssh-brute-force-then-success.md) |
| | T1110.003 Password Spraying | [SSH password spraying](docs/rules/ssh-password-spraying.md) |
| | T1003.001 LSASS Memory | [LSASS process memory accessed](docs/rules/sysmon-lsass-memory-access.md) |
| | T1003.008 /etc/passwd and /etc/shadow | [Password hash file read with sudo](docs/rules/linux-shadow-file-access.md) |
| Discovery (TA0007) | T1083 File and Directory Discovery | [Path traversal](docs/rules/web-path-traversal.md) |

That is 19 techniques across 8 of the 14 enterprise tactics. Resource Development,
Lateral Movement, Collection, Command and Control, Exfiltration and Impact have no rules
yet; the [indicator match rule](docs/rules/threat-intel-indicator-match.md) catches known
command-and-control infrastructure, but not the behaviour itself.

## Threat intelligence

### Indicators

The **Threat intel** page keeps a local store of known-bad IP addresses, domains and file
hashes (MD5, SHA-1, SHA-256). Add them one at a time or import a feed:

- **TXT**: one indicator per line; `#` starts a comment.
- **CSV**: a header row with a value column (`value`, `indicator`, `ioc`, ...) and,
  optionally, `type`, `description`, `confidence` (0-100 or low/medium/high), `tags`
  (separated by `;`), `source` and `expires`.

Values are normalised before they are stored: defanged forms such as `evil[.]example` and
`hxxp://...` are restored, URLs are reduced to their host, domains are lowercased and
IDNA-encoded, and hashes are typed by length. CIDR ranges are rejected rather than
silently expanded. Bad lines are reported with their line number and skipped; the rest of
the feed is imported. Importing the same feed again updates the existing entries. Try it
with [`samples/iocs.csv`](samples/iocs.csv).

### Matching

Events are checked against the active, unexpired indicators as they are ingested.
Source and destination IPs, the host of absolute URLs, Sysmon DNS queries and network
destinations, Sysmon `Hashes`, and ECS-style domain and hash fields in JSON records are
all checked. A domain indicator also matches its subdomains. A match sets
`threat.matched` on the event and records which indicator matched in which field.

Adding, importing or re-enabling indicators queues a **sweep** over stored events, so
activity from before the indicator was known is flagged too. The sweep then runs the
*Threat intel indicator match* rule over just the period with new matches. Deleting an
indicator clears the flag on events that no other indicator matches. Events can be
filtered to matches on the **Event search** page (or with `threat.matched:true`).

### Alert enrichment

When detection creates an alert or adds evidence to one, the worker enriches it. It
collects the alert's source IP and the IPs, domains and hashes in its evidence. It
checks each against the local store and, if configured, online providers, then stores a
verdict (malicious, suspicious, clean or unknown) on the alert. The verdict is shown in
the alert's threat intelligence panel, which can also be refreshed by hand.

With no API keys this all works offline from the local store. Online lookups are
optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WATCHPOST_ABUSEIPDB_API_KEY` | unset | Enables AbuseIPDB lookups for IP addresses. |
| `WATCHPOST_VIRUSTOTAL_API_KEY` | unset | Enables VirusTotal lookups for IPs, domains and hashes. |
| `WATCHPOST_ENRICHMENT_CACHE_HOURS` | 24 | How long a provider's answer is reused. |
| `WATCHPOST_ABUSEIPDB_DAILY_LIMIT` | 1000 | Requests per day (free tier). |
| `WATCHPOST_VIRUSTOTAL_PER_MINUTE` / `_DAILY_LIMIT` | 4 / 500 | Requests per minute and per day (free tier). |

Online lookups are limited in three ways:

- **What is sent:** only public indicators. Private, loopback, link-local, documentation
  and other reserved addresses, single-label host names, and names under reserved or
  internal suffixes (`.local`, `.internal`, `.corp`, `example.com`, ...) are checked
  locally and never leave the network.
- **How often:** answers are cached in PostgreSQL, so an address seen in a hundred
  alerts costs one request per cache period. Failed lookups are cached for 15 minutes.
- **Rate limits:** the request budgets live in Redis, so the API and every worker share
  one budget. A `429` pauses that provider for its `Retry-After`. Lookups held back by a
  limit leave the alert marked as pending, and a worker job retries those every ten
  minutes.

The "new address" rule uses IP addresses; country-level detection needs a GeoIP
database, which is not bundled so the platform can run fully offline.

## Investigation

### Alert triage

The **Alerts** queue filters by severity, status, rule, host, source IP, user, ATT&CK
technique, assignee and the period the alert was active, and sorts by latest activity,
severity or first seen. Select alerts to change their status or assignee together, or to
put them into a case.

An alert moves from **new** to **investigating** and ends as **true positive**,
**false positive** or **closed**. Ending it records when it was resolved; reopening
clears that. Only one open alert can exist per rule and entity (that is how repeated
hits are grouped), so reopening an alert is refused while a newer open alert already
tracks the same activity.

Each alert has its own page with the rule's notes, the threat intelligence panel, the
evidence events, the history of every status change and assignment, and a **timeline**:
all events that share the alert's host, IP address or user from a window before its
first event to the same window after its last (30 minutes by default, up to 24 hours),
with the evidence highlighted.

### Cases

A case groups related alerts into one investigation. Open one from selected alerts in
the queue or from the **Cases** page; its severity defaults to the highest among its
alerts. Linking a new alert moves it to investigating, and an alert belongs to one case
at a time.

A case moves through **open**, **in progress**, **resolved** and **closed**, with the
resolved and closed times recorded and a resolution text. Analysts add notes and **pin
events as evidence** (from the event search or an alert timeline), each with a note on
why it matters. Every change is written to the audit log, which is also the case's
activity history.

The case report can be downloaded as **Markdown** (lossless) or **PDF**. Both contain
the summary, resolution, ATT&CK techniques, entities, alerts, evidence, notes and
activity. The PDF uses the standard PDF fonts, so characters outside Latin-1 are shown
as their closest ASCII form or `?`.

### Event search

The **Event search** page takes a query and a time range, returns the newest events first
and pages through any number of results at the same speed (keyset pagination).

| Query | Matches |
| --- | --- |
| `user.name:root` | keyword fields match exactly and are case-sensitive, so their indexes are used |
| `host:web-*` | `*` and `?` are wildcards; patterns are case-insensitive |
| `process.command_line:mimikatz` | text fields (command line, URL, message, ...) match a case-insensitive substring |
| `source.ip:10.0.0.0/8` | IP fields take an address or a CIDR network |
| `ip:203.0.113.45` | either the source or the destination address |
| `status:>=500` | numbers and timestamps compare with `>`, `>=`, `<`, `<=` |
| `@timestamp:2026-10-12` | a bare date is that whole UTC day |
| `threat.matched:true` | events that matched a threat indicator |
| `destination.ip:*` | the field is present |
| `raw.event_data.TargetImage:*lsass*` | a path into the original record |
| `"Failed password"` | free text in the message, command line and URL |

Terms combine with `AND` (or a space), `OR`, `NOT` or a leading `-`, and parentheses.
Short names work for common fields (`host`, `user`, `action`, `outcome`, `url`, `status`,
`method`, `process`). `NOT` also matches events where the field is missing. Mistakes are
reported with their position, and an unknown field name gets a suggestion. Values are
always bound as parameters, never spliced into SQL.

### Entities and the ATT&CK matrix

Every host, user and IP address in the UI links to its **entity page**:

- how many events involve it, and when it was first and last seen
- events per day and its log sources
- the users, hosts or addresses it was seen with most
- local threat intel for an address
- its alerts, and the cases they belong to

An IP address matches as either end of a connection.

The **ATT&CK matrix** lays out the techniques the rules cover by tactic. Techniques
that raised alerts in the chosen period are highlighted and link to those alerts, and
the matrix also shows which techniques have only disabled rules.

## Dashboard

The **Overview** page opens with the security picture for the last 24 hours, 7 days,
30 days or all time, and refreshes every 30 seconds:

- open, new and unassigned alerts, open cases and stored events
- alerts over time, stacked by severity, and alerts by severity with how many are open
- the top attacking IPs (marked when they are in the threat intel store), top targeted
  users and top triggered rules, each linking to its entity page or alerts
- the ingestion rate, and the average throughput of ingestion jobs
- the mean and median time to resolve cases (opened to resolved) and alerts (raised
  to resolved)

Alerts are counted by when their activity started, so logs imported after the fact
still chart where the activity happened. The ingestion rate is read from the ingestion
jobs rather than by scanning events, so the page stays fast as the event table grows.
Every figure comes from `GET /api/dashboard?range=24h|7d|30d|all`.

## Security

### Sign-in and sessions

Passwords are hashed with Argon2id and must be 12 to 256 characters. Signing in from the
browser sets two cookies:

- `watchpost_session`: a signed JWT (HS256 with `WATCHPOST_SECRET_KEY`) holding the user
  id, a session version and a per-session CSRF secret. It is `HttpOnly`,
  `SameSite=Strict`, limited to `/api`, and `Secure` in production. Sessions last
  `WATCHPOST_SESSION_HOURS` (8 by default).
- `watchpost_csrf`: the same CSRF secret, readable by the UI, which sends it back in an
  `X-CSRF-Token` header on every request that changes data. A request whose header does
  not match its session is refused with 403.

Changing a password, signing out everywhere, an admin resetting someone's password and
deactivating an account all raise the user's session version, which ends every session
issued before it at once.

Failed sign-ins are counted per user name and per client address in Redis. After
`WATCHPOST_LOGIN_MAX_FAILURES` failures (5) within `WATCHPOST_LOGIN_WINDOW_MINUTES` (15)
further attempts get `429` with a `Retry-After` header. A successful sign-in clears the
count for that user name but not for the address, so spraying many names from one place
stays blocked. Unknown user names take as long to check as real ones and get the same
answer. If Redis is unreachable the throttle logs a warning and lets attempts through
rather than locking everyone out.

### Roles

| Role | Can |
| --- | --- |
| Viewer | Read everything except the user list details and the audit log. |
| Analyst | Everything a viewer can, plus triage alerts, work cases, upload logs, start detection runs, manage threat intel and validate or test rules. |
| Admin | Everything an analyst can, plus create, edit, enable and delete rules, manage users and read the audit log. |

The API enforces this on every route; the UI hides or disables what a role cannot use.
Admins cannot change their own role or deactivate themselves, so an active admin always
remains.

### API access for scripts

Scripts get a bearer token with the OAuth2 password flow and send it in an
`Authorization` header. Bearer requests need no CSRF header. The **Authorize** button on
`/api/docs` uses the same flow.

```bash
token=$(curl -s -d username=analyst.one -d password='...' \
  http://localhost:8000/api/auth/token | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $token" http://localhost:8000/api/alerts
```

### Audit log

Every sign-in, failed or blocked sign-in, sign-out and password change is recorded, along
with alert status changes and assignments, all case work, rule edits and toggles, log
uploads, detection runs, threat intel changes and account management. Each entry holds
the user, the action, its target, what changed, the client address and the browser.
Admins read it on the **Audit log** page or at `GET /api/audit`, filtered by area, user
or target. Entries cannot be edited or deleted through the app.

### Hardening

- **Input validation:** every request body and query parameter is validated by a
  Pydantic model with length limits, and all database access goes through SQLAlchemy
  with bound parameters, including the event search language.
- **Uploads:** log files are capped by `WATCHPOST_MAX_UPLOAD_BYTES` and feeds at 20 MiB,
  both checked while streaming. Content is sniffed rather than trusting the file name:
  only text logs (or gzip of one) are accepted, and binaries, zip archives and `.evtx`
  files are refused with an explanation.
- **Headers:** API responses carry `Content-Security-Policy: default-src 'none'`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store` and cross-origin isolation headers, plus HSTS
  in production. nginx sends a strict CSP and the same protections for the UI.
- **CORS:** only the origins in `WATCHPOST_CORS_ORIGINS` are allowed, with no wildcards.
  The bundled UI is served from the same origin through nginx and needs no CORS at all.
- **Proxies:** uvicorn trusts `X-Forwarded-For` only from private address ranges, so the
  audit log and the login throttle see the real client behind nginx.
- **Secrets:** production refuses to start without `WATCHPOST_SECRET_KEY`. Only
  `.env.example` is in the repository; the real `.env` is ignored by git.

## Sample data and attack scenarios

`watchpost generate-logs` writes a realistic data set for a small fictional company:
four Linux servers, a web shop, a Windows domain with eighteen workstations, and the people
who use them. Normal activity follows a working week (busy afternoons, quiet nights and
weekends): SSH sessions with sudo, cron jobs, nightly backups, shop visits, health checks
and crawlers, domain logons and Kerberos tickets, application launches, DNS lookups and
downloads. Six attacks are hidden in it:

| Attack | Category | Logs | Rules that catch it |
| --- | --- | --- | --- |
| SSH brute force from 203.0.113.45 ending in a password login as `backup` | Brute force | `auth.log` | SSH brute force, password spraying, brute force then login, login from a new address, indicator match |
| `backup` reads `/etc/shadow`, creates `svc-update`, adds it to `sudo` and installs a cron job | Privilege escalation, persistence | `auth.log` | Shadow file read, Linux user created, Linux admin group |
| Nikto, then sqlmap and path traversal against the shop from 198.51.100.23 | Web attack | `access.log` | Directory scanning, scanner user agent, SQL injection, path traversal, indicator match |
| 24 failed network logons on DC01 from 203.0.113.80, then a success as `administrator` | Brute force | Windows Security | Windows logon brute force, login from a new address, indicator match |
| Encoded PowerShell, a new account added to Administrators, a logon task, the Security log cleared | Privilege escalation, persistence, defense evasion | Windows Security | Encoded PowerShell, user created, privileged group, scheduled task, log cleared |
| A macro document starts encoded PowerShell that contacts its C2, drops a credential dumper that reads LSASS, and adds a Run key | Execution, credential access, persistence | Sysmon | Office spawns a shell, encoded PowerShell, LSASS access, Run key, indicator match |

```bash
uv run watchpost generate-logs --output demo --events 200000 --days 7   # from backend/
```

It writes `auth.log`, `access.log`, `windows_security.jsonl` and `sysmon.jsonl`, a threat
intel feed with the attackers' infrastructure (`iocs.csv`), and `scenarios.json`, which
lists each attack with its time window and the rules expected to fire. Options: `--events`
(the exact total, default 100,000), `--days` (1-90), `--end` (default: the current hour) and
`--seed` (the same seed always produces the same files).

Only private and documentation address ranges are used (`10.0.0.0/8`, `192.168.0.0/16`,
`203.0.113.0/24`, `198.51.100.0/24`) and every name is made up. Each person always logs in
from the same address and only ever mistypes a password once or twice, so the normal
activity raises no alerts at all: an integration test ingests a generated set and checks
that every built-in rule fires and that every alert belongs to a planted attack.

## Performance

`watchpost benchmark` generates a data set, loads it into a dedicated database and measures
the three things that matter at scale: how fast events go in, how long a full detection
pass takes, and how quickly searches answer. Ingestion runs through ordinary ingestion jobs
(parsing, indicator matching and inserts, exactly as the worker does them), detection runs
all 21 rules over every stored event, and searches go through the HTTP API as a signed-in
user, ten timed runs each after a warm-up.

```bash
# from backend/; the database name must contain 'bench' because its schema is rebuilt
uv run watchpost benchmark --database-url postgresql+asyncpg://watchpost:watchpost@localhost:5432/watchpost_bench
# or inside the stack
docker compose exec api watchpost benchmark --work-dir /tmp/bench \
  --database-url postgresql+asyncpg://watchpost:watchpost@db:5432/watchpost_bench
```

Results go to `benchmark-results.json` and `benchmark-results.md` in the work folder.

### Results on one million events

Measured on a laptop (Intel Core i7-8665U, 4 cores / 8 threads, 16 GB RAM, Windows 11)
with Python 3.12.10 and PostgreSQL 17.11 on the same machine, default settings, one
ingestion job at a time. Both runs use the same data set settings (seed 7). *Before* is the
code as it was when the benchmark was added; *after* includes the changes described below.

| | Before | After | Change |
| --- | ---: | ---: | ---: |
| Ingest 1,000,000 events | 20.0 min (833/s) | 7.1 min (2,334/s) | 2.8x faster |
| Detection, 21 rules over every event | 4.8 min | 2.2 min | 2.2x faster |
| Search for a rare command line (median) | 984 ms | 14 ms | 70x faster |

Ingestion per file, after:

| File | Events | Time | Events/s | Before |
| --- | ---: | ---: | ---: | ---: |
| `auth.log` | 250,000 | 77 s | 3,264 | 657 |
| `access.log` | 450,000 | 191 s | 2,355 | 1,273 |
| `windows_security.jsonl` | 200,000 | 104 s | 1,927 | 655 |
| `sysmon.jsonl` | 100,000 | 57 s | 1,755 | 619 |

Search response times through the API, after (50 results per page, newest first):

| Search | Request | Median | p95 |
| --- | --- | ---: | ---: |
| Newest events, no filter | `/api/events` | 16 ms | 18 ms |
| One address (indexed column) | `/api/events source.ip:203.0.113.45` | 14 ms | 16 ms |
| User and outcome | `/api/events user.name:backup AND event.outcome:success` | 16 ms | 21 ms |
| Status code outside a network | `/api/events status:404 AND NOT source.ip:10.0.0.0/8` | 28 ms | 30 ms |
| Failures in the last 24 hours | `/api/events outcome:failure` | 21 ms | 22 ms |
| Free text | `/api/events "Failed password"` | 392 ms | 532 ms |
| Substring of a command line | `/api/events process.command_line:sekurlsa` | 14 ms | 15 ms |
| Field inside the raw record | `/api/events raw.event_data.TargetImage:*lsass*` | 33 ms | 34 ms |
| Dashboard, last 7 days | `/api/dashboard 7d` | 301 ms | 374 ms |
| Alert queue | `/api/alerts` | 15 ms | 15 ms |

The detection run raised 27 alerts, every one of them for a planted attack.

### What was profiled and changed

1. **Event inserts** (ingestion, 7-14x faster inserts). Profiling a single job showed 85% of
   the time in `insert_events`. The insert passed the ORM entity, so SQLAlchemy used its
   bulk-insert path, which leaves `NULL` columns out of each row and groups rows by which
   columns are set: a batch of `auth.log` events became 1,729 statements for 2,000 rows.
   Batches are now copied with `COPY` into a per-connection temporary table and moved into
   `events` with a single `INSERT ... SELECT ... ON CONFLICT DO NOTHING RETURNING`, which keeps
   deduplication on the event hash.
2. **Row conversion** (2x faster). Each field's attribute path was split from its dotted
   name for every field of every event; it is now computed once with prepared getters.
3. **New-value rules** (detection). For every login, the rule walked the user's whole
   30-day history to build a set of earlier addresses, which is quadratic for busy
   accounts. Each history is now sorted per value and answered with a binary search.
4. **Detection queries** (detection). Threshold, sequence and new-value rules read events
   again around the scope, and those queries returned every event of the log source or
   user. Plain values a rule requires (`event.action: ssh_login`, `event.code: '4625'`) now
   become SQL conditions, and the new-value history reads only the columns the rule uses.
   On one day of data the follow-up queries went from 384,000 rows to 89,000.
5. **Substring search on command lines** (search). Finding a rare tool name read the whole
   table; a `pg_trgm` GIN index on `process_command_line` answers it from the index. It
   costs 7 MB at a million events because only process events have a command line.

One idea did not survive measurement: checking a whole list of rule values against one
lower-cased string instead of one value at a time made no difference to matching speed,
so it was left out.

The slowest part is now parsing, which is pure Python and runs on one core per ingestion
job: the access log parses at about 6,000 lines a second and the JSON formats at about
5,000. Inserts into a table that already holds a few hundred thousand rows also slow down
as its indexes grow, which is part of why the two Windows logs, ingested last and with the
largest raw records, have the lowest rates. Free-text search is the slowest query: messages and URLs
are not indexed, so a rare phrase means reading back through the table until 50 matches
turn up. See [Future improvements](#future-improvements).

## Data model

| Table | Purpose |
| --- | --- |
| `events` | Normalised log events. Unique `event_hash` (SHA-256 of source + raw line) deduplicates re-ingested data. Indexed by time and by entity (IP, user, host), with a trigram index on command lines for substring searches. |
| `rules` | Detection rules: Sigma-style YAML source plus parsed definition, severity, ATT&CK tactics/techniques, enabled flag, and whether it is built-in or custom. |
| `detection_runs` | One row per pass of the rules over an ingestion job's events, a time range, or the period with new threat-intel matches, with what it scanned and the alerts it created or updated. |
| `alerts` | Rule hits. A partial unique index on `group_key` for open alerts makes repeated hits update one alert instead of creating hundreds. |
| `alert_events` | Links alerts to the evidence events behind them. |
| `cases` / `case_notes` | Investigations that group alerts, with assignee, status, resolved and closed times, resolution and analyst notes. |
| `case_evidence` | Events pinned to a case as evidence, with the analyst's note. |
| `iocs` | Local threat-intel store of IPs, domains and file hashes, with source, confidence, tags and optional expiry. |
| `event_ioc_matches` | Which indicator matched which event, and in which field. `events.ioc_matched` is the indexed flag for filtering. |
| `enrichment_cache` | Answers from online providers per indicator, reused until they expire. |
| `users` | Analysts, admins and viewers, with Argon2id password hashes. |
| `audit_log` | Append-only record of analyst actions; also the activity history of alerts and cases. |
| `ingestion_jobs` | One row per uploaded or watched file: status, progress, inserted/duplicate/malformed counts and the first malformed records. |

Enum-like columns are `VARCHAR` with `CHECK` constraints rather than native PostgreSQL
enums, so adding a value is a simple migration.

## Development

### Backend

Uses [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
cd backend
uv sync                                   # create .venv with runtime + dev deps
uv run alembic upgrade head               # needs WATCHPOST_DATABASE_URL
uv run watchpost sync-rules               # load backend/rules/ into the database
uv run uvicorn watchpost.api.app:create_app --factory --reload
uv run arq watchpost.worker.settings.WorkerSettings
uv run watchpost generate-logs --output demo # realistic logs with planted attacks
```

Checks:

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy                               # strict mode
uv run pytest --cov                       # fails under 85% coverage
uv run pytest -m "not integration"        # unit tests only, no database needed
```

Integration tests need PostgreSQL. They use `WATCHPOST_TEST_DATABASE_URL` (default
`postgresql+asyncpg://watchpost:watchpost@localhost:5432/watchpost_test`) and **drop and
recreate the schema** of that database, so the suite refuses to run unless the database
name contains `test`. `docker compose up db` provides a server on localhost:5432.

### Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173, proxies /api to localhost:8000
npm run lint && npm run typecheck && npm run format:check && npm test
```

### Pre-commit

```bash
uv --directory backend run pre-commit install
```

The hooks run ruff, mypy, ESLint, Prettier and tsc, plus whitespace and merge-conflict
checks. CI (`.github/workflows/ci.yml`) runs the same checks, verifies that migrations
match the models, and runs both test suites.

## Project layout

```
backend/
  src/watchpost/
    core/        settings and logging
    db/          SQLAlchemy base, session helpers, models
    events/      normalised event schema, field registry, dedup hashing
    ingestion/   readers, parsers, batch pipeline, job runner, folder watcher
    detection/   rule schema, matchers, conditions, engine, runner, rule sync
    intel/       indicator parsing, feeds, matching, sweeps, providers, enrichment
    investigation/  alert triage, cases, timelines, entity profiles, ATT&CK matrix, reports
    search/      the event query language: parser and SQL compiler
    auth/        session tokens, sign-in checks and the login throttle
    datagen/     the synthetic log generator and its attack scenarios
    benchmark.py ingestion, detection and search timings
    accounts.py, audit.py, cli.py   users, the audit trail and the `watchpost` command
    dashboard.py the overview figures
    api/         FastAPI app factory, middleware, dependencies, routes
    worker/      arq settings, queue and jobs
  alembic/       migrations
  rules/         built-in detection rules (YAML)
  tests/         unit/ (no services) and integration/ (PostgreSQL)
frontend/
  src/           React app: api client, components, pages
docs/            one write-up per detection rule, screenshots
samples/         example logs for every supported format
watch/           drop files here for the folder watcher
docker-compose.yml
```

## Future improvements

- **More ATT&CK coverage**: lateral movement (remote service creation, PsExec-style logons,
  RDP from servers), command and control (beaconing intervals, rare domains), exfiltration
  (unusual outbound volume) and Linux persistence through cron and authorized_keys, which
  the generated attack already performs but no rule catches.
- **More log sources**: firewall and DNS server logs, cloud audit trails (CloudTrail, Entra
  ID sign-ins), and a syslog/HTTP listener so agents can ship events directly instead of
  writing files.
- **Faster parsing**: parsing is now the slowest part of ingestion. Running parsers in a
  process pool, or moving the hottest regular expressions and JSON handling to a compiled
  extension, would let one worker use every core.
- **Faster free text**: a full-text index (`tsvector`) on messages and URLs, so rare phrases
  are found from the index instead of by reading back through the table.
- **Scaling the event store**: monthly partitions of the `events` table with a retention
  policy, and a columnar or search engine back end (ClickHouse, OpenSearch) behind the same
  query language for deployments well beyond tens of millions of events.
- **Smarter detection**: compiling simple match rules to SQL so the database filters events
  before Python sees them, correlation rules that join alerts across hosts, and per-entity
  baselines instead of fixed thresholds.
- **Response**: notifications to chat or e-mail, playbooks attached to rules, and sharing
  cases with external responders.
- **Identity**: single sign-on with OIDC or SAML and multi-factor authentication.

## License

[MIT](LICENSE)
