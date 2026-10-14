# Watchpost

Watchpost is a self-hosted SOC investigation and threat detection platform. It ingests
security logs, normalises them into a common schema, runs detection rules mapped to
MITRE ATT&CK, raises alerts, and gives analysts a web interface to investigate and manage
cases.

It is a defensive tool only: it reads and analyses logs and never scans, probes or
modifies other systems.

> **Status:** foundation, log ingestion, the detection engine and threat intelligence
> are in place. Case management is being built on top of them.

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
        REDIS[(redis<br/>job queue)]
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
| SSH brute force | threshold | medium | T1110.001 |
| SSH password spraying | threshold | medium | T1110.003 |
| SSH brute force followed by a successful login | sequence | high | T1110.001, T1078 |
| Login from a new source address | new value | medium | T1078 |
| Local user account created on Linux | match | low | T1136.001 |
| User added to a Linux admin group | match | high | T1098 |
| Password hash file read with sudo | match | high | T1003.008 |
| Windows logon brute force | threshold | medium | T1110 |
| PowerShell with an encoded command | match | high | T1059.001, T1027 |
| Windows event log cleared | match | high | T1070.001 |
| Scheduled task created | match | medium | T1053.005 |
| Windows user account created | match | low | T1136.001 |
| Account added to a privileged Windows group | match | high | T1098 |
| LSASS process memory accessed | match | critical | T1003.001 |
| Office application started a shell or script host | match | high | T1566.001, T1204.002 |
| Registry Run key persistence | match | medium | T1547.001 |
| Web directory and file scanning | threshold | low | T1595.003 |
| SQL injection attempt in a web request | match | high | T1190 |
| Path traversal attempt in a web request | match | high | T1190, T1083 |
| Known attack tool user agent | match | medium | T1595.002 |
| Threat intel indicator match | match | high | (depends on the indicator) |

Together they map to 19 techniques across 8 of the 14 ATT&CK tactics (Reconnaissance,
Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential
Access and Discovery); lateral movement, collection, command and control, exfiltration and
impact are not covered yet. Each rule documents the attack, the evidence it looks for and
known false positives, and is tested against a matching and a non-matching example built
from real log lines. All 21 fire on the logs in `samples/` (the indicator match once
`samples/iocs.csv` has been imported).

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
filtered to matches on the **Events** page.

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

## Data model

| Table | Purpose |
| --- | --- |
| `events` | Normalised log events. Unique `event_hash` (SHA-256 of source + raw line) deduplicates re-ingested data. Indexed by time and by entity (IP, user, host). |
| `rules` | Detection rules: Sigma-style YAML source plus parsed definition, severity, ATT&CK tactics/techniques, enabled flag, and whether it is built-in or custom. |
| `detection_runs` | One row per pass of the rules over an ingestion job's events, a time range, or the period with new threat-intel matches, with what it scanned and the alerts it created or updated. |
| `alerts` | Rule hits. A partial unique index on `group_key` for open alerts makes repeated hits update one alert instead of creating hundreds. |
| `alert_events` | Links alerts to the evidence events behind them. |
| `cases` / `case_notes` | Investigations that group alerts, with assignee, status, timestamps and analyst notes. |
| `iocs` | Local threat-intel store of IPs, domains and file hashes, with source, confidence, tags and optional expiry. |
| `event_ioc_matches` | Which indicator matched which event, and in which field. `events.ioc_matched` is the indexed flag for filtering. |
| `enrichment_cache` | Answers from online providers per indicator, reused until they expire. |
| `users` | Analysts, admins and viewers. |
| `audit_log` | Append-only record of analyst actions. |
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
    api/         FastAPI app factory, middleware, dependencies, routes
    worker/      arq settings, queue and jobs
  alembic/       migrations
  rules/         built-in detection rules (YAML)
  tests/         unit/ (no services) and integration/ (PostgreSQL)
frontend/
  src/           React app: api client, components, pages
samples/         example logs for every supported format
watch/           drop files here for the folder watcher
docker-compose.yml
```

## License

[MIT](LICENSE)
