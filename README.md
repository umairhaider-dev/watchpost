# Watchpost

Watchpost is a self-hosted SOC investigation and threat detection platform. It ingests
security logs, normalises them into a common schema, runs detection rules mapped to
MITRE ATT&CK, raises alerts, and gives analysts a web interface to investigate and manage
cases.

It is a defensive tool only: it reads and analyses logs and never scans, probes or
modifies other systems.

> **Status:** foundation and log ingestion are in place. Detection, enrichment and case
> management are being built on top of them.

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
        MIGRATE[migrate<br/>alembic upgrade head]
    end
    UI --> NGINX --> API
    API --> DB
    API -- enqueue jobs --> REDIS
    REDIS --> WORKER
    WORKER --> DB
    MIGRATE --> DB
```

- **api**: FastAPI on async SQLAlchemy 2 (asyncpg). Serves the REST API under `/api`
  (OpenAPI docs at `/api/docs`).
- **worker**: an [arq](https://arq-docs.helpmanual.io/) worker that runs ingestion and
  detection jobs off a Redis queue.
- **migrate**: a one-shot container that applies Alembic migrations before the api and
  worker start.
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
3. Events are inserted in batches with `ON CONFLICT (event_hash) DO NOTHING`. The hash
   covers the log source and the raw line (for JSON, the record with its keys sorted), so
   ingesting the same data twice stores it once and reports exact duplicate counts.
4. Progress counters are committed with every batch, so the **Ingest** page shows live
   progress and the totals always match the database.

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

## Data model

| Table | Purpose |
| --- | --- |
| `events` | Normalised log events. Unique `event_hash` (SHA-256 of source + raw line) deduplicates re-ingested data. Indexed by time and by entity (IP, user, host). |
| `rules` | Detection rules: Sigma-style YAML source plus parsed definition, severity, ATT&CK tactics/techniques, enabled flag. |
| `alerts` | Rule hits. A partial unique index on `group_key` for open alerts makes repeated hits update one alert instead of creating hundreds. |
| `alert_events` | Links alerts to the evidence events behind them. |
| `cases` / `case_notes` | Investigations that group alerts, with assignee, status, timestamps and analyst notes. |
| `iocs` | Local threat-intel store of IPs, domains and file hashes. |
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
    api/         FastAPI app factory, middleware, dependencies, routes
    worker/      arq settings, queue and jobs
  alembic/       migrations
  tests/         unit/ (no services) and integration/ (PostgreSQL)
frontend/
  src/           React app: api client, components, pages
samples/         example logs for every supported format
watch/           drop files here for the folder watcher
docker-compose.yml
```

## License

MIT
