# Sample logs

Small, hand-written logs for trying out ingestion. They use only private and
documentation IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, `203.0.113.0/24`,
`198.51.100.0/24`) and made-up accounts.

| File | Parser (auto-detected) | What is in it |
| --- | --- | --- |
| `auth.log` | `linux_auth` | Normal admin activity, then an SSH brute force from 203.0.113.45 that ends in a successful login, `sudo cat /etc/shadow`, a new user added to the `sudo` group, failed sudo/su attempts and scanner noise. |
| `access.log` | `web_access` | Normal shop traffic, then a scanner (198.51.100.23) probing for admin pages, path traversal, SQL injection with sqlmap, XSS and password guessing, plus a TLS handshake sent to the HTTP port. |
| `windows_security.jsonl` | `windows` | Security log: password spraying against `administrator`, a successful network logon, encoded PowerShell, a new account added to Administrators, a scheduled task, and the audit log being cleared. |
| `sysmon.json` | `windows` | Sysmon as a pretty-printed JSON array (EVTX→JSON shape): Word spawning encoded PowerShell, DNS and C2 connection, a dropped binary reading LSASS memory, and a Run-key persistence entry. |
| `app_events.jsonl` | `json` | Application audit log mixing flat fields, epoch timestamps and ECS-style nested objects. |
| `malformed_lines.log` | `linux_auth` | Three broken lines among valid ones, to show how malformed lines are counted and reported. |

Upload them from the **Ingest** page, or copy them into the `watch/` folder.
Uploading the same file twice inserts nothing new: every event is
deduplicated by its hash.
