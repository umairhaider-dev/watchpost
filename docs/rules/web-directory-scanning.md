# Web directory and file scanning

| | |
| --- | --- |
| Rule | `web-directory-scanning` ([YAML](../../backend/rules/web/directory-scanning.yml)) |
| Type | Threshold: 20 "404 Not Found" responses in 2 minutes to one client |
| Severity | Low |
| ATT&CK | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Active Scanning: Wordlist Scanning (Reconnaissance) |
| Logs | Web server access log, combined format (`web_access`) |

## The attack

Content discovery tools (gobuster, dirbuster, ffuf, Nikto) request long wordlists of paths:
admin panels, backups, `.env` and `.git` files, old copies of scripts. Nearly every request
misses, but the few that hit reveal forgotten files and entry points for the next stage.

## Log evidence

```text
198.51.100.23 - - [12/Oct/2026:01:27:34 +0000] "GET /.env HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000002)"
198.51.100.23 - - [12/Oct/2026:01:27:34 +0000] "GET /.git/config HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)"
198.51.100.23 - - [12/Oct/2026:01:27:36 +0000] "GET /backup.zip HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000007)"
198.51.100.23 - - [12/Oct/2026:01:28:00 +0000] "GET /backup.bak HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000057)"
```

Each line becomes an `http_request` event with `source.ip`, `url.original` and
`http.response.status_code`.

## Detection logic

Responses with status 404 are counted per `source.ip`; twenty within any two-minute window
raise the alert. A real visitor produces a handful of 404s at most (a missing favicon, an old
link), while a wordlist scan produces hundreds per minute. The rule looks at volume only, so
it catches scanners that disguise their user agent.

## False positives and tuning

- A broken page with many missing images, seen by one busy client or a corporate proxy.
- Search engine crawlers following stale links.
- Because it is low severity, it is best read together with the other web rules: the same
  address showing up in [SQL injection](web-sql-injection.md) or
  [path traversal](web-path-traversal.md) alerts is a real attack in progress.

## Responding

1. Check whether any request from the address got a 200 for something that should not be
   public (search `source.ip:<address> AND status:200`).
2. Block or rate-limit the address at the edge if the scan is not authorised.
