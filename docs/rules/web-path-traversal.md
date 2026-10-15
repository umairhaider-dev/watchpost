# Path traversal attempt in a web request

| | |
| --- | --- |
| Rule | `web-path-traversal` ([YAML](../../backend/rules/web/path-traversal.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application, [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery |
| Logs | Web server access log, combined format (`web_access`) |

## The attack

An application that serves files by name (`/download?file=report.pdf`) may let `../`
sequences climb out of its folder and read any file the web server can: `/etc/passwd`,
configuration files with database passwords, or `win.ini` on Windows. Attackers encode the
dots and slashes, sometimes twice, to slip past filters.

## Log evidence

```text
198.51.100.23 - - [12/Oct/2026:01:34:34 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 157 "-" "python-requests/2.32.3"
198.51.100.23 - - [12/Oct/2026:01:34:35 +0000] "GET /download?file=..%2f..%2f..%2f..%2fetc%2fshadow HTTP/1.1" 400 157 "-" "python-requests/2.32.3"
198.51.100.23 - - [12/Oct/2026:01:34:38 +0000] "GET /static/%2e%2e/%2e%2e/%2e%2e/proc/self/environ HTTP/1.1" 400 157 "-" "python-requests/2.32.3"
```

## Detection logic

Two selections, either of which is enough (`1 of traversal_*`):

- `traversal_decoded`: the decoded URL (`details.url_decoded`) contains `../` or `..\`, or
  names a file that only makes sense on the server: `/etc/passwd`, `/etc/shadow`,
  `/proc/self/environ`, `win.ini`, `boot.ini`;
- `traversal_encoded`: the URL *as logged* contains encoded dots or slashes that survive one
  round of decoding: `%2e%2e`, `%252e`, `..%2f`, `..%5c`.

Checking both forms catches plain, encoded and double-encoded attempts. Alerts are grouped by
`source.ip`.

## False positives and tuning

- Applications that put relative paths in query strings by design (some file managers).
  Exclude the specific path with a selection on `url.original`.

## Responding

1. Check the status code: a **200** with a size close to the real file means the file was
   probably disclosed. Treat any secrets in it as leaked.
2. Fix the handler (resolve the path and check it stays under the intended folder) and block
   the source.
