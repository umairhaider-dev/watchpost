# Known attack tool user agent

| | |
| --- | --- |
| Rule | `web-scanner-user-agent` ([YAML](../../backend/rules/web/scanner-user-agent.yml)) |
| Type | Match |
| Severity | Medium |
| ATT&CK | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) Active Scanning: Vulnerability Scanning (Reconnaissance) |
| Logs | Web server access log, combined format (`web_access`) |

## The attack

Vulnerability scanners and exploitation tools announce themselves in the `User-Agent` header
unless the operator changes it, and many never do. Seeing `sqlmap` or `Nikto` in your logs
means someone is actively probing the site with tools built to find and exploit weaknesses.

## Log evidence

```text
198.51.100.23 - - [12/Oct/2026:01:27:34 +0000] "GET /admin/ HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
198.51.100.23 - - [12/Oct/2026:01:32:57 +0000] "GET /products?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 4952 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```

The quoted last field becomes `user_agent.original`.

## Detection logic

A case-insensitive substring match of `user_agent.original` against fifteen tool names:
sqlmap, nikto, nmap, masscan, zgrab, gobuster, dirbuster, wpscan, nuclei, acunetix, nessus,
openvas, wfuzz, ffuf and hydra. All requests from one `source.ip` collect into one alert.
It is a cheap early warning, not proof of compromise; attackers who change their user agent
are caught by the behavioural web rules instead.

## False positives and tuning

- Scans run by your own security team or an external testing company. Exclude their
  addresses, or keep the alert and close it as expected so the activity stays on record.

## Responding

1. Check whether the scan was authorised.
2. Look at the rest of the address's requests for successful exploitation (500 responses to
   injection payloads, 200 responses for sensitive files).
3. Block the address if the scan is not yours.
