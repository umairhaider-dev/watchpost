# Activity involving a known-bad indicator

| | |
| --- | --- |
| Rule | `threat-intel-indicator-match` ([YAML](../../backend/rules/intel/threat-intel-match.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | None of its own: the matched activity decides the technique |
| Logs | All sources |

## The attack

Any activity involving infrastructure or files already known to be malicious: a login from
an address that brute-forces SSH servers across the internet, a DNS lookup of a
command-and-control domain, or a process whose SHA-256 belongs to a known tool. The
indicators come from threat-intel feeds imported on the **Threat intel** page (or added by
hand).

## Log evidence

The generated `iocs.csv` lists the attackers' infrastructure:

```csv
value,type,description,confidence,tags
203.0.113.45,ip,SSH brute-force source reported by several organisations,85,ssh;brute-force
update-check[.]example[.]net,domain,PowerShell loader command-and-control domain,95,c2;powershell
3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a,sha256,Credential dumping tool,95,credential-access;malware
```

Matching events include the SSH failures from `203.0.113.45`, a Sysmon DNS query for
`update-check.example.net`, and the Sysmon process creation whose `Hashes` field contains
the tool's SHA-256.

## Detection logic

The rule itself is one line: `threat.matched: true`. The work happens during ingestion: every
event's source and destination addresses, domains (the host of an absolute URL, Sysmon DNS
queries and connection host names) and file hashes (Sysmon `Hashes`) are looked up in an
in-memory index of active indicators, and matches are flagged on the event and recorded in
`event_ioc_matches` with the field that matched. When a feed is imported **after** the logs, a
sweep checks stored events and queues a detection run for the period with new matches, so the
order of imports does not matter.

Alerts are grouped by `host.name` and `source.ip`. The alert's enrichment panel shows which
indicator matched, in which field, its source feed and confidence.

## False positives and tuning

- Stale indicators: addresses that have since been reassigned. Set an expiry on feed
  entries and deactivate old ones on the **Threat intel** page.
- Shared hosting, CDN or cloud addresses that also serve legitimate sites.
- Sinkholed domains that now point at security researchers.
- The indicator's confidence is the alert's confidence: low-confidence feeds are better kept
  for context than for alerting.

## Responding

1. Open the alert's enrichment panel to see the indicator, its source and confidence.
2. Follow the matched activity with the other rules: a matched address in a brute force, a
   matched domain in a PowerShell download, a matched hash on a host that also accessed
   LSASS.
