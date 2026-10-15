# Windows event log cleared

| | |
| --- | --- |
| Rule | `windows-audit-log-cleared` ([YAML](../../backend/rules/windows/audit-log-cleared.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs (Defense Evasion) |
| Logs | Windows Security and System logs as JSON (`windows`) |

## The attack

Attackers clear event logs to remove the record of what they did, usually as one of the
last steps before leaving a machine (`wevtutil cl Security`, `Clear-EventLog`). Clearing is
itself logged, and if the logs were already shipped to Watchpost, nothing is lost.

## Log evidence

Event 1102 is written to the Security log at the moment it is cleared:

```json
{"EventID": 1102, "Provider": "Microsoft-Windows-Eventlog", "Computer": "DC01.corp.example.local",
 "EventData": {"SubjectUserName": "administrator", "SubjectDomainName": "CORP"}}
```

Clearing any other log (System, Application) produces event 104 in the System log.

## Detection logic

Any event with `event.code` `1102` or `104` from the Windows logs, grouped by host. There is
no threshold: legitimate clearing is rare enough that every occurrence deserves a look.

## False positives and tuning

- An administrator clearing a full log while troubleshooting.
- Lab or test machines that are reset regularly. Exclude them by `host.name`.

## Responding

1. Look at everything recorded on the host in the hour **before** the clear: that is what
   the attacker wanted to hide. In the generated data it is a new admin account and a
   scheduled task.
2. Find who cleared it (`SubjectUserName`) and how that account logged on.
