# Registry Run key persistence

| | |
| --- | --- |
| Rule | `sysmon-registry-run-key` ([YAML](../../backend/rules/sysmon/registry-run-key.yml)) |
| Type | Match |
| Severity | Medium |
| ATT&CK | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys (Persistence, Privilege Escalation) |
| Logs | Sysmon event 13, registry value set (`windows`) |

## The attack

Programs listed under `...\CurrentVersion\Run` or `RunOnce` start every time the user logs
on. It is one of the oldest persistence tricks and still one of the most common: one
registry write, no administrator rights needed for the user's own hive.

## Log evidence

```json
{"EventID": 13, "Computer": "WS-FIN-07.corp.example.local",
 "EventData": {"EventType": "SetValue",
               "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "TargetObject": "HKU\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
               "Details": "C:\\Users\\g.adeyemi\\AppData\\Local\\Temp\\m.exe"}}
```

A value called `Updater`, written by PowerShell, pointing at an executable in the user's
Temp folder.

## Detection logic

`event.code: 13` where `TargetObject` contains `\CurrentVersion\Run\`,
`\CurrentVersion\RunOnce\` or `\CurrentVersion\Policies\Explorer\Run\`. Both the machine
(`HKLM`) and user (`HKU`, `HKCU`) hives match. Grouped by host and user. Other registry writes,
such as Office settings in the generated data, are ignored.

## False positives and tuning

- Software installers registering their updater or tray application (`OneDrive`, `Teams`,
  vendor update agents). These normally point into `Program Files`; values pointing into
  `AppData`, `Temp`, `ProgramData` or `Public` are the suspicious ones. A second rule with
  `Details|contains` on those folders and a higher severity is a good refinement.

## Responding

1. Check what `Details` points to and which process wrote the value (`Image`).
2. Delete the value, collect and remove the file, and look for the process that dropped it.
