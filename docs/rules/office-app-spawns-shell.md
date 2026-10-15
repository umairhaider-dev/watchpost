# Office application started a shell or script host

| | |
| --- | --- |
| Rule | `office-app-spawns-shell` ([YAML](../../backend/rules/sysmon/office-spawns-shell.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment, [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File (Initial Access, Execution) |
| Logs | Sysmon event 1 and Security event 4688 (`windows`) |

## The attack

A phishing email carries a document with a macro. When the user opens it and clicks
"Enable content", the macro starts PowerShell, `cmd.exe`, `mshta` or another built-in tool to
download and run the real payload. Word and Excel almost never need to start a shell, so
the parent-child pair is a very reliable signal.

## Log evidence

Sysmon process creation (event 1) on the finance workstation:

```json
{"EventID": 1, "Computer": "WS-FIN-07.corp.example.local",
 "EventData": {"User": "CORP\\g.adeyemi",
               "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...",
               "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
               "ParentCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\g.adeyemi\\Downloads\\invoice_4471.docm\""}}
```

The parser maps `Image` and `ParentImage` to `process.name` and `process.parent.name`
(`powershell.exe`, `winword.exe`).

## Detection logic

`event.action: process_created` where `process.parent.name` is an Office application (Word,
Excel, PowerPoint, Outlook, Access, OneNote, Publisher) and `process.name` is a shell, script
host or commonly abused binary: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`,
`cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`.
It works on both Sysmon and Security 4688 events. Alerts are grouped by host and user.

## False positives and tuning

- Add-ins or business macros that legitimately call scripts. Exclude them by the full
  command line of the child, never by the parent alone.

## Responding

1. Isolate the workstation: the user has most likely run the payload.
2. Find the document (`ParentCommandLine`) and the email it came in, and check who else
   received it.
3. Follow the child process: network connections, files it wrote, and further processes.
