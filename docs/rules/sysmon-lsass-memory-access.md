# LSASS process memory accessed

| | |
| --- | --- |
| Rule | `sysmon-lsass-memory-access` ([YAML](../../backend/rules/sysmon/lsass-memory-access.yml)) |
| Type | Match |
| Severity | Critical |
| ATT&CK | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory (Credential Access) |
| Logs | Sysmon event 10, process access (`windows`) |

## The attack

`lsass.exe` keeps the credentials of logged-on users in memory: NTLM hashes, Kerberos
tickets and sometimes plain-text passwords. Tools such as Mimikatz, ProcDump or the
`comsvcs.dll` MiniDump trick open LSASS with read access and copy them out, which lets the
attacker move to other machines as those users.

## Log evidence

Sysmon event 10 records one process opening another, with the access rights it asked for:

```json
{"EventID": 10, "Computer": "WS-FIN-07.corp.example.local",
 "EventData": {"SourceImage": "C:\\Users\\g.adeyemi\\AppData\\Local\\Temp\\m.exe",
               "TargetImage": "C:\\Windows\\System32\\lsass.exe",
               "GrantedAccess": "0x1010", "SourceUser": "CORP\\g.adeyemi"}}
```

`0x1010` is `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, exactly what Mimikatz's
`sekurlsa` module asks for.

## Detection logic

- `lsass_access`: `event.code: 10`, `TargetImage` ending in `\lsass.exe`, and `GrantedAccess`
  one of the masks credential dumpers request (`0x1010`, `0x1410`, `0x1438`, `0x143a`,
  `0x1f0fff`, `0x1f1fff`, `0x1f3fff`, `0x1fffff`);
- `system_process`: `SourceImage` ending in a known legitimate reader: `MsMpEng.exe`
  (Defender), `csrss.exe`, `wininit.exe`, `lsm.exe`, `wmiprvse.exe`.

The condition is `lsass_access and not system_process`. The generated data includes
Defender reading LSASS with `0x1410` during scans, which the exclusion correctly ignores.

## False positives and tuning

- Endpoint security or backup products not in the exclusion list. Add their full path, not
  just the file name, so malware cannot hide behind the same name.
- Windows Error Reporting capturing a crash of LSASS.

## Responding

This is a critical alert:

1. Isolate the host immediately.
2. Treat every account that was logged on to it as compromised and reset their passwords;
   for privileged accounts, also check for Kerberos ticket reuse.
3. Collect the source binary and look for how it got there (often an Office macro or an
   encoded PowerShell command shortly before).
