# Windows logon brute force

| | |
| --- | --- |
| Rule | `windows-logon-brute-force` ([YAML](../../backend/rules/windows/logon-brute-force.yml)) |
| Type | Threshold: 10 failed logons in 5 minutes from one address |
| Severity | Medium |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force (Credential Access) |
| Logs | Windows Security log as JSON (`windows`) |

## The attack

Password guessing against Windows services exposed to a network: SMB, RDP, WinRM or
Outlook Web Access. Built-in names like `administrator` and `guest` are tried first because
they exist everywhere.

## Log evidence

Event 4625 ("An account failed to log on") records the target account, the logon type and
the client address:

```json
{"EventID": 4625, "TimeCreated": "2026-10-13T02:56:00.8917400Z", "Computer": "DC01.corp.example.local",
 "EventData": {"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "203.0.113.80",
               "AuthenticationPackageName": "NTLM", "Status": "0xc000006d", "SubStatus": "0xc000006a"}}
```

The parser maps it to `event.action: logon`, `event.outcome: failure`, `event.code: 4625`,
`user.name` and `source.ip`. Sub-status `0xc000006a` means a wrong password for a real
account; `0xc0000064` means the account does not exist.

## Detection logic

Events with `event.code: 4625` **and** a source address (`source.ip|exists: true`) are counted
per `source.ip`; ten within five minutes raise the alert. Failures without an address (typing
the wrong password at the console) are ignored, because they cannot be tied to a remote
attacker.

## False positives and tuning

- A service or scheduled task still configured with an old password, retrying every minute.
- An application retrying a stored credential. Both show up as one account from one internal
  address: exclude them by name rather than raising the threshold.

## Responding

1. Check for a successful 4624 logon from the same address afterwards. The
   [new source address](login-from-new-source-ip.md) rule raises one if the account has never
   logged in from there.
2. Block the address, and make sure RDP and SMB are not reachable from the internet.
