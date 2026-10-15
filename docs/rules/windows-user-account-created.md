# Windows user account created

| | |
| --- | --- |
| Rule | `windows-user-account-created` ([YAML](../../backend/rules/windows/user-account-created.yml)) |
| Type | Match |
| Severity | Low |
| ATT&CK | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account (Persistence) |
| Logs | Windows Security log as JSON (`windows`) |

## The attack

With administrator rights, an attacker creates an account of their own so they can come
back even after the account they broke in with is reset. Names are chosen to look boring:
`helpdesk-svc`, `backup_admin`, `svc_sql`.

## Log evidence

Event 4720 ("A user account was created"):

```json
{"EventID": 4720, "Computer": "DC01.corp.example.local",
 "EventData": {"SubjectUserName": "administrator", "TargetUserName": "helpdesk-svc",
               "TargetSid": "S-1-5-21-1004336348-1177238915-682003330-1612", "SamAccountName": "helpdesk-svc"}}
```

The parser maps it to `event.action: user_created` with the **new** account in `user.name`;
`SubjectUserName` in the event data is the account that created it.

## Detection logic

Every event with `event.code: 4720`, grouped by host and new account name. It is low
severity on purpose: accounts are created all the time in an office, but each one should
match a request. It becomes interesting together with
[Account added to a privileged Windows group](windows-user-added-to-admin-group.md) a few
seconds later.

## False positives and tuning

- Normal onboarding by the helpdesk or an identity management system. If one service account
  creates all legitimate accounts, exclude it with a selection on `SubjectUserName`.

## Responding

1. Check the new account against tickets or HR records.
2. If it is unexplained, disable it and look at what the creating account did around that
   time.
