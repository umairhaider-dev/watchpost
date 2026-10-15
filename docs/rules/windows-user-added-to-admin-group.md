# Account added to a privileged Windows group

| | |
| --- | --- |
| Rule | `windows-user-added-to-admin-group` ([YAML](../../backend/rules/windows/user-added-to-admin-group.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation (Persistence, Privilege Escalation) |
| Logs | Windows Security log as JSON (`windows`) |

## The attack

Membership of Administrators gives full control of a machine; Domain Admins, Enterprise
Admins and Schema Admins give control of the whole domain. Adding an account the attacker
controls to one of these groups is how a foothold becomes lasting control.

## Log evidence

Event 4732 ("A member was added to a security-enabled local group"):

```json
{"EventID": 4732, "Computer": "DC01.corp.example.local",
 "EventData": {"SubjectUserName": "administrator", "MemberName": "-",
               "MemberSid": "S-1-5-21-1004336348-1177238915-682003330-1612",
               "TargetUserName": "Administrators", "TargetDomainName": "Builtin"}}
```

Here `TargetUserName` is the **group**. The member is the SID of the `helpdesk-svc` account
created a few seconds earlier; local group events often show only the SID.

## Detection logic

Events 4728 (global group), 4732 (local group) or 4756 (universal group) where
`TargetUserName` is `Administrators`, `Domain Admins`, `Enterprise Admins` or `Schema Admins`.
Fields from the original event data (like `TargetUserName`) can be used in rules directly.
Alerts are grouped by host and member.

## False positives and tuning

- Planned changes to administrator group membership. Large organisations may want to add
  other sensitive groups (Backup Operators, Account Operators) to the list.

## Responding

1. Resolve the member SID to an account and confirm the change with its owner.
2. If unexpected, remove the membership, disable the member, and review what the account that
   made the change did before and after.
