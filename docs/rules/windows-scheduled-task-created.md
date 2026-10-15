# Scheduled task created

| | |
| --- | --- |
| Rule | `windows-scheduled-task-created` ([YAML](../../backend/rules/windows/scheduled-task-created.yml)) |
| Type | Match |
| Severity | Medium |
| ATT&CK | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation) |
| Logs | Windows Security log as JSON (`windows`) |

## The attack

Scheduled tasks survive reboots, can run as SYSTEM, and can start at logon or on a timer,
which makes them one of the most common persistence mechanisms on Windows. Attackers give
them names that look like updaters so they are not noticed in Task Scheduler.

## Log evidence

Event 4698 ("A scheduled task was created") includes the full task XML:

```json
{"EventID": 4698, "Computer": "DC01.corp.example.local",
 "EventData": {"SubjectUserName": "administrator",
               "TaskName": "\\Microsoft\\Windows\\Update\\UpdaterTask",
               "TaskContent": "<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc SQBFAFgA...</Arguments></Exec></Actions></Task>"}}
```

The name looks like a Windows update task; the content runs hidden, encoded PowerShell at
every logon.

## Detection logic

Every event with `event.code: 4698`, grouped by host and the account that created it. The
rule does not try to judge the task: the analyst should read `TaskContent`, which is kept in
the event's raw record and shown on the alert page.

## False positives and tuning

- Software installers and updaters registering their own tasks.
- Administrators or deployment tools creating maintenance tasks.
- Tasks created by `SYSTEM` during software installation are the usual noise; tasks created
  by a user account outside a change window are the interesting ones.

## Responding

1. Read the task's command and arguments. PowerShell, `cmd /c`, script hosts or files in
   `AppData`, `Temp` or `ProgramData` are strong signs of malice.
2. Disable the task, collect the file it runs, and look for other persistence on the host.
