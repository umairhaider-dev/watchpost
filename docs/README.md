# Watchpost documentation

## Detection rules

One short write-up per built-in rule: the attack it looks for, what the evidence looks like
in the logs, how the rule decides, what else can trigger it and what to do first. The log
excerpts come from the generated data set (`watchpost generate-logs`), which plants an attack
for every rule.

| Rule | Logs | Type | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| [SSH brute force](rules/ssh-brute-force.md) | Linux auth | threshold | medium | T1110.001 |
| [SSH password spraying](rules/ssh-password-spraying.md) | Linux auth | threshold | medium | T1110.003 |
| [SSH brute force followed by a successful login](rules/ssh-brute-force-then-success.md) | Linux auth | sequence | high | T1110.001, T1078 |
| [Login from a new source address](rules/login-from-new-source-ip.md) | Linux auth, Windows, JSON | new value | medium | T1078 |
| [Password hash file read with sudo](rules/linux-shadow-file-access.md) | Linux auth | match | high | T1003.008 |
| [Local user account created on Linux](rules/linux-user-created.md) | Linux auth | match | low | T1136.001 |
| [User added to a Linux admin group](rules/linux-user-added-to-admin-group.md) | Linux auth | match | high | T1098 |
| [Web directory and file scanning](rules/web-directory-scanning.md) | Web access | threshold | low | T1595.003 |
| [Known attack tool user agent](rules/web-scanner-user-agent.md) | Web access | match | medium | T1595.002 |
| [SQL injection attempt in a web request](rules/web-sql-injection.md) | Web access | match | high | T1190 |
| [Path traversal attempt in a web request](rules/web-path-traversal.md) | Web access | match | high | T1190, T1083 |
| [Windows logon brute force](rules/windows-logon-brute-force.md) | Windows Security | threshold | medium | T1110 |
| [PowerShell with an encoded command](rules/windows-encoded-powershell.md) | Windows Security, Sysmon | match | high | T1059.001, T1027 |
| [Windows user account created](rules/windows-user-account-created.md) | Windows Security | match | low | T1136.001 |
| [Account added to a privileged Windows group](rules/windows-user-added-to-admin-group.md) | Windows Security | match | high | T1098 |
| [Scheduled task created](rules/windows-scheduled-task-created.md) | Windows Security | match | medium | T1053.005 |
| [Windows event log cleared](rules/windows-audit-log-cleared.md) | Windows Security | match | high | T1070.001 |
| [Office application started a shell or script host](rules/office-app-spawns-shell.md) | Sysmon, Windows Security | match | high | T1566.001, T1204.002 |
| [LSASS process memory accessed](rules/sysmon-lsass-memory-access.md) | Sysmon | match | critical | T1003.001 |
| [Registry Run key persistence](rules/sysmon-registry-run-key.md) | Sysmon | match | medium | T1547.001 |
| [Activity involving a known-bad indicator](rules/threat-intel-indicator-match.md) | All | match | high | - |

## Elsewhere

- The main [README](../README.md) covers installation, the architecture, writing rules,
  the event search language and the benchmark results.
- [samples/](../samples/README.md) holds small hand-written logs for trying out ingestion.
