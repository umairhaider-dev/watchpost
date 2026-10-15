# Local user account created on Linux

| | |
| --- | --- |
| Rule | `linux-user-created` ([YAML](../../backend/rules/linux/user-created.yml)) |
| Type | Match |
| Severity | Low |
| ATT&CK | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account (Persistence) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

After getting root, attackers often add an account of their own. It survives a password
reset of the account they broke in with, and a name like `svc-update` or `backup2` blends in
with the service accounts already on the box.

## Log evidence

```text
2026-10-12T15:57:02.436109+00:00 web-01 sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc-update
2026-10-12T15:57:02.848109+00:00 web-01 useradd[6915]: new group: name=svc-update, GID=1003
2026-10-12T15:57:02.849109+00:00 web-01 useradd[6915]: new user: name=svc-update, UID=1003, GID=1003, home=/home/svc-update, shell=/bin/bash, from=/dev/pts/1
```

The `new user:` line becomes `event.action: user_created` with the new account in
`user.name`; UID, home and shell are kept in the event details.

## Detection logic

Every `user_created` event, grouped by `host.name` and `user.name`. It is deliberately simple
and low severity: servers rarely gain accounts, so each one is worth a glance, and together
with [User added to a Linux admin group](linux-user-added-to-admin-group.md) it shows the
classic "create my own admin" pattern.

## False positives and tuning

- Planned onboarding, or configuration management creating accounts.
- Packages that create a system user on installation (`postgres`, `nginx`, `_apt`). These
  usually have a UID below 1000 and a `nologin` shell; exclude them with a selection on
  `details.shell` if they are noisy.

## Responding

1. Match the account against change records.
2. If it is unexplained, check the sudo commands around it to see who created it and what
   else they did, then lock the account and remove its keys and cron jobs.
