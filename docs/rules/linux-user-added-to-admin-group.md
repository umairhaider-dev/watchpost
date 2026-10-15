# User added to a Linux admin group

| | |
| --- | --- |
| Rule | `linux-user-added-to-admin-group` ([YAML](../../backend/rules/linux/user-added-to-admin-group.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation (Persistence, Privilege Escalation) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

Members of `sudo`, `wheel`, `admin` or `root` can run anything as root. Adding a freshly
created or compromised account to one of these groups turns it into a permanent
administrator that keeps working after the original way in is closed.

## Log evidence

```text
2026-10-12T15:57:18.812053+00:00 web-01 sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc-update
2026-10-12T15:57:19.224053+00:00 web-01 usermod[7077]: add 'svc-update' to group 'sudo'
```

The `usermod` (or `gpasswd`) line becomes `event.action: user_added_to_group`, with the member
in `user.name` and the group in `details.group`.

## Detection logic

`user_added_to_group` events whose `details.group` is one of `sudo`, `wheel`, `admin` or
`root`, grouped by host and member. Additions to other groups (`docker`, `www-data`) are
ignored here, although membership of `docker` is effectively root too and may be worth a rule
of your own.

## False positives and tuning

- A new administrator being onboarded through the normal change process.
- If your distribution uses another admin group name, add it to the list in the YAML.

## Responding

1. Confirm the change with whoever owns the host.
2. If it is not expected, remove the membership, lock the account, and trace the session that
   made the change back to its login.
