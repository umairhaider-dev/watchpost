# SSH brute force followed by a successful login

| | |
| --- | --- |
| Rule | `ssh-brute-force-then-success` ([YAML](../../backend/rules/linux/ssh-brute-force-then-success.yml)) |
| Type | Sequence: 5 failures, then a success, within 15 minutes from one address |
| Severity | High |
| ATT&CK | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts (Credential Access, Initial Access) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

This is the moment a brute force stops being background noise: after a run of wrong
passwords, the same address gets one right and opens a session. From here on the attacker
has a shell with that account's rights.

## Log evidence

```text
2026-10-12T15:52:31.904117+00:00 web-01 sshd[5527]: Failed password for backup from 203.0.113.45 port 52817 ssh2
2026-10-12T15:52:39.003561+00:00 web-01 sshd[5527]: Failed password for backup from 203.0.113.45 port 47705 ssh2
2026-10-12T15:52:52.388470+00:00 web-01 sshd[7410]: Accepted password for backup from 203.0.113.45 port 41530 ssh2
2026-10-12T15:52:52.392470+00:00 web-01 sshd[7410]: pam_unix(sshd:session): session opened for user backup(uid=1002) by (uid=0)
```

Failures are `event.action: ssh_login` with `event.outcome: failure`; the accepted login is the
same action with `event.outcome: success`.

## Detection logic

A sequence rule, grouped by `source.ip`:

1. `failures`: at least five failed SSH logins;
2. `success`: then a successful SSH login,

with the whole sequence inside `maxspan: 15m`. The steps must happen in this order, so a
success *followed* by typos does not match. The failures can be against any account; in the
generated data the attacker tries invalid names and `root` before guessing `backup`'s password.

## False positives and tuning

- A legitimate user who mistyped several times and then got it right from their usual
  address. The [new source address](login-from-new-source-ip.md) rule helps separate the two:
  a real user logs in from a familiar place.
- Raise the failure count if your users share a NAT address that produces many typos.

## Responding

Treat the account as compromised until proven otherwise:

1. Look at what the session did next: `user.name:<account> AND host:<host>` around the login.
2. Kill the session, lock the account and rotate its password and keys.
3. Check for persistence: new users, sudo group changes, cron jobs and authorized keys.
