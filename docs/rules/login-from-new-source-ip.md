# Login from a new source address

| | |
| --- | --- |
| Rule | `login-from-new-source-ip` ([YAML](../../backend/rules/linux/login-from-new-source-ip.yml)) |
| Type | New value: a `source.ip` the user has not logged in from in 30 days |
| Severity | Medium |
| ATT&CK | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts (Initial Access) |
| Logs | Linux `auth.log`, Windows Security, JSON application logs |

## The attack

Stolen or guessed credentials are used from the attacker's own infrastructure. Nothing about
the login itself is wrong (right user, right password), so the useful signal is *where* it
came from: an account that always connects from one place suddenly arrives from somewhere
else.

## Log evidence

The backup account logs in every night with its key from the backup server:

```text
2026-10-11T00:06:07.105181+00:00 web-01 sshd[33107]: Accepted publickey for backup from 10.20.0.30 port 40852 ssh2: ED25519 SHA256:VNANhndYzvgWvEaF9Y4ye5SXErB+vRfDSF8//J6fUTM
```

then, after a brute force, it logs in with a password from the internet:

```text
2026-10-12T15:52:52.388470+00:00 web-01 sshd[7410]: Accepted password for backup from 203.0.113.45 port 41530 ssh2
```

The same applies to Windows logon 4624 (`event.action: logon`) with an `IpAddress`.

## Detection logic

Successful logins (`event.action` is `ssh_login`, `logon` or `login`, with
`event.outcome: success`) are grouped by `user.name`. For each one, the rule checks the
user's successful logins over the previous 30 days (`lookback: 30d`); if this `source.ip`
is not among them, it raises an alert. Two details keep it quiet:

- users with no login history at all in the window are skipped, so the first days after
  setup do not alert on every account;
- machine accounts (names ending in `$`) are excluded.

The database query is narrowed to the users involved, so the lookback is cheap even with
millions of events.

## False positives and tuning

- People travelling, working from home or switching networks.
- New VPN egress addresses after a network change.
- Shorten the lookback for very mobile users or add their VPN ranges as a `not` selection.

## Responding

1. Compare the new address with the user's usual ones and ask the user if possible.
2. Check what happened just before: a brute force from the same address makes this an
   account takeover.
3. Review the session's activity and reset the credentials if anything is unexplained.
