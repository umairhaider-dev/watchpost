# SSH brute force

| | |
| --- | --- |
| Rule | `ssh-brute-force` ([YAML](../../backend/rules/linux/ssh-brute-force.yml)) |
| Type | Threshold: 10 failures in 5 minutes from one address |
| Severity | Medium |
| ATT&CK | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing (Credential Access) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

Any SSH server reachable from the internet is hit by tools that cycle through common
usernames and passwords, often thousands of attempts a day. Most of it is untargeted noise,
but a weak password on any account turns it into a shell for the attacker.

## Log evidence

sshd writes one line per rejected password:

```text
2026-10-12T15:51:54.428936+00:00 web-01 sshd[4230]: Failed password for root from 203.0.113.45 port 40491 ssh2
2026-10-12T15:51:56.851023+00:00 web-01 sshd[4230]: Failed password for root from 203.0.113.45 port 40491 ssh2
2026-10-12T15:52:00.115772+00:00 web-01 sshd[4230]: error: maximum authentication attempts exceeded for root from 203.0.113.45 port 40491 ssh2 [preauth]
```

The parser turns each failure into `event.action: ssh_login`, `event.outcome: failure`, with
`source.ip` and `user.name` (also for `Failed password for invalid user ...`).

## Detection logic

Failed SSH logins are counted per `source.ip`. When one address reaches ten failures inside
any five-minute window, an alert opens for that address; further failures from it update the
same open alert instead of creating new ones. The evidence is the failed login events.

## False positives and tuning

- A person or script retrying with an expired password from a fixed address.
- Your own vulnerability scans. Exclude the scanner's address with a `not` selection rather
  than raising the threshold for everyone.
- Raise `count` on servers that only face the internet through a bastion that already
  rate-limits; lower `timeframe` to catch slower, deliberate guessing.

## Responding

1. Check whether the same address ever logged in: the
   [brute force followed by a login](ssh-brute-force-then-success.md) rule covers this.
2. Look the address up on the **Threat intel** page and block it at the firewall if it is not
   one of yours.
3. Make sure password logins are disabled on internet-facing hosts (`PasswordAuthentication no`).
