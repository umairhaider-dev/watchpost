# SSH password spraying

| | |
| --- | --- |
| Rule | `ssh-password-spraying` ([YAML](../../backend/rules/linux/ssh-password-spraying.yml)) |
| Type | Threshold: 5 distinct accounts in 10 minutes from one address |
| Severity | Medium |
| ATT&CK | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying (Credential Access) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

Instead of many passwords against one account, the attacker tries one or two common
passwords against many accounts. Each account sees only a failure or two, so lockout
policies never trigger, but somewhere in a long list of names there is usually someone
using `Summer2026!`. Guessing which account names exist is part of the same technique.

## Log evidence

```text
2026-10-12T15:51:31.325599+00:00 web-01 sshd[3282]: Invalid user admin from 203.0.113.45 port 58615
2026-10-12T15:51:33.002924+00:00 web-01 sshd[3282]: Failed password for invalid user admin from 203.0.113.45 port 58615 ssh2
2026-10-12T15:51:34.129957+00:00 web-01 sshd[8062]: Invalid user ubuntu from 203.0.113.45 port 51647
2026-10-12T15:51:36.412880+00:00 web-01 sshd[8062]: Failed password for invalid user ubuntu from 203.0.113.45 port 51647 ssh2
```

`Invalid user` lines become `event.action: ssh_invalid_user` and failed passwords
`event.action: ssh_login`, both with `event.outcome: failure` and the attempted name in
`user.name`.

## Detection logic

Failures of either kind are grouped by `source.ip`, and the rule counts **distinct**
`user.name` values (`distinct: user.name`) rather than events. Five different accounts from
one address within ten minutes raises the alert. Hammering a single account does not trigger
this rule; that is what [SSH brute force](ssh-brute-force.md) is for.

## False positives and tuning

- A jump host or NAT gateway where many people share one address and mistype passwords.
- Configuration management that connects with several service accounts and one broken key.
- On busy shared addresses, raise the distinct count or exclude the gateway.

## Responding

1. List the accounts that were tried: real ones that exist on the host matter most.
2. Search for successful logins from the same address afterwards (`source.ip:<address> AND
   outcome:success`).
3. Block the address and review password policy for the accounts that exist.
