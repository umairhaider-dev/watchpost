# Password hash file read with sudo

| | |
| --- | --- |
| Rule | `linux-shadow-file-access` ([YAML](../../backend/rules/linux/shadow-file-access-via-sudo.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1003.008](https://attack.mitre.org/techniques/T1003/008/) OS Credential Dumping: /etc/passwd and /etc/shadow (Credential Access) |
| Logs | Linux `auth.log` / `secure` (`linux_auth`) |

## The attack

`/etc/shadow` and `/etc/gshadow` hold the password hashes of every local account. Once an
attacker has root (or a sudo-capable account), copying them lets them crack the passwords
offline and try them on other machines where the same people reuse passwords.

## Log evidence

sudo logs every command it runs:

```text
2026-10-12T15:56:40.849062+00:00 web-01 sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

The parser maps this to `event.action: sudo_command`, `user.name: backup` (who ran it) and
`process.command_line: /usr/bin/cat /etc/shadow`.

## Detection logic

Any `sudo_command` whose `process.command_line` contains `/etc/shadow` or `/etc/gshadow`.
Matching on the command line catches `cat`, `cp`, `less`, `tar` and editors alike. The alert
is grouped by `host.name` and `user.name`, so repeated reads by the same person on the same
host collect into one alert.

Reading the file directly as root (without sudo) is not logged by sudo and needs auditd or a
file-integrity tool to see.

## False positives and tuning

- Administrators auditing accounts or repairing a broken shadow file.
- Compliance scripts that check password ageing (better done with `chage`, which this rule
  does not match). Exclude a known script by its full command line.

## Responding

1. Find out how the account got sudo rights and whether its login was legitimate.
2. Assume the hashes are in the attacker's hands: force password changes for every local
   account on the host, starting with those that are reused elsewhere.
3. Check the same session for new accounts and group changes.
