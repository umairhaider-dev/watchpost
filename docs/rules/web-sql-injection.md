# SQL injection attempt in a web request

| | |
| --- | --- |
| Rule | `web-sql-injection` ([YAML](../../backend/rules/web/sql-injection.yml)) |
| Type | Match |
| Severity | High |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application (Initial Access) |
| Logs | Web server access log, combined format (`web_access`) |

## The attack

If an application builds SQL from request parameters without binding them, an attacker can
change the query: read other tables with `UNION SELECT`, bypass logins with `' OR '1'='1`,
or infer data one bit at a time by making the database sleep. Tools such as sqlmap automate
all of it and send dozens of payloads per parameter.

## Log evidence

```text
198.51.100.23 - - [12/Oct/2026:01:32:12 +0000] "GET /products?id=1%27%20AND%20SLEEP(5)--%20- HTTP/1.1" 500 5361 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
198.51.100.23 - - [12/Oct/2026:01:32:55 +0000] "GET /products?id=-1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables-- HTTP/1.1" 200 6112 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```

The parser stores the URL as logged in `url.original` and a URL-decoded copy in
`details.url_decoded`. Rule comparisons ignore case, as in Sigma, so `%27%20UNION%20SELECT`
is matched by `union select`.

## Detection logic

`details.url_decoded` is searched for fifteen payload fragments: `union select`,
`union all select`, tautologies (`' or '1'='1`, `' or 1=1`, `or 1=1--`, `' and '1'='1`),
schema discovery (`information_schema`, `@@version`, `concat(0x`, `extractvalue(`), time
delays (`sleep(`, `benchmark(`, `waitfor delay`, `pg_sleep(`) and `xp_cmdshell`. Matching the
decoded URL defeats simple percent-encoding. One alert collects all requests from the same
`source.ip`.

## False positives and tuning

- Search pages where users type SQL-like text (a forum about databases).
- Your own authorised application tests.
- Only the URL is visible in access logs: payloads in POST bodies need a WAF or application
  logging to detect.

## Responding

1. Look at the response codes: a **500** to a payload means the input probably reached the
   database unescaped; a **200** with an unusual size after `UNION SELECT` may mean data was
   returned. Either needs a developer to look at that parameter now.
2. Block the source and review the application's database logs for the same period.
