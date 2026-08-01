# Recon

Goal: a complete port/service picture within a few minutes, without blocking on
the slow scans. Everything runs inside the container via `htb x '...'`.

## Setup

```bash
T=10.10.11.x; NAME=machinename
htb x "mkdir -p /engagements/$NAME/{scans,loot,www}"
htb x "ip -4 addr show tun0 | grep inet"     # your attacker IP — use this in payloads
```

## Layered scanning

Run these three at once. The first gives you something to work with in seconds;
the others keep running in the background.

```bash
# 1. fast top ports, no ping (HTB hosts often drop ICMP)
htb x "nmap -Pn -T4 --top-ports 1000 -oN /engagements/$NAME/scans/nmap-top.txt $T"

# 2. full TCP range, background
htb x "nmap -Pn -T4 -p- --min-rate 3000 -oN /engagements/$NAME/scans/nmap-all.txt $T" &

# 3. UDP top 100, background — slow, but SNMP/TFTP/NFS live here
htb x "nmap -Pn -sU -T4 --top-ports 100 -oN /engagements/$NAME/scans/nmap-udp.txt $T" &
```

Then deep-scan only the ports that are actually open:

```bash
PORTS=$(htb x "grep -oP '^\d+(?=/tcp\s+open)' /engagements/$NAME/scans/nmap-all.txt | paste -sd,")
htb x "nmap -Pn -sCV -p $PORTS -oN /engagements/$NAME/scans/nmap-deep.txt $T"
```

`-sCV` (default scripts + version) is where the useful detail comes from:
versions, TLS subject names, SMB signing, HTTP titles, anonymous FTP.

## Hostnames and vhosts — do this immediately

Lab web apps are frequently virtual-host gated: hitting the raw IP gives a
default page or a redirect, while `Host: machine.htb` gives the real app.

Sources of the real hostname, in order of reliability:
- nmap `-sCV` output: `http-title`, redirect `Location:` headers
- TLS certificate CN/SAN (`ssl-cert` script output)
- SMB/LDAP domain name (`nmap --script smb-os-discovery`)
- the HTB machine name itself, as `<name>.htb`

Add every candidate to the container's hosts file:

```bash
htb x "echo '$T machine.htb www.machine.htb' >> /etc/hosts"
```

Append only — `sed -i /etc/hosts` fails inside a container with
`Device or resource busy`, because `/etc/hosts` is bind-mounted and `sed -i`
works by renaming a temporary file over the original. To replace a line, read
the file, filter it, and append the corrected set rather than editing in place.

When the raw IP 302s to a hostname, that is vhost gating and it is worth
fuzzing for more vhosts *immediately* — the hostname you were given is rarely
the only one. Take the response size of a deliberately wrong `Host` header as
the `-fs` filter:

```bash
htb x "curl -s -o /dev/null -w '%{size_download}\n' -H 'Host: nope.machine.htb' http://$T/"
htb x "ffuf -u http://$T/ -H 'Host: FUZZ.machine.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <size> -s"
```

Then fuzz for more subdomains once you know the base domain — see
`references/web.md`.

## Reading the output

For each open port, record in FINDINGS.md: port, protocol, service, exact
version string. The version string is the input to `searchsploit`:

```bash
htb x "searchsploit apache 2.4.49"
htb x "searchsploit -m <path>"       # copy a PoC into the working directory
```

Version-based exploits are only worth chasing when the version is precise and
the exploit is remote-unauthenticated. A vague banner is a `LEAD`, not a plan.

## Quick triage table

| Open | First move |
|------|-----------|
| 21 FTP | anonymous login, then `ls -la`, look for uploads dir writable + web root |
| 22 SSH | note version; never brute force root; wait for credentials from elsewhere |
| 53 DNS | zone transfer `dig axfr @$T domain.htb` |
| 80/443/8080 | full web track — see `references/web.md` |
| 111/2049 | `showmount -e $T`, mount NFS exports |
| 135/139/445 | SMB track — shares, null session, RID cycling |
| 161 UDP | `onesixtyone`, then `snmpwalk` with community `public` |
| 389/636 | LDAP anonymous bind, dump naming contexts |
| 1433/3306/5432 | default creds, then service-specific file read/write |
| 3389 | note it; useful after you have credentials |
| 5985/5986 | WinRM — instant shell once you have Windows creds |
| 6379 | Redis unauthenticated — see `references/services.md` |
