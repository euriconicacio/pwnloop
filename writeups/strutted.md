# strutted — write-up

> **HTB · Medium · Linux · retired.** Flags redacted.

## Recon
Two ports: 22 (OpenSSH 8.9p1) and 80 (nginx 1.18.0). Port 80 redirects to
`strutted.htb` — add it to hosts. The homepage is "Strutted™ - Instant Image
Uploads": `.action` endpoints and a `JSESSIONID` cookie mark it as Apache
Struts 2. The nav exposes `/upload.action` (a multipart image upload) and
`/download.action` ("download our Docker image").

## Pinning the version from leaked source
`/download.action` hands over `strutted.zip`: the Dockerfile, `tomcat-users.xml`,
and the entire application source. `pom.xml` pins `struts2-core` at **6.3.0.1**.
That version falls squarely inside **CVE-2024-53677 / S2-067** (Struts
6.0.0–6.3.0.2), a flaw in the legacy `FileUploadInterceptor` file-upload logic.

Reading `Upload.java` shows exactly why it is exploitable here: the destination
is `new File(timeDir, uploadFileName)` and `uploadFileName` has a public setter.
The validation is image-only — allowed content-types `image/jpeg|png|gif` and a
magic-byte check on the first bytes — but nothing constrains the *path*.

## Foothold — CVE-2024-53677
The bug: Struts lets you override the derived `uploadFileName` by supplying the
override parameter `top.UploadFileName`, and the file field is sent capitalised
as `Upload`. Set that override to a traversal path and the file lands wherever
you point it, escaping the per-upload timestamp directory.

Delivery:
- File part: name `Upload`, a `GIF89a`-prefixed polyglot whose body is a JSP
  command webshell, content-type `image/gif` — passes both image guards.
- Override part: `top.UploadFileName=../../shell.jsp` — from
  `webapps/ROOT/uploads/<ts>/` that resolves to `webapps/ROOT/shell.jsp`.

`GET /shell.jsp?cmd=id` returns `uid=998(tomcat)`. Full RCE, unauthenticated.

## Lateral — credential reuse
`tomcat` cannot read `/home/james`. But this is the host, not a container
(full filesystem, `/home/james`, `james` = "Network Administrator", uid 1000).
The host `tomcat-users.xml` (`/etc/tomcat9/`) carries a *commented-out* account
`admin:IT14d6SSP81k`. Commented or not, it is a live secret — and it is reused
as the SSH password for james. `user.txt` falls.

Note the decoy: the Docker image shipped a *different* Tomcat password
(`skqKY6360z!Y`), which does **not** work for SSH. The real one is only in the
host config.

## Root — sudo tcpdump
`sudo -l` for james: `(ALL) NOPASSWD: /usr/sbin/tcpdump`. The tcpdump `-z`
post-rotate option runs a command as root when a capture file rotates
(GTFOBins). Point it at a script that makes a SUID `/bin/bash`, trigger a
one-second rotation on `lo`, and `bash -p` is a root shell. `root.txt` falls.

## What a defender should take away
The whole chain is one leaked source archive long: it handed over the exact
Struts version (the RCE), the build layout, and — on the host — a reused
password. Patch Struts to >= 6.4.0 and the door never opens.
