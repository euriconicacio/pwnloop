# VulnEscape — Write-up

> Flags redacted.

## The box
Windows 10 standalone, only RDP open, `KioskUser0` with no password and NLA disabled → an Edge
**Assigned-Access kiosk** ("Busan Expo / Conference Display", Korean locale).

## Escape (the part I got wrong first)
I spent a long time fighting the *kiosk* Edge's restricted file dialog (`Ctrl+O`): drive browsing
was blocked (`NoViewOnDrive`), `edge://` pages returned `ERR_KIOSK_BLOCKED_ASSIGNED_ACCESS`, the
right-click "New" menu was suppressed, and Edge downloaded any `file://` it opened to the file's
read-only *source* directory — so `cmd.exe` could not be extracted and there was no launch
primitive. DevTools, Task Manager, `Ctrl+N` and F11 were all blocked.

The miss: I never pressed the plain **Windows key**. It opens the Start menu, from which a
*separate, full* Microsoft Edge launches — with a normal address bar and normal downloads. That
single step dissolves every wall above.

## User → shell → root
- Full Edge → `file:///C:/Users/kioskUser0/Desktop/user.txt` → **user flag**.
- The allow-list trusts `msedge.exe` **by name**. Edge → `file:///C:/Windows/System32/cmd.exe`
  downloads cmd; enable "ask where to save", re-download, **Save As `msedge.exe`**, run it → `cmd`
  as KioskUser0 (Explorer rename is policy-blocked, but renaming during the Save-As is not).
- `C:\_admin\profiles.xml` → Remote Desktop Plus profile for `admin`, reversibly-encrypted password
  recoverable in plaintext (BulletsPassView x64) → `admin:Twisting3021`.
- `runas /user:admin powershell` → admin at Medium integrity (UAC). `Start-Process powershell
  -Verb RunAs` → one-click UAC consent → High integrity → **root flag**.

## Lessons
- A single-RDP-port Windows host that "only shows a kiosk" is a kiosk-escape box, not a broken AD
  host. Enumerate the kiosk's escape surface top-down: **Start menu / Win key first**, then a full
  browser's address bar, then the file-dialog tricks — not the other way round.
- App allow-lists that match by *name* fall to a rename; the clean delivery is a browser Save-As
  (not an Explorer rename, which is often policy-blocked).
- A local admin under default UAC is one `-Verb RunAs` click from High integrity.
