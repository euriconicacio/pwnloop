# RetroTwo — Hack The Box, Easy, Windows / Active Directory

*Flags redacted. Machine confirmed retired before publication.*

A Server 2008 R2 domain controller. The path: a guest share hands you a
password-protected Access database, its macro hands you a service account, a
chain of AD ACLs hands you an RDP session on the DC, and an unpatched spooler
hands you SYSTEM.

## Recon

A textbook DC surface: 53/88/135/139/389/445/464/593/636/3268/3269/3389 plus
5722 (DFSR) and 9389 (ADWS). rootDSE gives `BLN01.retro2.vl`, domain `retro2.vl`.
SMB reports **guest access enabled** and a non-default **`Public`** share readable
by guest.

## Foothold: an Access database with a hardcoded credential

`Public\DB\staff.accdb`. RID-cycling as guest (`nxc --rid-brute`) also enumerates
the domain, including service accounts `ldapreader` and `inventory`.

The `.accdb` is a native ACE database with a database password — Office agile
encryption. `office2john` extracts the hash, John cracks it: **`class08`**.

Reading it is the fiddly part: it is not an OLE/OOXML container, so `msoffcrypto`
and `olevba` refuse it, and `mdbtools` can't handle encrypted ACE. The tool that
works is **jackcess** (+ `jackcess-encrypt`): open with a `CryptCodecProvider`,
and the VBA project lives as OLE streams in the hidden `MSysAccessStorage`
table. Pull the module stream, read `MODULEOFFSET` from the `dir` stream, and
decompress the source with oletools' MS-OVBA `decompress_stream`:

```
Sub ImportStaffUsersFromLDAP()
    strUser = "retro2\ldapreader"
    strPassword = "ppYaVcB5R"
    ...
```

`ldapreader : ppYaVcB5R` is valid on SMB and LDAP.

## Lateral: machine accounts → SERVICES → Remote Desktop Users

BloodHound as `ldapreader` shows the intended chain:

- **Domain Computers → GenericWrite / ForceChangePassword → ADMWS01$, FS01$, FS02$**
- **ADMWS01$ → AddMember/AddSelf → SERVICES**
- **SERVICES → member of Remote Desktop Users**
- `admin` (RID 1000) → member of Administrators (the DA-equivalent target)

`MachineAccountQuota` is 10, so `ldapreader` can add a computer — which lands in
Domain Computers and inherits the rights over the pre-created machine accounts:

```
addcomputer  ldapreader        -> PWN01$
bloodyAD set password  PWN01$  -> ADMWS01$        (ForceChangePassword)
bloodyAD add groupMember  ADMWS01$ -> SERVICES ldapreader   (AddMember)
```

Now `ldapreader` is in SERVICES → Remote Desktop Users, so it can **RDP to the
DC**. `user.txt` is at `C:\user.txt` — the drive root rather than a user desktop,
which is worth checking on any DC where the usual profile paths come up empty.

*(Headless RDP note: drive the session with `xfreerdp3` rendered to an `Xvfb`
display; run a lightweight WM like `openbox` so keyboard/mouse focus is stable,
and use `xdotool` + `scrot`. Use `/tls:seclevel:0` for the 2008 R2 legacy TLS, and
`/drive:` redirection — `\\tsclient` — as an egress-free file channel in and out.)*

## Root: local PrintNightmare

On the DC as `ldapreader` there is no local misconfig (PowerUp is clean apart
from an autologon breadcrumb for `admin`, whose password is an LSA secret you
can't read without SYSTEM), egress is **fully blocked** (reverse shells and
outbound 443/8080/445 all fail), and the Print Spooler is **running**.

Egress-blocked + spooler-up points at the **local** PrintNightmare
(CVE-2021-1675): the malicious DLL is loaded from the target's own disk, no
callback needed. The mechanics, on PowerShell v2:

1. Define `DRIVER_INFO_2` + `AddPrinterDriverEx` via `Add-Type` (PSReflect fails
   on PS2 — use a plain C# P/Invoke).
2. Copy a **valid** existing driver (`UNIDRV.DLL`) and your evil DLL into a
   writable dir — reference *copies*, not the in-use store files (referencing the
   locked store DLLs returns `ERROR_SHARING_VIOLATION`).
3. `AddPrinterDriverEx(NULL, 2, &di, APD_COPY_ALL_FILES|APD_COPY_FROM_DIRECTORY|APD_INSTALL_WARNED_DRIVER)`
   with `pConfigFile` = evil DLL. The `0x8000` warned-driver flag is what bypasses
   the signature check (omit it and you get `ERROR_ACCESS_DENIED`); the config DLL
   is loaded during the call and its `DllMain` runs as `NT AUTHORITY\SYSTEM`.

The DLL just reads `C:\Users\Administrator\Desktop\root.txt`. Delivering the DLL
via `\\tsclient` (RDP drive redirect) and copying the flag back out the same way
makes the whole thing egress-free.

## What went wrong the first time (and the lesson)

The trigger took several iterations to get right (`3014` unknown driver → `5`
access denied → `32` sharing violation → success), and I re-ran it far too many
times while tuning. **Every AddPrinterDriverEx call adds a driver, and the spooler
eventually wedged** — new calls hung indefinitely, freezing the RDP session, and
the box needed a reset. On the reset box a *single* clean trigger read the flag in
seconds. PrintNightmare is destructive to the spooler; prove the primitive once,
then fire the real payload once — don't hammer it.

## Failed / discarded leads

- AS-REP roast, Kerberoast, `ldapreader` password spray — nothing.
- Coerce + relay to (unsigned) LDAP for RBCD/DCSync — dead: the DC has no egress,
  so the coerced callback can't reach the relay.
- Reading the `admin` autologon LSA secret directly — needs SYSTEM, which is the
  thing PrintNightmare provides, so it's circular until the spooler win.
