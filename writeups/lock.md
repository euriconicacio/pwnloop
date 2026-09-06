# Lock — Hack The Box, Easy, Windows

Standalone Windows Server 2022. Four ports, and a clean supply-chain-to-SYSTEM
chain: a leaked Gitea token → CI/CD RCE → a saved RDP password → a vulnerable
PDF24 install.

## Recon

```
80/tcp   IIS 10.0            "Lock - Index"
445/tcp  SMB (Win2022)
3000/tcp Gitea 1.21.3
3389/tcp RDP  (CN=Lock, name LOCK)
```

No AD ports — this is a member/standalone box. With only four ports, the path is
in one of them, and a self-hosted Gitea is the loudest lead.

## Foothold — leaked token → CI/CD RCE

Gitea's `/explore/repos` shows one public repo: `ellen.freeman/dev-scripts`,
containing `repos.py`. The current file reads the token from an environment
variable — but the **initial commit** (`dcc869b`) still has it hardcoded:

```python
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'
```

*A blanked secret is a signpost, not a fix — always read the history.*

The token authenticates to the API as `ellen.freeman` and unlocks a private repo,
`website`, whose readme says: *"CI/CD integration is now active — changes to the
repository will automatically be deployed to the webserver."* Port 80 indeed
serves the repo's files (`/changelog.txt` matches).

So: clone `website` with the token, drop an `.aspx` command handler, commit, push.
Seconds later it is live at `http://10.129.x.x/diag.aspx` and runs as
`lock\ellen.freeman`. Write access to a repo became RCE on the web server.

## Lateral — mRemoteNG password

`ellen`'s `Documents\config.xml` is an mRemoteNG connections file with a saved
RDP connection for `Gale.Dekarios` and an AES-GCM password blob. mRemoteNG's
default KDF passphrase is `mR3m` (PBKDF2-SHA1, 1000 iters, GCM). Decrypting gives
`ty8wnW9qCKDosXo6`, which is valid over SMB and RDP. `user.txt` is Gale's.

## Privesc — CVE-2023-49147 (PDF24 Creator 11.15.1)

Enumerating as Gale: `C:\Program Files\PDF24` (service runs as LocalSystem, but
the folder isn't user-writable so no binary swap), Gale is in **Remote Desktop
Users**, and RDP is open. PDF24 11.15.1 is vulnerable to CVE-2023-49147: an
**unprivileged** `msiexec /fa {ProductCode}` repair (no UAC) runs
`pdf24-PrinterInstall.exe` as SYSTEM, which writes `faxPrnInst.log` from a
**visible console window**.

The exploit needs an interactive desktop (RDP), driven here headlessly through an
Xvfb + xfreerdp + xdotool harness:

1. Run the repair once so `faxPrnInst.log` exists.
2. Hold an **exclusive (RWH) oplock** on that log. (A read-only oplock breaks
   *without* blocking the opener — it must be exclusive so the SYSTEM process
   blocks until acknowledged, which we never do.)
3. Repair again. When the SYSTEM printer-install touches the oplocked log, its
   console window (`pdf24-PrinterInstall.exe`) freezes open.
4. Right-click its title bar → **Properties** → click the **"legacy console
   mode"** hyperlink. Being a SYSTEM process, this opens the default browser as
   SYSTEM (choose **Firefox**, not Edge/IE).
5. In Firefox, **Ctrl+O** → in the file dialog, browse to `System32`, right-click
   `cmd.exe` → **Open**. A shell titled *Administrator: cmd.exe* spawns as
   `NT AUTHORITY\SYSTEM`.

`root.txt` follows.

## Leads that failed / were ruled out

- **AlwaysInstallElevated** — not set. No non-Microsoft SYSTEM scheduled tasks.
- **PDF24 folder/binary write** — Users have RX only; no service-binary hijack.
- **Read-oplock (level II)** — first attempt broke but did *not* hold the SYSTEM
  process; the console flashed and closed. Switching to an exclusive oplock was
  the fix.
- **`/drive` redirection** for tooling — needs FUSE, unavailable in the box
  container; delivered `oplock.exe` through the same git → webroot channel instead.

## Chain in one line

Leaked Gitea PAT → CI/CD ASPX deploy (RCE as ellen) → mRemoteNG password (gale)
→ PDF24 CVE-2023-49147 MSI-repair oplock → SYSTEM.
