# Rainbow — Hack The Box, Medium, Windows

> Flags redacted.

A black-box box that is really a binary-exploitation exercise wearing a web-server costume,
followed by a textbook Windows UAC bypass.

## Recon
Seven ports: FTP(21), IIS(80), SMB(135/139/445), RDP(3389) and a custom HTTP service on
8080 whose header reads `X-Powered-By: Rainbow 0.1`. TTL 127 => Windows.

Anonymous FTP is the gift: it serves `rainbow.exe` (the live 8080 server), `dev.txt`
("our webserver keeps crashing, so we added a restart script; it picks a port 8080-8090")
and `restart.ps1` (an infinite loop that relaunches `C:\rainbow\rainbow.exe`). When a box
hands you the exact binary running a service, the path is almost always to reverse it.

## Reversing rainbow.exe
- 32-bit PE. DllCharacteristics = 0x8000: **no ASLR, no DEP, no SafeSEH**. No GS cookie.
  Every mitigation that would matter is off.
- The connection handler `recv`s up to 4096 bytes, then a C++ parser splits method / path /
  headers. For a POST it reads `Content-Length`, pulls the body, and then:
  `sprintf(dst[ebp-0x2a0], "%s", body)` — an unbounded copy of attacker data into a
  656-byte stack buffer. That is the bug.

## Why SEH, not a plain return overwrite
Two facts force the technique:
1. The copy is `sprintf`/`%s`: it stops at the first null in the source and appends exactly
   one null at the destination end.
2. Every code address in the only non-ASLR module is `0x0040xxxx` — its most-significant
   byte is null.

So the only address you can place is the *last* four bytes, using sprintfs own terminator
as the null MSB. A `jmp esp` return overwrite is useless because nothing you control sits
after that address. The function is an SEH frame, which is the escape: overwrite the
exception-registration record instead.

- SE-handler <- `pop/pop/ret` gadget (here 0x004091b7), placed as the final bytes so its
  null MSB is the auto-terminator.
- next-SEH <- a short `jmp` backward, bouncing to a 5-byte near-jmp that lands on stack
  shellcode at the top of the buffer.
- The exception fires for free: the overflow smashes C++ `std::string` locals whose
  destructors run at function exit and dereference garbage.

Offsets from the buffer: next-SEH at 660, SE-handler at 664, total source 667 bytes.
Shellcode is a null/CRLF-free `windows/shell_reverse_tcp`. Full exploit in `exploit.py`.

Fire it and a shell returns as `rainbow`. **user.txt.** `EXITFUNC=thread` keeps the parent
alive; even so, treat the service as fragile — re-firing it repeatedly can leave a wedged
process that the restart script will not replace, so get one stable shell and stay in it.

## Privilege escalation — an admin behind a filtered token
`whoami /groups` is the tell: `BUILTIN\Administrators` is present but **deny-only**, and the
label is **Medium**. `rainbow` *is* a local Administrator; UAC just handed the process a
filtered token. This is not a hunt for a misconfig — it is a UAC bypass.

fodhelper.exe is auto-elevating and consults a user-writable handler:
`HKCU\Software\Classes\ms-settings\Shell\Open\command`. Set its default to your command and
`DelegateExecute` to empty, then launch fodhelper and it runs your command at High
integrity. Two gotchas that cost time here:
- The shell is 32-bit, so `System32` is redirected to `SysWOW64`. Use the 64-bit
  `reg.exe` and `fodhelper.exe` via `C:\Windows\Sysnative\...`, or the keys land in the
  wrong view and fodhelper ignores them.
- Launch fodhelper detached (`Start-Process`), not `start ""` from a console-less reverse
  shell, which blocks.

The elevated command copies `C:\Users\Administrator\Desktop\root.txt` into a folder the
`rainbow` user owns, and the Medium shell reads it back. **root.txt.**

## Lessons
- A binary served over anonymous FTP is an invitation to reverse it; do that before
  touching a fuzzer.
- Read the mitigation flags first — they choose the technique. Null-MSB code addresses plus
  a null-terminating copy is the classic SEH-overwrite fingerprint.
- On Windows, `Administrators` shown as *deny-only* at Medium integrity means "admin, go
  bypass UAC", not "hunt for a privilege".
