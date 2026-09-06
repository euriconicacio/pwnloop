# Guardian — Hack The Box, Hard, Linux

## Recon
Two ports: OpenSSH 8.9p1 and Apache 2.4.52. Port 80 redirects to `guardian.htb`,
and the static site names two more vhosts: `portal.guardian.htb` (a Student
Portal) and, later, `gitea.guardian.htb`. All three go into `/etc/hosts`.

## Foothold path (web)
The portal ships a "Portal Guide" PDF that leaks the default student password
`GU1234`, and the public marketing page lists real student IDs in its
testimonials. One account still had the default password, giving a student
session.

Inside, the chat feature is the door. Conversations are addressed by
attacker-controlled numeric user IDs (`chat_users[0]` / `chat_users[1]`) with no
check that you belong to the thread — a classic IDOR. Walking the low IDs dumps
staff conversations, and the admin↔jamil thread hands over a Gitea password.

## Foothold (Gitea RCE)
`gitea.guardian.htb` runs Gitea 1.23.7, vulnerable to **CVE-2026-60004** — a
diffpatch endpoint that lets a user with write access to a repo inject a git hook
which runs on the server. The leaked password logs `jamil` into Gitea; creating a
throwaway repo gives the required write access; the hook fires as the `gitea`
service account. Note the gitea login name is `jamil`, not the `jamil.enockson`
seen in the portal — the mismatch cost a first attempt.

## From service account to a real user
The `gitea` account can read the portal's MySQL database and source. The users
table stores `sha256($password . $salt)`, and the salt (`8Sb)tM1vs1SS`) is sitting
in the portal config. With the salt known, the hashes are trivially crackable
offline — rockyou returns `jamil = copperhouse56`. That password is **reused** for
the `jamil` system account, so `ssh jamil@…` lands a real shell and `user.txt`.

## jamil → mark
jamil belongs to group `admins` and can `sudo -u mark` a Python toolkit,
`/opt/scripts/utilities/utilities.py`. The privileged actions gate on
`getpass.getuser() == "mark"`, but `system-status` does not — and the script does
`from utils import status`. Crucially `utils/status.py` is writable by the
`admins` group. Overwrite `status.py`, run the tool as mark via the sudo rule, and
your code runs as mark. (I used it to drop an SSH key, then restored the file.)

## mark → root
mark can `sudo /usr/local/bin/safeapache2ctl` — a small C wrapper that runs
`apache2ctl -f /home/mark/confs/<file>.conf` as root. It refuses configs whose
lines *start with* `Include`, `IncludeOptional`, or `LoadModule`. Two things beat
it:

1. **Prefix-only check.** The blacklist compares from the first character. Apache
   ignores leading whitespace, so ` LoadModule …` (one leading space) is parsed by
   Apache but slips past the filter.
2. **Piped logs run as root.** During log initialization Apache spawns the program
   in a piped `ErrorLog "|/path/script"` — and it runs as root. To reach that stage
   the config must load an MPM (the whitespace trick) and open a `Listen` socket on
   a free port; without both, Apache aborts before opening logs.

The piped script copies `bash` to a SUID-root binary. `bash -p` then reads
`root.txt`.

## Lessons / dead ends
- The document-upload flow (phpword/phpspreadsheet) looked like an XXE foothold but
  was a dead end: patched versions, no `LIBXML_NOENT`.
- Cracking failed until the *salt from config* was included — the same hashes are
  uncrackable if you treat them as plain sha256.
- The apache wrapper's piped-log payload does nothing until you realize Apache
  needs a valid MPM **and** a Listen to reach `open_logs`; adding `Listen` was the
  difference between "Terminated, nothing happened" and root.
