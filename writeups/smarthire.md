# SmartHIRE — Hack The Box, Medium, Linux

*Machine status: retired. Flags shown are from my own run — strip them before publishing anywhere.*

## Recon

Two ports: SSH (OpenSSH 8.9p1, Ubuntu 22.04) and nginx 1.18.0 on 80, which
redirects the raw IP to `http://smarthire.htb/`. A 302-to-hostname is the signal
to fuzz vhosts immediately. `ffuf` with a 20k host wordlist returned one extra
name that nothing links to:

```
models  [Status: 401]  ->  models.smarthire.htb
```

`models.smarthire.htb` answers `401` with `WWW-Authenticate: Basic realm="mlflow"`
and the body points at `mlflow.org/docs/latest/auth` — i.e. **MLflow's built-in
basic auth** (shipped since MLflow 2.5), not a generic nginx gate.

## The app

`smarthire.htb` is a Flask app ("AI-first hiring platform"). Registration takes
`username`, `company`, `password`; the session is an `itsdangerous`-signed Flask
cookie carrying `{company, user_id, username}` — no role field. The dashboard
exposes:

- `/upload_hiring_data` — "trains" a model from a CSV and **registers it in
  MLflow** as `{company}-{user_id}-model`.
- `/predict` — loads that model and scores a resume CSV.
- `/model_info` — queries the MLflow registry.

So the web app is a thin front end over an MLflow registry, and the model name
is derived from a field (`company`) the attacker chooses at registration.

## Foothold: default creds → model-deserialization RCE

MLflow's built-in auth ships a default admin. It was never changed:

```
admin:password  ->  200 on /api/2.0/mlflow/experiments/search
```

Version endpoint: MLflow **2.14.1**. The registry showed my model's artifact
`source` as `mlflow-artifacts:/0/<run>/artifacts/model` — the MLflow server
proxies its own artifact store (`/api/2.0/mlflow-artifacts/artifacts/...`).

The key observation is in the app source (later confirmed): `/predict` does

```python
model_uri = f"models:/{user_model_name}/latest"
loaded_model = pyfunc.load_model(model_uri)   # <-- unpickles on the Flask host
pred = loaded_model.predict(input_df)
```

A pyfunc/sklearn model is a pickle; `load_model` deserializes it **on whatever
host calls it** — here, the Flask app. With registry write access I can register
a poisoned model version under my own model name whose pickle executes on load.

`poison_model.py` (in the engagement dir) does it over the MLflow REST API:
create a run, upload a crafted `MLmodel` (declaring the `python_function` loader
as `mlflow.sklearn` with `model.pkl`) plus a `model.pkl` whose `__reduce__`
returns `(os.system, (CMD,))`, then `POST /model-versions/create` pointing at
that artifact dir. Hitting `/predict` then returned:

```
{"message":"'int' object has no attribute 'predict'","status":"error"}
```

That error *is* the proof: the pickle ran `os.system` (returning int `0`), the
"model" became that int, and `.predict()` failed on it. A `tcpdump` on `tun0`
caught the target's ICMP and a full TCP handshake to my listener, confirming both
execution and open egress. Swapping the command for a bash reverse shell landed a
shell as `svcweb` in `/var/www/smarthire.htb`.

For a stable channel I planted an SSH key (22 is open) and logged in. `svcweb` is
in groups `devs` and `mlflowweb`. `user.txt` is group-readable.

## Privesc: a writable dir on root's import path

```
sudo -l
(root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

`mlflowctl.py` builds its plugin system like this:

```python
PLUGINS_DIR = BASE_DIR / "plugins"
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

`plugins/dev` is `drwxrwxr-x root:devs` — and `svcweb` is in `devs`.
`site.addsitedir()` does two things: it appends the directory to `sys.path`, and
it **processes `.pth` files in it — executing any line that begins with
`import`**. That is arbitrary code execution for anyone who can write a file into
`plugins/dev`, and it runs as root because the tool is invoked under `sudo`.

Dropping a one-line `.pth`:

```
import os; os.system("cp /bin/bash /tmp/.rb && chmod 6755 /tmp/.rb")
```

then running `sudo … mlflowctl.py status` produced a SUID-root `bash`.
`/tmp/.rb -p` gives `euid=0`; read `root.txt`.

(The intended shadowing route — dropping `mlflow_actions.py`/`backup_models.py`
into `dev` to override the `core` modules — also works, but the `.pth` trick is
order-independent and needs no knowledge of which module imports first.)

## Leads that didn't matter

- The `company`-controlled model name suggested a path/name-injection angle; it
  turned out unnecessary once default creds gave full registry write.
- The hardcoded `SECRET_KEY` in `config.py` would allow Flask session forgery,
  but there is no role in the session and no admin area, so it is not on the
  critical path.

## Takeaways

- An HTTP 401 whose realm and docs link name the product is a version/footprint,
  not a wall — fingerprint the *component*, then check its defaults first.
- "Load a model" from any registry you can write to is deserialization: the host
  that calls `load_model` is the host you get code execution on.
- `site.addsitedir()` on a non-root-owned directory is a root-equivalent grant
  via `.pth` execution — independent of whatever the program imports.
