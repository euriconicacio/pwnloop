# Configuration management and deployment infrastructure

Desired-state platforms (Puppet, Chef, Salt, Ansible Tower/AWX, SCCM) and the
pipelines around them are the highest-value targets in an internal network, and
they are routinely enumerated as if they were web servers. They are not: they are
**authenticated APIs whose whole purpose is to run code as root or SYSTEM on
every machine they manage.**

## Why they outrank a domain controller as a target

- Control of the master is code execution on **every managed node**, including
  hosts you have no other route to, as the most privileged local account.
- The material they distribute *is* credentials: a compiled catalog, a playbook
  vault, a task-sequence variable. Secrets that exist to be deployed pass
  through them in usable form.
- They are trusted by design, so their traffic and their changes look normal.

## Enumerate as an API

Find the control port (they are rarely on 80/443), then establish what
authentication it wants. Most use **mutual TLS with their own CA**, which means:

- the client certificate is on **every managed node** — any host you already own
  is a certificate store, and an agent's cert plus key plus the CA is usually
  world-readable to root or SYSTEM;
- a working mTLS handshake is not authorization. Expect the master to serve one
  node its own state and silently refuse anything else — asking for another
  node's configuration is the first thing its authors defended against. A request
  that hangs or returns an empty body is usually that refusal, not a bug in your
  request.

So: do not try to impersonate another node from outside. **Drive the agent that
is already installed on a host you own** — it is authenticated, it is scheduled,
and it will fetch and apply whatever the master has for it.

## The two directions of attack

**Master → node.** If you can write what the master serves — a manifest, a
playbook, a state file, a task sequence — you have code execution as root or
SYSTEM on whichever node it targets, at the next check-in. This is the cleanest
lateral path into a hardened host that you cannot reach directly: you never
authenticate to it at all, it comes to you. Target the block that applies to the
node you want, not the global one; a global change hits every machine in the
estate, which is loud, hard to undo, and can break the environment.

**Node → master.** The agent's own configuration names the master, the
environment and often a deploy or repository credential. A local service account
running a scheduled deployment tool is worth reading precisely because it must
authenticate to something to pull code.

## A CI server's build runner is command execution as whatever the agent runs as

A CI/build platform (TeamCity, Jenkins, Bamboo, GoCD, Drone) exists to run
arbitrary commands on its build agents. So **any account that can edit a build
configuration is OS command execution on the agent host** — no CVE required,
this is the product working as designed. The escalation lever is *who the agent
runs as*: a build agent co-located with the server and running as `root`/SYSTEM
(a common lab and small-shop layout) turns "I can log in as a project admin"
into host root. Check the agent's owner (`ps -eo user,cmd | grep -i agent`)
early; if it is `root`, getting to any admin login is the whole privesc.

Everything is drivable over the REST API, which matters when the server is bound
to `localhost` and you reach it from a foothold on the same box (TeamCity
`127.0.0.1:8111` is the recurring case). The TeamCity sequence, all
`POST /app/rest/...` with basic auth:

```
projects                          <newProjectDescription .../>
buildTypes                        <buildType .../>
buildTypes/id:<bt>/steps          <step type="simpleRunner"> script.content = <cmd>, use.custom.script=true
buildQueue                        <build><buildType id="<bt>"/></build>
```

then read the result from `downloadBuildLog.html?buildId=<n>` — the command's
stdout comes back in the build log, so this works with **no egress** from the
target. Roles live at `/app/rest/users/username:<u>/roles`; `SYSTEM_ADMIN`
(scope `g`) is full control. Getting the admin credential is usually the hard
part and rarely a CI-side bug — it comes from credential reuse or from capturing
a login the box performs itself (see the credential-capture-in-transit note in
`references/privesc-linux.md`). Clean up: delete the project you created
(`DELETE /app/rest/projects/id:<id>`), which removes the build type, steps and
build history with it.

## Self-hosted git as a deployment platform (push = RCE)

A self-hosted git server (Gitea, Forgejo, GitLab, or plain hooks) often *is* the
deployment platform: a webhook, Actions runner, or `post-receive` hook copies a
repo to a webroot or app directory on push. Treat write access to such a repo
exactly like `master → node` above — it is code execution wherever the repo is
deployed, at the next push. The tell is in plain sight: a repo readme or CI
config that says "auto-deploy"/"CI/CD", a repo named `website`/`www`/`site`, or
a deploy hook under the repo's settings. **Confirm the sink before spending a
payload**: fetch a known repo file off the target's web port (e.g.
`/changelog.txt`) — if it matches the repo, that server serves this repo, so a
committed handler in the served language (`.aspx` on IIS, `.php`/`.jsp`
elsewhere) will execute there. Push it, then poll the URL; deploys are usually
seconds. The write credential is frequently a token leaked in history (see
`references/source-review.md`) rather than a login. This same push→webroot
channel is also a general **file-delivery** primitive: drop any binary you need
onto a Windows target through it when SMB/`/drive` upload is unavailable.

**Keeping anything alive past a CI job (Jenkins ProcessTreeKiller).** A pipeline
step is a one-shot channel: when the build ends the runner reaps the whole process
tree, so a tunnel or reverse shell you background from a `Jenkinsfile`/Action dies
silently the moment the job finishes — you see it connect, then vanish. Jenkins
identifies "its" processes by an environment variable (`JENKINS_NODE_COOKIE`, and
older `BUILD_ID`); launch your persistent process with those overridden and
detached from the job's session and file descriptors:

```groovy
sh 'JENKINS_NODE_COOKIE=dontKillMe setsid sh -c "./agent >/dev/null 2>&1 </dev/null &"'
```

Then re-establish it on demand: because the job re-runs on every push (poll or
webhook), a self-contained step that re-launches the tunnel is a durable channel
even if the process is killed. Beware one wedged build blocks later builds of the
*same* branch job — push a *new branch* to get a second, independent job onto a
free executor rather than waiting.

## When the platform is broken, fixing it is part of the exploit

A master that hangs, times out or returns empty on every request may be
*defective*, not defended — a serialisation bug, a corrupt cache, a bad plugin.
If you have code execution on the master host, repairing the fault so the service
resumes is a legitimate and often necessary step: the intended path may depend on
machinery that does not currently run. Read the service's own logs and source
before concluding that a silent response means you are unauthorised.

Record such a repair as an artifact you introduced, and undo it at cleanup like
any other change.

## Cleanup obligations are heavier here

Anything you deploy through a management platform is **re-applied on a schedule**
and propagates on its own. An account you create through a manifest comes back
after you delete it, and the platform may roll your change back without telling
you. Remove the source of the change first, then the effect, then confirm across
a full check-in interval that neither returned.
