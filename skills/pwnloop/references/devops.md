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
