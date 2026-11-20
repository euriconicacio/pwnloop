# Blockchain / smart-contract apps (EVM dev nodes)

A recurring modern-lab shape: a web app backed by a local EVM node (anvil / hardhat /
geth-dev) on **8545**, with Solidity contracts (`Chat.sol`, `Database.sol`, a token, a
"bank") holding the app's state. The vulnerabilities are almost never in the crypto; they
are in treating a **public ledger as private storage** and in how the app brokers access to
the node. Reason about it as: *what is readable on-chain, and what hands me the RPC?*

## First principles that keep biting the defender

- **On-chain storage is world-readable.** `private` state variables and `internal`
  mappings are only a *source-language* visibility hint. Anyone who can reach the node reads
  raw slots with `eth_getStorageAt`. Secrets (passwords, keys, "hidden" flags) stored in a
  contract are disclosed by design.
- **`onlyOwner` / access modifiers guard *transactions*, not *reads*.** A getter marked
  `onlyOwner` still returns its data to an `eth_call` whose `from` you set to the owner —
  `eth_call` is a *simulated* call with no signature, so you impersonate any address for
  free. Spoof `from = owner` and every owner-gated view function answers. (If you cannot
  guess the owner, `eth_accounts` on a dev node usually lists it; or read the slot directly.)
- **Events leak history.** `eth_getLogs` over the contract replays every emitted event —
  registrations, role changes, transfers — in cleartext, including non-indexed string args.
  Deploy-time events often name the seeded admin/secondary accounts.
- **Deterministic dev keys.** anvil/hardhat mnemonics are public; a node started with a
  fixed `-m "<mnemonic>"` has well-known private keys. Finding the mnemonic in a setup
  script = signing authority.

## Getting to the RPC when a proxy is in front of 8545

Labs commonly wrap the node in a small proxy that method-allow-lists (e.g. only
`eth_blockNumber` passes; everything else → "couldn't verify token"). The token is the
point: it is usually *handed to a privileged UI*, not secret.

1. Enumerate the allow-list — sweep methods, note which pass tokenless. A read-only health
   method (blockNumber) passing while `eth_call`/`eth_getStorageAt`/`eth_getLogs` are blocked
   is the signature of a token-gated proxy.
2. Find who mints the token. Reach the app's **admin/privileged** surface (see the auth
   chains in `web.md`/`api.md`), then look for an endpoint that returns the token — in this
   class it was `GET /api/json-rpc -> {"Authorization": "<token>"}`, replayed as a `token`
   header on `POST /api/json-rpc`. The app proxies RPC on the web port; you rarely need
   :8545 directly once you have the header.
3. With RPC, read the secret: `eth_call <getter> from=<owner>`, or `eth_getStorageAt`, or
   `eth_getLogs`. Decode return data as ABI (offsets→length→bytes for dynamic types).

## Tooling

- `cast` (Foundry) if on the box: `cast call <addr> "getAccount(string)" admin --from <owner>
  -r <rpc>` — but it cannot add a custom auth header, so for a token-gated proxy hand-roll
  the JSON-RPC `POST` (curl / a short Python with `urllib`).
- Selectors/ABI with no web3 lib: `keccak256("sig(types)")[:4]` (pycryptodome
  `Crypto.Hash.keccak`), then append ABI-encoded args. Keep a small `readchain.py` that
  takes method+from+data and posts through the proxy.

## After the read

The recovered on-chain password is frequently **reused for a system account** — map the
app username to a Unix user via the account events (the deploy-seeded "secondary admin" is a
common SSH user), then `references/privesc-linux.md`. The chain is almost always
*web-auth → proxy token → on-chain read → credential reuse*, not an exploit of the chain
itself.
