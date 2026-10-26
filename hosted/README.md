# Bearer hosted page

This is the M3 deployment candidate. It is intentionally separate from the Rust verifier and is not deployed yet.

The server exposes only fixed operations:

- `GET /api/collection` returns the configured collection and public run records.
- `POST /api/verify-item` accepts an allowlisted item number and runs `mainnet-verify-item` with its fixed txid-list file.
- `POST /api/challenge` accepts the configured holder item only, creates a fresh challenge, runs the off-chain `mainnet-attest` helper, then runs `mainnet-proof` using the proof's self-contained `chain_txids` list.

Every operation has a per-IP minute rate limit, a persisted UTC daily cap, and a file kill switch. Browser requests never carry wallet paths, identities, UFVKs, or spending keys. The server must run with a service account that can read the configured files, and those files must stay outside the repository.

Run locally only after filling the environment from `.env.example`:

```sh
node hosted/server.mjs
```

Deployment remains blocked until the mainnet mint is sealed and `mainnet-verify-item` returns `VALID` for all three items plus `SUPPLY SEALED count=3`. No deployment or public page claim is made by this folder alone.
