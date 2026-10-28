# Bearer hosted page

This is the M3 hosted page. It is intentionally separate from the Rust verifier. The live deployment is at `https://zollect.ajkadri.dev`.

The server exposes only fixed operations:

- `GET /api/collection` returns the configured collection and public run records.
- `POST /api/verify-item` accepts an allowlisted item number and runs `mainnet-verify-item` with its fixed txid-list file.
- `POST /api/challenge` accepts the configured holder item only, creates a fresh challenge, runs the off-chain `mainnet-attest` helper, then runs `mainnet-proof` using the proof's self-contained `chain_txids` list.
- `POST /api/attack` accepts only `old-proof`, `forged-signature`, and `wrong-key`. It runs fixed server-side proof fixtures through `mainnet-proof` and returns the verifier output. The fixtures contain viewing material and proofs only, never spending keys.

Every checker operation has a shared 30-request-per-IP minute rate limit, a four-run concurrency cap with a ten-second wait queue, a 5,000-request global UTC daily cap and a 300-request per-IP daily cap, plus a file kill switch. Attack fixtures use the same guards. Browser requests never carry wallet paths, identities, UFVKs, or spending keys. The server must run with a service account that can read the configured files, and those files must stay outside the repository.

Run locally only after filling the environment from `.env.example`:

```sh
node hosted/server.mjs
```

The deployed configuration points at the sealed `lagos-lights` mainnet collection and keeps all wallet paths, identities, and proof fixtures outside this repository.
