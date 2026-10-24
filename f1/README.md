# F1 regtest threshold experiment

Python 3.11+, OpenSSL, Rust, and a funded Ironwood regtest node are required. Never use this harness with real funds.

Build `frost-client`, `frostd` and `zcash-sign` from ZcashFoundation/frost-tools commit `06c0dbdbb1bac9b99cd255e74ba2f387c295e660` with its committed lockfile. Build the local PCZT checker with:

```sh
cargo build --manifest-path verifier/Cargo.toml --release --locked --features trustee
```

Measure free disk before every build. Allow at least 2 GB for incremental artifacts plus 2 GB remaining free, and monitor disk usage during builds.

Use a protected state directory outside the repository. `dkg.py --tools BIN_DIR --state STATE_DIR` initializes three identities and runs three separate DKG processes through an encrypted loopback relay. It stays running to retain the relay. Each process loads one trustee configuration. The parent reads public metadata only. The coordinator configuration has its private FROST key package removed. Do not run a trusted dealer or a self-test that gathers shares.

Run `generate.py BIN_DIR STATE_DIR CHECKER` to generate a fund viewing key with upstream zcash-sign and re-encode its public address for regtest. This uses test-network text encoding internally, without connecting to testnet. Fund the resulting address from mined regtest coins, then mine confirmations.

The checker uses the activation heights in `verifier/src/main.rs`: pre-NU5 upgrades at 1, NU5 through NU6.3 at 2, NU7 disabled. RPC access verifies the regtest genesis. Wallet birthday is 2. Keep RPC and relay listeners on loopback.

Prepare a payout with `CHECKER fund-prepare RPC_URL STATE_DIR/fund.fvk RECIPIENT_FILE AMOUNT_ZAT STATE_DIR LABEL`. This writes a proven PCZT and a local approval record containing network, recipient, amount and fee. Preserve that approval before proposing any change.

Run `sign.py --tools BIN_DIR --state STATE_DIR --checker CHECKER --pczt PCZT_FILE --approval APPROVAL_FILE --run NEW_RUN_DIR`. Each trustee guard checks note commitments, nullifiers, randomized keys, recipient, amount and fee against the actual PCZT. It answers the upstream signing prompt only if the requested sighash matches. The coordinator uses public commitments and signature shares, never private key shares. Upstream zcash-sign inserts the aggregate signature; the checker verifies and extracts the transaction. Broadcast only to the regtest node and confirm mining and recipient receipt.

For the negative controls, prepare a fresh payout from unspent change. Run `sign.py` with `--single`: it must observe `IncorrectNumberOfCommitments`, produce no aggregate signature and produce no transaction. Then prepare another PCZT with a different recipient. Run `guard.py` for trustee 2 with that PCZT and the unchanged original approval. It must refuse before generating a signature share. A generic connection failure is inconclusive.

`sign.py` closes unfinished sessions only in this dedicated relay/group. Stop the relay after the experiment. Preserve trustee state privately and delete unused build folders after preserving needed binaries.

The experiment shares one host and OS user across processes. It does not establish protection from a compromised host or approval store. Viewing keys and PCZT note data are private local artifacts. Ongoing privacy and payout-proof claims require separate F2/F3 experiments. See [credits](../CREDITS.md).
