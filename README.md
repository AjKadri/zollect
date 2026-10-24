# Zecathon feasibility experiments

New CLI feasibility experiments for carrier-note ownership and trustee spending on Ironwood regtest.

Build the independent verifier:

```sh
cargo build --manifest-path verifier/Cargo.toml --release --locked
verifier/target/release/zecathon-carrier-verifier issuance RPC_URL public/issuer.ufvk carrier-20261024
```

It reads chain data and the published issuer viewing key, follows issuer-controlled minting inputs, checks three distinct zero-value vault notes, and checks FINAL sealing. A post-FINAL issuer mint returns FAIL. The recorded regtest chain includes that deliberate attack.

The burn receiver is derived from public hash bytes without generating a spending key. Its unspendability relies on the difficulty of finding corresponding secret key material.

Publishing the issuer viewing key reveals issuer-readable addresses, values, memos and history. This is feasibility code, not a production privacy claim. See [CREDITS.md](CREDITS.md).

O2 adds `proof RPC_URL PROOF_FILE CHALLENGE` and `link RPC_URL ISSUER_UFVK_FILE ALICE_PROOF BOB_PROOF`. Proofs contain owner viewing keys and stay on the VPS in the recorded experiment. The optional `sender` feature builds signing/transfer commands for separate single-owner processes. It is not used for F1 trustee shares.

Live regtest observations cover issuance, rejection of a fourth mint, and an Alice-to-Bob transfer with Alice SPENT, Bob HELD and same-Action linkage. Further attack and privacy experiments remain outstanding.

F1 used three separate trustee processes for 2-of-3 DKG. Trustees 1 and 2 produced a mined payout. Trustee 1 alone received `IncorrectNumberOfCommitments`, and trustee 2's approval guard refused a substituted recipient. See [F1 setup](f1/README.md). Mainnet was not used. O3/O4 and F2/F3 remain untested.
