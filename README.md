# Zecathon feasibility experiments

New CLI experiments for carrier-note ownership on Ironwood regtest.

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
