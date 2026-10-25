# Zecathon feasibility experiments

New CLI feasibility experiments for carrier-note ownership and trustee spending on Ironwood regtest.

Build the independent verifier:

```sh
cargo build --manifest-path verifier/Cargo.toml --release --locked
verifier/target/release/zecathon-carrier-verifier issuance RPC_URL public/issuer.ufvk COLLECTION [SECONDARY_RPC_URL]
```

The independent checker accepts any collection id, item number and hop count. It follows issuer-controlled minting inputs, requires zero-value item notes in distinct vault addresses, and checks FINAL sealing without a fixed item count. A post-FINAL issuer mint returns FAIL.

The burn receiver is derived from public hash bytes without generating a spending key. Its unspendability relies on the difficulty of finding corresponding secret key material.

Publishing the issuer viewing key reveals issuer-readable addresses, values, memos and history. This is feasibility code, not a production privacy claim. See [CREDITS.md](CREDITS.md).

O2 adds `proof RPC_URL PROOF_FILE CHALLENGE [SECONDARY_RPC_URL]` and `link RPC_URL ISSUER_UFVK_FILE ALICE_PROOF BOB_PROOF [SECONDARY_RPC_URL]`. Proofs keep the challenge signature and may include the vault viewing key. The checker requires exactly one item and no other note at that vault address. Fees come from a separate funding-wallet input in the same transaction. Supplying a second RPC endpoint makes the checker refuse disagreement in height, tip hash or scanned transaction data.

The optional `sender` feature builds signing, transfer and two-party atomic-sale commands for separate single-owner processes. `sale-prepare` applies the buyer funding signature and strips buyer private fields. `sale-sign` verifies the payment and standard ZIP-317 fee before adding the seller carrier signature. The sender-only `attack-double-spend` fixture deliberately constructs a competing spend of an already-spent carrier for O3; normal `transfer` still refuses it locally.

Regtest evidence covers issuance, rejection of a fourth mint, Alice-to-Bob transfer, atomic sale, real double-spend rejection, correct-hop forged-successor binding rejection and lagging-server refusal. The O3 item-2-history row is marked a test-definition error because the supplied chain leaves item 2 HELD, while O4 independently proves a SPENT old proof. See [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) for judge-safe outputs and [MAINNET_CONFIRMATION_PLAN.md](MAINNET_CONFIRMATION_PLAN.md) for the approval-gated public-server plan.

F1 used three separate trustee processes for 2-of-3 DKG. Trustees 1 and 2 produced a mined payout. Trustee 1 alone received `IncorrectNumberOfCommitments`, and trustee 2's approval guard refused a substituted recipient. See [F1 setup](f1/README.md). Mainnet was not used.
