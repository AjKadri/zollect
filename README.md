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

The `mainnet` feature adds read-only `mainnet-snapshot PRIMARY_HTTPS SECONDARY_HTTPS`, `mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK_FILE COLLECTION ITEM TXID_LIST_FILE`, and `mainnet-proof PRIMARY_HTTPS SECONDARY_HTTPS PROOF_FILE CHALLENGE [TXID_LIST_FILE]` commands. The two verification commands read one txid per line from an allowlisted item-chain file, or use the proof's self-contained `chain_txids` list, fetch only those transactions from both public light-wallet servers, compare the complete responses, and run the checker over the fetched rows. They print a `VERIFY_TIMING` line in milliseconds. They never create, sign or broadcast a transaction. The sender feature also provides `mainnet-sale-prepare`, which creates a buyer-signed PCZT without a broadcast, and `mainnet-sale-sign`, which verifies the PCZT, adds the seller signature, applies the final fee and cumulative guards, and only then broadcasts. The existing approval-gated `mainnet-transfer` and `mainnet-sale` commands remain available. All mainnet send paths require a separate funding-wallet input, exact vault purity, same-Action carrier binding, two-server agreement, final-fee logging and the 200,000-zatoshi running-total guard. The older birthday-based scanner remains available for regtest and sender workflows, but is not used by these fast mainnet verification commands.

Regtest evidence covers issuance, rejection of a fourth mint, Alice-to-Bob transfer, atomic sale, real double-spend rejection, correct-hop forged-successor binding rejection and lagging-server refusal. The O3 item-2-history row is marked a test-definition error because the supplied chain leaves item 2 HELD, while O4 independently proves a SPENT old proof. See [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) for judge-safe outputs and [MAINNET_CONFIRMATION_PLAN.md](MAINNET_CONFIRMATION_PLAN.md) for the approval-gated public-server plan.

The M3 deployment candidate is in [hosted/](hosted/). It is not deployed. Its gate is a mined FINAL seal and a real `VALID` plus `SUPPLY SEALED count=3` result from the fast mainnet checker.

F1 used three separate trustee processes for 2-of-3 DKG. Trustees 1 and 2 produced a mined payout. Trustee 1 alone received `IncorrectNumberOfCommitments`, and trustee 2's approval guard refused a substituted recipient. See [F1 setup](f1/README.md). Mainnet was not used.
