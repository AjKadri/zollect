# Mainnet confirmation plan

Status: M2 PARTIAL. No further mainnet wallet operation is approved until the prior two-server stop is reviewed.

## Gate

Use two independently configured public mainnet light-wallet servers. Before each scan or signing step, compare their chain height, tip hash, relevant compact-block or transaction data, and wallet scan result. Refuse the operation if either server disagrees, lags, fails, or returns incomplete data. Do not log seeds, spending keys, key shares, encrypted wallet files, or private PCZT fields.

The sender build remains regtest-only. The mainnet boundary is present behind the `mainnet` feature: `MainnetConfig` uses the pinned `MAIN_NETWORK` parameters, and `MainnetLightwalletd` uses the pinned librustzcash lightwalletd gRPC client with verified HTTPS endpoints. It obtains `GetLightdInfo` and `GetLatestBlock` from both servers, refuses a chain-name, height or tip-hash mismatch, compares full transaction responses before returning them, and only sends after a consistent snapshot. Read-only `mainnet-verify-item` and `mainnet-proof` commands now use a known txid list or a proof's `chain_txids` list, fetch only those transactions from both servers, and print `VERIFY_TIMING`. The existing checker still refuses a `main` chain without a distinct secondary server.

The adapter rejects plaintext endpoints, endpoint credentials, duplicate endpoints and incomplete tip data. Mainnet feature compilation and offline endpoint-validation tests are allowed before approval. Wallet scans, transaction fetches, signing, fee estimation and broadcasts remain approval-gated.

The read-only M1 check is `carrier-verifier mainnet-snapshot PRIMARY_HTTPS SECONDARY_HTTPS`. It prints only the matching chain name, height and tip hash. It does not scan a wallet, sign, estimate fees or broadcast.

The fast verification target was measured on the two public servers. The challenge-proof checker returned `HELD` in `766 ms` on the final release binary. The known-txid item path fetched and decoded its two rows in `803 ms`, then correctly refused the current unsealed mainnet issuance. A `VALID` item result remains deferred until the interrupted M2 mint has a FINAL seal.

## Three operations

1. Create an issuer account, one fresh dedicated vault address for each item, and a separate issuer funding wallet. Mint zero-value carrier notes for a new collection and seal it with FINAL. Confirm the independent checker accepts the arbitrary collection and item number, and that each vault address has exactly one note.
2. Alice signs one zero-value carrier transfer to Bob's fresh dedicated vault. The transaction uses a separate funding-wallet input for the ZIP-317 fee. Confirm Alice is SPENT, Bob is HELD, and the same Action binds the successor.
3. Bob lists the item. Carol uses a separate seed, a separate buyer funding wallet, and a fresh vault. Carol prepares one PCZT with carrier output to her vault, payment to Bob, and change to her funding wallet. Carol signs and strips private buyer fields. Bob checks the price, fee, action binding and two-server agreement, then signs the carrier input last. Broadcast one transaction and confirm Bob is SPENT and Carol is HELD.

## Budget

All carrier notes are zero value. The sale payment is capped at 0.001 ZEC. Use standard ZIP-317 fees and calculate every fee before signing. Abort unless the sale payment plus all mint, transfer and sale fees is at most 0.002 ZEC. No transaction is broadcast if the projected total is over the cap.

## Approval stop conditions

Do not run this plan until approval is given. Stop without signing or broadcasting if the servers disagree, the fee estimate exceeds the cap, the wallet path requires a vault to pay its own fee, the checker cannot prove exact-vault purity, or any output would expose secret key material.
