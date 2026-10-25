# Mainnet confirmation plan

Status: NOT RUN. This document requires explicit approval before any mainnet wallet or light-wallet request is made.

## Gate

Use two independently configured public mainnet light-wallet servers. Before each scan or signing step, compare their chain height, tip hash, relevant compact-block or transaction data, and wallet scan result. Refuse the operation if either server disagrees, lags, fails, or returns incomplete data. Do not log seeds, spending keys, key shares, encrypted wallet files, or private PCZT fields.

The current sender build is regtest-only. Before approval, add a reviewed mainnet network configuration and a lightwalletd transport adapter. Do not bypass the regtest guard or substitute a public server without that review.

## Three operations

1. Create an issuer account, one fresh dedicated vault address for each item, and a separate issuer funding wallet. Mint zero-value carrier notes for a new collection and seal it with FINAL. Confirm the independent checker accepts the arbitrary collection and item number, and that each vault address has exactly one note.
2. Alice signs one zero-value carrier transfer to Bob's fresh dedicated vault. The transaction uses a separate funding-wallet input for the ZIP-317 fee. Confirm Alice is SPENT, Bob is HELD, and the same Action binds the successor.
3. Bob lists the item. Carol uses a separate seed, a separate buyer funding wallet, and a fresh vault. Carol prepares one PCZT with carrier output to her vault, payment to Bob, and change to her funding wallet. Carol signs and strips private buyer fields. Bob checks the price, fee, action binding and two-server agreement, then signs the carrier input last. Broadcast one transaction and confirm Bob is SPENT and Carol is HELD.

## Budget

All carrier notes are zero value. The sale payment is capped at 0.001 ZEC. Use standard ZIP-317 fees and calculate every fee before signing. Abort unless the sale payment plus all mint, transfer and sale fees is at most 0.002 ZEC. No transaction is broadcast if the projected total is over the cap.

## Approval stop conditions

Do not run this plan until approval is given. Stop without signing or broadcasting if the servers disagree, the fee estimate exceeds the cap, the wallet path requires a vault to pay its own fee, the checker cannot prove exact-vault purity, or any output would expose secret key material.
