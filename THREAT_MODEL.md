# Threat model

This project proves carrier-note ownership while keeping the buyer's funding wallet separate from the item vault.

## Atomic sale

The buyer signs the funding input first. The seller then approves and signs the carrier input. Seller approval checks:

- the transaction spends exactly the seller's carrier note;
- the seller's item vault has no second note and the carrier is not already spent;
- the carrier output is in the same Action, has value zero, and leaves the seller's vault;
- exactly one payment goes to the seller's own payment address for the listed amount; and
- the final transaction fee is standard ZIP-317 and stays within the transaction and running-total guards.

The seller does not need to read the carrier output memo before signing. The buyer is responsible for constructing the successor memo, and the post-sale LINK check proves that the mined successor preserves the collection, item and hop metadata in the same Action.

The seller intentionally learns the buyer's one-time item-vault address because it is the recipient of the zero-value carrier output. The seller does not receive the buyer's funding-wallet keys, viewing key, input witnesses, nullifiers or derivation data. The buyer's funding wallet remains separate from the item vault. Transaction-level values needed for fee and payment validation are not treated as a funding-wallet identity disclosure.

## Verification boundary

The checker uses the published issuer viewing key and the proof's challenge-bound control signature. It checks exact-vault purity, spent state, Action binding and the post-sale memo link. A proof or a UI result is not evidence that a transaction was mined unless the two-server transaction lookup confirms it.

## Residual risks

- A public observer can see the mined transaction and its shielded commitment structure.
- The seller can associate the one-time item-vault recipient with this sale.
- The seller must not be given buyer funding-wallet secrets or a funding-wallet viewing key.
- The two-server refusal is required because one light-wallet server is not an independent consistency guarantee.
