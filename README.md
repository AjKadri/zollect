# Zollect

**Own it on Zcash. Prove it anywhere.**
Collectibles held as shielded notes: provable by anyone, traceable by no one.

Live site: https://zollect.ajkadri.dev · Zecathon entry, Private Markets track

---

## What it is

Zcash mainnet has no token or NFT support, so Zcash collectibles today are rows in a marketplace's database. The buyer holds nothing on the chain and can't prove ownership without the marketplace.

Zollect puts the item itself on the chain. Each collectible, a **zote**, is a zero-value note in Zcash's Ironwood shielded pool, in a vault that holds that zote and nothing else. Whoever controls the vault key owns the zote.

- **Unique by construction.** When a zote moves, Ironwood binds the new note to the spent one in the same action, and the old note's nullifier is published. There is exactly one successor, and the network rejects a second spend.
- **Provable on demand.** The owner answers a fresh challenge by signing it with the zote's key. A checker confirms the zote is genuine, traces back to a sealed collection, and is still held. Old owners and forgeries fail.
- **Private.** On the chain, mints, transfers and sales look like any other shielded transaction. Nobody watching can tell who owns what, who bought or who sold.
- **Safe to sell.** A sale is one jointly built transaction: the zote goes to the buyer and the ZEC to the seller, or nothing happens.

No protocol change is needed. It runs on Zcash mainnet today.

## Live on mainnet

The **Lagos Lights** collection: three zotes, minted and sealed. Tobi received zote #2 and sold it to Kemi in a single atomic transaction.

| Step | Transaction |
|---|---|
| Seal (3 items) | [`d44ab08a…fbd61ec`](https://mainnet.zcashexplorer.app/transactions/d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec) |
| Zote #2 to Tobi | [`2a4f5bae…5f0a14`](https://mainnet.zcashexplorer.app/transactions/2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14) |
| Tobi sells to Kemi | [`c08b51ee…cdda0`](https://mainnet.zcashexplorer.app/transactions/c08b51eeffce637bb62d7ab309956bff21c98e99715031526d7edf2a494cdda0) |

Checker results: all three items `VALID`, `SUPPLY SEALED count=3`; Tobi `SPENT`; Kemi `HELD`; `LINK VALID` (same action). Full list: [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) and the [evidence page](https://zollect.ajkadri.dev/evidence.html).

## Check it yourself

Easiest: open the site and use **Verify**, **Challenge Kemi** and **Try to cheat**. They run the real checker against mainnet.

From source (Rust, stable toolchain):

```sh
cargo build --manifest-path verifier/Cargo.toml --release --locked --features mainnet

verifier/target/release/zecathon-carrier-verifier mainnet-verify-item \
  https://na.zec.rocks:443 https://eu.zec.rocks:443 \
  public/lagos-lights.issuer.ufvk lagos-lights 2 public/lagos-lights.mint-txids
```

Expected: `ITEM 1 VALID`, `ITEM 2 VALID`, `ITEM 3 VALID`, `SUPPLY SEALED count=3`. More commands and expected outputs: [docs](https://zollect.ajkadri.dev/docs.html#verify).

Every check fetches only the listed transactions from **two independent light-wallet servers**, compares the full responses and refuses if they disagree. It never signs or broadcasts.

## Repository map

| Path | What |
|---|---|
| `verifier/` | Rust checker (read-only) and sender tools (mint, transfer, sale), feature-gated |
| `hosted/` | Website and its small Node server with fixed, rate-limited read-only endpoints |
| `public/` | Public collection data: issuer viewing key, transaction lists, sample proofs |
| `PUBLIC_EVIDENCE.md` | Every command and output behind the claims above |
| `THREAT_MODEL.md` | Who learns what, and the residual risks |

The [Zote standard draft](https://zollect.ajkadri.dev/standard.html) describes how any wallet or marketplace could support zotes.

## Privacy, briefly

Chain watchers learn nothing beyond the existence of shielded transactions. A verifier learns that one zote is genuine and held, plus that zote's own vault history; vaults hold one zote only, so no balances or other holdings leak. The seller learns the buyer's one-time vault, not their funding wallet. The issuer's viewing key is public by design. Light-wallet servers see request IP and timing. Details: [THREAT_MODEL.md](THREAT_MODEL.md).

## Limits

- No wallet support yet: Zodl, Zingo and others don't recognise zotes, and importing a vault seed into an ordinary wallet could spend the zote. Zotes live in Zollect's vault tool.
- The seal is enforced by the checker, not by consensus.
- Double-spend, forged-successor and mint-after-seal attacks were tested on regtest; the website tests old, forged and wrong-key proofs live on mainnet.
- The demo collection and owners are ours; this is not user traction.
- An earlier mainnet collection is superseded because of a seal bug, fixed in commit `69ae6b6`.
- Prototype code, not audited.

## Credits

The carrier-note idea comes from [Zarrier](https://github.com/Reiunmute/zcash-carrier), a testnet proof of concept. Zollect is a new implementation for Ironwood mainnet, written during Zecathon. Built on the Zcash Rust crates. See [CREDITS.md](CREDITS.md).

AI coding assistants (Codex, Claude) were used during development under the author's direction.

## Licence

Licensed under either of Apache-2.0 or MIT, at your option.
