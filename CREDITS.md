# Credits

- Zarrier's carrier-note ownership design, documented in [Reiunmute/zcash-carrier](https://github.com/Reiunmute/zcash-carrier), informs the O1 and O2 experiments. This credits the design precedent. No product source has been copied.
- The [frost-zec prototype](https://github.com/OpenPGP-Wallet/frost-zec) provides the reference context for Ironwood threshold signing and checking a PCZT against an approved payment.
- The Zcash Foundation's [frost-tools](https://github.com/ZcashFoundation/frost-tools), including frost-client, frostd, and zcash-sign, and its [reddsa](https://github.com/ZcashFoundation/reddsa) library provide the F1 DKG and signing toolchain. The experiment uses frost-tools commit `06c0dbdbb1bac9b99cd255e74ba2f387c295e660`, including aryaethn's [Ironwood external-signing support](https://github.com/ZcashFoundation/frost-tools/pull/593).
- [Zebra](https://github.com/ZcashFoundation/zebra), [lightwalletd](https://github.com/zcash/lightwalletd), [zcash-devtool](https://github.com/zcash/zcash-devtool), and [librustzcash](https://github.com/zcash/librustzcash) provide the upstream node, indexing, wallet, and protocol tools.

Upstream dependencies retain their own licenses. The experiment harness and verifier are new code written during the build window. Execution results and privacy limits are recorded separately from these acknowledgments.
