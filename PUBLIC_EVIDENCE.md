# Public evidence

Sanitized commands and checker outputs only. Local paths, machine details and keys are omitted.

## Superseded mainnet collection

```text
carrier-m2: unsealed; first seal used a builder bug, fixed in 69ae6b6; superseded by lagos-lights
```

## O1

```text
COMMAND carrier-verifier issuance RPC_URL ISSUER_UFVK carrier-20261024
FINAL txid=c30b0bbbedaa51c5466133da0fcd51a58af58f996596f3f24d2532855805ff74 action=0
ITEM 1 VALID txid=eb7b2e2b179da5eee9383f8a9dda5c61af7e62ccc4b097b19326bc92bfe36935 action=0
ITEM 2 VALID txid=65f99494522c2300e0cd2a60d4af6a05f730c536ea9db2eaba1b3aa707e7d169 action=1
ITEM 3 VALID txid=5554a30d611b5421fa799a36b84e190b6928e21ebf2e232fce4a2f5abbf9b603 action=1
SUPPLY SEALED count=3

COMMAND carrier-verifier issuance RPC_URL ISSUER_UFVK carrier-20261024
Error: FAIL mint_after_FINAL txid=e979c3ffe4b8bf541f117a74ea7e034ac07bb777212f51d10d16aafbe007a302
```

## Replacement mainnet collection: lagos-lights

```text
COMMAND carrier-verifier mainnet-mint PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_WALLET ISSUER_IDENTITY FUNDING_WALLET FUNDING_IDENTITY BIRTHDAY lagos-lights BOOTSTRAP ISSUER_BOOTSTRAP_ADDRESS 0
FEE fee_zat=10000 running_total_before_zat=0 projected_total_zat=10000 cap_zat=200000
BROADCAST txid=7f1d30c2875daa7b1e2dacfb97004c86a443c3d75a6b73dff103c9e186d97b36 fee_zat=10000 running_total_zat=10000 stage=bootstrap
MAINNET TRANSACTION txid=7f1d30c2875daa7b1e2dacfb97004c86a443c3d75a6b73dff103c9e186d97b36 height=3531325 bytes=9166

FEE_PRE_ESTIMATE fee_zat=15000 spends=2 outputs=3 actions=3
FEE_FINAL fee_zat=15000 actions=3
FEE fee_zat=15000 running_total_before_zat=10000 projected_total_zat=25000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=abfb41a26bc70de6484f7b8edf4828ef079b4b8fda2857cb1858ee79130cfbda fee_zat=15000 running_total_zat=25000 stage=mint subject=1
MAINNET TRANSACTION txid=abfb41a26bc70de6484f7b8edf4828ef079b4b8fda2857cb1858ee79130cfbda height=3531327 bytes=12322

FEE_PRE_ESTIMATE fee_zat=15000 spends=2 outputs=3 actions=3
FEE_FINAL fee_zat=15000 actions=3
FEE fee_zat=15000 running_total_before_zat=25000 projected_total_zat=40000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=4971340fa5620a37ddd84b1b1890c3b8c24958100173e8fabb65ccf41ea4cca7 fee_zat=15000 running_total_zat=40000 stage=mint subject=2
MAINNET TRANSACTION txid=4971340fa5620a37ddd84b1b1890c3b8c24958100173e8fabb65ccf41ea4cca7 height=3531328 bytes=12322

FEE_PRE_ESTIMATE fee_zat=15000 spends=2 outputs=3 actions=3
FEE_FINAL fee_zat=15000 actions=3
FEE fee_zat=15000 running_total_before_zat=40000 projected_total_zat=55000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=9ec4773a8828fac9dfd7a141a0294dbdbe338d263555080ddcaae3ff369fa060 fee_zat=15000 running_total_zat=55000 stage=mint subject=3
MAINNET TRANSACTION txid=9ec4773a8828fac9dfd7a141a0294dbdbe338d263555080ddcaae3ff369fa060 height=3531329 bytes=12322

FEE_PRE_ESTIMATE fee_zat=10000 spends=2 outputs=2 actions=2
FEE_FINAL fee_zat=10000 actions=2
FEE fee_zat=10000 running_total_before_zat=55000 projected_total_zat=65000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec fee_zat=10000 running_total_zat=65000 stage=mint subject=FINAL
MAINNET TRANSACTION txid=d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec height=3531330 bytes=9166
```

```text
COMMAND carrier-verifier mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK lagos-lights 1 MINT_TXID_LIST_FILE
FINAL txid=d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec action=0 height=3531330
ITEM 1 VALID txid=abfb41a26bc70de6484f7b8edf4828ef079b4b8fda2857cb1858ee79130cfbda action=2 cmx=6a44a03186657519c928c068212550f53313518890dc5846062320aa89e09e1d
ITEM 2 VALID txid=4971340fa5620a37ddd84b1b1890c3b8c24958100173e8fabb65ccf41ea4cca7 action=2 cmx=4efd3afe51ec24ee0eacff5af02c654c3bbbdcf5039fb6fdea3d1a6506eb4a19
ITEM 3 VALID txid=9ec4773a8828fac9dfd7a141a0294dbdbe338d263555080ddcaae3ff369fa060 action=0 cmx=6de2c6b676700d2c1b2a93cf08dfbcdf6ae8056756071b69b16a6df51c546c20
SUPPLY SEALED count=3
VERIFY_TIMING mode=verify-any-item tx_count=5 elapsed_ms=1217
```

```text
COMMAND carrier-verifier mainnet-transfer PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_WALLET ISSUER_IDENTITY 4971340fa5620a37ddd84b1b1890c3b8c24958100173e8fabb65ccf41ea4cca7 2 TOBI_TRANSFER_VAULT FUNDING_WALLET FUNDING_IDENTITY BIRTHDAY 65000
FEE_PRE_ESTIMATE fee_zat=10000 spends=2 outputs=2 actions=2
FEE_FINAL fee_zat=10000 actions=2
FEE fee_zat=10000 sale_price_zat=0 running_total_before_zat=65000 projected_total_zat=75000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 fee_zat=10000 running_total_zat=75000 stage=transfer collection=lagos-lights item=2 hop=1
MAINNET TRANSACTION txid=2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 height=3531336 bytes=9166
```

```text
COMMAND carrier-verifier mainnet-proof PRIMARY_HTTPS SECONDARY_HTTPS TOBI_PROOF CHALLENGE MINT_TXID_LIST_FILE
HELD collection=lagos-lights item=2 hop=1 txid=2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 action=1 cmx=5e73b9369a03f23b7ba7aad0667c890e99fcf20a392292da3b321201f01a941b nullifier=ffacce3dbeb13bb5c5129b516e2b1a2ddf27b5381d0809e4dc5dab974419fa3b control_signature=VALID
VERIFY_TIMING mode=challenge-proof tx_count=6 elapsed_ms=1274
```

```text
COMMAND carrier-verifier mainnet-sale PRIMARY_HTTPS SECONDARY_HTTPS TOBI_WALLET TOBI_ID FUNDING_WALLET FUNDING_IDENTITY 2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 1 KEMI_SALE_VAULT TOBI_PAYMENT BIRTHDAY 20000 75000
Error: Buyer funding note cannot cover sale price and fee
```

Approved sale retry configuration: buyer funding birthday 3531306, with the approved earliest-lower fallback 3530540. Sale price remained 20000 zatoshi. The final-built-transaction fee guard remained 20000 zatoshi per transaction and 200000 zatoshi projected running total.

```text
COMMAND carrier-verifier mainnet-sale PRIMARY_HTTPS SECONDARY_HTTPS TOBI_WALLET TOBI_ID FUNDING_WALLET FUNDING_IDENTITY 2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 1 KEMI_SALE_VAULT TOBI_PAYMENT 3531306 20000 75000
Error: Buyer funding note cannot cover sale price and fee
EXIT_STATUS=1

COMMAND carrier-verifier mainnet-sale PRIMARY_HTTPS SECONDARY_HTTPS TOBI_WALLET TOBI_ID FUNDING_WALLET FUNDING_IDENTITY 2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 1 KEMI_SALE_VAULT TOBI_PAYMENT 3530540 20000 75000
Error: Buyer funding note cannot cover sale price and fee
EXIT_STATUS=1
```

No sale txid, fee estimate, signing, projected-total line, or broadcast exists. No post-sale checker output exists because no sale was mined.

## O2

```text
COMMAND carrier-verifier proof RPC_URL ALICE_PROOF CHALLENGE
SPENT item=1 txid=eb7b2e2b179da5eee9383f8a9dda5c61af7e62ccc4b097b19326bc92bfe36935 action=0 nullifier=f46b497de342c2906046509cd98d41d820085eb7dafde72266ec950c784fc806 spending_txid=81544880f9e1c5d734d3589d98438a8a104d45e39e0723af0f85038ff659040d

COMMAND carrier-verifier proof RPC_URL BOB_PROOF CHALLENGE
HELD item=1 txid=81544880f9e1c5d734d3589d98438a8a104d45e39e0723af0f85038ff659040d action=0 cmx=fe2c6c96c6a009a61a48e41e3b356ec41a0a9bb5ea4169edbf05799ec887b908 nullifier=abc200105f3b3654c8aa2928713b598a38e41f25146ef71644d39b651363c13e control_signature=VALID

COMMAND carrier-verifier link RPC_URL ISSUER_UFVK ALICE_PROOF BOB_PROOF
LINK VALID item=1 spent_nullifier=f46b497de342c2906046509cd98d41d820085eb7dafde72266ec950c784fc806 successor_txid=81544880f9e1c5d734d3589d98438a8a104d45e39e0723af0f85038ff659040d same_action=0 memo=ZEC-O1|carrier-20261024|1|1
```

## O3

```text
COMMAND carrier-verifier attack-double-spend RPC_URL ALICE_WALLET ALICE_ID eb7b2e2b179da5eee9383f8a9dda5c61af7e62ccc4b097b19326bc92bfe36935 0 FORGED_VAULT DOUBLE_SPEND_RAW FUNDING_WALLET FUNDING_ID
ATTACK_FIXTURE allow_spent_carrier=true
CONSTRUCTION candidate=1 carrier_input_action=1 requested_successor_action=1
READY txid=912b65f78d22d08b28f474c5914ddb51418af240b60be168499c0b7133ef68c1 same_action=1 collection=carrier-20261024 item=1 hop=1 raw_file=DOUBLE_SPEND_RAW

COMMAND sendrawtransaction DOUBLE_SPEND_RAW
{"jsonrpc":"1.0","id":"o3-double-spend-v2","result":null,"error":{"code":-25,"message":"failed to validate tx: WtxId(\"private\"), error: transaction did not pass consensus validation: could not contextually validate transaction on best chain: ironwood double-spend: duplicate nullifier: Nullifier(Nullifier(0x06c84f780c95ec6622e7fddab75e0820d8418dd99c50466090c242e37d496bf4)), in finalized state: false"}}
PASS: competing spend rejected because the nullifier was already recorded

COMMAND carrier-verifier attest RPC_URL FORGED_WALLET FORGED_ID b9f2ee66943748ba80249577e6d14746d5826b585bc69f6d74249d6e4ad9f050 1 CHALLENGE FORGED_HOP1_PROOF carrier-20261024 1
CONTROL_PROOF collection=carrier-20261024 item=1 hop=1 txid=b9f2ee66943748ba80249577e6d14746d5826b585bc69f6d74249d6e4ad9f050 action=1

COMMAND carrier-verifier link RPC_URL ISSUER_UFVK ALICE_OLD_PROOF FORGED_HOP1_PROOF
CHAIN test height=524 hash=31a3c51ac6a6eac6d323dcf9b7a6fe6fb81e409693ab1fb6b76e964e819e694f
Error: FAIL successor is not in the spent carrier's Action
FAIL: forged successor had the correct next hop but failed same-Action binding

COMMAND carrier-verifier proof RPC_URL ITEM2_HISTORY_PROOF CHALLENGE
HELD collection=carrier-20261024 item=2 hop=0 txid=65f99494522c2300e0cd2a60d4af6a05f730c536ea9db2eaba1b3aa707e7d169 action=1 cmx=401504da861c8e4ecd187f528916570d8c5aa2e000dc3a3d80e4f4c1524f331d nullifier=37cb0c76d96a59a6c4ca4ee97c6125c508f99745e0429e13f05db024830eaf02 control_signature=VALID
TEST-DEFINITION ERROR: O3 item-2-history asked for SPENT, but the supplied history leaves item 2 HELD; O4 covers SPENT with BOB_OLD_PROOF

COMMAND carrier-verifier proof RPC_URL CAROL_PROOF CHALLENGE SECONDARY_RPC_URL
Error: FAIL RPC_SERVER_DISAGREEMENT primary_height=484 primary_hash=27d89be88537f4aeea53b3027cbf9e0eb55f6c3091f7fbb4647724e1b5321b00 secondary_height=483 secondary_hash=e3289003f000a72a2e7d88ba118bbd8d2e5878c35758ec4db07ca31e26f46272
PASS
```

## O4

```text
COMMAND carrier-verifier sale-prepare RPC_URL SELLER_PROOF BUYER_FUNDING_WALLET BUYER_FUNDING_ID BUYER_VAULT SELLER_PAYMENT 100000 SALE_PCZT
SALE_PCZT_READY collection=carrier-20261024 item=1 carrier_action=1 buyer_action=0 price_zat=100000 buyer_signature=APPLIED private_buyer_fields=REDACTED

COMMAND carrier-verifier sale-sign RPC_URL SELLER_PROOF SELLER_WALLET SELLER_ID SELLER_PAYMENT 100000 1 0 SALE_PCZT SALE_RAW
SALE_CHECK payment=VERIFIED price_zat=100000 fee_zat=15000 buyer_signature=VERIFIED seller_signature=EMPTY
ATOMIC_SALE txid=5cc0d2b86f4f9eeb324a0025277171348935c20f47e6168e132137597cde8b31 carrier_action=1 buyer_action=0 payment_zat=100000 fee_zat=15000

COMMAND sendrawtransaction SALE_RAW
OUTPUT 5cc0d2b86f4f9eeb324a0025277171348935c20f47e6168e132137597cde8b31

COMMAND carrier-verifier proof RPC_URL BOB_OLD_PROOF CHALLENGE
SPENT collection=carrier-20261024 item=1 hop=1 txid=81544880f9e1c5d734d3589d98438a8a104d45e39e0723af0f85038ff659040d action=0 spending_txid=5cc0d2b86f4f9eeb324a0025277171348935c20f47e6168e132137597cde8b31

COMMAND carrier-verifier proof RPC_URL CAROL_PROOF CHALLENGE
HELD collection=carrier-20261024 item=1 hop=2 txid=5cc0d2b86f4f9eeb324a0025277171348935c20f47e6168e132137597cde8b31 action=1 cmx=bc73a8b835db737183a880c853bebfd70e5a87adc4f7af9df960fca230695f05 nullifier=1287f3e6c923cac3dccde0521834a6ef69f0f927745ea1daa294bb2316a70430 control_signature=VALID

COMMAND carrier-verifier link RPC_URL ISSUER_UFVK BOB_OLD_PROOF CAROL_PROOF
LINK VALID collection=carrier-20261024 item=1 spent_nullifier=abc200105f3b3654c8aa2928713b598a38e41f25146ef71644d39b651363c13e successor_txid=5cc0d2b86f4f9eeb324a0025277171348935c20f47e6168e132137597cde8b31 same_action=1 memo=ZEC-O1|carrier-20261024|1|2
```

## M1 read-only mainnet consistency

```text
COMMAND carrier-verifier mainnet-snapshot https://na.zec.rocks:443 https://eu.zec.rocks:443
MAINNET CONSISTENT chain=main height=3530459 tip_hash=9a22339893b5176d878fb4ad94676de6d7eb2106c0cdcd24dd5e020000000000
```

## M2 stage (a) stopped

```text
COMMAND carrier-verifier mainnet-mint PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_WALLET ISSUER_IDENTITY FUNDING_WALLET FUNDING_IDENTITY 3530540 carrier-m2 BOOTSTRAP ISSUER_BOOTSTRAP_ADDRESS 0
FEE fee_zat=10000 running_total_before_zat=0 projected_total_zat=10000 cap_zat=200000
BROADCAST txid=89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16 fee_zat=10000 running_total_zat=10000 stage=bootstrap

COMMAND carrier-verifier mainnet-tx PRIMARY_HTTPS SECONDARY_HTTPS 89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16
Error: lightwalletd transaction request failed
Caused by: code: 'Some requested entity was not found', message: "Transaction not found in mempool or best chain"
```

Stage (a): FAIL. No item mint or seal broadcast followed.

## M2 monitoring stopped on server disagreement

```text
TXID 89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16
BROADCAST_RESPONSE error_code=0

CHECK t+4m
SERVER_CHECK transaction not found in mempool or best chain
EXPLORER_CHECK HTTP_CODE=403 BYTES=162

CHECK t+6m
SERVER_CHECK transaction not found in mempool or best chain
EXPLORER_CHECK HTTP_CODE=403 BYTES=162

CHECK t+8m
SERVER_CHECK transaction not found in mempool or best chain
EXPLORER_CHECK HTTP_CODE=403 BYTES=162

CHECK t+10m
SERVER_CHECK transaction not found in mempool or best chain
EXPLORER_CHECK HTTP_CODE=403 BYTES=162

CHECK t+12m
SERVER_CHECK FAIL LIGHTWALLETD_INCOMPLETE_INFO info_height=3530594 tip_height=3530595
SERVER_CHECK FAIL LIGHTWALLETD_INCOMPLETE_INFO info_height=3530595 tip_height=3530594
EXPLORER_CHECK HTTP_CODE=403 BYTES=162
```

Stage (a): FAIL. Monitoring stopped at the first server disagreement. No rebroadcast or funding-note spend followed.

## Corrected mainnet lookup and stage-(a) stop

```text
COMMAND carrier-verifier mainnet-tx PRIMARY_HTTPS SECONDARY_HTTPS 89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16
MAINNET TRANSACTION txid=89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16 height=3530585 bytes=9166

TEST known_mined_mainnet_transaction_is_found_on_both_servers
PASS height=3530585 data_present=true

COMMAND carrier-verifier mainnet-mint PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_WALLET ISSUER_IDENTITY FUNDING_WALLET FUNDING_IDENTITY 3530540 carrier-m2 1 ITEM_1_VAULT 10000
Error: Computed mint fee changed during build
```

Stage (a): FAIL. The corrected item-1 attempt stopped before fee output and broadcast. No alternate settings or further mainnet spending followed.

## Approved fee guard and stage-(a) partial run

```text
FEE_PRE_ESTIMATE fee_zat=15000 spends=2 outputs=3 actions=3
FEE_FINAL fee_zat=15000 actions=3
FEE fee_zat=15000 running_total_before_zat=10000 projected_total_zat=25000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6 fee_zat=15000 running_total_zat=25000 stage=mint subject=1
MAINNET TRANSACTION txid=e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6 height=3531199 bytes=12322

FEE_PRE_ESTIMATE fee_zat=15000 spends=2 outputs=3 actions=3
FEE_FINAL fee_zat=15000 actions=3
FEE fee_zat=15000 running_total_before_zat=25000 projected_total_zat=40000 tx_cap_zat=20000 cap_zat=200000
BROADCAST txid=1d72c7f8db51d489f2431319a04725f627090ae5690eae6ebb7a1b4613d571eb fee_zat=15000 running_total_zat=40000 stage=mint subject=2
MAINNET TRANSACTION txid=1d72c7f8db51d489f2431319a04725f627090ae5690eae6ebb7a1b4613d571eb height=0 bytes=12322
Error: FAIL LIGHTWALLETD_INCOMPLETE_INFO server=primary info_height=3531220 tip_height=3531219
```

Stage (a): FAIL. Item 3, FINAL sealing, and the mainnet checker were stopped by the two-server refusal rule.

## Known-txid verification timing

```text
COMMAND carrier-verifier mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK carrier-m2 1 TXID_LIST_FILE
Error: FAIL LIGHTWALLETD_INCOMPLETE_INFO server=primary info_height=3531228 tip_height=3531229
real 3.88

COMMAND carrier-verifier mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK carrier-m2 1 TXID_LIST_FILE
Error: FAIL supply not sealed with any items
VERIFY_TIMING mode=verify-any-item tx_count=2 status=FAIL elapsed_ms=803
```

The two-server fast path fetched only the known bootstrap and item-1 transactions. The transport and checker path completed under 10 seconds, but the requested item remained semantically unverified because the interrupted mainnet run has no FINAL seal. No `VALID` claim is made.

```text
COMMAND carrier-verifier mainnet-proof PRIMARY_HTTPS SECONDARY_HTTPS PROOF_FILE speed-check-20261026
HELD collection=carrier-m2 item=1 hop=0 txid=e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6 action=2 cmx=b963e132cf150599a5ad6eefc149e3eab9c7cbeb71398281bf0b33e85dca3a25 nullifier=444703a4b5a992cd473b32773b12bc084abb6b81d72e4b273a9ff9b13b75f90a control_signature=VALID
VERIFY_TIMING mode=challenge-proof tx_count=2 elapsed_ms=769
```

Challenge proof: PASS, under 10 seconds. No mainnet transaction was signed or broadcast by the verification benchmark.

Final release binary confirmation:

```text
Error: FAIL LIGHTWALLETD_INCOMPLETE_INFO server=primary info_height=3531239 tip_height=3531240
real 0.45

HELD collection=carrier-m2 item=1 hop=0 txid=e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6 action=2 cmx=b963e132cf150599a5ad6eefc149e3eab9c7cbeb71398281bf0b33e85dca3a25 nullifier=444703a4b5a992cd473b32773b12bc084abb6b81d72e4b273a9ff9b13b75f90a control_signature=VALID
VERIFY_TIMING mode=challenge-proof tx_count=2 elapsed_ms=766
```

## Mainnet seal and issuance check

```text
MAINNET TRANSACTION txid=53470e9b48d1cb0d69980de66b0ac8f33cf6dad3f267ca083ad0126ab855a73b height=3531276 bytes=12322
MAINNET TRANSACTION txid=018fa54fc256cb7b8250c24cdd444b64b5c3b50be82721c7be959bf8810d688b height=3531291 bytes=9166

COMMAND carrier-verifier mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK carrier-m2 1 MINT_TXID_LIST_FILE
Error: FAIL supply not sealed with any items
VERIFY_TIMING mode=verify-any-item tx_count=5 status=FAIL elapsed_ms=8077
```

The seal is mined, but the issuance checker did not produce the required three `VALID` lines and `SUPPLY SEALED count=3`. No transfer or sale was attempted.

Approved consistency change: with aligned tips, a single server whose `info_height` is exactly one block from its own tip is retried after 3 seconds, up to 3 retries. Larger or persistent gaps still refuse.

## Issuance checker diagnosis and regression result

```text
COMMAND carrier-verifier mainnet-verify-item PRIMARY_HTTPS SECONDARY_HTTPS ISSUER_UFVK carrier-m2 1 MINT_TXID_LIST_FILE
TXID_LIST
89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16
e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6
1d72c7f8db51d489f2431319a04725f627090ae5690eae6ebb7a1b4613d571eb
53470e9b48d1cb0d69980de66b0ac8f33cf6dad3f267ca083ad0126ab855a73b
018fa54fc256cb7b8250c24cdd444b64b5c3b50be82721c7be959bf8810d688b
Error: FAIL supply not sealed with any items sealed=false item_count=3 marker_txids=["e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6", "1d72c7f8db51d489f2431319a04725f627090ae5690eae6ebb7a1b4613d571eb", "53470e9b48d1cb0d69980de66b0ac8f33cf6dad3f267ca083ad0126ab855a73b"] authenticated_marker_txids=["e5eca593949babaf8ca695010f888de9b20dbf2db41c3d18a4dc8af560940de6", "1d72c7f8db51d489f2431319a04725f627090ae5690eae6ebb7a1b4613d571eb", "53470e9b48d1cb0d69980de66b0ac8f33cf6dad3f267ca083ad0126ab855a73b"] tx_count=5
VERIFY_TIMING mode=verify-any-item tx_count=5 status=FAIL elapsed_ms=1229
```

```text
COMMAND carrier-verifier issuance RPC_URL ISSUER_UFVK COLLECTION
FINAL txid=c30b0bbbedaa51c5466133da0fcd51a58af58f996596f3f24d2532855805ff74 action=0 height=264
Error: FAIL mint_after_FINAL txid=e979c3ffe4b8bf541f117a74ea7e034ac07bb777212f51d10d16aafbe007a302
```
