# Public evidence

Sanitized commands and checker outputs only. Local paths, machine details and keys are omitted.

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
