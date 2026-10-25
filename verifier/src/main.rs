#[cfg(feature = "mainnet")]
#[allow(dead_code)]
mod lightwalletd;
#[cfg(feature = "mainnet")]
#[allow(dead_code)]
mod network;
mod ownership;
#[cfg(feature = "sender")]
mod sender;
#[cfg(feature = "trustee")]
mod trustee;
use anyhow::{Context, Result, anyhow, bail, ensure};
use orchard::{
    Address, Note,
    keys::{FullViewingKey, Scope},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    process::Command,
};
use zcash_keys::{address::UnifiedAddress, keys::UnifiedFullViewingKey};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
};

fn network() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    let two = Some(BlockHeight::from_u32(2));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: two,
        nu6: two,
        nu6_1: two,
        nu6_2: two,
        nu6_3: two,
        nu7: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo(text: &str) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        bytes
    }

    #[test]
    fn carrier_memo_accepts_arbitrary_collection_item_and_hop() {
        assert_eq!(
            parse_carrier_memo(&memo("ZEC-O1|collection-x|42|17")),
            Some(CarrierMemo {
                collection: "collection-x".into(),
                item: Some(42),
                hop: 17,
            })
        );
    }

    #[test]
    fn carrier_memo_accepts_final_marker_without_item_count_assumption() {
        assert_eq!(
            parse_carrier_memo(&memo("ZEC-O1|another-collection|FINAL|99")),
            Some(CarrierMemo {
                collection: "another-collection".into(),
                item: None,
                hop: 99,
            })
        );
    }

    #[test]
    fn carrier_memo_rejects_malformed_or_non_carrier_text() {
        assert!(parse_carrier_memo(&memo("ZEC-O1|collection-x|0|1")).is_none());
        assert!(parse_carrier_memo(&memo("memo for item 1")).is_none());
        assert!(carrier_memo("collection-x", 42, 17).is_ok());
    }
}

// Nothing resembling a spending key is derived for this burn receiver. The point
// is obtained by rejection sampling domain-separated public hash bytes. Spending
// would require finding corresponding secret key material, assumed infeasible.
fn burn_address() -> Address {
    for counter in 0u32.. {
        let mut bytes = [0u8; 43];
        let d = Sha256::digest(b"zecathon-o1-burn-diversifier-v1");
        bytes[..11].copy_from_slice(&d[..11]);
        let mut hash = Sha256::new();
        hash.update(b"zecathon-o1-burn-public-point-v1");
        hash.update(counter.to_le_bytes());
        bytes[11..].copy_from_slice(&hash.finalize());
        if let Some(address) = Option::<Address>::from(Address::from_raw_address_bytes(&bytes)) {
            return address;
        }
    }
    unreachable!()
}

fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let out = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &body,
            url,
        ])
        .output()?;
    ensure!(
        out.status.success(),
        "RPC transport failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(value["error"].is_null(), "RPC error: {}", value["error"]);
    Ok(value["result"].clone())
}

fn rpc_batch(url: &str, calls: &[(&str, Value)]) -> Result<Vec<Value>> {
    let request:Vec<_>=calls.iter().enumerate().map(|(i,(method,params))|
        json!({"jsonrpc":"2.0","id":i+1,"method":method,"params":params})).collect();
    let body = serde_json::to_string(&request)?;
    let out = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &body,
            url,
        ])
        .output()?;
    ensure!(
        out.status.success(),
        "Batch transport failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replies: Vec<Value> = serde_json::from_slice(&out.stdout)?;
    let mut results = HashMap::new();
    for reply in replies {
        ensure!(
            reply["error"].is_null(),
            "Batch RPC error: {}",
            reply["error"]
        );
        let id = reply["id"].as_u64().context("Missing batch id")? as usize;
        ensure!(
            id > 0 && id <= calls.len() && !results.contains_key(&id),
            "Unexpected batch id"
        );
        results.insert(id, reply["result"].clone());
    }
    (1..=calls.len())
        .map(|id| results.remove(&id).context("Missing batch result"))
        .collect()
}

#[derive(Clone)]
struct SeenNote {
    note: Note,
    memo: [u8; 512],
    owned: bool,
}

#[derive(Clone)]
struct ChainTx {
    txid: String,
    height: u64,
    nullifiers: Vec<String>,
    commitments: Vec<[u8; 32]>,
    notes: Vec<(usize, SeenNote)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CarrierMemo {
    collection: String,
    item: Option<u64>,
    hop: u64,
}

const CARRIER_MEMO_PREFIX: &str = "ZEC-O1";

fn parse_carrier_memo(memo: &[u8; 512]) -> Option<CarrierMemo> {
    let mut fields = memo_text(memo).split('|');
    if fields.next()? != CARRIER_MEMO_PREFIX {
        return None;
    }
    let collection = fields.next()?.to_owned();
    if collection.is_empty() {
        return None;
    }
    let subject = fields.next()?;
    let hop = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    let item = if subject == "FINAL" {
        None
    } else {
        let item: u64 = subject.parse().ok()?;
        if item == 0 {
            return None;
        }
        Some(item)
    };
    Some(CarrierMemo {
        collection,
        item,
        hop,
    })
}

fn carrier_memo(collection: &str, item: u64, hop: u64) -> Result<MemoBytes> {
    ensure!(
        !collection.is_empty() && !collection.contains('|'),
        "Invalid collection id"
    );
    ensure!(item > 0, "Item number must be positive");
    Ok(MemoBytes::from_bytes(
        format!("{CARRIER_MEMO_PREFIX}|{collection}|{item}|{hop}").as_bytes(),
    )?)
}

fn load_chain_from_server(url: &str, fvks: &[&FullViewingKey]) -> Result<Vec<ChainTx>> {
    let chain = rpc(url, "getblockchaininfo", json!([]))?;
    let chain_name = chain["chain"].as_str().unwrap_or("unknown");
    let genesis = rpc(url, "getblockhash", json!([0]))?;
    let tip = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No chain height")?;
    let tip_hash = rpc(url, "getblockhash", json!([tip]))?;
    let ivks: Vec<_> = fvks
        .iter()
        .flat_map(|fvk| [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)])
        .collect();
    let ovks: Vec<_> = fvks
        .iter()
        .flat_map(|fvk| [fvk.to_ovk(Scope::External), fvk.to_ovk(Scope::Internal)])
        .collect();
    let mut txs = Vec::new();
    let heights: Vec<_> = (1..=tip).collect();
    let mut records = Vec::new();
    for chunk in heights.chunks(64) {
        let calls: Vec<_> = chunk
            .iter()
            .map(|h| ("getblock", json!([h.to_string(), 1])))
            .collect();
        for (height, block) in chunk.iter().zip(rpc_batch(url, &calls)?) {
            ensure!(block["height"] == *height, "Unexpected block height");
            for id in block["tx"]
                .as_array()
                .context("Missing tx list")?
                .iter()
                .skip(1)
            {
                records.push((*height, id.as_str().context("Invalid txid")?.to_owned()));
            }
        }
    }
    for chunk in records.chunks(64) {
        let calls: Vec<_> = chunk
            .iter()
            .map(|(_, id)| ("getrawtransaction", json!([id, 0])))
            .collect();
        for ((height, txid), raw_hex) in chunk.iter().zip(rpc_batch(url, &calls)?) {
            let raw = hex::decode(raw_hex.as_str().context("Missing raw tx")?)?;
            let tx = Transaction::read(raw.as_slice(), BranchId::Nu6_3)?;
            ensure!(tx.txid().to_string() == *txid, "Raw txid mismatch");
            if let Some(bundle) = tx.ironwood_bundle() {
                let mut notes: HashMap<usize, SeenNote> = HashMap::new();
                for (index, _, note, _, memo) in bundle.recover_outputs_with_ovks(&ovks) {
                    notes.insert(
                        index,
                        SeenNote {
                            note,
                            memo,
                            owned: false,
                        },
                    );
                }
                for (index, _, note, _, memo) in bundle.decrypt_outputs_with_keys(&ivks) {
                    notes.insert(
                        index,
                        SeenNote {
                            note,
                            memo,
                            owned: true,
                        },
                    );
                }
                let mut notes: Vec<_> = notes.into_iter().collect();
                notes.sort_by_key(|(i, _)| *i);
                txs.push(ChainTx {
                    txid: txid.clone(),
                    height: *height,
                    notes,
                    nullifiers: bundle
                        .actions()
                        .iter()
                        .map(|a| hex::encode(a.nullifier().to_bytes()))
                        .collect(),
                    commitments: bundle
                        .actions()
                        .iter()
                        .map(|a| a.cmx().to_bytes())
                        .collect(),
                });
            }
        }
    }
    ensure!(
        rpc(url, "getblockhash", json!([tip]))? == tip_hash,
        "Chain changed during scan"
    );
    ensure!(
        rpc(url, "getblockcount", json!([]))? == tip,
        "Chain advanced during scan; retry on a stable tip"
    );
    println!(
        "CHAIN {chain_name} height={tip} hash={tip_hash} genesis={}",
        genesis.as_str().unwrap_or("unknown")
    );
    Ok(txs)
}

fn compare_chain_views(primary: &[ChainTx], secondary: &[ChainTx]) -> Result<()> {
    ensure!(
        primary.len() == secondary.len(),
        "FAIL RPC_SERVER_DISAGREEMENT transaction_count primary={} secondary={}",
        primary.len(),
        secondary.len()
    );
    for (left, right) in primary.iter().zip(secondary) {
        ensure!(
            left.txid == right.txid
                && left.height == right.height
                && left.nullifiers == right.nullifiers
                && left.commitments == right.commitments,
            "FAIL RPC_SERVER_DISAGREEMENT txid={} secondary_txid={}",
            left.txid,
            right.txid
        );
    }
    Ok(())
}

fn chain_tip(url: &str) -> Result<(u64, String)> {
    let height = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No chain height")?;
    let hash = rpc(url, "getblockhash", json!([height]))?
        .as_str()
        .context("No tip hash")?
        .to_owned();
    Ok((height, hash))
}

fn chain_identity(url: &str) -> Result<(String, String)> {
    let chain = rpc(url, "getblockchaininfo", json!([]))?;
    let chain_name = chain["chain"].as_str().context("No chain name")?.to_owned();
    let genesis = rpc(url, "getblockhash", json!([0]))?
        .as_str()
        .context("No genesis hash")?
        .to_owned();
    Ok((chain_name, genesis))
}

fn load_chain(
    url: &str,
    fvks: &[&FullViewingKey],
    secondary_url: Option<&str>,
) -> Result<Vec<ChainTx>> {
    let primary_identity = chain_identity(url)?;
    ensure!(
        primary_identity.0 != "main" || secondary_url.is_some(),
        "FAIL MAINNET_REQUIRES_TWO_SERVERS"
    );
    let primary = load_chain_from_server(url, fvks)?;
    if let Some(secondary_url) = secondary_url {
        ensure!(
            url != secondary_url,
            "FAIL RPC_SERVER_DISAGREEMENT duplicate server endpoint"
        );
        let secondary = load_chain_from_server(secondary_url, fvks)?;
        let secondary_identity = chain_identity(secondary_url)?;
        ensure!(
            primary_identity == secondary_identity,
            "FAIL RPC_SERVER_DISAGREEMENT chain_identity primary={:?} secondary={:?}",
            primary_identity,
            secondary_identity
        );
        let (primary_height, primary_hash) = chain_tip(url)?;
        let (secondary_height, secondary_hash) = chain_tip(secondary_url)?;
        ensure!(
            primary_height == secondary_height && primary_hash == secondary_hash,
            "FAIL RPC_SERVER_DISAGREEMENT primary_height={} primary_hash={} secondary_height={} secondary_hash={}",
            primary_height,
            primary_hash,
            secondary_height,
            secondary_hash
        );
        compare_chain_views(&primary, &secondary)?;
        println!("RPC_SERVERS CONSISTENT primary={url} secondary={secondary_url}");
    }
    Ok(primary)
}

fn load_chain_for_key(
    url: &str,
    fvk: &FullViewingKey,
    secondary_url: Option<&str>,
) -> Result<Vec<ChainTx>> {
    load_chain(url, &[fvk], secondary_url)
}

fn memo_text(memo: &[u8; 512]) -> &str {
    std::str::from_utf8(memo)
        .unwrap_or("")
        .trim_end_matches('\0')
}

fn verify_issuance(
    txs: &[ChainTx],
    fvk: &FullViewingKey,
    collection: &str,
    strict: bool,
) -> Result<Vec<(u64, String, usize, String)>> {
    let mut owned = HashSet::new();
    let mut successor: Option<String> = None;
    let mut sealed = false;
    let mut items = Vec::new();
    let mut vaults = HashSet::new();
    for tx in txs {
        let authenticated = tx.nullifiers.iter().any(|nf| owned.contains(nf));
        let markers: Vec<_> = tx
            .notes
            .iter()
            .filter_map(|(index, n)| {
                parse_carrier_memo(&n.memo)
                    .filter(|m| m.collection == collection)
                    .map(|m| (*index, n, m))
            })
            .collect();
        if authenticated && !markers.is_empty() {
            ensure!(!sealed, "FAIL mint_after_FINAL txid={}", tx.txid);
            ensure!(markers.len() == 1, "FAIL ambiguous issuance marker");
            if let Some(nf) = &successor {
                ensure!(
                    tx.nullifiers.contains(nf),
                    "FAIL disconnected issuer sequence"
                );
            }
            let (index, note, marker) = &markers[0];
            let incoming_change: Vec<_> = tx
                .notes
                .iter()
                .filter(|(_, n)| n.owned && n.note.value().inner() > 0)
                .collect();
            if marker.item.is_none() {
                ensure!(
                    note.note.recipient() == burn_address(),
                    "FAIL wrong FINAL burn receiver"
                );
                ensure!(
                    incoming_change.is_empty(),
                    "FAIL spendable issuer continuation after FINAL"
                );
                sealed = true;
                successor = None;
                println!(
                    "FINAL txid={} action={} height={}",
                    tx.txid, index, tx.height
                );
                if !strict {
                    break;
                }
            } else {
                let number = marker.item.context("FAIL malformed item marker")?;
                ensure!(marker.hop == 0, "FAIL issued item has nonzero hop");
                ensure!(
                    items.iter().all(|(item, _, _, _)| *item != number),
                    "FAIL duplicate item number"
                );
                ensure!(
                    note.note.value().inner() == 0,
                    "FAIL item is not zero value"
                );
                ensure!(
                    vaults.insert(note.note.recipient().to_raw_address_bytes()),
                    "FAIL reused vault address"
                );
                ensure!(
                    incoming_change.len() == 1,
                    "FAIL issuer sequence continuation is ambiguous"
                );
                successor = Some(hex::encode(
                    incoming_change[0].1.note.nullifier(fvk).to_bytes(),
                ));
                let cmx = hex::encode(
                    orchard::note::ExtractedNoteCommitment::from(note.note.commitment()).to_bytes(),
                );
                items.push((number, tx.txid.clone(), *index, cmx));
            }
        }
        for (_, n) in &tx.notes {
            if n.owned {
                owned.insert(hex::encode(n.note.nullifier(fvk).to_bytes()));
            }
        }
    }
    ensure!(
        sealed && !items.is_empty(),
        "FAIL supply not sealed with any items"
    );
    for (number, txid, index, cmx) in &items {
        println!("ITEM {number} VALID txid={txid} action={index} cmx={cmx}");
    }
    if strict {
        println!("SUPPLY SEALED count={}", items.len());
    } else {
        println!(
            "MINT_PREFIX VALID count={} through_FINAL; later mint audit is separate",
            items.len()
        );
    }
    Ok(items)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("burn") => {
            let ua = UnifiedAddress::from_receivers(
                Some(burn_address()),
                None,
                None,
                None,
                #[cfg(feature = "mainnet")]
                None,
            )
            .context("Burn encoding failed")?;
            println!("{}", ua.encode(&network()));
            Ok(())
        }
        Some("issuance") if (args.len() == 5 || args.len() == 6) => {
            let key = fs::read_to_string(&args[3])?;
            let ufvk = UnifiedFullViewingKey::decode(&network(), key.trim())
                .map_err(|e| anyhow!("Invalid UFVK: {e}"))?;
            let fvk = ufvk
                .orchard()
                .context("Issuer key has no Orchard component")?;
            let txs = load_chain_for_key(&args[2], fvk, args.get(5).map(String::as_str))?;
            verify_issuance(&txs, fvk, &args[4], true).map(|_| ())
        }
        Some("proof") if (args.len() == 5 || args.len() == 6) => ownership::verify_proof(
            &args[2],
            &args[3],
            &args[4],
            args.get(5).map(String::as_str),
        ),
        Some("link") if (args.len() == 6 || args.len() == 7) => ownership::verify_link(
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            args.get(6).map(String::as_str),
        ),
        #[cfg(feature = "sender")]
        Some("transfer") if (args.len() == 11 || args.len() == 12) => sender::transfer(
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            args[6].parse()?,
            &args[7],
            &args[8],
            &args[9],
            &args[10],
            args.get(11).map(String::as_str),
        ),
        #[cfg(feature = "sender")]
        Some("attack-double-spend") if (args.len() == 11 || args.len() == 12) => {
            sender::attack_double_spend(
                &args[2],
                &args[3],
                &args[4],
                &args[5],
                args[6].parse()?,
                &args[7],
                &args[8],
                &args[9],
                &args[10],
                args.get(11).map(String::as_str),
            )
        }
        #[cfg(feature = "sender")]
        Some("attest") if args.len() == 11 || args.len() == 12 => sender::attest(
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            args[6].parse()?,
            &args[7],
            &args[8],
            &args[9],
            args[10].parse()?,
            args.get(11).map(String::as_str),
        ),
        #[cfg(feature = "sender")]
        Some("sale-prepare") if args.len() == 10 || args.len() == 11 => sender::sale_prepare(
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            &args[6],
            &args[7],
            args[8].parse()?,
            &args[9],
            args.get(10).map(String::as_str),
        ),
        #[cfg(feature = "sender")]
        Some("sale-sign") if args.len() == 12 || args.len() == 13 => sender::sale_sign(
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            &args[6],
            args[7].parse()?,
            args[8].parse()?,
            args[9].parse()?,
            &args[10],
            &args[11],
            args.get(12).map(String::as_str),
        ),
        #[cfg(feature = "trustee")]
        Some("fund-import") if args.len() == 5 => trustee::import(&args[2], &args[3], &args[4]),
        #[cfg(feature = "trustee")]
        Some("fund-prepare") if args.len() == 8 => trustee::prepare(
            &args[2],
            &args[3],
            &args[4],
            args[5].parse()?,
            &args[6],
            &args[7],
        ),
        #[cfg(feature = "trustee")]
        Some("fund-check") if args.len() == 6 => {
            trustee::check(&args[2], &args[3], &args[4], &args[5])
        }
        #[cfg(feature = "trustee")]
        Some("fund-extract") if args.len() == 4 => trustee::extract(&args[2], &args[3]),
        _ => bail!(
            "Usage: carrier-verifier burn | issuance RPC_URL ISSUER_UFVK_FILE COLLECTION [SECONDARY_RPC_URL] | proof RPC_URL PROOF_FILE CHALLENGE [SECONDARY_RPC_URL] | link RPC_URL ISSUER_UFVK_FILE ALICE_PROOF BOB_PROOF [SECONDARY_RPC_URL] | attack-double-spend RPC_URL VAULT_WALLET VAULT_ID ORIGIN_TX ORIGIN_ACTION RECIPIENT OUTPUT FUNDING_WALLET FUNDING_ID [SECONDARY_RPC_URL]"
        ),
    }
}
