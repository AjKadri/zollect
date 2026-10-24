#[cfg(feature = "sender")]
mod sender;
mod ownership;
#[cfg(feature = "trustee")]
mod trustee;
use std::{collections::{HashMap, HashSet}, fs, process::Command};
use anyhow::{anyhow, bail, ensure, Context, Result};
use orchard::{keys::{FullViewingKey, Scope}, Address, Note};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zcash_keys::{address::UnifiedAddress, keys::UnifiedFullViewingKey};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{consensus::{BlockHeight, BranchId}, local_consensus::LocalNetwork};

fn network() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    let two = Some(BlockHeight::from_u32(2));
    LocalNetwork { overwinter:one, sapling:one, blossom:one, heartwood:one,
        canopy:one, nu5:two, nu6:two, nu6_1:two, nu6_2:two, nu6_3:two, nu7:None }
}

// Nothing resembling a spending key is derived for this burn receiver. The point
// is obtained by rejection sampling domain-separated public hash bytes. Spending
// would require finding corresponding secret key material, assumed infeasible.
fn burn_address() -> Address {
    for counter in 0u32.. {
        let mut bytes = [0u8;43];
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
    let out = Command::new("curl").args(["--fail", "--silent", "--show-error", "--max-time", "30",
        "-H", "Content-Type: application/json", "--data-binary", &body, url]).output()?;
    ensure!(out.status.success(), "RPC transport failed: {}", String::from_utf8_lossy(&out.stderr));
    let value: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(value["error"].is_null(), "RPC error: {}", value["error"]);
    Ok(value["result"].clone())
}

fn rpc_batch(url: &str, calls: &[(&str,Value)]) -> Result<Vec<Value>> {
    let request:Vec<_>=calls.iter().enumerate().map(|(i,(method,params))|
        json!({"jsonrpc":"2.0","id":i+1,"method":method,"params":params})).collect();
    let body=serde_json::to_string(&request)?;
    let out=Command::new("curl").args(["--fail","--silent","--show-error","--max-time","30",
        "-H","Content-Type: application/json","--data-binary",&body,url]).output()?;
    ensure!(out.status.success(),"Batch transport failed: {}",String::from_utf8_lossy(&out.stderr));
    let replies:Vec<Value>=serde_json::from_slice(&out.stdout)?;
    let mut results=HashMap::new();
    for reply in replies {
        ensure!(reply["error"].is_null(),"Batch RPC error: {}",reply["error"]);
        let id=reply["id"].as_u64().context("Missing batch id")? as usize;
        ensure!(id>0 && id<=calls.len() && !results.contains_key(&id),"Unexpected batch id");
        results.insert(id,reply["result"].clone());
    }
    (1..=calls.len()).map(|id|results.remove(&id).context("Missing batch result")).collect()
}

#[derive(Clone)]
struct SeenNote { note: Note, memo: [u8;512], owned: bool }
struct ChainTx { txid: String, height: u64, nullifiers: Vec<String>, commitments: Vec<[u8;32]>, notes: Vec<(usize, SeenNote)> }

fn load_chain(url: &str, fvk: &FullViewingKey) -> Result<Vec<ChainTx>> {
    ensure!(rpc(url,"getblockhash",json!([0]))? == json!("029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"), "Not the expected regtest genesis");
    let tip = rpc(url,"getblockcount",json!([]))?.as_u64().context("No chain height")?;
    let tip_hash = rpc(url,"getblockhash",json!([tip]))?;
    let ivks = [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)];
    let ovks = [fvk.to_ovk(Scope::External), fvk.to_ovk(Scope::Internal)];
    let mut txs = Vec::new();
    let heights:Vec<_>=(1..=tip).collect();
    let mut records=Vec::new();
    for chunk in heights.chunks(64) {
        let calls:Vec<_>=chunk.iter().map(|h|("getblock",json!([h.to_string(),1]))).collect();
        for (height,block) in chunk.iter().zip(rpc_batch(url,&calls)?) {
            ensure!(block["height"]==*height,"Unexpected block height");
            for id in block["tx"].as_array().context("Missing tx list")?.iter().skip(1) {
                records.push((*height,id.as_str().context("Invalid txid")?.to_owned()));
            }
        }
    }
    for chunk in records.chunks(64) {
        let calls:Vec<_>=chunk.iter().map(|(_,id)|("getrawtransaction",json!([id,0]))).collect();
        for ((height,txid),raw_hex) in chunk.iter().zip(rpc_batch(url,&calls)?) {
            let raw=hex::decode(raw_hex.as_str().context("Missing raw tx")?)?;
            let tx=Transaction::read(raw.as_slice(),BranchId::Nu6_3)?;
            ensure!(tx.txid().to_string()==*txid,"Raw txid mismatch");
            if let Some(bundle)=tx.ironwood_bundle() {
                let mut notes:HashMap<usize,SeenNote>=HashMap::new();
                for (index,_,note,_,memo) in bundle.recover_outputs_with_ovks(&ovks) {
                    notes.insert(index,SeenNote{note,memo,owned:false});
                }
                for (index,_,note,_,memo) in bundle.decrypt_outputs_with_keys(&ivks) {
                    notes.insert(index,SeenNote{note,memo,owned:true});
                }
                let mut notes:Vec<_>=notes.into_iter().collect();
                notes.sort_by_key(|(i,_)|*i);
                txs.push(ChainTx{txid:txid.clone(),height:*height,notes,
                    nullifiers:bundle.actions().iter().map(|a|hex::encode(a.nullifier().to_bytes())).collect(),
                    commitments:bundle.actions().iter().map(|a|a.cmx().to_bytes()).collect()});
            }
        }
    }
    ensure!(rpc(url,"getblockhash",json!([tip]))? == tip_hash, "Chain changed during scan");
    ensure!(rpc(url,"getblockcount",json!([]))? == tip, "Chain advanced during scan; retry on a stable tip");
    println!("CHAIN regtest height={tip} hash={tip_hash}");
    Ok(txs)
}

fn memo_text(memo: &[u8;512]) -> &str {
    std::str::from_utf8(memo).unwrap_or("").trim_end_matches('\0')
}

fn verify_issuance(txs: &[ChainTx], fvk: &FullViewingKey, collection: &str, strict: bool) -> Result<Vec<(usize,String,usize,String)>> {
    let prefix = format!("ZEC-O1|{collection}|");
    let mut owned = HashSet::new();
    let mut successor: Option<String> = None;
    let mut sealed = false;
    let mut items = Vec::new();
    let mut vaults = HashSet::new();
    for tx in txs {
        let authenticated = tx.nullifiers.iter().any(|nf| owned.contains(nf));
        let markers: Vec<_> = tx.notes.iter().filter_map(|(index,n)| {
            memo_text(&n.memo).strip_prefix(&prefix).map(|m|(*index,n,m))
        }).collect();
        if authenticated && !markers.is_empty() {
            ensure!(!sealed, "FAIL mint_after_FINAL txid={}", tx.txid);
            ensure!(markers.len()==1, "FAIL ambiguous issuance marker");
            if let Some(nf) = &successor {
                ensure!(tx.nullifiers.contains(nf), "FAIL disconnected issuer sequence");
            }
            let (index, note, marker) = markers[0];
            let incoming_change: Vec<_> = tx.notes.iter().filter(|(_,n)| n.owned && n.note.value().inner()>0).collect();
            if marker == "FINAL|0" {
                ensure!(items.len()==3, "FAIL FINAL before exactly three items");
                ensure!(note.note.recipient()==burn_address(), "FAIL wrong FINAL burn receiver");
                ensure!(incoming_change.is_empty(), "FAIL spendable issuer continuation after FINAL");
                sealed = true;
                successor = None;
                println!("FINAL txid={} action={} height={}",tx.txid,index,tx.height);
                if !strict { break; }
            } else {
                let (number,hop)=marker.split_once('|').context("FAIL malformed memo")?;
                let number: usize=number.parse()?;
                ensure!(hop=="0" && number==items.len()+1 && number<=3, "FAIL invalid item or hop");
                ensure!(note.note.value().inner()==0, "FAIL item is not zero value");
                ensure!(vaults.insert(note.note.recipient().to_raw_address_bytes()), "FAIL reused vault address");
                ensure!(incoming_change.len()==1, "FAIL issuer sequence continuation is ambiguous");
                successor=Some(hex::encode(incoming_change[0].1.note.nullifier(fvk).to_bytes()));
                let cmx=hex::encode(orchard::note::ExtractedNoteCommitment::from(note.note.commitment()).to_bytes());
                items.push((number,tx.txid.clone(),index,cmx));
            }
        }
        for (_,n) in &tx.notes {
            if n.owned { owned.insert(hex::encode(n.note.nullifier(fvk).to_bytes())); }
        }
    }
    ensure!(sealed && items.len()==3, "FAIL supply not sealed at exactly three");
    for (number,txid,index,cmx) in &items {
        println!("ITEM {number} VALID txid={txid} action={index} cmx={cmx}");
    }
    if strict { println!("SUPPLY SEALED count=3"); } else { println!("MINT_PREFIX VALID count=3 through_FINAL; later mint audit is separate"); }
    Ok(items)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("burn") => {
            let ua=UnifiedAddress::from_receivers(Some(burn_address()),None,None,None).context("Burn encoding failed")?;
            println!("{}",ua.encode(&network()));
            Ok(())
        }
        Some("issuance") if args.len()==5 => {
            let key=fs::read_to_string(&args[3])?;
            let ufvk=UnifiedFullViewingKey::decode(&network(),key.trim()).map_err(|e|anyhow!("Invalid UFVK: {e}"))?;
            let fvk=ufvk.orchard().context("Issuer key has no Orchard component")?;
            let txs=load_chain(&args[2],fvk)?;
            verify_issuance(&txs,fvk,&args[4],true).map(|_|())
        }
        Some("proof") if args.len()==5 => ownership::verify_proof(&args[2],&args[3],&args[4]),
        Some("link") if args.len()==6 => ownership::verify_link(&args[2],&args[3],&args[4],&args[5]),
        #[cfg(feature = "sender")]
        Some("transfer") if args.len()==9 => sender::transfer(&args[2],&args[3],&args[4],&args[5],args[6].parse()?,&args[7],&args[8]),
        #[cfg(feature = "sender")]
        Some("attest") if args.len()==10 => sender::attest(&args[2],&args[3],&args[4],&args[5],args[6].parse()?,&args[7],&args[8],&args[9]),
        #[cfg(feature = "trustee")]
        Some("fund-import") if args.len()==5 => trustee::import(&args[2],&args[3],&args[4]),
        #[cfg(feature = "trustee")]
        Some("fund-prepare") if args.len()==8 => trustee::prepare(&args[2],&args[3],&args[4],args[5].parse()?,&args[6],&args[7]),
        #[cfg(feature = "trustee")]
        Some("fund-check") if args.len()==6 => trustee::check(&args[2],&args[3],&args[4],&args[5]),
        #[cfg(feature = "trustee")]
        Some("fund-extract") if args.len()==4 => trustee::extract(&args[2],&args[3]),
        _ => bail!("Usage: carrier-verifier burn | issuance RPC_URL ISSUER_UFVK_FILE COLLECTION"),
    }
}
