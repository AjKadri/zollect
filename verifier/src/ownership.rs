use super::*;
use orchard::primitives::redpallas::{Signature, VerificationKey, SpendAuth};

pub(crate) fn message(challenge: &str, txid: &str, action: usize, cmx: &str, nf: &str) -> Vec<u8> {
    format!("zecathon-carrier-control-v1|{challenge}|{txid}|{action}|{cmx}|{nf}").into_bytes()
}

fn load_proof(path: &str) -> Result<(Value,FullViewingKey)> {
    let p:Value=serde_json::from_slice(&fs::read(path)?)?;
    let ufvk=UnifiedFullViewingKey::decode(&network(),p["ufvk"].as_str().context("Missing UFVK")?)
        .map_err(|_|anyhow!("Invalid proof UFVK"))?;
    Ok((p,ufvk.orchard().context("Missing Orchard key")?.clone()))
}

pub(crate) fn verify_proof(url: &str, file: &str, expected_challenge: &str) -> Result<()> {
    let (proof,fvk)=load_proof(file)?;
    ensure!(proof["challenge"] == expected_challenge, "FAIL wrong challenge");
    let txid=proof["txid"].as_str().context("Missing txid")?;
    let action=proof["action"].as_u64().context("Missing action")? as usize;
    let txs=load_chain(url,&fvk)?;
    let tx=txs.iter().find(|t|t.txid==txid).context("FAIL note transaction not mined")?;
    let n=&tx.notes.iter().find(|(i,n)|*i==action && n.owned).context("FAIL key does not decrypt note")?.1;
    ensure!(n.note.value().inner()==0,"FAIL carrier value is not zero");
    ensure!(memo_text(&n.memo).starts_with("ZEC-O1|carrier-20261024|1|"),"FAIL not item1");
    let cmx=hex::encode(tx.commitments[action]);
    let nf=hex::encode(n.note.nullifier(&fvk).to_bytes());
    ensure!(proof["cmx"]==cmx && proof["nullifier"]==nf,"FAIL proof-note mismatch");
    let key_bytes:[u8;32]=fvk.to_bytes()[..32].try_into()?;
    let vk=VerificationKey::<SpendAuth>::try_from(key_bytes).map_err(|_|anyhow!("FAIL invalid control verification key"))?;
    let signature:[u8;64]=hex::decode(proof["signature"].as_str().context("Missing signature")?)?.try_into().map_err(|_|anyhow!("Bad signature length"))?;
    vk.verify(&message(expected_challenge,txid,action,&cmx,&nf),&Signature::from(signature)).map_err(|_|anyhow!("FAIL invalid control signature"))?;
    let spender=txs.iter().find(|t|t.nullifiers.contains(&nf));
    if let Some(spender)=spender {
        println!("SPENT item=1 txid={txid} action={action} nullifier={nf} spending_txid={}",spender.txid);
    } else {
        println!("HELD item=1 txid={txid} action={action} cmx={cmx} nullifier={nf} control_signature=VALID");
    }
    Ok(())
}

pub(crate) fn verify_link(url: &str, issuer_file: &str, alice_file: &str, bob_file: &str) -> Result<()> {
    let (alice,alice_fvk)=load_proof(alice_file)?;
    let (bob,bob_fvk)=load_proof(bob_file)?;
    let txs=load_chain(url,&alice_fvk)?;
    let origin=alice["txid"].as_str().context("Missing origin")?;
    let origin_action=alice["action"].as_u64().context("Missing origin action")? as usize;
    // Authenticate the original mint from the issuer's chain prefix through FINAL.
    // The strict issuance command still rejects the later deliberate item4 attack.
    let issuer_key=fs::read_to_string(issuer_file)?;
    let issuer=UnifiedFullViewingKey::decode(&network(),issuer_key.trim()).map_err(|_|anyhow!("Invalid issuer key"))?;
    let issuer_fvk=issuer.orchard().context("No issuer Orchard key")?;
    let issuer_txs=load_chain(url,issuer_fvk)?;
    let items=verify_issuance(&issuer_txs,issuer_fvk,"carrier-20261024",false)?;
    ensure!(items.iter().any(|(n,t,i,_)|*n==1 && t==origin && *i==origin_action),"FAIL origin not in issuer's sealed mint prefix");
    let old_tx=txs.iter().find(|t|t.txid==origin).context("Origin not mined")?;
    let old=&old_tx.notes.iter().find(|(i,n)|*i==origin_action && n.owned).context("Wrong original owner key")?.1;
    ensure!(memo_text(&old.memo)=="ZEC-O1|carrier-20261024|1|0","FAIL wrong original memo");
    let old_nf=hex::encode(old.note.nullifier(&alice_fvk).to_bytes());
    let successor=bob["txid"].as_str().context("Missing successor txid")?;
    let action=bob["action"].as_u64().context("Missing successor action")? as usize;
    let tx=txs.iter().find(|t|t.txid==successor).context("Successor not mined")?;
    ensure!(tx.nullifiers.get(action)==Some(&old_nf),"FAIL successor is not in spent carrier's Action");
    let raw=hex::decode(rpc(url,"getrawtransaction",json!([successor,0]))?.as_str().context("Missing raw successor")?)?;
    let parsed=Transaction::read(raw.as_slice(),BranchId::Nu6_3)?;
    let bundle=parsed.ironwood_bundle().context("No Ironwood bundle")?;
    let (note,_,memo)=bundle.decrypt_output_with_key(action,&bob_fvk.to_ivk(Scope::External))
        .context("FAIL same-Action output is not Bob's note")?;
    ensure!(note.value().inner()==0 && memo_text(&memo)=="ZEC-O1|carrier-20261024|1|1","FAIL successor memo/value changed");
    ensure!(bob["cmx"]==hex::encode(tx.commitments[action]),"FAIL wrong successor commitment");
    println!("LINK VALID item=1 spent_nullifier={old_nf} successor_txid={successor} same_action={action} memo=ZEC-O1|carrier-20261024|1|1");
    Ok(())
}
