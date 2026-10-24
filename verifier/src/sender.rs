use super::*;
use std::{convert::Infallible, io::Read, path::Path};
use bip0039::{English, Mnemonic};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{keys::SpendAuthorizingKey, tree::MerkleHashOrchard};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{builder::{BuildConfig,Builder,BundlePadding}, fees::zip317};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{memo::MemoBytes,value::Zatoshis};
use zeroize::Zeroizing;

// Single-owner O2 operations only. F1 trustee shares are never read by this code.
fn spending_key(wallet: &str, identity: &str) -> Result<UnifiedSpendingKey> {
    let config:toml::Value=toml::from_str(&fs::read_to_string(Path::new(wallet).join("keys.toml"))?)?;
    ensure!(config["network"].as_str()==Some("regtest"),"Only regtest wallets accepted");
    let encrypted=config["mnemonic"].as_str().context("Missing encrypted seed")?;
    let ids=age::IdentityFile::from_file(identity.to_owned())?.into_identities()?;
    let decryptor=age::Decryptor::new(age::armor::ArmoredReader::new(encrypted.as_bytes()))?;
    let mut reader=decryptor.decrypt(ids.iter().map(|i|i.as_ref() as _))?;
    let mut plaintext=Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;
    let phrase=std::str::from_utf8(&plaintext).map_err(|_|anyhow!("Invalid encrypted seed encoding"))?;
    let mnemonic=Mnemonic::<English>::from_phrase(phrase).map_err(|_|anyhow!("Invalid encrypted mnemonic"))?;
    let seed=Zeroizing::new(mnemonic.to_seed(""));
    UnifiedSpendingKey::from_seed(&network(),&seed[..],zip32::AccountId::ZERO)
        .map_err(|_|anyhow!("Unable to derive regtest account"))
}

pub(crate) fn witness(txs: &[ChainTx], txid: &str, action: usize) -> Result<orchard::tree::MerklePath> {
    let mut tree=CommitmentTree::<MerkleHashOrchard,32>::empty();
    let mut result:Option<IncrementalWitness<MerkleHashOrchard,32>>=None;
    for tx in txs {
        for (index,bytes) in tx.commitments.iter().enumerate() {
            let node=Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes)).context("Invalid commitment")?;
            if let Some(w)=&mut result { w.append(node).map_err(|_|anyhow!("Witness tree full"))?; }
            tree.append(node).map_err(|_|anyhow!("Commitment tree full"))?;
            if tx.txid==txid && index==action {
                result=IncrementalWitness::from_tree(tree.clone());
            }
        }
    }
    Ok(result.context("No note witness")?.path().context("No Merkle path")?.into())
}

pub(crate) fn transfer(url: &str,wallet: &str,identity: &str,origin: &str,origin_action: usize,bob_address: &str,output: &str) -> Result<()> {
    let usk=spending_key(wallet,identity)?;
    let fvk=orchard::keys::FullViewingKey::from(usk.orchard());
    let txs=load_chain(url,&fvk)?;
    let old_tx=txs.iter().find(|t|t.txid==origin).context("Carrier tx not found")?;
    let carrier=&old_tx.notes.iter().find(|(i,n)|*i==origin_action && n.owned).context("Carrier not owned")?.1;
    ensure!(carrier.note.value().inner()==0 && memo_text(&carrier.memo)=="ZEC-O1|carrier-20261024|1|0","Wrong carrier");
    let spent:HashSet<_>=txs.iter().flat_map(|t|t.nullifiers.iter().cloned()).collect();
    ensure!(!spent.contains(&hex::encode(carrier.note.nullifier(&fvk).to_bytes())),"Carrier already spent");
    let (fee_tx,fee_index,fee_note)=txs.iter().flat_map(|t|t.notes.iter().map(move |(i,n)|(t,*i,n)))
        .find(|(_,_,n)|n.owned && n.note.value().inner()>10000 && !spent.contains(&hex::encode(n.note.nullifier(&fvk).to_bytes())))
        .context("Need an unspent Ironwood fee note")?;
    let carrier_path=witness(&txs,origin,origin_action)?;
    let fee_path=witness(&txs,&fee_tx.txid,fee_index)?;
    let anchor=carrier_path.root(carrier.note.commitment().into());
    ensure!(fee_path.root(fee_note.note.commitment().into())==anchor,"Witness anchors differ");
    let recipient=UnifiedAddress::decode(&network(),bob_address).context("Invalid Bob address")?;
    let recipient=*recipient.orchard().context("No Orchard receiver")?;
    let tip=rpc(url,"getblockcount",json!([]))?.as_u64().context("No tip")? as u32;
    let prover=LocalTxProver::bundled();
    for candidate in 1..=32 {
        let mut b=Builder::new(network(),BlockHeight::from_u32(tip+1),BuildConfig::Standard {
            sapling_anchor:None,orchard_anchor:None,ironwood_anchor:Some(anchor),
            orchard_padding:BundlePadding::DEFAULT,ironwood_padding:BundlePadding::DEFAULT });
        b.add_ironwood_spend::<Infallible>(fvk.clone(),carrier.note,carrier_path.clone()).map_err(|e|anyhow!("Carrier input: {e:?}"))?;
        b.add_ironwood_spend::<Infallible>(fvk.clone(),fee_note.note,fee_path.clone()).map_err(|e|anyhow!("Fee input: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(Some(fvk.to_ovk(Scope::External)),recipient,Zatoshis::ZERO,MemoBytes::from_bytes(b"ZEC-O1|carrier-20261024|1|1")?)
            .map_err(|e|anyhow!("Carrier output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(Some(fvk.to_ovk(Scope::External)),fee_note.note.recipient(),Zatoshis::from_u64(fee_note.note.value().inner()-10000)?,MemoBytes::empty())
            .map_err(|e|anyhow!("Fee change: {e:?}"))?;
        let built=b.build(&transparent::builder::TransparentSigningSet::new(),&[],&[SpendAuthorizingKey::from(usk.orchard())],UnwrapErr(SysRng),&prover,&prover,&zip317::FeeRule::standard())
            .map_err(|e|anyhow!("Build failed: {e:?}"))?;
        let input=built.ironwood_meta().spend_action_index(0).context("No carrier input position")?;
        let out=built.ironwood_meta().output_action_index(0).context("No carrier output position")?;
        println!("CONSTRUCTION candidate={candidate} carrier_input_action={input} requested_successor_action={out}");
        if input!=out { continue; }
        let tx=built.transaction();
        let mut raw=Vec::new(); tx.write(&mut raw)?;
        fs::write(output,raw)?;
        println!("READY txid={} same_action={input} memo=ZEC-O1|carrier-20261024|1|1 raw_file={output}",tx.txid());
        let manifest=json!({"txid":tx.txid().to_string(),"action":input,"origin_txid":origin,"origin_action":origin_action});
        fs::write(format!("{output}.json"),serde_json::to_vec_pretty(&manifest)?)?;
        return Ok(());
    }
    bail!("No same-Action candidate constructed; nothing broadcast")
}

pub(crate) fn attest(url: &str,wallet: &str,identity: &str,txid: &str,action: usize,challenge: &str,output: &str,expected_memo: &str) -> Result<()> {
    let usk=spending_key(wallet,identity)?;
    let ufvk=usk.to_unified_full_viewing_key();
    let fvk=ufvk.orchard().context("No Orchard key")?;
    let txs=load_chain(url,fvk)?;
    let tx=txs.iter().find(|t|t.txid==txid).context("No target transaction")?;
    let n=&tx.notes.iter().find(|(i,n)|*i==action && n.owned).context("Key does not decrypt target note")?.1;
    ensure!(memo_text(&n.memo)==expected_memo,"Wrong item memo");
    let cmx=hex::encode(tx.commitments[action]);
    let nf=hex::encode(n.note.nullifier(fvk).to_bytes());
    let key=SpendAuthorizingKey::from(usk.orchard()).randomize(&pasta_curves::pallas::Scalar::from(0));
    let signature=key.sign(UnwrapErr(SysRng),&crate::ownership::message(challenge,txid,action,&cmx,&nf));
    let proof=json!({"challenge":challenge,"txid":txid,"action":action,"cmx":cmx,"nullifier":nf,"ufvk":ufvk.encode(&network())?,"signature":hex::encode(<[u8;64]>::from(&signature))});
    fs::write(output,serde_json::to_vec_pretty(&proof)?)?;
    println!("CONTROL_PROOF item=1 txid={txid} action={action} proof_file={output}");
    Ok(())
}
