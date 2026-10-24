//! Regtest F1 PCZT preparation and approval checks. This module never reads a share.
use super::*;
use std::{convert::Infallible, path::Path};
use pasta_curves::group::ff::PrimeField;
use pczt::{Pczt, roles::{creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
    verifier::{Verifier, OrchardError}, tx_extractor::TransactionExtractor}};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zcash_primitives::transaction::{builder::{Builder, BuildConfig, BundlePadding},
    fees::zip317, sighash::SignableInput, sighash_v6::v6_signature_hash, txid::TxIdDigester};
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

fn read_fvk(path: &str) -> Result<FullViewingKey> {
    let bytes: [u8;96] = fs::read(path)?.try_into().map_err(|_|anyhow!("Invalid fund FVK length"))?;
    FullViewingKey::from_bytes(&bytes).context("Invalid fund FVK")
}

// zcash-sign generates the group viewing key using test-network text encoding.
// Re-encode the identical key for this regtest. No mainnet/testnet RPC is used.
pub(crate) fn import(input: &str, output: &str, address_output: &str) -> Result<()> {
    let text=fs::read_to_string(input)?;
    let line=text.lines().find_map(|l|l.strip_prefix("Unified Full Viewing Key: "))
        .context("Missing zcash-sign viewing key")?;
    let encoded:String=serde_json::from_str(line)?;
    let key=UnifiedFullViewingKey::decode(&zcash_protocol::consensus::TEST_NETWORK,&encoded)
        .map_err(|_|anyhow!("Invalid generated viewing key"))?;
    let fvk=key.orchard().context("Missing Orchard key")?;
    fs::write(output,fvk.to_bytes())?;
    let address=UnifiedAddress::from_receivers(Some(fvk.address_at(0u64,Scope::External)),None,None,None).context("Cannot encode fund address")?
        .encode(&network());
    fs::write(address_output,&address)?;
    println!("FUND_ADDRESS regtest {address}");
    Ok(())
}

pub(crate) fn prepare(url: &str, fvk_path: &str, recipient_path: &str, amount: u64, directory: &str, label: &str) -> Result<()> {
    ensure!(amount>0,"Payout must be positive on regtest");
    let fvk=read_fvk(fvk_path)?;
    let txs=load_chain(url,&fvk)?;
    let spent:HashSet<_>=txs.iter().flat_map(|t|t.nullifiers.iter().cloned()).collect();
    let (tx,index,n)=txs.iter().flat_map(|t|t.notes.iter().map(move |(i,n)|(t,*i,n)))
        .find(|(_,_,n)|n.owned && n.note.value().inner()>amount+10000 && !spent.contains(&hex::encode(n.note.nullifier(&fvk).to_bytes())))
        .context("No unspent fund note sufficient for payout and ZIP-317 fee")?;
    let path=crate::sender::witness(&txs,&tx.txid,index)?;
    let anchor=path.root(n.note.commitment().into());
    let address=fs::read_to_string(recipient_path)?;
    let recipient=UnifiedAddress::decode(&network(),address.trim()).context("Invalid recipient")?;
    let recipient=*recipient.orchard().context("No Orchard receiver")?;
    let tip=rpc(url,"getblockcount",json!([]))?.as_u64().context("Missing height")? as u32;
    let mut b=Builder::new(network(),BlockHeight::from_u32(tip+1),BuildConfig::Standard {
        sapling_anchor:None,orchard_anchor:None,ironwood_anchor:Some(anchor),
        orchard_padding:BundlePadding::DEFAULT,ironwood_padding:BundlePadding::DEFAULT });
    b.add_ironwood_spend::<Infallible>(fvk.clone(),n.note,path).map_err(|e|anyhow!("Input: {e:?}"))?;
    b.add_ironwood_output::<Infallible>(Some(fvk.to_ovk(Scope::External)),recipient,Zatoshis::from_u64(amount)?,MemoBytes::empty())
        .map_err(|e|anyhow!("Payout: {e:?}"))?;
    b.add_ironwood_output::<Infallible>(Some(fvk.to_ovk(Scope::External)),fvk.address_at(1u64,Scope::Internal),
        Zatoshis::from_u64(n.note.value().inner()-amount-10000)?,MemoBytes::empty()).map_err(|e|anyhow!("Change: {e:?}"))?;
    let built=b.build_for_pczt(UnwrapErr(SysRng),&zip317::FeeRule::standard()).map_err(|e|anyhow!("PCZT build: {e:?}"))?;
    let pczt=Creator::build_from_parts(built.pczt_parts).context("PCZT version unsupported")?;
    let pczt=IoFinalizer::new(pczt).finalize_io(UnwrapErr(SysRng)).map_err(|e|anyhow!("IO finalization: {e:?}"))?;
    let pk=orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let pczt=Prover::new(pczt).create_ironwood_proof(UnwrapErr(SysRng),&pk)
        .map_err(|e|anyhow!("Ironwood proof: {e:?}"))?.finish();
    let directory=Path::new(directory);fs::create_dir_all(directory)?;
    fs::write(directory.join(format!("{label}.pczt")),pczt.serialize().map_err(|e|anyhow!("PCZT serialization: {e:?}"))?)?;
    fs::write(directory.join(format!("{label}.approval.json")),serde_json::to_vec_pretty(&json!({"network":"regtest","recipient":address.trim(),"amount":amount,"fee":10000}))?)?;
    println!("PCZT_READY label={label} funding_txid={} amount_zat={amount} fee_zat=10000",tx.txid);
    Ok(())
}

pub(crate) fn check(input: &str, approval_path: &str, fvk_path: &str, directory: &str) -> Result<()> {
    let bytes=fs::read(input)?;
    let pczt=Pczt::parse(&bytes).map_err(|e|anyhow!("Invalid PCZT: {e:?}"))?;
    let approval:Value=serde_json::from_slice(&fs::read(approval_path)?)?;
    ensure!(approval["network"]=="regtest" && approval["fee"]==10000,"Invalid approval");
    let address=UnifiedAddress::decode(&network(),approval["recipient"].as_str().context("Missing approved recipient")?)
        .context("Invalid approved address")?;
    let recipient=*address.orchard().context("Approval has no Orchard receiver")?;
    let amount=approval["amount"].as_u64().context("Missing approved amount")?;
    let fvk=read_fvk(fvk_path)?;
    ensure!(pczt.transparent().inputs().is_empty() && pczt.transparent().outputs().is_empty()
        && pczt.sapling().spends().is_empty() && pczt.sapling().outputs().is_empty()
        && pczt.orchard().actions().is_empty(),"Unexpected value pool");
    ensure!(*pczt.global().consensus_branch_id()==u32::from(BranchId::Nu6_3)
        && *pczt.global().tx_version()==6 && *pczt.global().coin_type()==1,"Wrong chain context");
    let mut alpha=None;
    let mut real_spends=0;
    let mut paid=0;
    let mut in_value=0u64;
    let mut out_value=0u64;
    Verifier::new(pczt.clone()).with_ironwood::<String,_>(|bundle| {
        bundle.verify_cross_address_restriction()?;
        for action in bundle.actions() {
            action.verify_cv_net()?;
            action.spend().verify_nullifier(Some(&fvk))?;
            action.spend().verify_rk(Some(&fvk))?;
            action.output().verify_note_commitment(action.spend())?;
            let value=action.output().value().as_ref().ok_or_else(||OrchardError::Custom("Missing value".into()))?.inner();
            let to=action.output().recipient().as_ref().ok_or_else(||OrchardError::Custom("Missing recipient".into()))?;
            in_value+=action.spend().value().as_ref().ok_or_else(||OrchardError::Custom("Missing spend value".into()))?.inner();
            out_value+=value;
            if value>0 {
                if *to==recipient && value==amount { paid+=1; }
                else if fvk.scope_for_address(to).is_none() { return Err(OrchardError::Custom("REFUSED recipient or amount differs from approval".into())); }
            }
            if action.spend().spend_auth_sig().is_none() {
                real_spends+=1;
                alpha=action.spend().alpha().as_ref().map(|a|a.to_repr());
            }
        }
        Ok(())
    }).map_err(|e|anyhow!("PCZT approval check: {e:?}"))?;
    ensure!(paid==1,"REFUSED approved payout not found exactly once");
    ensure!(in_value.checked_sub(out_value)==Some(10000),"REFUSED fee differs from approval");
    ensure!(real_spends==1,"Expected one fund spend");
    let tx=pczt.clone().into_effects().map_err(|e|anyhow!("Effects: {e:?}"))?;
    let sighash=v6_signature_hash(&tx,&SignableInput::Shielded,&tx.digest(TxIdDigester));
    let directory=Path::new(directory);fs::create_dir_all(directory)?;
    fs::write(directory.join("sighash.bin"),sighash.as_ref())?;
    fs::write(directory.join("alpha.bin"),alpha.context("No real spend randomizer")?)?;
    println!("APPROVED recipient_and_amount=VERIFIED commitments=VERIFIED fee_zat=10000 real_spends=1 sighash={}",hex::encode(sighash.as_ref()));
    Ok(())
}

pub(crate) fn extract(input: &str, output: &str) -> Result<()> {
    let pczt=Pczt::parse(&fs::read(input)?).map_err(|e|anyhow!("Invalid PCZT: {e:?}"))?;
    let tx=TransactionExtractor::new(pczt).extract(UnwrapErr(SysRng)).map_err(|e|anyhow!("Extraction failed: {e:?}"))?;
    let mut bytes=Vec::new();tx.write(&mut bytes)?;fs::write(output,bytes)?;
    println!("SIGNED_TRANSACTION txid={} file={output}",tx.txid());
    Ok(())
}
