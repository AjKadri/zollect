use super::*;
use bip0039::{English, Mnemonic};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{keys::SpendAuthorizingKey, tree::MerkleHashOrchard};
use pczt::{
    Pczt,
    roles::{
        creator::Creator,
        io_finalizer::IoFinalizer,
        prover::Prover,
        redactor::Redactor,
        signer::Signer,
        tx_extractor::TransactionExtractor,
        verifier::{OrchardError, Verifier},
    },
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::{cmp::max, convert::Infallible, io::Read, path::Path};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};
use zeroize::Zeroizing;

fn spending_key(wallet: &str, identity: &str) -> Result<UnifiedSpendingKey> {
    let config: toml::Value =
        toml::from_str(&fs::read_to_string(Path::new(wallet).join("keys.toml"))?)?;
    ensure!(
        config["network"].as_str() == Some("regtest"),
        "Only regtest wallets accepted"
    );
    let encrypted = config["mnemonic"]
        .as_str()
        .context("Missing encrypted seed")?;
    let ids = age::IdentityFile::from_file(identity.to_owned())?.into_identities()?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(encrypted.as_bytes()))?;
    let mut reader = decryptor.decrypt(ids.iter().map(|i| i.as_ref() as _))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;
    let phrase =
        std::str::from_utf8(&plaintext).map_err(|_| anyhow!("Invalid encrypted seed encoding"))?;
    let mnemonic = Mnemonic::<English>::from_phrase(phrase)
        .map_err(|_| anyhow!("Invalid encrypted mnemonic"))?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    UnifiedSpendingKey::from_seed(&network(), &seed[..], zip32::AccountId::ZERO)
        .map_err(|_| anyhow!("Unable to derive regtest account"))
}

fn payment_matches(
    recipient: Option<&[u8; 43]>,
    value: Option<u64>,
    expected_recipient: &[u8; 43],
    expected_value: u64,
) -> bool {
    recipient.is_some_and(|recipient| recipient == expected_recipient)
        && value == Some(expected_value)
}

pub(crate) fn witness(
    txs: &[ChainTx],
    txid: &str,
    action: usize,
) -> Result<orchard::tree::MerklePath> {
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut result: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    for tx in txs {
        for (index, bytes) in tx.commitments.iter().enumerate() {
            let node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
                .context("Invalid commitment")?;
            if let Some(w) = &mut result {
                w.append(node).map_err(|_| anyhow!("Witness tree full"))?;
            }
            tree.append(node)
                .map_err(|_| anyhow!("Witness tree full"))?;
            if tx.txid == txid && index == action {
                result = IncrementalWitness::from_tree(tree.clone());
            }
        }
    }
    Ok(result
        .context("No note witness")?
        .path()
        .context("No Merkle path")?
        .into())
}

pub(crate) fn transfer(
    url: &str,
    vault_wallet: &str,
    vault_identity: &str,
    origin: &str,
    origin_action: usize,
    recipient_address: &str,
    output: &str,
    funding_wallet: &str,
    funding_identity: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    transfer_inner(
        url,
        vault_wallet,
        vault_identity,
        origin,
        origin_action,
        recipient_address,
        output,
        funding_wallet,
        funding_identity,
        secondary_url,
        true,
    )
}

fn ensure_regtest_chain(url: &str) -> Result<()> {
    let chain = rpc(url, "getblockchaininfo", json!([]))?;
    ensure!(
        chain["chain"].as_str() == Some("test"),
        "Only regtest RPC endpoints are accepted by the sender"
    );
    Ok(())
}

pub(crate) fn attack_double_spend(
    url: &str,
    vault_wallet: &str,
    vault_identity: &str,
    origin: &str,
    origin_action: usize,
    recipient_address: &str,
    output: &str,
    funding_wallet: &str,
    funding_identity: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    println!("ATTACK_FIXTURE allow_spent_carrier=true");
    transfer_inner(
        url,
        vault_wallet,
        vault_identity,
        origin,
        origin_action,
        recipient_address,
        output,
        funding_wallet,
        funding_identity,
        secondary_url,
        false,
    )
}

fn transfer_inner(
    url: &str,
    vault_wallet: &str,
    vault_identity: &str,
    origin: &str,
    origin_action: usize,
    recipient_address: &str,
    output: &str,
    funding_wallet: &str,
    funding_identity: &str,
    secondary_url: Option<&str>,
    reject_spent_carrier: bool,
) -> Result<()> {
    ensure_regtest_chain(url)?;
    if let Some(secondary_url) = secondary_url {
        ensure_regtest_chain(secondary_url)?;
    }
    let vault_usk = spending_key(vault_wallet, vault_identity)?;
    let vault_fvk = orchard::keys::FullViewingKey::from(vault_usk.orchard());
    let funding_usk = spending_key(funding_wallet, funding_identity)?;
    let funding_fvk = orchard::keys::FullViewingKey::from(funding_usk.orchard());
    ensure!(
        vault_fvk.to_bytes() != funding_fvk.to_bytes(),
        "Funding wallet must be separate from item vault"
    );

    let vault_txs = load_chain_for_key(url, &vault_fvk, secondary_url)?;
    let funding_txs = load_chain_for_key(url, &funding_fvk, secondary_url)?;
    let old_tx = vault_txs
        .iter()
        .find(|t| t.txid == origin)
        .context("Carrier tx not found")?;
    let carrier = &old_tx
        .notes
        .iter()
        .find(|(i, n)| *i == origin_action && n.owned)
        .context("Carrier not owned")?
        .1;
    let vault_recipient = carrier.note.recipient().to_raw_address_bytes();
    let vault_notes: Vec<_> = vault_txs
        .iter()
        .flat_map(|t| t.notes.iter())
        .filter(|(_, n)| n.owned && n.note.recipient().to_raw_address_bytes() == vault_recipient)
        .collect();
    ensure!(
        vault_notes.len() == 1,
        "Item vault must hold exactly one item and no other notes; found={}",
        vault_notes.len()
    );
    let old_memo = parse_carrier_memo(&carrier.memo).context("Origin is not a carrier note")?;
    let item = old_memo.item.context("Origin is not an item note")?;
    ensure!(
        carrier.note.value().inner() == 0,
        "Carrier must have zero value"
    );
    let spent: HashSet<_> = vault_txs
        .iter()
        .flat_map(|t| t.nullifiers.iter().cloned())
        .collect();
    let carrier_nullifier = hex::encode(carrier.note.nullifier(&vault_fvk).to_bytes());
    if reject_spent_carrier {
        ensure!(!spent.contains(&carrier_nullifier), "Carrier already spent");
    } else {
        ensure!(
            spent.contains(&carrier_nullifier),
            "Attack fixture requires an already-spent carrier"
        );
    }
    let (fee_tx, fee_index, fee_note) = funding_txs
        .iter()
        .flat_map(|t| t.notes.iter().map(move |(i, n)| (t, *i, n)))
        .find(|(_, _, n)| {
            n.owned
                && n.note.value().inner() > 10000
                && !spent.contains(&hex::encode(n.note.nullifier(&funding_fvk).to_bytes()))
        })
        .context("Need an unspent funding-wallet Ironwood fee note")?;
    let carrier_path = witness(&vault_txs, origin, origin_action)?;
    let fee_path = witness(&vault_txs, &fee_tx.txid, fee_index)?;
    let anchor = carrier_path.root(carrier.note.commitment().into());
    ensure!(
        fee_path.root(fee_note.note.commitment().into()) == anchor,
        "Witness anchors differ"
    );
    let recipient = UnifiedAddress::decode(&network(), recipient_address)
        .context("Invalid recipient address")?;
    let recipient = *recipient.orchard().context("No Orchard receiver")?;
    ensure!(
        recipient.to_raw_address_bytes() != vault_recipient
            && vault_fvk.scope_for_address(&recipient).is_none(),
        "Recipient must be a fresh address outside the item vault"
    );
    let tip = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No tip")? as u32;
    let successor_memo = carrier_memo(
        &old_memo.collection,
        item,
        old_memo.hop.checked_add(1).context("Hop overflow")?,
    )?;
    let prover = LocalTxProver::bundled();
    for candidate in 1..=32 {
        let mut b = Builder::new(
            network(),
            BlockHeight::from_u32(tip + 1),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        b.add_ironwood_spend::<Infallible>(vault_fvk.clone(), carrier.note, carrier_path.clone())
            .map_err(|e| anyhow!("Carrier input: {e:?}"))?;
        b.add_ironwood_spend::<Infallible>(funding_fvk.clone(), fee_note.note, fee_path.clone())
            .map_err(|e| anyhow!("Funding input: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(
            None,
            recipient,
            Zatoshis::ZERO,
            successor_memo.clone(),
        )
        .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(
            Some(funding_fvk.to_ovk(Scope::External)),
            funding_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::from_u64(fee_note.note.value().inner() - 10000)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Funding change: {e:?}"))?;
        let built = b
            .build(
                &transparent::builder::TransparentSigningSet::new(),
                &[],
                &[
                    SpendAuthorizingKey::from(vault_usk.orchard()),
                    SpendAuthorizingKey::from(funding_usk.orchard()),
                ],
                UnwrapErr(SysRng),
                &prover,
                &prover,
                &zip317::FeeRule::standard(),
            )
            .map_err(|e| anyhow!("Build failed: {e:?}"))?;
        let input = built
            .ironwood_meta()
            .spend_action_index(0)
            .context("No carrier input position")?;
        let out = built
            .ironwood_meta()
            .output_action_index(0)
            .context("No carrier output position")?;
        println!(
            "CONSTRUCTION candidate={candidate} carrier_input_action={input} requested_successor_action={out}"
        );
        if input != out {
            continue;
        }
        let tx = built.transaction();
        let mut raw = Vec::new();
        tx.write(&mut raw)?;
        fs::write(output, raw)?;
        println!(
            "READY txid={} same_action={input} collection={} item={} hop={} raw_file={output}",
            tx.txid(),
            old_memo.collection,
            item,
            old_memo.hop + 1
        );
        let manifest = json!({
            "txid": tx.txid().to_string(), "action": input,
            "origin_txid": origin, "origin_action": origin_action,
            "collection": old_memo.collection, "item": item, "hop": old_memo.hop + 1,
        });
        fs::write(
            format!("{output}.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        return Ok(());
    }
    bail!("No same-Action candidate constructed; nothing broadcast")
}

pub(crate) fn attest(
    url: &str,
    wallet: &str,
    identity: &str,
    txid: &str,
    action: usize,
    challenge: &str,
    output: &str,
    collection: &str,
    item: u64,
    secondary_url: Option<&str>,
) -> Result<()> {
    let usk = spending_key(wallet, identity)?;
    let ufvk = usk.to_unified_full_viewing_key();
    let fvk = ufvk.orchard().context("No Orchard key")?;
    let txs = load_chain_for_key(url, fvk, secondary_url)?;
    let tx = txs
        .iter()
        .find(|t| t.txid == txid)
        .context("No target transaction")?;
    let n = &tx
        .notes
        .iter()
        .find(|(i, n)| *i == action && n.owned)
        .context("Key does not decrypt target note")?
        .1;
    let memo = parse_carrier_memo(&n.memo).context("Target is not a carrier item")?;
    ensure!(
        memo.collection == collection && memo.item == Some(item),
        "Target item metadata mismatch"
    );
    let cmx = hex::encode(tx.commitments[action]);
    let nf = hex::encode(n.note.nullifier(fvk).to_bytes());
    let key =
        SpendAuthorizingKey::from(usk.orchard()).randomize(&pasta_curves::pallas::Scalar::from(0));
    let signature = key.sign(
        UnwrapErr(SysRng),
        &crate::ownership::message(challenge, txid, action, &cmx, &nf),
    );
    let proof = json!({
        "challenge": challenge, "collection": collection, "item": item, "hop": memo.hop,
        "txid": txid, "action": action, "cmx": cmx, "nullifier": nf,
        "vault_recipient": hex::encode(n.note.recipient().to_raw_address_bytes()),
        "ufvk": ufvk.encode(&network())?, "signature": hex::encode(<[u8;64]>::from(&signature)),
    });
    fs::write(output, serde_json::to_vec_pretty(&proof)?)?;
    println!(
        "CONTROL_PROOF collection={} item={} hop={} txid={} action={} proof_file={output}",
        collection, item, memo.hop, txid, action
    );
    Ok(())
}

fn listing_key(path: &str) -> Result<(Value, FullViewingKey)> {
    let proof: Value = serde_json::from_slice(&fs::read(path)?)?;
    let ufvk = UnifiedFullViewingKey::decode(
        &network(),
        proof["ufvk"].as_str().context("Missing seller UFVK")?,
    )
    .map_err(|_| anyhow!("Invalid seller UFVK"))?;
    Ok((
        proof,
        ufvk.orchard()
            .context("Seller proof has no Orchard key")?
            .clone(),
    ))
}

pub(crate) fn sale_prepare(
    url: &str,
    seller_proof_file: &str,
    buyer_funding_wallet: &str,
    buyer_funding_identity: &str,
    buyer_vault_address: &str,
    seller_payment_address: &str,
    price: u64,
    output: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    ensure!(price > 0, "Sale price must be positive");
    let (seller_proof, seller_fvk) = listing_key(seller_proof_file)?;
    let collection = seller_proof["collection"]
        .as_str()
        .context("Missing seller collection")?;
    let item = seller_proof["item"]
        .as_u64()
        .context("Missing seller item")?;
    let hop = seller_proof["hop"].as_u64().context("Missing seller hop")?;
    let origin = seller_proof["txid"]
        .as_str()
        .context("Missing seller txid")?;
    let origin_action = seller_proof["action"]
        .as_u64()
        .context("Missing seller action")? as usize;
    let seller_txs = load_chain_for_key(url, &seller_fvk, secondary_url)?;
    let origin_tx = seller_txs
        .iter()
        .find(|t| t.txid == origin)
        .context("Seller item transaction not mined")?;
    let carrier = &origin_tx
        .notes
        .iter()
        .find(|(i, n)| *i == origin_action && n.owned)
        .context("Seller proof note is not owned by seller UFVK")?
        .1;
    let seller_recipient = carrier.note.recipient().to_raw_address_bytes();
    let seller_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|t| t.notes.iter())
        .filter(|(_, n)| n.owned && n.note.recipient().to_raw_address_bytes() == seller_recipient)
        .collect();
    ensure!(
        seller_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_notes.len()
    );
    let old_memo =
        parse_carrier_memo(&carrier.memo).context("Seller note is not a carrier item")?;
    ensure!(
        old_memo.collection == collection && old_memo.item == Some(item) && old_memo.hop == hop,
        "Seller proof metadata does not match its note"
    );
    ensure!(
        seller_proof["nullifier"] == hex::encode(carrier.note.nullifier(&seller_fvk).to_bytes()),
        "Seller proof nullifier does not match its note"
    );
    ensure!(
        carrier.note.value().inner() == 0,
        "Carrier must have zero value"
    );
    let buyer_usk = spending_key(buyer_funding_wallet, buyer_funding_identity)?;
    let buyer_fvk = orchard::keys::FullViewingKey::from(buyer_usk.orchard());
    ensure!(
        buyer_fvk.to_bytes() != seller_fvk.to_bytes(),
        "Buyer funding wallet must be separate from seller vault"
    );
    let buyer_txs = load_chain_for_key(url, &buyer_fvk, secondary_url)?;
    let spent: HashSet<_> = buyer_txs
        .iter()
        .flat_map(|t| t.nullifiers.iter().cloned())
        .collect();
    let (funding_tx, funding_index, funding_note) = buyer_txs
        .iter()
        .flat_map(|t| t.notes.iter().map(move |(i, n)| (t, *i, n)))
        .find(|(_, _, n)| {
            n.owned
                && n.note.value().inner() > price.saturating_add(15000)
                && !spent.contains(&hex::encode(n.note.nullifier(&buyer_fvk).to_bytes()))
        })
        .context("Need a buyer funding note covering price and ZIP-317 fee")?;
    let buyer_vault = UnifiedAddress::decode(&network(), buyer_vault_address)
        .context("Invalid buyer vault address")?;
    let buyer_vault = *buyer_vault
        .orchard()
        .context("Buyer vault has no Orchard receiver")?;
    ensure!(
        buyer_vault.to_raw_address_bytes() != seller_recipient
            && buyer_fvk.scope_for_address(&buyer_vault).is_none(),
        "Buyer vault must be fresh and separate from the seller vault"
    );
    let seller_payment = UnifiedAddress::decode(&network(), seller_payment_address)
        .context("Invalid seller payment address")?;
    let seller_payment = *seller_payment
        .orchard()
        .context("Seller payment has no Orchard receiver")?;
    let carrier_path = witness(&seller_txs, origin, origin_action)?;
    let funding_path = witness(&seller_txs, &funding_tx.txid, funding_index)?;
    let anchor = carrier_path.root(carrier.note.commitment().into());
    ensure!(
        funding_path.root(funding_note.note.commitment().into()) == anchor,
        "Witness anchors differ"
    );
    let successor_memo = carrier_memo(
        collection,
        item,
        hop.checked_add(1).context("Hop overflow")?,
    )?;
    let tip = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No tip")? as u32;
    let proving_key =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let mut fee_probe = Builder::new(
        network(),
        BlockHeight::from_u32(tip + 1),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    fee_probe
        .add_ironwood_spend::<Infallible>(seller_fvk.clone(), carrier.note, carrier_path.clone())
        .map_err(|e| anyhow!("Carrier fee probe input: {e:?}"))?;
    fee_probe
        .add_ironwood_spend::<Infallible>(
            buyer_fvk.clone(),
            funding_note.note,
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Buyer fee probe input: {e:?}"))?;
    fee_probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_vault,
            Zatoshis::ZERO,
            successor_memo.clone(),
        )
        .map_err(|e| anyhow!("Carrier fee probe output: {e:?}"))?;
    fee_probe
        .add_ironwood_output::<Infallible>(
            None,
            seller_payment,
            Zatoshis::from_u64(price)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Seller fee probe output: {e:?}"))?;
    fee_probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Buyer fee probe output: {e:?}"))?;
    let fee_zat = fee_probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Sale fee calculation: {e:?}"))?
        .into_u64();
    let change = funding_note
        .note
        .value()
        .inner()
        .checked_sub(price + fee_zat)
        .context("Buyer funding note is too small")?;
    for candidate in 1..=64 {
        let mut b = Builder::new(
            network(),
            BlockHeight::from_u32(tip + 1),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        b.add_ironwood_spend::<Infallible>(seller_fvk.clone(), carrier.note, carrier_path.clone())
            .map_err(|e| anyhow!("Carrier input: {e:?}"))?;
        b.add_ironwood_spend::<Infallible>(
            buyer_fvk.clone(),
            funding_note.note,
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Buyer funding input: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(
            None,
            buyer_vault,
            Zatoshis::ZERO,
            successor_memo.clone(),
        )
        .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(
            None,
            seller_payment,
            Zatoshis::from_u64(price)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Seller payment output: {e:?}"))?;
        b.add_ironwood_output::<Infallible>(
            Some(buyer_fvk.to_ovk(Scope::External)),
            buyer_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::from_u64(change)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Buyer change output: {e:?}"))?;
        let built = b
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .map_err(|e| anyhow!("Sale PCZT build: {e:?}"))?;
        let carrier_action = built
            .ironwood_meta
            .spend_action_index(0)
            .context("No carrier action")?;
        let carrier_output = built
            .ironwood_meta
            .output_action_index(0)
            .context("No carrier output action")?;
        if carrier_action != carrier_output {
            println!(
                "SALE_CONSTRUCTION candidate={candidate} carrier_input_action={carrier_action} requested_successor_action={carrier_output}"
            );
            continue;
        }
        let buyer_action = built
            .ironwood_meta
            .spend_action_index(1)
            .context("No buyer funding action")?;
        let pczt =
            Creator::build_from_parts(built.pczt_parts).context("PCZT version unsupported")?;
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .map_err(|e| anyhow!("Sale IO finalization: {e:?}"))?;
        let pczt = Prover::new(pczt)
            .create_ironwood_proof(UnwrapErr(SysRng), &proving_key)
            .map_err(|e| anyhow!("Sale Ironwood proof: {e:?}"))?
            .finish();
        let mut signer = Signer::new(pczt).map_err(|e| anyhow!("Buyer signer setup: {e:?}"))?;
        signer
            .sign_ironwood(
                UnwrapErr(SysRng),
                buyer_action,
                &SpendAuthorizingKey::from(buyer_usk.orchard()),
            )
            .map_err(|e| anyhow!("Buyer funding signature: {e:?}"))?;
        let pczt = Redactor::new(signer.finish())
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(buyer_action, |mut action| {
                    action.clear_spend_fvk();
                    action.clear_spend_rho();
                    action.clear_spend_rseed();
                    action.clear_spend_witness();
                    action.clear_spend_alpha();
                    action.clear_spend_zip32_derivation();
                    action.clear_spend_proprietary();
                });
            })
            .finish();
        fs::write(
            output,
            pczt.serialize()
                .map_err(|e| anyhow!("Sale PCZT serialization: {e:?}"))?,
        )?;
        let manifest = json!({
            "collection": collection, "item": item, "hop": hop + 1,
            "origin_txid": origin, "origin_action": origin_action,
            "carrier_action": carrier_action, "buyer_action": buyer_action,
            "price_zat": price,
        });
        fs::write(
            format!("{output}.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        println!(
            "SALE_PCZT_READY collection={} item={} carrier_action={} buyer_action={} price_zat={} buyer_signature=APPLIED private_buyer_fields=REDACTED pczt_file={output}",
            collection, item, carrier_action, buyer_action, price
        );
        return Ok(());
    }
    bail!("No same-Action sale candidate constructed; nothing signed or broadcast")
}

pub(crate) fn sale_sign(
    url: &str,
    seller_proof_file: &str,
    seller_wallet: &str,
    seller_identity: &str,
    seller_payment_address: &str,
    price: u64,
    carrier_action: usize,
    buyer_action: usize,
    input: &str,
    output: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    let (seller_proof, seller_fvk) = listing_key(seller_proof_file)?;
    let seller_txs = load_chain_for_key(url, &seller_fvk, secondary_url)?;
    let seller_txid = seller_proof["txid"]
        .as_str()
        .context("Missing seller txid")?;
    let seller_action = seller_proof["action"]
        .as_u64()
        .context("Missing seller action")? as usize;
    let seller_tx = seller_txs
        .iter()
        .find(|t| t.txid == seller_txid)
        .context("Seller proof transaction not mined")?;
    let seller_note = &seller_tx
        .notes
        .iter()
        .find(|(i, n)| *i == seller_action && n.owned)
        .context("Seller proof note is not owned by seller key")?
        .1;
    ensure!(
        seller_proof["nullifier"]
            == hex::encode(seller_note.note.nullifier(&seller_fvk).to_bytes()),
        "Seller proof nullifier is stale"
    );
    let collection = seller_proof["collection"]
        .as_str()
        .context("Missing seller collection")?;
    let item = seller_proof["item"]
        .as_u64()
        .context("Missing seller item")?;
    let hop = seller_proof["hop"].as_u64().context("Missing seller hop")?;
    let seller_memo =
        parse_carrier_memo(&seller_note.memo).context("Seller note is not a carrier item")?;
    ensure!(
        seller_memo.collection == collection
            && seller_memo.item == Some(item)
            && seller_memo.hop == hop,
        "Seller proof metadata does not match its note"
    );
    ensure!(
        seller_note.note.value().inner() == 0,
        "Seller carrier value is not zero"
    );
    let seller_recipient = seller_note.note.recipient().to_raw_address_bytes();
    ensure!(
        seller_proof["vault_recipient"] == hex::encode(seller_recipient),
        "Seller proof vault recipient is stale"
    );
    let seller_vault_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|t| t.notes.iter())
        .filter(|(_, n)| n.owned && n.note.recipient().to_raw_address_bytes() == seller_recipient)
        .collect();
    ensure!(
        seller_vault_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_vault_notes.len()
    );
    let seller_vault_nullifiers: HashSet<_> = seller_txs
        .iter()
        .flat_map(|t| t.notes.iter())
        .filter(|(_, n)| n.owned && n.note.recipient().to_raw_address_bytes() == seller_recipient)
        .map(|(_, n)| hex::encode(n.note.nullifier(&seller_fvk).to_bytes()))
        .collect();
    let seller_nullifier = hex::encode(seller_note.note.nullifier(&seller_fvk).to_bytes());
    ensure!(
        !seller_txs
            .iter()
            .any(|t| { t.txid != seller_txid && t.nullifiers.contains(&seller_nullifier) }),
        "Seller item is already spent"
    );
    let pczt = Pczt::parse(&fs::read(input)?).map_err(|e| anyhow!("Invalid sale PCZT: {e:?}"))?;
    let actions = pczt.ironwood().actions();
    ensure!(
        carrier_action < actions.len() && buyer_action < actions.len(),
        "Sale action index out of range"
    );
    ensure!(
        carrier_action != buyer_action,
        "Carrier and buyer actions must differ"
    );
    let expected_nullifier: [u8; 32] = hex::decode(&seller_nullifier)?
        .try_into()
        .map_err(|_| anyhow!("Invalid seller nullifier"))?;
    ensure!(
        actions[carrier_action].spend().nullifier() == &expected_nullifier,
        "Sale carrier input does not match seller proof"
    );
    ensure!(
        actions[carrier_action].spend().spend_auth_sig().is_none(),
        "Seller carrier action is already signed"
    );
    ensure!(
        actions[buyer_action].spend().spend_auth_sig().is_some(),
        "Buyer funding signature is missing"
    );
    let carrier_output = actions[carrier_action].output();
    ensure!(
        carrier_output.value().as_ref() == Some(&0u64),
        "Sale carrier output must be zero value"
    );
    let carrier_recipient = carrier_output
        .recipient()
        .as_ref()
        .context("Sale carrier recipient is missing")?;
    ensure!(
        carrier_recipient != &seller_recipient,
        "Sale carrier output must leave the seller vault"
    );
    let seller_payment = UnifiedAddress::decode(&network(), seller_payment_address)
        .context("Invalid seller payment address")?;
    let seller_payment = *seller_payment
        .orchard()
        .context("Seller payment has no Orchard receiver")?;
    let mut inputs = 0u64;
    let mut outputs = 0u64;
    let mut matching_payments = 0usize;
    let mut seller_payment_outputs = 0usize;
    let vault_spends = actions
        .iter()
        .filter(|action| {
            seller_vault_nullifiers.contains(&hex::encode(action.spend().nullifier()))
        })
        .count();
    ensure!(
        vault_spends == 1,
        "REFUSED sale must spend exactly one seller vault note"
    );
    Verifier::new(pczt.clone())
        .with_ironwood::<String, _>(|bundle| {
            bundle.verify_cross_address_restriction()?;
            for (index, action) in bundle.actions().iter().enumerate() {
                action.verify_cv_net()?;
                if index == carrier_action {
                    action.spend().verify_nullifier(Some(&seller_fvk))?;
                    action.spend().verify_rk(Some(&seller_fvk))?;
                }
                action.output().verify_note_commitment(action.spend())?;
                let input_value = action
                    .spend()
                    .value()
                    .as_ref()
                    .ok_or_else(|| OrchardError::Custom("Sale input value was stripped".into()))?
                    .inner();
                let output_value = action
                    .output()
                    .value()
                    .as_ref()
                    .ok_or_else(|| OrchardError::Custom("Sale output value missing".into()))?
                    .inner();
                inputs = inputs
                    .checked_add(input_value)
                    .ok_or_else(|| OrchardError::Custom("Sale input sum overflow".into()))?;
                outputs = outputs
                    .checked_add(output_value)
                    .ok_or_else(|| OrchardError::Custom("Sale output sum overflow".into()))?;
                if let Some(to) = action.output().recipient().as_ref() {
                    if *to == seller_payment {
                        seller_payment_outputs += 1;
                    }
                    let recipient_raw = to.to_raw_address_bytes();
                    let expected_raw = seller_payment.to_raw_address_bytes();
                    if payment_matches(
                        Some(&recipient_raw),
                        Some(output_value),
                        &expected_raw,
                        price,
                    ) {
                        matching_payments += 1;
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| anyhow!("Sale approval check: {e:?}"))?;
    ensure!(
        seller_payment_outputs == 1 && matching_payments == 1,
        "REFUSED seller payment does not match listed price exactly once"
    );
    let expected_fee = zip317::FeeRule::standard().marginal_fee().into_u64()
        * max(zip317::FeeRule::standard().grace_actions(), actions.len()) as u64;
    ensure!(
        inputs.checked_sub(outputs) == Some(expected_fee),
        "REFUSED sale fee is not standard ZIP-317"
    );
    println!(
        "SALE_CHECK payment=VERIFIED price_zat={} fee_zat={} buyer_signature=VERIFIED seller_signature=EMPTY",
        price, expected_fee
    );
    let seller_usk = spending_key(seller_wallet, seller_identity)?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("Seller signer setup: {e:?}"))?;
    signer
        .sign_ironwood(
            UnwrapErr(SysRng),
            carrier_action,
            &SpendAuthorizingKey::from(seller_usk.orchard()),
        )
        .map_err(|e| anyhow!("Seller carrier signature: {e:?}"))?;
    let tx = TransactionExtractor::new(signer.finish())
        .extract(UnwrapErr(SysRng))
        .map_err(|e| anyhow!("Sale extraction: {e:?}"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    fs::write(output, raw)?;
    println!(
        "ATOMIC_SALE txid={} carrier_action={} buyer_action={} payment_zat={} fee_zat={} raw_file={output}",
        tx.txid(),
        carrier_action,
        buyer_action,
        price,
        expected_fee
    );
    Ok(())
}

const AUCTION_MEMO_PREFIX: &str = "ZEC-A2";

fn auction_commitment(auction_id: &str, bidder_id: &str, bid_zat: u64, nonce: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"zecathon-auction-bid-v1|");
    hash.update(auction_id.as_bytes());
    hash.update(b"|");
    hash.update(bidder_id.as_bytes());
    hash.update(b"|");
    hash.update(bid_zat.to_string().as_bytes());
    hash.update(b"|");
    hash.update(nonce.as_bytes());
    hex::encode(hash.finalize())
}

fn auction_memo(auction_id: &str, bidder_id: &str, commitment: &str) -> Result<MemoBytes> {
    ensure!(
        !auction_id.is_empty()
            && !bidder_id.is_empty()
            && !auction_id.contains('|')
            && !bidder_id.contains('|')
            && commitment.len() == 64
            && commitment.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid auction commitment fields"
    );
    Ok(MemoBytes::from_bytes(
        format!("{AUCTION_MEMO_PREFIX}|{auction_id}|{bidder_id}|{commitment}").as_bytes(),
    )?)
}

fn auction_address(value: &str, label: &str) -> Result<Address> {
    let address = UnifiedAddress::decode(&network(), value)
        .with_context(|| format!("Invalid {label} address"))?;
    Ok(*address
        .orchard()
        .with_context(|| format!("{label} address has no Orchard receiver"))?)
}

fn parse_auction_memo(memo: &[u8; 512]) -> Option<(String, String, String)> {
    let mut fields = memo_text(memo).split('|');
    if fields.next()? != AUCTION_MEMO_PREFIX {
        return None;
    }
    let auction_id = fields.next()?.to_owned();
    let bidder_id = fields.next()?.to_owned();
    let commitment = fields.next()?.to_owned();
    if fields.next().is_some()
        || auction_id.is_empty()
        || bidder_id.is_empty()
        || commitment.len() != 64
        || !commitment.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((auction_id, bidder_id, commitment))
}

pub(crate) fn auction_bid(
    url: &str,
    bidder_wallet: &str,
    bidder_identity: &str,
    escrow_address: &str,
    auction_id: &str,
    bidder_id: &str,
    bid_zat: u64,
    nonce: &str,
    refund_address: &str,
    output: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    ensure!(bid_zat > 0, "Bid must be positive");
    ensure!(!nonce.is_empty(), "Bid nonce must be non-empty");
    ensure_regtest_chain(url)?;
    if let Some(secondary_url) = secondary_url {
        ensure_regtest_chain(secondary_url)?;
    }
    let bidder_usk = spending_key(bidder_wallet, bidder_identity)?;
    let bidder_fvk = orchard::keys::FullViewingKey::from(bidder_usk.orchard());
    let bidder_txs = load_chain_for_key(url, &bidder_fvk, secondary_url)?;
    let spent: HashSet<_> = bidder_txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    let (funding_tx, funding_index, funding_note) = bidder_txs
        .iter()
        .flat_map(|tx| tx.notes.iter().map(move |(index, note)| (tx, *index, note)))
        .find(|(_, _, note)| {
            note.owned
                && note.note.value().inner() > bid_zat.saturating_add(15000)
                && !spent.contains(&hex::encode(note.note.nullifier(&bidder_fvk).to_bytes()))
        })
        .context("Need an unspent bidder note covering bid and fee")?;
    let escrow = auction_address(escrow_address, "escrow")?;
    let refund = auction_address(refund_address, "refund")?;
    ensure!(
        bidder_fvk.scope_for_address(&escrow).is_none()
            && bidder_fvk.scope_for_address(&refund).is_some(),
        "Refund address must belong to bidder wallet and escrow must be separate"
    );
    let commitment = auction_commitment(auction_id, bidder_id, bid_zat, nonce);
    let bid_memo = auction_memo(auction_id, bidder_id, &commitment)?;
    let funding_path = witness(&bidder_txs, &funding_tx.txid, funding_index)?;
    let anchor = funding_path.root(funding_note.note.commitment().into());
    let tip = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No tip")? as u32;
    let mut fee_probe = Builder::new(
        network(),
        BlockHeight::from_u32(tip + 1),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    fee_probe
        .add_ironwood_spend::<Infallible>(
            bidder_fvk.clone(),
            funding_note.note,
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Bid fee probe input: {e:?}"))?;
    fee_probe
        .add_ironwood_output::<Infallible>(
            None,
            escrow,
            Zatoshis::from_u64(bid_zat)?,
            bid_memo.clone(),
        )
        .map_err(|e| anyhow!("Bid escrow output: {e:?}"))?;
    fee_probe
        .add_ironwood_output::<Infallible>(
            Some(bidder_fvk.to_ovk(Scope::External)),
            bidder_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::from_u64(1)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Bid change output: {e:?}"))?;
    let fee_zat = fee_probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Bid fee calculation: {e:?}"))?
        .into_u64();
    let change = funding_note
        .note
        .value()
        .inner()
        .checked_sub(bid_zat + fee_zat)
        .context("Bidder note is too small after fee")?;
    let prover = LocalTxProver::bundled();
    let mut builder = Builder::new(
        network(),
        BlockHeight::from_u32(tip + 1),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<Infallible>(bidder_fvk.clone(), funding_note.note, funding_path)
        .map_err(|e| anyhow!("Bid input: {e:?}"))?;
    builder
        .add_ironwood_output::<Infallible>(
            None,
            escrow,
            Zatoshis::from_u64(bid_zat)?,
            bid_memo,
        )
        .map_err(|e| anyhow!("Bid escrow output: {e:?}"))?;
    builder
        .add_ironwood_output::<Infallible>(
            Some(bidder_fvk.to_ovk(Scope::External)),
            bidder_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::from_u64(change)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Bid change output: {e:?}"))?;
    let built = builder
        .build(
            &transparent::builder::TransparentSigningSet::new(),
            &[],
            &[SpendAuthorizingKey::from(bidder_usk.orchard())],
            UnwrapErr(SysRng),
            &prover,
            &prover,
            &zip317::FeeRule::standard(),
        )
        .map_err(|e| anyhow!("Bid build: {e:?}"))?;
    let tx = built.transaction();
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    fs::write(output, raw)?;
    fs::write(
        format!("{output}.json"),
        serde_json::to_vec_pretty(&json!({
            "auction_id": auction_id,
            "bidder": bidder_id,
            "bid_zat": bid_zat,
            "nonce": nonce,
            "commitment": commitment,
            "refund_address": refund_address,
            "commit_txid": tx.txid().to_string(),
        }))?,
    )?;
    println!(
        "AUCTION_BID_READY auction={} bidder={} bid_zat={} commitment={} fee_zat={} raw_file={} reveal_file={}.json txid={}",
        auction_id, bidder_id, bid_zat, commitment, fee_zat, output, output, tx.txid()
    );
    Ok(())
}

pub(crate) fn auction_settle(
    url: &str,
    seller_wallet: &str,
    seller_identity: &str,
    origin: &str,
    origin_action: usize,
    escrow_wallet: &str,
    escrow_identity: &str,
    funding_wallet: &str,
    funding_identity: &str,
    winner_vault_address: &str,
    seller_payment_address: &str,
    auction_id: &str,
    close_height: u32,
    reveals_file: &str,
    output: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    ensure_regtest_chain(url)?;
    if let Some(secondary_url) = secondary_url {
        ensure_regtest_chain(secondary_url)?;
    }
    let tip = rpc(url, "getblockcount", json!([]))?
        .as_u64()
        .context("No tip")? as u32;
    ensure!(
        tip >= close_height,
        "Auction is not closed: tip={} close_height={close_height}",
        tip
    );
    let reveals: Vec<Value> = serde_json::from_slice(&fs::read(reveals_file)?)?;
    ensure!(!reveals.is_empty(), "Auction needs at least one reveal");

    let seller_usk = spending_key(seller_wallet, seller_identity)?;
    let seller_fvk = orchard::keys::FullViewingKey::from(seller_usk.orchard());
    let escrow_usk = spending_key(escrow_wallet, escrow_identity)?;
    let escrow_fvk = orchard::keys::FullViewingKey::from(escrow_usk.orchard());
    let funding_usk = spending_key(funding_wallet, funding_identity)?;
    let funding_fvk = orchard::keys::FullViewingKey::from(funding_usk.orchard());
    ensure!(
        seller_fvk.to_bytes() != escrow_fvk.to_bytes()
            && seller_fvk.to_bytes() != funding_fvk.to_bytes()
            && escrow_fvk.to_bytes() != funding_fvk.to_bytes(),
        "Seller, escrow and fee wallets must be separate"
    );
    let seller_txs = load_chain_for_key(url, &seller_fvk, secondary_url)?;
    let escrow_txs = load_chain_for_key(url, &escrow_fvk, secondary_url)?;
    let funding_txs = load_chain_for_key(url, &funding_fvk, secondary_url)?;
    let origin_tx = seller_txs
        .iter()
        .find(|tx| tx.txid == origin)
        .context("Seller carrier transaction not found")?;
    let carrier = &origin_tx
        .notes
        .iter()
        .find(|(index, note)| *index == origin_action && note.owned)
        .context("Seller carrier is not owned")?
        .1;
    let seller_recipient = carrier.note.recipient().to_raw_address_bytes();
    let seller_vault_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.notes.iter())
        .filter(|(_, note)| {
            note.owned && note.note.recipient().to_raw_address_bytes() == seller_recipient
        })
        .collect();
    ensure!(
        seller_vault_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_vault_notes.len()
    );
    let carrier_meta =
        parse_carrier_memo(&carrier.memo).context("Seller note is not a carrier")?;
    let item = carrier_meta.item.context("Seller note is not an item")?;
    ensure!(
        carrier.note.value().inner() == 0,
        "Seller carrier must be zero value"
    );
    let seller_nullifier = hex::encode(carrier.note.nullifier(&seller_fvk).to_bytes());
    ensure!(
        !seller_txs
            .iter()
            .any(|tx| tx.txid != origin && tx.nullifiers.contains(&seller_nullifier)),
        "Seller carrier is already spent"
    );
    let winner_vault = auction_address(winner_vault_address, "winner vault")?;
    let seller_payment = auction_address(seller_payment_address, "seller payment")?;
    ensure!(
        winner_vault.to_raw_address_bytes() != seller_recipient
            && seller_fvk.scope_for_address(&winner_vault).is_none()
            && seller_payment.to_raw_address_bytes() != seller_recipient,
        "Winner vault and seller payment must be outside the seller item vault"
    );
    let carrier_path = witness(&seller_txs, origin, origin_action)?;
    let anchor = carrier_path.root(carrier.note.commitment().into());
    let escrow_spent: HashSet<_> = escrow_txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    let mut bidders = Vec::new();
    let mut bidder_ids = HashSet::new();
    for reveal in reveals {
        let bidder = reveal["bidder"].as_str().context("Reveal missing bidder")?;
        let bid_zat = reveal["bid_zat"].as_u64().context("Reveal missing bid")?;
        let nonce = reveal["nonce"].as_str().context("Reveal missing nonce")?;
        let commitment = reveal["commitment"]
            .as_str()
            .context("Reveal missing commitment")?;
        let refund_address = reveal["refund_address"]
            .as_str()
            .context("Reveal missing refund")?;
        ensure!(bidder_ids.insert(bidder.to_owned()), "Duplicate bidder reveal");
        ensure!(
            auction_commitment(auction_id, bidder, bid_zat, nonce) == commitment,
            "Reveal commitment mismatch for bidder={bidder}"
        );
        let refund = auction_address(refund_address, "refund")?;
        let commit_txid = reveal["commit_txid"]
            .as_str()
            .context("Reveal missing commit txid")?;
        let matches: Vec<_> = escrow_txs
            .iter()
            .flat_map(|tx| tx.notes.iter().map(move |(index, note)| (tx, *index, note)))
            .filter(|(tx, _, note)| {
                tx.height <= u64::from(close_height)
                    && note.owned
                    && tx.txid == commit_txid
                    && note.note.value().inner() == bid_zat
                    && parse_auction_memo(&note.memo).is_some_and(
                        |(memo_auction, memo_bidder, memo_commitment)| {
                            memo_auction == auction_id
                                && memo_bidder == bidder
                                && memo_commitment == commitment
                        },
                    )
            })
            .collect();
        ensure!(
            matches.len() == 1,
            "Reveal commit note not found exactly once for bidder={bidder}"
        );
        let (tx, index, note) = matches[0];
        let nullifier = hex::encode(note.note.nullifier(&escrow_fvk).to_bytes());
        ensure!(
            !escrow_spent.contains(&nullifier),
            "Reveal commit note already spent"
        );
        ensure!(
            witness(&escrow_txs, &tx.txid, index)?
                .root(note.note.commitment().into())
                == anchor,
            "Escrow witness anchor differs"
        );
        println!(
            "AUCTION_REVEAL auction={} bidder={} bid_zat={} commitment=VALID commit_txid={} close_height={}",
            auction_id, bidder, bid_zat, commit_txid, close_height
        );
        bidders.push((
            bidder.to_owned(),
            bid_zat,
            refund,
            note.note,
            tx.txid.clone(),
            index,
        ));
    }
    ensure!(bidders.len() >= 2, "Auction needs at least two revealed bids");
    bidders.sort_by_key(|(_, bid, _, _, _, _)| std::cmp::Reverse(*bid));
    ensure!(
        bidders[0].1 > bidders[1].1,
        "Auction tie requires an explicit tie-break rule"
    );
    let winner = &bidders[0];
    let successor_memo = carrier_memo(
        &carrier_meta.collection,
        item,
        carrier_meta.hop + 1,
    )?;
    let funding_spent: HashSet<_> = funding_txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    let (funding_tx, funding_index, funding_note) = funding_txs
        .iter()
        .flat_map(|tx| tx.notes.iter().map(move |(index, note)| (tx, *index, note)))
        .find(|(_, _, note)| {
            note.owned
                && note.note.value().inner() > 15000
                && !funding_spent.contains(&hex::encode(note.note.nullifier(&funding_fvk).to_bytes()))
        })
        .context("Need a separate fee-wallet note")?;
    let funding_path = witness(&funding_txs, &funding_tx.txid, funding_index)?;
    ensure!(
        funding_path.root(funding_note.note.commitment().into()) == anchor,
        "Funding witness anchor differs"
    );
    let add_outputs = |builder: &mut Builder<_, _>, fee_change: u64| -> Result<()> {
        builder
            .add_ironwood_output::<Infallible>(
                None,
                winner_vault,
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("Winner carrier output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                seller_payment,
                Zatoshis::from_u64(winner.1)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Seller payment output: {e:?}"))?;
        for (_, bid, refund, _, _, _) in bidders.iter().skip(1) {
            builder
                .add_ironwood_output::<Infallible>(
                    None,
                    *refund,
                    Zatoshis::from_u64(*bid)?,
                    MemoBytes::empty(),
                )
                .map_err(|e| anyhow!("Refund output: {e:?}"))?;
        }
        builder
            .add_ironwood_output::<Infallible>(
                Some(funding_fvk.to_ovk(Scope::External)),
                funding_fvk.address_at(1u64, Scope::Internal),
                Zatoshis::from_u64(fee_change)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Fee-wallet change output: {e:?}"))?;
        Ok(())
    };
    let mut fee_probe = Builder::new(
        network(),
        BlockHeight::from_u32(tip + 1),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    fee_probe
        .add_ironwood_spend::<Infallible>(seller_fvk.clone(), carrier.note, carrier_path.clone())
        .map_err(|e| anyhow!("Auction carrier fee input: {e:?}"))?;
    for (_, _, _, note, txid, index) in &bidders {
        fee_probe
            .add_ironwood_spend::<Infallible>(
                escrow_fvk.clone(),
                *note,
                witness(&escrow_txs, txid, *index)?,
            )
            .map_err(|e| anyhow!("Auction escrow fee input: {e:?}"))?;
    }
    fee_probe
        .add_ironwood_spend::<Infallible>(
            funding_fvk.clone(),
            funding_note.note,
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Auction funding fee input: {e:?}"))?;
    add_outputs(&mut fee_probe, 1)?;
    let fee_zat = fee_probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Auction fee calculation: {e:?}"))?
        .into_u64();
    let fee_change = funding_note
        .note
        .value()
        .inner()
        .checked_sub(fee_zat)
        .context("Fee-wallet note is too small")?;
    let prover = LocalTxProver::bundled();
    let mut keys = Vec::with_capacity(bidders.len() + 2);
    keys.push(SpendAuthorizingKey::from(seller_usk.orchard()));
    for _ in &bidders {
        keys.push(SpendAuthorizingKey::from(escrow_usk.orchard()));
    }
    keys.push(SpendAuthorizingKey::from(funding_usk.orchard()));
    for candidate in 1..=64 {
        let mut builder = Builder::new(
            network(),
            BlockHeight::from_u32(tip + 1),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_ironwood_spend::<Infallible>(
                seller_fvk.clone(),
                carrier.note,
                carrier_path.clone(),
            )
            .map_err(|e| anyhow!("Auction carrier input: {e:?}"))?;
        for (_, _, _, note, txid, index) in &bidders {
            builder
                .add_ironwood_spend::<Infallible>(
                    escrow_fvk.clone(),
                    *note,
                    witness(&escrow_txs, txid, *index)?,
                )
                .map_err(|e| anyhow!("Auction escrow input: {e:?}"))?;
        }
        builder
            .add_ironwood_spend::<Infallible>(
                funding_fvk.clone(),
                funding_note.note,
                funding_path.clone(),
            )
            .map_err(|e| anyhow!("Auction funding input: {e:?}"))?;
        add_outputs(&mut builder, fee_change)?;
        let built = builder
            .build(
                &transparent::builder::TransparentSigningSet::new(),
                &[],
                &keys,
                UnwrapErr(SysRng),
                &prover,
                &prover,
                &zip317::FeeRule::standard(),
            )
            .map_err(|e| anyhow!("Auction settlement build: {e:?}"))?;
        let carrier_action = built
            .ironwood_meta()
            .spend_action_index(0)
            .context("No auction carrier action")?;
        let successor_action = built
            .ironwood_meta()
            .output_action_index(0)
            .context("No auction successor action")?;
        println!(
            "AUCTION_CONSTRUCTION candidate={} carrier_action={} successor_action={}",
            candidate, carrier_action, successor_action
        );
        if carrier_action != successor_action {
            continue;
        }
        let tx = built.transaction();
        let mut raw = Vec::new();
        tx.write(&mut raw)?;
        fs::write(output, raw)?;
        fs::write(
            format!("{output}.json"),
            serde_json::to_vec_pretty(&json!({
                "auction_id": auction_id,
                "close_height": close_height,
                "winner": winner.0,
                "winning_bid_zat": winner.1,
                "refund_count": bidders.len() - 1,
                "fee_zat": fee_zat,
                "txid": tx.txid().to_string(),
                "carrier_action": carrier_action,
                "successor_action": successor_action,
            }))?,
        )?;
        println!(
            "AUCTION_SETTLEMENT_READY auction={} winner={} winning_bid_zat={} refunds={} close_height={} tip={} txid={} carrier_action={} fee_zat={} raw_file={}",
            auction_id,
            winner.0,
            winner.1,
            bidders.len() - 1,
            close_height,
            tip,
            tx.txid(),
            carrier_action,
            fee_zat,
            output
        );
        return Ok(());
    }
    bail!("No same-Action auction settlement candidate constructed; nothing broadcast")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_seller_rejects_wrong_payment_amount_or_recipient() {
        let seller_payment = [7u8; 43];
        let wrong_recipient = [8u8; 43];
        assert!(payment_matches(
            Some(&seller_payment),
            Some(100_000),
            &seller_payment,
            100_000
        ));
        assert!(!payment_matches(
            Some(&seller_payment),
            Some(99_999),
            &seller_payment,
            100_000
        ));
        assert!(!payment_matches(
            Some(&wrong_recipient),
            Some(100_000),
            &seller_payment,
            100_000
        ));
    }

    #[test]
    fn auction_commitment_binds_bid_fields() {
        let first = auction_commitment("lagos-lights-auction", "bidder-a", 100_000, "nonce-a");
        assert_eq!(first.len(), 64);
        assert_ne!(
            first,
            auction_commitment("lagos-lights-auction", "bidder-a", 100_001, "nonce-a")
        );
        assert_ne!(
            first,
            auction_commitment("lagos-lights-auction", "bidder-b", 100_000, "nonce-a")
        );
    }
}
