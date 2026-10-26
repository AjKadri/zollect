#![cfg(all(feature = "mainnet", feature = "sender"))]

use super::*;
use crate::lightwalletd::MainnetLightwalletd;
use anyhow::{Context, Result, ensure};
use bip0039::{English, Mnemonic};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{keys::SpendAuthorizingKey, tree::MerkleHashOrchard};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    io::Read,
    path::Path,
};
use transparent::builder::TransparentSigningSet;
use zcash_client_backend::proto::service::RawTransaction;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::{
    transaction::fees::zip317,
    transaction::{
        Transaction,
        builder::{BuildConfig, Builder, BundlePadding},
    },
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MAIN_NETWORK, MainNetwork},
    memo::MemoBytes,
    value::Zatoshis,
};
use zeroize::Zeroizing;

const M2_CAP_ZAT: u64 = 200_000;
const M2_TX_FEE_CAP_ZAT: u64 = 20_000;
const ISSUER_BOOTSTRAP_ZAT: u64 = 10_000;

fn spending_key(wallet: &str, identity: &str) -> Result<UnifiedSpendingKey> {
    let config: toml::Value =
        toml::from_str(&fs::read_to_string(Path::new(wallet).join("keys.toml"))?)?;
    ensure!(
        config["network"].as_str() == Some("main"),
        "Only mainnet wallets accepted"
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
    UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed[..], zip32::AccountId::ZERO)
        .map_err(|_| anyhow!("Unable to derive mainnet account"))
}

fn address(address: &str) -> Result<orchard::Address> {
    let unified = UnifiedAddress::decode(&MAIN_NETWORK, address.trim())
        .map_err(|_| anyhow!("Invalid mainnet recipient address"))?;
    unified
        .orchard()
        .copied()
        .context("Mainnet address has no Orchard receiver")
}

fn load_chain(
    servers: &MainnetLightwalletd,
    birthday: u32,
    fvk: &FullViewingKey,
) -> Result<(Vec<ChainTx>, CommitmentTree<MerkleHashOrchard, 32>)> {
    let (_, tree_state, rows) = servers.consistent_chain_data(birthday)?;
    let initial_tree = tree_state
        .ironwood_tree()
        .map_err(|e| anyhow!("Invalid Ironwood tree state: {e:?}"))?;
    let txs = decode_chain(&rows, fvk)?;
    Ok((txs, initial_tree))
}

fn decode_chain(
    rows: &[(u32, Vec<u8>, RawTransaction)],
    fvk: &FullViewingKey,
) -> Result<Vec<ChainTx>> {
    let ivks = [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)];
    let ovks = [fvk.to_ovk(Scope::External), fvk.to_ovk(Scope::Internal)];
    let mut txs = Vec::new();
    for (height, _, raw) in rows {
        let height = BlockHeight::from_u32(*height);
        let tx = Transaction::read(
            raw.data.as_slice(),
            BranchId::for_height(&MAIN_NETWORK, height),
        )?;
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
            notes.sort_by_key(|(index, _)| *index);
            txs.push(ChainTx {
                txid: tx.txid().to_string(),
                height: u64::from(height),
                notes,
                nullifiers: bundle
                    .actions()
                    .iter()
                    .map(|action| hex::encode(action.nullifier().to_bytes()))
                    .collect(),
                commitments: bundle
                    .actions()
                    .iter()
                    .map(|action| action.cmx().to_bytes())
                    .collect(),
            });
        }
    }
    Ok(txs)
}

fn load_chain_pair(
    servers: &MainnetLightwalletd,
    birthday: u32,
    issuer_fvk: &FullViewingKey,
    funding_fvk: &FullViewingKey,
) -> Result<(
    Vec<ChainTx>,
    Vec<ChainTx>,
    CommitmentTree<MerkleHashOrchard, 32>,
)> {
    let (_, tree_state, rows) = servers.consistent_chain_data(birthday)?;
    let initial_tree = tree_state
        .ironwood_tree()
        .map_err(|e| anyhow!("Invalid Ironwood tree state: {e:?}"))?;
    let issuer_txs = decode_chain(&rows, issuer_fvk)?;
    let funding_txs = decode_chain(&rows, funding_fvk)?;
    Ok((issuer_txs, funding_txs, initial_tree))
}

fn witness(
    txs: &[ChainTx],
    initial_tree: CommitmentTree<MerkleHashOrchard, 32>,
    txid: &str,
    action: usize,
) -> Result<orchard::tree::MerklePath> {
    let mut tree = initial_tree;
    let mut result: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    for tx in txs {
        for (index, bytes) in tx.commitments.iter().enumerate() {
            let node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
                .context("Invalid commitment")?;
            if let Some(witness) = &mut result {
                witness
                    .append(node)
                    .map_err(|_| anyhow!("Witness tree full"))?;
            }
            tree.append(node)
                .map_err(|_| anyhow!("Witness tree full"))?;
            if tx.txid == txid && index == action {
                result = IncrementalWitness::from_tree(tree.clone());
            }
        }
    }
    Ok(result
        .context("No mainnet note witness")?
        .path()
        .context("No mainnet Merkle path")?
        .into())
}

fn unspent_positive(
    txs: &[ChainTx],
    fvk: &FullViewingKey,
) -> Result<(String, usize, Note, [u8; 512], u64)> {
    let spent: HashSet<_> = txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    txs.iter()
        .rev()
        .flat_map(|tx| tx.notes.iter().map(move |(index, note)| (tx, *index, note)))
        .find_map(|(tx, index, seen)| {
            let nullifier = hex::encode(seen.note.nullifier(fvk).to_bytes());
            (seen.owned && seen.note.value().inner() > 0 && !spent.contains(&nullifier)).then(
                || {
                    (
                        tx.txid.clone(),
                        index,
                        seen.note.clone(),
                        seen.memo,
                        seen.note.value().inner(),
                    )
                },
            )
        })
        .context("No unspent positive mainnet note")
}

fn block_height(snapshot_height: u64) -> Result<BlockHeight> {
    let next = snapshot_height
        .checked_add(1)
        .context("Mainnet height overflow")?;
    Ok(BlockHeight::from_u32(
        u32::try_from(next).context("Mainnet height exceeds u32")?,
    ))
}

fn build_signed(
    builder: Builder<MainNetwork, ()>,
    keys: &[SpendAuthorizingKey],
) -> Result<Transaction> {
    let prover = LocalTxProver::bundled();
    Ok(builder
        .build(
            &TransparentSigningSet::new(),
            &[],
            keys,
            UnwrapErr(SysRng),
            &prover,
            &prover,
            &zip317::FeeRule::standard(),
        )
        .map_err(|e| anyhow!("Mainnet build failed: {e:?}"))?
        .transaction()
        .clone())
}

fn mint_fee_shape(subject: &str) -> Result<(usize, usize, usize)> {
    let spends = 2;
    let outputs = if subject == "FINAL" { 2 } else { 3 };
    let actions = orchard::builder::BundleType::DEFAULT
        .num_actions(
            orchard::bundle::BundleVersion::ironwood_v3().default_flags(),
            spends,
            outputs,
        )
        .map_err(|e| anyhow!("Mint action count failed: {e}"))?;
    Ok((spends, outputs, actions))
}

fn final_mint_fee_zat(
    subject: &str,
    funding_value: u64,
    issuer_value: u64,
    funding_change: u64,
) -> Result<u64> {
    let input_value = if subject == "FINAL" {
        funding_value
            .checked_add(issuer_value)
            .context("Mint input value overflow")?
    } else {
        funding_value
    };
    input_value
        .checked_sub(funding_change)
        .context("Final mint transaction fee underflow")
}

pub(crate) fn write_ufvk(wallet: &str, identity: &str, output: &str) -> Result<()> {
    let usk = spending_key(wallet, identity)?;
    fs::write(
        output,
        usk.to_unified_full_viewing_key().encode(&MAIN_NETWORK)?,
    )?;
    println!("MAINNET_UFVK_WRITTEN");
    Ok(())
}

pub(crate) fn issuance(
    primary: &str,
    secondary: &str,
    issuer_ufvk: &str,
    collection: &str,
    birthday: u32,
) -> Result<()> {
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let text = fs::read_to_string(issuer_ufvk)?;
    let ufvk = UnifiedFullViewingKey::decode(&MAIN_NETWORK, text.trim())
        .map_err(|_| anyhow!("Invalid mainnet issuer UFVK"))?;
    let fvk = ufvk.orchard().context("Issuer UFVK has no Orchard key")?;
    let (txs, _) = load_chain(&servers, birthday, fvk)?;
    verify_issuance(&txs, fvk, collection, true).map(|_| ())
}

pub(crate) fn attest(
    primary: &str,
    secondary: &str,
    wallet: &str,
    identity: &str,
    txid: &str,
    action: usize,
    challenge: &str,
    output: &str,
    collection: &str,
    item: u64,
    txid_file: &str,
) -> Result<()> {
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let usk = spending_key(wallet, identity)?;
    let ufvk = usk.to_unified_full_viewing_key();
    let fvk = ufvk.orchard().context("No mainnet Orchard key")?;
    let txids = crate::read_known_txids(txid_file)?;
    let txs = crate::load_known_mainnet_transactions(&servers, &txids, fvk)?;
    let target = txs
        .iter()
        .find(|transaction| transaction.txid == txid)
        .context("No target mainnet transaction")?;
    let note = &target
        .notes
        .iter()
        .find(|(index, note)| *index == action && note.owned)
        .context("Mainnet key does not decrypt target note")?
        .1;
    let memo = parse_carrier_memo(&note.memo).context("Target is not a carrier item")?;
    ensure!(
        memo.collection == collection && memo.item == Some(item),
        "Target item metadata mismatch"
    );
    let cmx = hex::encode(
        *target
            .commitments
            .get(action)
            .context("Mainnet proof action out of range")?,
    );
    let nullifier = hex::encode(note.note.nullifier(fvk).to_bytes());
    let key =
        SpendAuthorizingKey::from(usk.orchard()).randomize(&pasta_curves::pallas::Scalar::from(0));
    let signature = key.sign(
        UnwrapErr(SysRng),
        &crate::ownership::message(challenge, txid, action, &cmx, &nullifier),
    );
    let proof = json!({
        "challenge": challenge, "collection": collection, "item": item, "hop": memo.hop,
        "txid": txid, "action": action, "cmx": cmx, "nullifier": nullifier,
        "vault_recipient": hex::encode(note.note.recipient().to_raw_address_bytes()),
        "ufvk": ufvk.encode(&MAIN_NETWORK)?, "signature": hex::encode(<[u8; 64]>::from(&signature)),
        "chain_txids": txids,
    });
    fs::write(output, serde_json::to_vec_pretty(&proof)?)?;
    println!(
        "CONTROL_PROOF collection={} item={} hop={} txid={} action={} proof_file={output}",
        collection, item, memo.hop, txid, action
    );
    Ok(())
}

pub(crate) fn mint(
    primary: &str,
    secondary: &str,
    issuer_wallet: &str,
    issuer_identity: &str,
    funding_wallet: &str,
    funding_identity: &str,
    birthday: u32,
    collection: &str,
    subject: &str,
    destination: &str,
    running_total: u64,
) -> Result<()> {
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let issuer_usk = spending_key(issuer_wallet, issuer_identity)?;
    let funding_usk = spending_key(funding_wallet, funding_identity)?;
    let issuer_fvk = FullViewingKey::from(issuer_usk.orchard());
    let funding_fvk = FullViewingKey::from(funding_usk.orchard());
    ensure!(
        issuer_fvk.to_bytes() != funding_fvk.to_bytes(),
        "Funding wallet must be separate from issuer wallet"
    );

    let snapshot = servers.consistent_snapshot()?;
    let height = block_height(snapshot.height)?;
    let (issuer_txs, funding_txs, initial_tree) =
        load_chain_pair(&servers, birthday, &issuer_fvk, &funding_fvk)?;
    let (funding_txid, funding_action, funding_note, _, funding_value) =
        unspent_positive(&funding_txs, &funding_fvk)?;
    let funding_path = witness(
        &funding_txs,
        initial_tree.clone(),
        &funding_txid,
        funding_action,
    )?;
    let funding_anchor = funding_path.root(funding_note.commitment().into());

    if subject == "BOOTSTRAP" {
        let recipient = address(destination)?;
        let change_address = funding_fvk.address_at(1u64, Scope::Internal);
        let mut probe = Builder::new(
            MAIN_NETWORK,
            height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(funding_anchor.into()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        probe
            .add_ironwood_spend::<Infallible>(
                funding_fvk.clone(),
                funding_note,
                funding_path.clone(),
            )
            .map_err(|e| anyhow!("Funding input: {e:?}"))?;
        probe
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::from_u64(ISSUER_BOOTSTRAP_ZAT)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Issuer bootstrap output: {e:?}"))?;
        probe
            .add_ironwood_output::<Infallible>(
                None,
                change_address,
                Zatoshis::ZERO,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Funding change probe: {e:?}"))?;
        let fee = probe
            .get_fee(&zip317::FeeRule::standard())
            .map_err(|e| anyhow!("Bootstrap fee calculation failed: {e:?}"))?
            .into_u64();
        let change = funding_value
            .checked_sub(ISSUER_BOOTSTRAP_ZAT + fee)
            .context("Funding note cannot cover issuer bootstrap and fee")?;
        let mut builder = Builder::new(
            MAIN_NETWORK,
            height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(funding_anchor.into()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_ironwood_spend::<Infallible>(funding_fvk.clone(), funding_note, funding_path)
            .map_err(|e| anyhow!("Funding input: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::from_u64(ISSUER_BOOTSTRAP_ZAT)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Issuer bootstrap output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                Some(funding_fvk.to_ovk(Scope::External)),
                change_address,
                Zatoshis::from_u64(change)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Funding change: {e:?}"))?;
        let tx = build_signed(builder, &[SpendAuthorizingKey::from(funding_usk.orchard())])?;
        let actual_fee = funding_value - ISSUER_BOOTSTRAP_ZAT - change;
        ensure!(
            actual_fee == fee,
            "Computed bootstrap fee changed during build"
        );
        let mut raw = Vec::new();
        tx.write(&mut raw)?;
        let projected = running_total
            .checked_add(fee)
            .context("M2 total overflow")?;
        println!(
            "FEE fee_zat={fee} running_total_before_zat={running_total} projected_total_zat={projected} cap_zat={M2_CAP_ZAT}"
        );
        ensure!(projected <= M2_CAP_ZAT, "ABORT M2 fee cap exceeded");
        servers.send_transaction(raw)?;
        println!(
            "BROADCAST txid={} fee_zat={fee} running_total_zat={projected} stage=bootstrap",
            tx.txid()
        );
        return Ok(());
    }

    let (issuer_txid, issuer_action, issuer_note, _, issuer_value) =
        unspent_positive(&issuer_txs, &issuer_fvk)?;
    let issuer_path = witness(
        &issuer_txs,
        initial_tree.clone(),
        &issuer_txid,
        issuer_action,
    )?;
    let issuer_anchor = issuer_path.root(issuer_note.commitment().into());
    ensure!(
        issuer_anchor == funding_anchor,
        "Mainnet witness anchors differ"
    );
    let successor_memo = if subject == "FINAL" {
        MemoBytes::from_bytes(format!("ZEC-O1|{collection}|FINAL|0").as_bytes())?
    } else {
        let item: u64 = subject
            .parse()
            .context("Item number must be positive or FINAL")?;
        ensure!(item > 0, "Item number must be positive");
        carrier_memo(collection, item, 0)?
    };
    let funding_change_address = funding_fvk.address_at(1u64, Scope::Internal);
    let mut probe = Builder::new(
        MAIN_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(issuer_anchor.into()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    probe
        .add_ironwood_spend::<Infallible>(issuer_fvk.clone(), issuer_note, issuer_path.clone())
        .map_err(|e| anyhow!("Issuer input: {e:?}"))?;
    probe
        .add_ironwood_spend::<Infallible>(funding_fvk.clone(), funding_note, funding_path.clone())
        .map_err(|e| anyhow!("Funding input: {e:?}"))?;
    if subject == "FINAL" {
        probe
            .add_ironwood_output::<Infallible>(
                None,
                burn_address(),
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("FINAL output: {e:?}"))?;
    } else {
        let recipient = address(destination)?;
        probe
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        probe
            .add_ironwood_output::<Infallible>(
                None,
                issuer_fvk.address_at(2u64, Scope::Internal),
                Zatoshis::from_u64(issuer_value)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Issuer continuation probe: {e:?}"))?;
    }
    probe
        .add_ironwood_output::<Infallible>(
            None,
            funding_change_address,
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Funding change probe: {e:?}"))?;
    let fee = probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Mint fee calculation failed: {e:?}"))?
        .into_u64();
    let (probe_spends, probe_outputs, probe_actions) = mint_fee_shape(subject)?;
    let change = if subject == "FINAL" {
        funding_value
            .checked_add(issuer_value)
            .and_then(|value| value.checked_sub(fee))
            .context("Funding and issuer notes cannot cover fee")?
    } else {
        funding_value
            .checked_sub(fee)
            .context("Funding note cannot cover fee")?
    };
    let mut builder = Builder::new(
        MAIN_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(issuer_anchor.into()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<Infallible>(issuer_fvk.clone(), issuer_note, issuer_path)
        .map_err(|e| anyhow!("Issuer input: {e:?}"))?;
    builder
        .add_ironwood_spend::<Infallible>(funding_fvk.clone(), funding_note, funding_path)
        .map_err(|e| anyhow!("Funding input: {e:?}"))?;
    if subject == "FINAL" {
        builder
            .add_ironwood_output::<Infallible>(None, burn_address(), Zatoshis::ZERO, successor_memo)
            .map_err(|e| anyhow!("FINAL output: {e:?}"))?;
    } else {
        let recipient = address(destination)?;
        builder
            .add_ironwood_output::<Infallible>(None, recipient, Zatoshis::ZERO, successor_memo)
            .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                Some(issuer_fvk.to_ovk(Scope::External)),
                issuer_fvk.address_at(2u64, Scope::Internal),
                Zatoshis::from_u64(issuer_value)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Issuer continuation: {e:?}"))?;
    }
    builder
        .add_ironwood_output::<Infallible>(
            Some(funding_fvk.to_ovk(Scope::External)),
            funding_change_address,
            Zatoshis::from_u64(change)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Funding change: {e:?}"))?;
    let tx = build_signed(
        builder,
        &[
            SpendAuthorizingKey::from(issuer_usk.orchard()),
            SpendAuthorizingKey::from(funding_usk.orchard()),
        ],
    )?;
    let final_fee = final_mint_fee_zat(subject, funding_value, issuer_value, change)?;
    let final_actions = tx
        .ironwood_bundle()
        .context("Final mint transaction has no Ironwood bundle")?
        .actions()
        .len();
    println!(
        "FEE_PRE_ESTIMATE fee_zat={fee} spends={probe_spends} outputs={probe_outputs} actions={probe_actions}"
    );
    println!("FEE_FINAL fee_zat={final_fee} actions={final_actions}");
    let projected = running_total
        .checked_add(final_fee)
        .context("M2 total overflow")?;
    println!(
        "FEE fee_zat={final_fee} running_total_before_zat={running_total} projected_total_zat={projected} tx_cap_zat={M2_TX_FEE_CAP_ZAT} cap_zat={M2_CAP_ZAT}"
    );
    ensure!(
        final_fee <= M2_TX_FEE_CAP_ZAT,
        "ABORT M2 transaction fee cap exceeded final_fee_zat={} cap_zat={}",
        final_fee,
        M2_TX_FEE_CAP_ZAT
    );
    ensure!(projected <= M2_CAP_ZAT, "ABORT M2 fee cap exceeded");
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    servers.send_transaction(raw)?;
    println!(
        "BROADCAST txid={} fee_zat={final_fee} running_total_zat={projected} stage=mint subject={subject}",
        tx.txid()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_fee_shape_matches_non_final_and_final_outputs() {
        assert_eq!(mint_fee_shape("1").unwrap(), (2, 3, 3));
        assert_eq!(mint_fee_shape("FINAL").unwrap(), (2, 2, 2));
    }

    #[test]
    fn final_fee_excludes_non_final_issuer_continuation_value() {
        assert_eq!(
            final_mint_fee_zat("1", 180_000, 10_000, 170_000).unwrap(),
            10_000
        );
        assert_eq!(
            final_mint_fee_zat("FINAL", 180_000, 10_000, 180_000).unwrap(),
            10_000
        );
    }
}
