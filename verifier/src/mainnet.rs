#![cfg(all(feature = "mainnet", feature = "sender"))]

use super::*;
use crate::lightwalletd::MainnetLightwalletd;
use anyhow::{Context, Result, ensure};
use bip0039::{English, Mnemonic};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{keys::SpendAuthorizingKey, tree::MerkleHashOrchard};
use pczt::{
    Pczt,
    orchard::EncCiphertext,
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
use std::{
    cmp::max,
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

#[cfg(not(feature = "prepare-only"))]
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
                Some(issuer_fvk.to_ovk(Scope::External)),
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
            .add_ironwood_output::<Infallible>(
                Some(issuer_fvk.to_ovk(Scope::External)),
                burn_address(),
                Zatoshis::ZERO,
                successor_memo,
            )
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

#[cfg(not(feature = "prepare-only"))]
pub(crate) fn transfer(
    primary: &str,
    secondary: &str,
    vault_wallet: &str,
    vault_identity: &str,
    origin_txid: &str,
    origin_action: usize,
    recipient_address: &str,
    funding_wallet: &str,
    funding_identity: &str,
    birthday: u32,
    running_total: u64,
) -> Result<()> {
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let vault_usk = spending_key(vault_wallet, vault_identity)?;
    let vault_fvk = FullViewingKey::from(vault_usk.orchard());
    let funding_usk = spending_key(funding_wallet, funding_identity)?;
    let funding_fvk = FullViewingKey::from(funding_usk.orchard());
    ensure!(
        vault_fvk.to_bytes() != funding_fvk.to_bytes(),
        "Funding wallet must be separate from item vault"
    );
    let snapshot = servers.consistent_snapshot()?;
    let height = block_height(snapshot.height)?;
    let (vault_txs, funding_txs, initial_tree) =
        load_chain_pair(&servers, birthday, &vault_fvk, &funding_fvk)?;
    let old_tx = vault_txs
        .iter()
        .find(|tx| tx.txid == origin_txid)
        .context("Carrier transaction not found")?;
    let carrier = &old_tx
        .notes
        .iter()
        .find(|(index, _)| *index == origin_action)
        .context("Carrier note not recovered")?
        .1;
    let vault_recipient = carrier.note.recipient().to_raw_address_bytes();
    let vault_notes: Vec<_> = vault_txs
        .iter()
        .flat_map(|tx| tx.notes.iter())
        .filter(|(_, note)| note.note.recipient().to_raw_address_bytes() == vault_recipient)
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
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    let carrier_nullifier = hex::encode(carrier.note.nullifier(&vault_fvk).to_bytes());
    ensure!(!spent.contains(&carrier_nullifier), "Carrier already spent");
    let (funding_tx, funding_action, funding_note, _, funding_value) =
        unspent_positive(&funding_txs, &funding_fvk)?;
    let carrier_path = witness(&vault_txs, initial_tree.clone(), origin_txid, origin_action)?;
    let funding_path = witness(
        &funding_txs,
        initial_tree.clone(),
        &funding_tx,
        funding_action,
    )?;
    let anchor = carrier_path.root(carrier.note.commitment().into());
    ensure!(
        funding_path.root(funding_note.commitment().into()) == anchor,
        "Witness anchors differ"
    );
    let recipient = address(recipient_address)?;
    ensure!(
        recipient.to_raw_address_bytes() != vault_recipient
            && vault_fvk.scope_for_address(&recipient).is_none(),
        "Recipient must be a fresh address outside the item vault"
    );
    let successor_memo = carrier_memo(
        &old_memo.collection,
        item,
        old_memo.hop.checked_add(1).context("Hop overflow")?,
    )?;
    let mut probe = Builder::new(
        MAIN_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    probe
        .add_ironwood_spend::<Infallible>(
            vault_fvk.clone(),
            carrier.note.clone(),
            carrier_path.clone(),
        )
        .map_err(|e| anyhow!("Carrier fee probe input: {e:?}"))?;
    probe
        .add_ironwood_spend::<Infallible>(
            funding_fvk.clone(),
            funding_note.clone(),
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Funding fee probe input: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(None, recipient, Zatoshis::ZERO, successor_memo.clone())
        .map_err(|e| anyhow!("Carrier fee probe output: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            funding_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Funding fee probe change: {e:?}"))?;
    let fee = probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Transfer fee calculation failed: {e:?}"))?
        .into_u64();
    let change = funding_value
        .checked_sub(fee)
        .context("Funding note cannot cover transfer fee")?;
    let prover = LocalTxProver::bundled();
    for candidate in 1..=64 {
        let mut builder = Builder::new(
            MAIN_NETWORK,
            height,
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
                vault_fvk.clone(),
                carrier.note.clone(),
                carrier_path.clone(),
            )
            .map_err(|e| anyhow!("Carrier input: {e:?}"))?;
        builder
            .add_ironwood_spend::<Infallible>(
                funding_fvk.clone(),
                funding_note.clone(),
                funding_path.clone(),
            )
            .map_err(|e| anyhow!("Funding input: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                Some(funding_fvk.to_ovk(Scope::External)),
                funding_fvk.address_at(1u64, Scope::Internal),
                Zatoshis::from_u64(change)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Funding change: {e:?}"))?;
        let built = builder
            .build(
                &TransparentSigningSet::new(),
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
            .map_err(|e| anyhow!("Transfer build failed: {e:?}"))?;
        let carrier_action = built
            .ironwood_meta()
            .spend_action_index(0)
            .context("No carrier action")?;
        let successor_action = built
            .ironwood_meta()
            .output_action_index(0)
            .context("No successor action")?;
        if carrier_action != successor_action {
            println!(
                "TRANSFER_CONSTRUCTION candidate={candidate} carrier_input_action={carrier_action} requested_successor_action={successor_action}"
            );
            continue;
        }
        let tx = built.transaction();
        let final_actions = tx
            .ironwood_bundle()
            .context("Final transfer has no Ironwood bundle")?
            .actions()
            .len();
        let final_fee = funding_value
            .checked_sub(change)
            .context("Transfer fee underflow")?;
        ensure!(
            final_actions == 2,
            "Transfer action count changed during build"
        );
        println!("FEE_PRE_ESTIMATE fee_zat={fee} spends=2 outputs=2 actions=2");
        println!("FEE_FINAL fee_zat={final_fee} actions={final_actions}");
        let projected = running_total
            .checked_add(final_fee)
            .context("M2 total overflow")?;
        println!(
            "FEE fee_zat={final_fee} sale_price_zat=0 running_total_before_zat={running_total} projected_total_zat={projected} tx_cap_zat={M2_TX_FEE_CAP_ZAT} cap_zat={M2_CAP_ZAT}"
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
            "BROADCAST txid={} fee_zat={final_fee} running_total_zat={projected} stage=transfer collection={} item={} hop={}",
            tx.txid(),
            old_memo.collection,
            item,
            old_memo.hop + 1
        );
        return Ok(());
    }
    bail!("No same-Action transfer constructed; nothing broadcast")
}

fn mainnet_seller_proof(path: &str) -> Result<(Value, FullViewingKey)> {
    let proof: Value = serde_json::from_slice(&fs::read(path)?)?;
    let encoded = proof["ufvk"].as_str().context("Missing seller UFVK")?;
    let ufvk = UnifiedFullViewingKey::decode(&MAIN_NETWORK, encoded)
        .map_err(|_| anyhow!("Invalid seller mainnet UFVK"))?;
    let fvk = ufvk.orchard().context("Seller UFVK has no Orchard key")?;
    Ok((proof, fvk.clone()))
}

pub(crate) fn sale_prepare(
    primary: &str,
    secondary: &str,
    seller_proof_file: &str,
    buyer_funding_wallet: &str,
    buyer_funding_identity: &str,
    buyer_vault_address: &str,
    seller_payment_address: &str,
    birthday: u32,
    price: u64,
    running_total: u64,
    output: &str,
) -> Result<()> {
    ensure!(price > 0, "Sale price must be positive");
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let (seller_proof, seller_fvk) = mainnet_seller_proof(seller_proof_file)?;
    let collection = seller_proof["collection"]
        .as_str()
        .context("Missing seller collection")?;
    let item = seller_proof["item"].as_u64().context("Missing seller item")?;
    let hop = seller_proof["hop"].as_u64().context("Missing seller hop")?;
    let origin_txid = seller_proof["txid"]
        .as_str()
        .context("Missing seller txid")?;
    let origin_action = seller_proof["action"]
        .as_u64()
        .context("Missing seller action")? as usize;
    let seller_nullifier = seller_proof["nullifier"]
        .as_str()
        .context("Missing seller nullifier")?;
    let vault_recipient = seller_proof["vault_recipient"]
        .as_str()
        .context("Missing seller vault recipient")?;
    let buyer_usk = spending_key(buyer_funding_wallet, buyer_funding_identity)?;
    let buyer_fvk = FullViewingKey::from(buyer_usk.orchard());
    ensure!(
        buyer_fvk.to_bytes() != seller_fvk.to_bytes(),
        "Buyer funding wallet must be separate from seller vault"
    );
    let snapshot = servers.consistent_snapshot()?;
    let height = block_height(snapshot.height)?;
    let (seller_txs, buyer_txs, initial_tree) =
        load_chain_pair(&servers, birthday, &seller_fvk, &buyer_fvk)?;
    let seller_tx = seller_txs
        .iter()
        .find(|tx| tx.txid == origin_txid)
        .context("Seller item transaction not found")?;
    let seller_note = &seller_tx
        .notes
        .iter()
        .find(|(index, note)| *index == origin_action && note.owned)
        .context("Seller carrier note not recovered")?
        .1;
    let seller_memo = parse_carrier_memo(&seller_note.memo).context("Seller note is not a carrier item")?;
    ensure!(
        seller_memo.collection == collection
            && seller_memo.item == Some(item)
            && seller_memo.hop == hop,
        "Seller proof metadata does not match its note"
    );
    ensure!(
        hex::encode(seller_note.note.nullifier(&seller_fvk).to_bytes()) == seller_nullifier,
        "Seller proof nullifier does not match its note"
    );
    ensure!(
        hex::encode(seller_note.note.recipient().to_raw_address_bytes()) == vault_recipient,
        "Seller proof vault recipient is stale"
    );
    ensure!(
        seller_note.note.value().inner() == 0,
        "Seller carrier value is not zero"
    );
    let seller_vault_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.notes.iter())
        .filter(|(_, note)| {
            hex::encode(note.note.recipient().to_raw_address_bytes()) == vault_recipient
        })
        .collect();
    ensure!(
        seller_vault_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_vault_notes.len()
    );
    let spent: HashSet<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    ensure!(
        !spent.contains(seller_nullifier),
        "Seller item is already spent"
    );
    let (funding_tx, funding_action, funding_note, _, funding_value) =
        unspent_positive(&buyer_txs, &buyer_fvk)?;
    let buyer_vault = address(buyer_vault_address)?;
    let seller_recipient = seller_note.note.recipient().to_raw_address_bytes();
    ensure!(
        buyer_vault.to_raw_address_bytes() != seller_recipient
            && buyer_fvk.scope_for_address(&buyer_vault).is_none(),
        "Buyer vault must be fresh and separate from seller vault"
    );
    let seller_payment = address(seller_payment_address)?;
    ensure!(
        seller_payment.to_raw_address_bytes() != seller_recipient
            && seller_payment.to_raw_address_bytes() != buyer_vault.to_raw_address_bytes(),
        "Seller payment must be separate from both vaults"
    );
    let seller_path = witness(
        &seller_txs,
        initial_tree.clone(),
        origin_txid,
        origin_action,
    )?;
    let funding_path = witness(
        &buyer_txs,
        initial_tree,
        &funding_tx,
        funding_action,
    )?;
    let anchor = seller_path.root(seller_note.note.commitment().into());
    ensure!(
        funding_path.root(funding_note.commitment().into()) == anchor,
        "Witness anchors differ"
    );
    let successor_memo = carrier_memo(
        collection,
        item,
        hop.checked_add(1).context("Hop overflow")?,
    )?;
    let mut probe = Builder::new(
        MAIN_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    probe
        .add_ironwood_spend::<Infallible>(
            seller_fvk.clone(),
            seller_note.note.clone(),
            seller_path.clone(),
        )
        .map_err(|e| anyhow!("Seller fee probe input: {e:?}"))?;
    probe
        .add_ironwood_spend::<Infallible>(
            buyer_fvk.clone(),
            funding_note.clone(),
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Buyer fee probe input: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_vault,
            Zatoshis::ZERO,
            successor_memo.clone(),
        )
        .map_err(|e| anyhow!("Carrier fee probe output: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            seller_payment,
            Zatoshis::from_u64(price)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Payment fee probe output: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Buyer fee probe change: {e:?}"))?;
    let fee = probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Sale fee calculation failed: {e:?}"))?
        .into_u64();
    let change = funding_value
        .checked_sub(price)
        .and_then(|value| value.checked_sub(fee))
        .context("Buyer funding note cannot cover sale price and fee")?;
    let proving_key = orchard::circuit::ProvingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    for candidate in 1..=64 {
        let mut builder = Builder::new(
            MAIN_NETWORK,
            height,
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
                seller_note.note.clone(),
                seller_path.clone(),
            )
            .map_err(|e| anyhow!("Seller input: {e:?}"))?;
        builder
            .add_ironwood_spend::<Infallible>(
                buyer_fvk.clone(),
                funding_note.clone(),
                funding_path.clone(),
            )
            .map_err(|e| anyhow!("Buyer funding input: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                buyer_vault,
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                seller_payment,
                Zatoshis::from_u64(price)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Seller payment: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                Some(buyer_fvk.to_ovk(Scope::External)),
                buyer_fvk.address_at(1u64, Scope::Internal),
                Zatoshis::from_u64(change)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Buyer funding change: {e:?}"))?;
        let built = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .map_err(|e| anyhow!("Sale PCZT build: {e:?}"))?;
        let carrier_action = built
            .ironwood_meta
            .spend_action_index(0)
            .context("No seller action")?;
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
        let final_fee = funding_value
            .checked_sub(price)
            .and_then(|value| value.checked_sub(change))
            .context("Sale fee underflow")?;
        ensure!(
            final_fee <= M2_TX_FEE_CAP_ZAT,
            "ABORT M2 transaction fee cap exceeded final_fee_zat={} cap_zat={}",
            final_fee,
            M2_TX_FEE_CAP_ZAT
        );
        let projected = running_total
            .checked_add(price)
            .and_then(|value| value.checked_add(final_fee))
            .context("M2 total overflow")?;
        ensure!(projected <= M2_CAP_ZAT, "ABORT M2 fee cap exceeded");
        println!("FEE_PRE_ESTIMATE fee_zat={fee} spends=2 outputs=3 actions=3");
        println!("FEE_FINAL fee_zat={final_fee} actions=3");
        println!(
            "FEE fee_zat={final_fee} sale_price_zat={price} running_total_before_zat={running_total} projected_total_zat={projected} tx_cap_zat={M2_TX_FEE_CAP_ZAT} cap_zat={M2_CAP_ZAT}"
        );
        let pczt = Creator::build_from_parts(built.pczt_parts)
            .context("PCZT version unsupported")?;
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
        fs::write(
            format!("{output}.json"),
            serde_json::to_vec_pretty(&json!({
                "collection": collection,
                "item": item,
                "hop": hop + 1,
                "origin_txid": origin_txid,
                "origin_action": origin_action,
                "carrier_action": carrier_action,
                "buyer_action": buyer_action,
                "price_zat": price,
                "fee_zat": final_fee,
            }))?,
        )?;
        println!(
            "SALE_PCZT_READY collection={} item={} carrier_action={} buyer_action={} price_zat={} fee_zat={} projected_total_zat={} buyer_signature=APPLIED private_buyer_fields=REDACTED pczt_file={output}",
            collection, item, carrier_action, buyer_action, price, final_fee, projected
        );
        return Ok(());
    }
    bail!("No same-Action sale candidate constructed; nothing signed or broadcast")
}

#[cfg(not(feature = "prepare-only"))]
pub(crate) fn sale_sign(
    primary: &str,
    secondary: &str,
    seller_proof_file: &str,
    seller_wallet: &str,
    seller_identity: &str,
    seller_payment_address: &str,
    birthday: u32,
    price: u64,
    carrier_action: usize,
    buyer_action: usize,
    input: &str,
    output: &str,
    running_total: u64,
) -> Result<()> {
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let (seller_proof, seller_fvk) = mainnet_seller_proof(seller_proof_file)?;
    let collection = seller_proof["collection"]
        .as_str()
        .context("Missing seller collection")?;
    let item = seller_proof["item"].as_u64().context("Missing seller item")?;
    let hop = seller_proof["hop"].as_u64().context("Missing seller hop")?;
    let origin_txid = seller_proof["txid"]
        .as_str()
        .context("Missing seller txid")?;
    let origin_action = seller_proof["action"]
        .as_u64()
        .context("Missing seller action")? as usize;
    let (seller_txs, _) = load_chain(&servers, birthday, &seller_fvk)?;
    let seller_tx = seller_txs
        .iter()
        .find(|tx| tx.txid == origin_txid)
        .context("Seller item transaction not found")?;
    let seller_note = &seller_tx
        .notes
        .iter()
        .find(|(index, note)| *index == origin_action && note.owned)
        .context("Seller carrier note not recovered")?
        .1;
    let seller_memo = parse_carrier_memo(&seller_note.memo).context("Seller note is not a carrier item")?;
    ensure!(
        seller_memo.collection == collection
            && seller_memo.item == Some(item)
            && seller_memo.hop == hop,
        "Seller proof metadata does not match its note"
    );
    let seller_recipient = seller_note.note.recipient().to_raw_address_bytes();
    ensure!(
        hex::encode(seller_recipient) == seller_proof["vault_recipient"].as_str().unwrap_or_default(),
        "Seller proof vault recipient is stale"
    );
    ensure!(seller_note.note.value().inner() == 0, "Seller carrier value is not zero");
    let seller_vault_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.notes.iter())
        .filter(|(_, note)| note.note.recipient().to_raw_address_bytes() == seller_recipient)
        .collect();
    ensure!(
        seller_vault_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_vault_notes.len()
    );
    let seller_nullifier = hex::encode(seller_note.note.nullifier(&seller_fvk).to_bytes());
    ensure!(
        !seller_txs
            .iter()
            .any(|tx| tx.txid != origin_txid && tx.nullifiers.contains(&seller_nullifier)),
        "Seller item is already spent"
    );
    let pczt = Pczt::parse(&fs::read(input)?).map_err(|e| anyhow!("Invalid sale PCZT: {e:?}"))?;
    let actions = pczt.ironwood().actions();
    ensure!(
        carrier_action < actions.len() && buyer_action < actions.len(),
        "Sale action index out of range"
    );
    ensure!(carrier_action != buyer_action, "Carrier and buyer actions must differ");
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
    let expected_memo = carrier_memo(collection, item, hop.checked_add(1).context("Hop overflow")?)?;
    let output_memo = match carrier_output.enc_ciphertext() {
        EncCiphertext::MemoPlaintext(memo) => memo.to_memo(),
        EncCiphertext::Encrypted(_) => bail!("Sale carrier memo is not available for approval"),
    };
    ensure!(
        output_memo == *expected_memo.as_array(),
        "Sale carrier output memo does not preserve ownership metadata"
    );
    let seller_payment = address(seller_payment_address)?;
    let mut inputs = 0u64;
    let mut outputs = 0u64;
    let mut matching_payments = 0usize;
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
                    if *to == seller_payment && output_value == price {
                        matching_payments += 1;
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| anyhow!("Sale approval check: {e:?}"))?;
    ensure!(
        matching_payments == 1,
        "REFUSED seller payment does not match listed price exactly once"
    );
    let expected_fee = zip317::FeeRule::standard().marginal_fee().into_u64()
        * max(zip317::FeeRule::standard().grace_actions(), actions.len()) as u64;
    let final_fee = inputs
        .checked_sub(outputs)
        .context("Sale fee underflow")?;
    ensure!(
        final_fee == expected_fee,
        "REFUSED sale fee is not standard ZIP-317"
    );
    let projected = running_total
        .checked_add(price)
        .and_then(|value| value.checked_add(final_fee))
        .context("M2 total overflow")?;
    ensure!(
        final_fee <= M2_TX_FEE_CAP_ZAT,
        "ABORT M2 transaction fee cap exceeded final_fee_zat={} cap_zat={}",
        final_fee,
        M2_TX_FEE_CAP_ZAT
    );
    ensure!(projected <= M2_CAP_ZAT, "ABORT M2 fee cap exceeded");
    println!(
        "FEE_FINAL fee_zat={final_fee} actions={} buyer_signature=VERIFIED",
        actions.len()
    );
    println!(
        "FEE fee_zat={final_fee} sale_price_zat={price} running_total_before_zat={running_total} projected_total_zat={projected} tx_cap_zat={M2_TX_FEE_CAP_ZAT} cap_zat={M2_CAP_ZAT}"
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
    fs::write(output, raw.clone())?;
    println!(
        "ATOMIC_SALE_READY txid={} carrier_action={} buyer_action={} payment_zat={} fee_zat={} raw_file={output}",
        tx.txid(), carrier_action, buyer_action, price, final_fee
    );
    servers.send_transaction(raw)?;
    println!(
        "BROADCAST txid={} fee_zat={} running_total_zat={} stage=sale collection={} item={} hop={}",
        tx.txid(), final_fee, projected, collection, item, hop + 1
    );
    Ok(())
}

#[cfg(not(feature = "prepare-only"))]
pub(crate) fn sale(
    primary: &str,
    secondary: &str,
    seller_wallet: &str,
    seller_identity: &str,
    buyer_funding_wallet: &str,
    buyer_funding_identity: &str,
    origin_txid: &str,
    origin_action: usize,
    buyer_vault_address: &str,
    seller_payment_address: &str,
    birthday: u32,
    price: u64,
    running_total: u64,
) -> Result<()> {
    ensure!(price > 0, "Sale price must be positive");
    let servers = MainnetLightwalletd::new(primary, secondary)?;
    let seller_usk = spending_key(seller_wallet, seller_identity)?;
    let seller_fvk = FullViewingKey::from(seller_usk.orchard());
    let buyer_usk = spending_key(buyer_funding_wallet, buyer_funding_identity)?;
    let buyer_fvk = FullViewingKey::from(buyer_usk.orchard());
    ensure!(
        seller_fvk.to_bytes() != buyer_fvk.to_bytes(),
        "Buyer funding wallet must be separate from seller vault"
    );
    let snapshot = servers.consistent_snapshot()?;
    let height = block_height(snapshot.height)?;
    let (seller_txs, buyer_txs, initial_tree) =
        load_chain_pair(&servers, birthday, &seller_fvk, &buyer_fvk)?;
    let seller_tx = seller_txs
        .iter()
        .find(|tx| tx.txid == origin_txid)
        .context("Seller carrier transaction not found")?;
    let seller_note = &seller_tx
        .notes
        .iter()
        .find(|(index, _)| *index == origin_action)
        .context("Seller carrier note not recovered")?
        .1;
    let seller_recipient = seller_note.note.recipient().to_raw_address_bytes();
    let seller_vault_notes: Vec<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.notes.iter())
        .filter(|(_, note)| note.note.recipient().to_raw_address_bytes() == seller_recipient)
        .collect();
    ensure!(
        seller_vault_notes.len() == 1,
        "Seller item vault must hold exactly one item and no other notes; found={}",
        seller_vault_notes.len()
    );
    let seller_memo =
        parse_carrier_memo(&seller_note.memo).context("Seller note is not a carrier item")?;
    let item = seller_memo.item.context("Seller note is not an item")?;
    ensure!(
        seller_note.note.value().inner() == 0,
        "Seller carrier value is not zero"
    );
    let spent: HashSet<_> = seller_txs
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().cloned())
        .collect();
    let seller_nullifier = hex::encode(seller_note.note.nullifier(&seller_fvk).to_bytes());
    ensure!(
        !spent.contains(&seller_nullifier),
        "Seller carrier already spent"
    );
    let (funding_tx, funding_action, funding_note, _, funding_value) =
        unspent_positive(&buyer_txs, &buyer_fvk)?;
    let buyer_vault = address(buyer_vault_address)?;
    ensure!(
        buyer_vault.to_raw_address_bytes() != seller_recipient
            && buyer_fvk.scope_for_address(&buyer_vault).is_none(),
        "Buyer vault must be fresh and separate from seller vault"
    );
    let seller_payment = address(seller_payment_address)?;
    ensure!(
        seller_payment.to_raw_address_bytes() != seller_recipient
            && seller_payment.to_raw_address_bytes() != buyer_vault.to_raw_address_bytes(),
        "Seller payment must be separate from both vaults"
    );
    let seller_path = witness(
        &seller_txs,
        initial_tree.clone(),
        origin_txid,
        origin_action,
    )?;
    let funding_path = witness(
        &buyer_txs,
        initial_tree.clone(),
        &funding_tx,
        funding_action,
    )?;
    let anchor = seller_path.root(seller_note.note.commitment().into());
    ensure!(
        funding_path.root(funding_note.commitment().into()) == anchor,
        "Witness anchors differ"
    );
    let successor_memo = carrier_memo(
        &seller_memo.collection,
        item,
        seller_memo.hop.checked_add(1).context("Hop overflow")?,
    )?;
    let mut probe = Builder::new(
        MAIN_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    probe
        .add_ironwood_spend::<Infallible>(
            seller_fvk.clone(),
            seller_note.note.clone(),
            seller_path.clone(),
        )
        .map_err(|e| anyhow!("Seller fee probe input: {e:?}"))?;
    probe
        .add_ironwood_spend::<Infallible>(
            buyer_fvk.clone(),
            funding_note.clone(),
            funding_path.clone(),
        )
        .map_err(|e| anyhow!("Buyer fee probe input: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_vault,
            Zatoshis::ZERO,
            successor_memo.clone(),
        )
        .map_err(|e| anyhow!("Carrier fee probe output: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            seller_payment,
            Zatoshis::from_u64(price)?,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Payment fee probe output: {e:?}"))?;
    probe
        .add_ironwood_output::<Infallible>(
            None,
            buyer_fvk.address_at(1u64, Scope::Internal),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| anyhow!("Buyer fee probe change: {e:?}"))?;
    let fee = probe
        .get_fee(&zip317::FeeRule::standard())
        .map_err(|e| anyhow!("Sale fee calculation failed: {e:?}"))?
        .into_u64();
    let change = funding_value
        .checked_sub(price)
        .and_then(|value| value.checked_sub(fee))
        .context("Buyer funding note cannot cover sale price and fee")?;
    let prover = LocalTxProver::bundled();
    for candidate in 1..=64 {
        let mut builder = Builder::new(
            MAIN_NETWORK,
            height,
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
                seller_note.note.clone(),
                seller_path.clone(),
            )
            .map_err(|e| anyhow!("Seller input: {e:?}"))?;
        builder
            .add_ironwood_spend::<Infallible>(
                buyer_fvk.clone(),
                funding_note.clone(),
                funding_path.clone(),
            )
            .map_err(|e| anyhow!("Buyer funding input: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                buyer_vault,
                Zatoshis::ZERO,
                successor_memo.clone(),
            )
            .map_err(|e| anyhow!("Carrier output: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                None,
                seller_payment,
                Zatoshis::from_u64(price)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Seller payment: {e:?}"))?;
        builder
            .add_ironwood_output::<Infallible>(
                Some(buyer_fvk.to_ovk(Scope::External)),
                buyer_fvk.address_at(1u64, Scope::Internal),
                Zatoshis::from_u64(change)?,
                MemoBytes::empty(),
            )
            .map_err(|e| anyhow!("Buyer funding change: {e:?}"))?;
        let built = builder
            .build(
                &TransparentSigningSet::new(),
                &[],
                &[
                    SpendAuthorizingKey::from(seller_usk.orchard()),
                    SpendAuthorizingKey::from(buyer_usk.orchard()),
                ],
                UnwrapErr(SysRng),
                &prover,
                &prover,
                &zip317::FeeRule::standard(),
            )
            .map_err(|e| anyhow!("Sale build failed: {e:?}"))?;
        let seller_action = built
            .ironwood_meta()
            .spend_action_index(0)
            .context("No seller action")?;
        let carrier_action = built
            .ironwood_meta()
            .output_action_index(0)
            .context("No carrier output action")?;
        if seller_action != carrier_action {
            println!(
                "SALE_CONSTRUCTION candidate={candidate} seller_input_action={seller_action} requested_successor_action={carrier_action}"
            );
            continue;
        }
        let tx = built.transaction();
        let final_actions = tx
            .ironwood_bundle()
            .context("Final sale has no Ironwood bundle")?
            .actions()
            .len();
        let final_fee = funding_value
            .checked_sub(price)
            .and_then(|value| value.checked_sub(change))
            .context("Sale fee underflow")?;
        ensure!(final_actions == 3, "Sale action count changed during build");
        println!("FEE_PRE_ESTIMATE fee_zat={fee} spends=2 outputs=3 actions=3");
        println!("FEE_FINAL fee_zat={final_fee} actions={final_actions}");
        let projected = running_total
            .checked_add(price)
            .and_then(|value| value.checked_add(final_fee))
            .context("M2 total overflow")?;
        println!(
            "FEE fee_zat={final_fee} sale_price_zat={price} running_total_before_zat={running_total} projected_total_zat={projected} tx_cap_zat={M2_TX_FEE_CAP_ZAT} cap_zat={M2_CAP_ZAT}"
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
            "BROADCAST txid={} fee_zat={final_fee} sale_price_zat={price} running_total_zat={projected} stage=sale collection={} item={} hop={}",
            tx.txid(),
            seller_memo.collection,
            item,
            seller_memo.hop + 1
        );
        return Ok(());
    }
    bail!("No same-Action sale constructed; nothing broadcast")
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
