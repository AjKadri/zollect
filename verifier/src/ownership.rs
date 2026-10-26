use super::*;
use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use zcash_protocol::consensus::Parameters;

pub(crate) fn message(challenge: &str, txid: &str, action: usize, cmx: &str, nf: &str) -> Vec<u8> {
    format!("zecathon-carrier-control-v1|{challenge}|{txid}|{action}|{cmx}|{nf}").into_bytes()
}

pub(crate) fn load_proof_for<N: Parameters>(path: &str, network: &N) -> Result<(Value, FullViewingKey)> {
    let proof: Value = serde_json::from_slice(&fs::read(path)?)?;
    let ufvk =
        UnifiedFullViewingKey::decode(network, proof["ufvk"].as_str().context("Missing UFVK")?)
            .map_err(|_| anyhow!("Invalid proof UFVK"))?;
    Ok((
        proof,
        ufvk.orchard().context("Missing Orchard key")?.clone(),
    ))
}

fn load_proof(path: &str) -> Result<(Value, FullViewingKey)> {
    load_proof_for(path, &network())
}

struct ProofTarget {
    fvk: FullViewingKey,
    txid: String,
    action: usize,
    memo: CarrierMemo,
    nullifier: String,
    cmx: String,
    spent_by: Option<String>,
}

fn validate_proof(
    url: &str,
    file: &str,
    expected_challenge: &str,
    secondary_url: Option<&str>,
) -> Result<ProofTarget> {
    let (proof, fvk) = load_proof(file)?;
    let txs = load_chain_for_key(url, &fvk, secondary_url)?;
    validate_proof_data(&proof, &fvk, &txs, expected_challenge)
}

fn validate_proof_data(
    proof: &Value,
    fvk: &FullViewingKey,
    txs: &[ChainTx],
    expected_challenge: &str,
) -> Result<ProofTarget> {
    ensure!(
        proof["challenge"] == expected_challenge,
        "FAIL wrong challenge"
    );
    let collection = proof["collection"].as_str().context("Missing collection")?;
    let item = proof["item"].as_u64().context("Missing item")?;
    ensure!(item > 0, "FAIL invalid item number");
    let txid = proof["txid"].as_str().context("Missing txid")?.to_owned();
    let action = proof["action"].as_u64().context("Missing action")? as usize;
    let tx = txs
        .iter()
        .find(|t| t.txid == txid)
        .context("FAIL note transaction not mined")?;
    let n = &tx
        .notes
        .iter()
        .find(|(i, n)| *i == action && n.owned)
        .context("FAIL key does not decrypt note")?
        .1;
    ensure!(
        n.note.value().inner() == 0,
        "FAIL carrier value is not zero"
    );
    let memo = parse_carrier_memo(&n.memo).context("FAIL note has no carrier memo")?;
    ensure!(
        memo.collection == collection && memo.item == Some(item),
        "FAIL proof item metadata mismatch"
    );
    let vault_recipient = n.note.recipient().to_raw_address_bytes();
    ensure!(
        proof["vault_recipient"] == hex::encode(vault_recipient),
        "FAIL proof vault recipient mismatch"
    );
    let owned_notes: Vec<_> = txs
        .iter()
        .flat_map(|t| t.notes.iter())
        .filter(|(_, n)| n.owned && n.note.recipient().to_raw_address_bytes() == vault_recipient)
        .collect();
    ensure!(
        owned_notes.len() == 1,
        "FAIL vault must hold exactly one item and no other notes; found={}",
        owned_notes.len()
    );
    ensure!(
        owned_notes[0].0 == action
            && txs
                .iter()
                .any(|t| t.txid == txid && t.notes.iter().any(|(i, n)| *i == action && n.owned)),
        "FAIL proof note is not the vault's single item"
    );
    let cmx = hex::encode(
        *tx.commitments
            .get(action)
            .context("FAIL proof action out of range")?,
    );
    let nullifier = hex::encode(n.note.nullifier(&fvk).to_bytes());
    ensure!(
        proof["cmx"] == cmx && proof["nullifier"] == nullifier,
        "FAIL proof-note mismatch"
    );
    let key_bytes: [u8; 32] = fvk.to_bytes()[..32].try_into()?;
    let vk = VerificationKey::<SpendAuth>::try_from(key_bytes)
        .map_err(|_| anyhow!("FAIL invalid control verification key"))?;
    let signature: [u8; 64] =
        hex::decode(proof["signature"].as_str().context("Missing signature")?)?
            .try_into()
            .map_err(|_| anyhow!("Bad signature length"))?;
    vk.verify(
        &message(expected_challenge, &txid, action, &cmx, &nullifier),
        &Signature::from(signature),
    )
    .map_err(|_| anyhow!("FAIL invalid control signature"))?;
    let spent_by = txs
        .iter()
        .find(|t| t.nullifiers.contains(&nullifier))
        .map(|t| t.txid.clone());
    Ok(ProofTarget {
        fvk: fvk.clone(),
        txid,
        action,
        memo,
        nullifier,
        cmx,
        spent_by,
    })
}

pub(crate) fn verify_proof(
    url: &str,
    file: &str,
    expected_challenge: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    let target = validate_proof(url, file, expected_challenge, secondary_url)?;
    if let Some(spending_txid) = target.spent_by {
        println!(
            "SPENT collection={} item={} hop={} txid={} action={} nullifier={} spending_txid={}",
            target.memo.collection,
            target.memo.item.unwrap(),
            target.memo.hop,
            target.txid,
            target.action,
            target.nullifier,
            spending_txid
        );
    } else {
        println!(
            "HELD collection={} item={} hop={} txid={} action={} cmx={} nullifier={} control_signature=VALID",
            target.memo.collection,
            target.memo.item.unwrap(),
            target.memo.hop,
            target.txid,
            target.action,
            target.cmx,
            target.nullifier
        );
    }
    Ok(())
}

#[cfg(feature = "mainnet")]
pub(crate) fn verify_proof_with_network<N: Parameters>(
    file: &str,
    expected_challenge: &str,
    txs: &[ChainTx],
    network: &N,
) -> Result<()> {
    let (proof, fvk) = load_proof_for(file, network)?;
    let target = validate_proof_data(&proof, &fvk, txs, expected_challenge)?;
    if let Some(spending_txid) = target.spent_by {
        println!(
            "SPENT collection={} item={} hop={} txid={} action={} nullifier={} spending_txid={}",
            target.memo.collection,
            target.memo.item.unwrap(),
            target.memo.hop,
            target.txid,
            target.action,
            target.nullifier,
            spending_txid
        );
    } else {
        println!(
            "HELD collection={} item={} hop={} txid={} action={} cmx={} nullifier={} control_signature=VALID",
            target.memo.collection,
            target.memo.item.unwrap(),
            target.memo.hop,
            target.txid,
            target.action,
            target.cmx,
            target.nullifier
        );
    }
    Ok(())
}

pub(crate) fn verify_link(
    url: &str,
    issuer_file: &str,
    alice_file: &str,
    bob_file: &str,
    secondary_url: Option<&str>,
) -> Result<()> {
    let challenge = load_proof(alice_file)?.0["challenge"]
        .as_str()
        .context("Missing Alice challenge")?
        .to_owned();
    let alice = validate_proof(url, alice_file, &challenge, secondary_url)?;
    let bob = validate_proof(url, bob_file, &challenge, secondary_url)?;
    ensure!(
        alice.spent_by.is_some(),
        "FAIL old owner proof is not SPENT"
    );
    ensure!(bob.spent_by.is_none(), "FAIL successor proof is SPENT");
    ensure!(
        alice.memo.collection == bob.memo.collection && alice.memo.item == bob.memo.item,
        "FAIL successor collection or item changed"
    );
    ensure!(
        bob.memo.hop == alice.memo.hop.checked_add(1).context("FAIL hop overflow")?,
        "FAIL successor hop is not previous hop plus one"
    );

    if alice.memo.hop == 0 {
        let issuer_key = fs::read_to_string(issuer_file)?;
        let issuer = UnifiedFullViewingKey::decode(&network(), issuer_key.trim())
            .map_err(|_| anyhow!("Invalid issuer key"))?;
        let issuer_fvk = issuer.orchard().context("No issuer Orchard key")?;
        let issuer_txs = load_chain_for_key(url, issuer_fvk, secondary_url)?;
        let items = verify_issuance(&issuer_txs, issuer_fvk, &alice.memo.collection, false)?;
        ensure!(
            items
                .iter()
                .any(|(n, t, i, _)| *n == alice.memo.item.unwrap()
                    && t == &alice.txid
                    && *i == alice.action),
            "FAIL origin not in issuer's sealed mint prefix"
        );
    }

    let owner_txs = load_chain_for_key(url, &alice.fvk, secondary_url)?;
    let old_tx = owner_txs
        .iter()
        .find(|t| t.txid == alice.txid)
        .context("FAIL origin not mined")?;
    ensure!(
        old_tx.nullifiers.iter().all(|nf| nf != &alice.nullifier),
        "FAIL origin unexpectedly spends itself"
    );
    let successor_tx = owner_txs
        .iter()
        .find(|t| t.txid == bob.txid)
        .context("FAIL successor not mined")?;
    ensure!(
        successor_tx.nullifiers.get(bob.action) == Some(&alice.nullifier),
        "FAIL successor is not in the spent carrier's Action"
    );
    println!(
        "LINK VALID collection={} item={} spent_nullifier={} successor_txid={} same_action={} memo={}|{}|{}|{}",
        alice.memo.collection,
        alice.memo.item.unwrap(),
        alice.nullifier,
        bob.txid,
        bob.action,
        CARRIER_MEMO_PREFIX,
        bob.memo.collection,
        bob.memo.item.unwrap(),
        bob.memo.hop
    );
    Ok(())
}

#[cfg(feature = "mainnet")]
pub(crate) fn verify_link_with_network<N: Parameters>(
    alice_file: &str,
    bob_file: &str,
    expected_challenge: &str,
    alice_txs: &[ChainTx],
    bob_txs: &[ChainTx],
    network: &N,
) -> Result<()> {
    let (alice_proof, alice_fvk) = load_proof_for(alice_file, network)?;
    let (bob_proof, bob_fvk) = load_proof_for(bob_file, network)?;
    let alice = validate_proof_data(&alice_proof, &alice_fvk, alice_txs, expected_challenge)?;
    let bob = validate_proof_data(&bob_proof, &bob_fvk, bob_txs, expected_challenge)?;
    ensure!(alice.spent_by.is_some(), "FAIL old owner proof is not SPENT");
    ensure!(bob.spent_by.is_none(), "FAIL successor proof is SPENT");
    ensure!(
        alice.memo.collection == bob.memo.collection && alice.memo.item == bob.memo.item,
        "FAIL successor collection or item changed"
    );
    ensure!(
        bob.memo.hop == alice.memo.hop.checked_add(1).context("FAIL hop overflow")?,
        "FAIL successor hop is not previous hop plus one"
    );
    let old_tx = alice_txs
        .iter()
        .find(|t| t.txid == alice.txid)
        .context("FAIL origin not mined")?;
    ensure!(
        old_tx.nullifiers.iter().all(|nf| nf != &alice.nullifier),
        "FAIL origin unexpectedly spends itself"
    );
    let successor_tx = alice_txs
        .iter()
        .find(|t| t.txid == bob.txid)
        .context("FAIL successor not mined")?;
    ensure!(
        successor_tx.nullifiers.get(bob.action) == Some(&alice.nullifier),
        "FAIL successor is not in the spent carrier's Action"
    );
    println!(
        "LINK VALID collection={} item={} spent_nullifier={} successor_txid={} same_action={} memo={}|{}|{}|{}",
        alice.memo.collection,
        alice.memo.item.unwrap(),
        alice.nullifier,
        bob.txid,
        bob.action,
        CARRIER_MEMO_PREFIX,
        bob.memo.collection,
        bob.memo.item.unwrap(),
        bob.memo.hop
    );
    Ok(())
}
