use crate::network::{MAINNET_CHAIN_NAME, MainnetConfig};
use anyhow::{Context, Result, ensure};
use std::{thread, time::Duration};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, Empty, RawTransaction, TreeState, TxFilter,
    compact_tx_streamer_client::CompactTxStreamerClient,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerSnapshot {
    pub(crate) chain_name: String,
    pub(crate) height: u64,
    pub(crate) tip_hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EndpointSnapshot {
    chain_name: String,
    info_height: u64,
    tip_height: u64,
    tip_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Endpoint {
    url: String,
}

const MAX_SNAPSHOT_RETRIES: usize = 3;
const SNAPSHOT_RETRY_DELAY: Duration = Duration::from_secs(3);

fn displayed_txid_hash(txid: &str) -> Result<Vec<u8>> {
    let mut hash = hex::decode(txid).context("Invalid transaction id hex")?;
    ensure!(hash.len() == 32, "Invalid transaction id length");
    hash.reverse();
    Ok(hash)
}

impl Endpoint {
    fn new(url: &str) -> Result<Self> {
        let url = url.trim();
        ensure!(
            url.starts_with("https://"),
            "Mainnet lightwalletd endpoints must use HTTPS"
        );
        ensure!(
            url.len() > "https://".len()
                && !url.chars().any(char::is_whitespace)
                && !url.contains('@')
                && !url.contains('?')
                && !url.contains('#'),
            "Invalid mainnet lightwalletd endpoint"
        );
        Ok(Self {
            url: url.to_owned(),
        })
    }

    fn snapshot(&self) -> Result<EndpointSnapshot> {
        let url = self.url.clone();
        run(async move {
            let mut client = CompactTxStreamerClient::connect(url)
                .await
                .context("lightwalletd connection failed")?;
            let info = client
                .get_lightd_info(Empty {})
                .await
                .context("lightwalletd info request failed")?
                .into_inner();
            let tip = client
                .get_latest_block(ChainSpec {})
                .await
                .context("lightwalletd tip request failed")?
                .into_inner();
            ensure!(
                info.chain_name == MAINNET_CHAIN_NAME,
                "FAIL MAINNET_CHAIN_MISMATCH expected={} observed={}",
                MAINNET_CHAIN_NAME,
                info.chain_name
            );
            ensure!(!tip.hash.is_empty(), "FAIL LIGHTWALLETD_MISSING_TIP_HASH");
            Ok(EndpointSnapshot {
                chain_name: info.chain_name,
                info_height: info.block_height,
                tip_height: tip.height,
                tip_hash: tip.hash,
            })
        })
    }

    fn transaction(&self, txid: &str) -> Result<RawTransaction> {
        let hash = displayed_txid_hash(txid)?;
        self.transaction_hash(hash)
    }

    fn transaction_hash(&self, hash: Vec<u8>) -> Result<RawTransaction> {
        let url = self.url.clone();
        run(async move {
            let mut client = CompactTxStreamerClient::connect(url)
                .await
                .context("lightwalletd connection failed")?;
            Ok(client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash,
                })
                .await
                .context("lightwalletd transaction request failed")?
                .into_inner())
        })
    }

    fn tree_state(&self, height: u32) -> Result<TreeState> {
        let url = self.url.clone();
        run(async move {
            let mut client = CompactTxStreamerClient::connect(url)
                .await
                .context("lightwalletd connection failed")?;
            Ok(client
                .get_tree_state(BlockId {
                    height: u64::from(height),
                    ..Default::default()
                })
                .await
                .context("lightwalletd tree-state request failed")?
                .into_inner())
        })
    }

    fn compact_blocks(&self, start: u32, end: u32) -> Result<Vec<CompactBlock>> {
        ensure!(start <= end, "Invalid compact-block range");
        let url = self.url.clone();
        run(async move {
            let mut client = CompactTxStreamerClient::connect(url)
                .await
                .context("lightwalletd connection failed")?;
            let mut stream = client
                .get_block_range(BlockRange {
                    start: Some(BlockId {
                        height: u64::from(start),
                        ..Default::default()
                    }),
                    end: Some(BlockId {
                        height: u64::from(end),
                        ..Default::default()
                    }),
                    pool_types: Vec::new(),
                })
                .await
                .context("lightwalletd compact-block request failed")?
                .into_inner();
            let mut blocks = Vec::new();
            while let Some(block) = stream
                .message()
                .await
                .context("lightwalletd compact-block stream failed")?
            {
                blocks.push(block);
            }
            ensure!(
                blocks.len() == (end - start + 1) as usize,
                "lightwalletd returned an incomplete compact-block range: expected={} observed={}",
                end - start + 1,
                blocks.len()
            );
            Ok(blocks)
        })
    }

    fn send_transaction(&self, raw: Vec<u8>) -> Result<()> {
        let url = self.url.clone();
        run(async move {
            let mut client = CompactTxStreamerClient::connect(url)
                .await
                .context("lightwalletd connection failed")?;
            let response = client
                .send_transaction(RawTransaction {
                    data: raw,
                    height: 0,
                })
                .await
                .context("lightwalletd broadcast request failed")?
                .into_inner();
            ensure!(
                response.error_code == 0,
                "lightwalletd rejected transaction: {} {}",
                response.error_code,
                response.error_message
            );
            Ok(())
        })
    }
}

fn run<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("unable to create lightwalletd runtime")?
        .block_on(future)
}

#[derive(Clone, Debug)]
pub(crate) struct MainnetLightwalletd {
    primary: Endpoint,
    secondary: Endpoint,
}

impl MainnetLightwalletd {
    pub(crate) fn new(primary: &str, secondary: &str) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = MainnetConfig;
        config.validate_chain_name(MAINNET_CHAIN_NAME)?;
        let primary = Endpoint::new(primary)?;
        let secondary = Endpoint::new(secondary)?;
        ensure!(
            primary.url != secondary.url,
            "FAIL RPC_SERVER_DISAGREEMENT duplicate server endpoint"
        );
        Ok(Self { primary, secondary })
    }

    pub(crate) fn consistent_snapshot(&self) -> Result<ServerSnapshot> {
        for attempt in 0..=MAX_SNAPSHOT_RETRIES {
            let primary = self.primary.snapshot()?;
            let secondary = self.secondary.snapshot()?;
            ensure!(
                primary.chain_name == secondary.chain_name,
                "FAIL RPC_SERVER_DISAGREEMENT lightwalletd chain name differs"
            );

            if primary.tip_height == secondary.tip_height {
                ensure!(
                    primary.tip_hash == secondary.tip_hash,
                    "FAIL RPC_SERVER_DISAGREEMENT lightwalletd tip hash differs height={}",
                    primary.tip_height
                );
                ensure!(
                    primary.info_height == primary.tip_height,
                    "FAIL LIGHTWALLETD_INCOMPLETE_INFO server=primary info_height={} tip_height={}",
                    primary.info_height,
                    primary.tip_height
                );
                ensure!(
                    secondary.info_height == secondary.tip_height,
                    "FAIL LIGHTWALLETD_INCOMPLETE_INFO server=secondary info_height={} tip_height={}",
                    secondary.info_height,
                    secondary.tip_height
                );
                return Ok(ServerSnapshot {
                    chain_name: primary.chain_name,
                    height: primary.tip_height,
                    tip_hash: primary.tip_hash,
                });
            }

            let tip_gap = primary.tip_height.abs_diff(secondary.tip_height);
            ensure!(
                tip_gap == 1,
                "FAIL RPC_SERVER_DISAGREEMENT lightwalletd tip heights differ primary={} secondary={}",
                primary.tip_height,
                secondary.tip_height
            );
            ensure!(
                attempt < MAX_SNAPSHOT_RETRIES,
                "FAIL RPC_SERVER_DISAGREEMENT persistent one-block tip gap primary={} secondary={}",
                primary.tip_height,
                secondary.tip_height
            );
            thread::sleep(SNAPSHOT_RETRY_DELAY);
        }
        unreachable!("snapshot retry loop must return or fail")
    }

    pub(crate) fn transaction(&self, txid: &str) -> Result<RawTransaction> {
        self.consistent_snapshot()?;
        let primary = self.primary.transaction(txid)?;
        let secondary = self.secondary.transaction(txid)?;
        ensure!(
            primary == secondary,
            "FAIL RPC_SERVER_DISAGREEMENT lightwalletd transaction differs txid={txid}"
        );
        Ok(primary)
    }

    pub(crate) fn consistent_chain_data(
        &self,
        birthday: u32,
    ) -> Result<(
        ServerSnapshot,
        TreeState,
        Vec<(u32, Vec<u8>, RawTransaction)>,
    )> {
        let snapshot = self.consistent_snapshot()?;
        ensure!(
            birthday > 0 && u64::from(birthday) <= snapshot.height,
            "Wallet birthday is outside the current mainnet tip"
        );
        let tree_height = birthday - 1;
        let primary_tree = self.primary.tree_state(tree_height)?;
        let secondary_tree = self.secondary.tree_state(tree_height)?;
        ensure!(
            primary_tree == secondary_tree,
            "FAIL RPC_SERVER_DISAGREEMENT lightwalletd tree state differs height={tree_height}"
        );
        let end = u32::try_from(snapshot.height).context("Mainnet height exceeds u32")?;
        let primary_blocks = self.primary.compact_blocks(birthday, end)?;
        let secondary_blocks = self.secondary.compact_blocks(birthday, end)?;
        ensure!(
            primary_blocks == secondary_blocks,
            "FAIL RPC_SERVER_DISAGREEMENT lightwalletd compact blocks differ"
        );

        let txids: Vec<_> = primary_blocks
            .iter()
            .flat_map(|block| {
                let height: u32 = block.height().into();
                block.vtx.iter().map(move |tx| (height, tx.txid.clone()))
            })
            .collect();
        let mut transactions = Vec::with_capacity(txids.len());
        for (height, hash) in txids {
            let primary = self.primary.transaction_hash(hash.clone())?;
            let secondary = self.secondary.transaction_hash(hash.clone())?;
            ensure!(
                primary == secondary,
                "FAIL RPC_SERVER_DISAGREEMENT lightwalletd transaction differs height={height}"
            );
            transactions.push((height, hash, primary));
        }
        Ok((snapshot, primary_tree, transactions))
    }

    pub(crate) fn send_transaction(&self, raw: Vec<u8>) -> Result<()> {
        self.consistent_snapshot()?;
        self.primary.send_transaction(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_MINED_TXID: &str =
        "89dfe6217eefd93a59d39e6b4f19ecb1fbba31f8b89a080652f57f50c38eef16";

    #[test]
    fn mainnet_pair_requires_distinct_https_endpoints_without_connecting() {
        assert!(MainnetLightwalletd::new("http://one.example", "https://two.example").is_err());
        assert!(MainnetLightwalletd::new("https://one.example", "https://one.example").is_err());
        assert!(
            MainnetLightwalletd::new("https://one.example?token=redacted", "https://two.example")
                .is_err()
        );
        assert!(
            MainnetLightwalletd::new("https://one.example#fragment", "https://two.example")
                .is_err()
        );
        assert!(MainnetLightwalletd::new("https://one.example", "https://two.example").is_ok());
    }

    #[test]
    fn displayed_txid_is_reversed_for_lightwalletd() {
        let hash = displayed_txid_hash(KNOWN_MINED_TXID).unwrap();
        assert_eq!(
            hex::encode(hash),
            "16ef8ec3507ff55206089ab8f831bafbb1ec194f6b9ed3593ad9ef7e21e6df89"
        );
    }

    #[test]
    fn only_one_block_tip_gap_is_retryable() {
        let primary = EndpointSnapshot {
            chain_name: MAINNET_CHAIN_NAME.to_owned(),
            info_height: 10,
            tip_height: 10,
            tip_hash: vec![1],
        };
        let secondary = EndpointSnapshot {
            chain_name: MAINNET_CHAIN_NAME.to_owned(),
            info_height: 9,
            tip_height: 9,
            tip_hash: vec![2],
        };
        assert_eq!(primary.tip_height.abs_diff(secondary.tip_height), 1);
        assert_ne!(primary.tip_height.abs_diff(secondary.tip_height), 2);
    }

    #[test]
    #[ignore = "requires public mainnet lightwalletd servers"]
    fn known_mined_mainnet_transaction_is_found_on_both_servers() {
        let servers =
            MainnetLightwalletd::new("https://na.zec.rocks:443", "https://eu.zec.rocks:443")
                .unwrap();
        let transaction = servers.transaction(KNOWN_MINED_TXID).unwrap();
        assert_eq!(transaction.height, 3530585);
        assert!(!transaction.data.is_empty());
    }
}
