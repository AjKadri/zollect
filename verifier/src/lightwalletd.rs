use crate::network::{MAINNET_CHAIN_NAME, MainnetConfig};
use anyhow::{Context, Result, ensure};
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

#[derive(Clone, Debug)]
struct Endpoint {
    url: String,
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

    fn snapshot(&self) -> Result<ServerSnapshot> {
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
            ensure!(
                info.block_height == tip.height,
                "FAIL LIGHTWALLETD_INCOMPLETE_INFO info_height={} tip_height={}",
                info.block_height,
                tip.height
            );
            ensure!(!tip.hash.is_empty(), "FAIL LIGHTWALLETD_MISSING_TIP_HASH");
            Ok(ServerSnapshot {
                chain_name: info.chain_name,
                height: tip.height,
                tip_hash: tip.hash,
            })
        })
    }

    fn transaction(&self, txid: &str) -> Result<RawTransaction> {
        let hash = hex::decode(txid).context("Invalid transaction id hex")?;
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
        let primary = self.primary.snapshot()?;
        let secondary = self.secondary.snapshot()?;
        ensure!(
            primary == secondary,
            "FAIL RPC_SERVER_DISAGREEMENT lightwalletd chain state differs"
        );
        Ok(primary)
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
}
