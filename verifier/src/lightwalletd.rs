use crate::network::{MAINNET_CHAIN_NAME, MainnetConfig};
use anyhow::{Context, Result, ensure};
use zcash_client_backend::proto::service::{
    ChainSpec, Empty, RawTransaction, TxFilter, compact_tx_streamer_client::CompactTxStreamerClient,
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
        let url = self.url.clone();
        let hash = hex::decode(txid).context("Invalid transaction id hex")?;
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
