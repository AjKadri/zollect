use anyhow::{Result, ensure};
use zcash_protocol::consensus::{MAIN_NETWORK, MainNetwork, NetworkType, Parameters};

pub(crate) const MAINNET_CHAIN_NAME: &str = "main";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MainnetConfig;

impl MainnetConfig {
    pub(crate) const fn parameters(self) -> MainNetwork {
        MAIN_NETWORK
    }

    pub(crate) fn validate_chain_name(self, chain_name: &str) -> Result<()> {
        ensure!(
            chain_name == MAINNET_CHAIN_NAME,
            "FAIL MAINNET_CHAIN_MISMATCH expected={} observed={}",
            MAINNET_CHAIN_NAME,
            chain_name
        );
        ensure!(
            self.parameters().network_type() == NetworkType::Main,
            "FAIL MAINNET_CONFIG_INVALID"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_config_is_main_and_rejects_other_chain_names() {
        let config = MainnetConfig;
        assert_eq!(config.parameters().network_type(), NetworkType::Main);
        config.validate_chain_name("main").unwrap();
        assert!(config.validate_chain_name("regtest").is_err());
    }
}
