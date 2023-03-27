use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    pub private_key: String,
    pub listen_port: u16,
    pub address: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: String,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read the configuration file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse the configuration file: {0}")]
    ParseError(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_config() {
        let config_str = r#"
            [Interface]
            PrivateKey = "private_key"
            ListenPort = 12345
            Address = ["192.168.1.1/24", "192.168.2.1/24"]

            [[Peers]]
            PublicKey = "public_key"
            PresharedKey = "preshared_key"
            Endpoint = "example.com:12345"
            AllowedIPs = "192.168.3.0/24"
        "#;

        let config: Config = toml::from_str(config_str).unwrap();

        assert_eq!(config.interface.private_key, "private_key");
        assert_eq!(config.interface.listen_port, 12345);
        assert_eq!(
            config.interface.address,
            vec!["192.168.1.1/24", "192.168.2.1/24"]
        );

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].public_key, "public_key");
        assert_eq!(
            config.peers[0].preshared_key.clone().unwrap(),
            "preshared_key"
        );
        assert_eq!(
            config.peers[0].endpoint.clone().unwrap(),
            "example.com:12345"
        );
        assert_eq!(config.peers[0].allowed_ips, "192.168.3.0/24");

        let serialized_config = toml::to_string(&config).unwrap();
        let deserialized_config: Config = toml::from_str(&serialized_config).unwrap();

        assert_eq!(config, deserialized_config);
    }
}
