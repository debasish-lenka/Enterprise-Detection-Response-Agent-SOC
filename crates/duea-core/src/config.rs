use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub agent: AgentSection,
    pub transport: TransportSection,
    #[serde(default)]
    pub modules: ModulesSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSection {
    pub name: String,
    pub environment: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportSection {
    #[serde(rename = "type")]
    pub transport_type: String,
    pub manager_host: String,
    pub manager_port: u16,
    pub tls_version: String,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModulesSection {
    #[serde(default)]
    pub fim: FimModule,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FimModule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u64,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl Default for FimModule {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: 3600,
            paths: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

fn default_scan_interval() -> u64 {
    3600
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.agent.name.trim().is_empty() {
            anyhow::bail!("agent.name must not be empty");
        }
        if self.transport.manager_port == 0 {
            anyhow::bail!("transport.manager_port must be a non-zero port number");
        }
        if self.transport.transport_type != "mtls" {
            anyhow::bail!("transport.type must be 'mtls'");
        }
        if self.transport.transport_type == "mtls" {
            if self.transport.ca_cert_path.is_none() {
                anyhow::bail!("transport.ca_cert_path is required for mTLS");
            }
            if self.transport.client_cert_path.is_none() {
                anyhow::bail!("transport.client_cert_path is required for mTLS");
            }
            if self.transport.client_key_path.is_none() {
                anyhow::bail!("transport.client_key_path is required for mTLS");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_config() {
        let toml_str = r#"
            [agent]
            name = "agent-01"
            environment = "lab"

            [transport]
            type = "mtls"
            manager_host = "localhost"
            manager_port = 8443
            tls_version = "1.3"
            ca_cert_path = "/etc/duea/ca.pem"
            client_cert_path = "/etc/duea/client.pem"
            client_key_path = "/etc/duea/client.key"

            [modules.fim]
            enabled = true
            scan_interval_secs = 3600
            paths = ["/etc", "/var/log"]
            exclude_patterns = ["*.tmp", "*.log"]
        "#;
        let config: Config = toml::from_str(toml_str).expect("config should parse");
        assert_eq!(config.agent.name, "agent-01");
        assert_eq!(config.transport.manager_port, 8443);
        assert!(config.modules.fim.enabled);
        assert_eq!(config.modules.fim.scan_interval_secs, 3600);
        assert_eq!(config.modules.fim.paths, vec!["/etc", "/var/log"]);
    }

    #[test]
    fn defaults_modules_when_absent() {
        let toml_str = r#"
            [agent]
            name = "agent-01"
            environment = "lab"

            [transport]
            type = "mtls"
            manager_host = "localhost"
            manager_port = 8443
            tls_version = "1.3"
            ca_cert_path = "/etc/duea/ca.pem"
            client_cert_path = "/etc/duea/client.pem"
            client_key_path = "/etc/duea/client.key"
        "#;
        let config: Config = toml::from_str(toml_str).expect("config should parse");
        assert!(!config.modules.fim.enabled);
        assert_eq!(config.modules.fim.scan_interval_secs, 3600);
    }

    #[test]
    fn rejects_empty_agent_name() {
        let toml_str = r#"
            [agent]
            name = ""
            environment = "lab"

            [transport]
            type = "mtls"
            manager_host = "localhost"
            manager_port = 8443
            tls_version = "1.3"
            ca_cert_path = "/etc/duea/ca.pem"
            client_cert_path = "/etc/duea/client.pem"
            client_key_path = "/etc/duea/client.key"
        "#;
        let config: Config = toml::from_str(toml_str).expect("config should parse");
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_missing_mtls_certs() {
        let toml_str = r#"
            [agent]
            name = "agent-01"
            environment = "lab"

            [transport]
            type = "mtls"
            manager_host = "localhost"
            manager_port = 8443
            tls_version = "1.3"
        "#;
        let config: Config = toml::from_str(toml_str).expect("config should parse");
        assert!(config.validate().is_err());
    }
}