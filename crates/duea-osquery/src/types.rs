use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryConfig {
    pub socket_path: PathBuf,
    pub config_path: Option<PathBuf>,
    pub extensions: Vec<OsqueryExtension>,
    pub query_interval_secs: u64,
    pub queries: Vec<OsqueryQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryExtension {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryQuery {
    pub name: String,
    pub query: String,
    pub interval_secs: u64,
    pub snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryResult {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<HashMap<String, serde_json::Value>>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for OsqueryConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/var/osquery/osquery.em"),
            config_path: None,
            extensions: Vec::new(),
            query_interval_secs: 3600,
            queries: vec![
                OsqueryQuery {
                    name: "processes".to_string(),
                    query: "SELECT pid, name, path, cmdline, cwd, uid, gid FROM processes;".to_string(),
                    interval_secs: 3600,
                    snapshot: false,
                },
                OsqueryQuery {
                    name: "listening_ports".to_string(),
                    query: "SELECT pid, port, address, protocol FROM listening_ports;".to_string(),
                    interval_secs: 3600,
                    snapshot: true,
                },
                OsqueryQuery {
                    name: "users".to_string(),
                    query: "SELECT uid, gid, username, description, directory, shell FROM users;".to_string(),
                    interval_secs: 86400,
                    snapshot: true,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_standard_queries() {
        let config = OsqueryConfig::default();
        assert_eq!(config.queries.len(), 3);
        assert!(config.queries.iter().any(|q| q.name == "processes"));
        assert!(config.queries.iter().any(|q| q.name == "listening_ports"));
        assert!(config.queries.iter().any(|q| q.name == "users"));
    }
}