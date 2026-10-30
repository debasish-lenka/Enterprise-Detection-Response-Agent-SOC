use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    pub rules_paths: Vec<PathBuf>,
    pub scan_paths: Vec<PathBuf>,
    pub scan_interval_secs: u64,
    pub max_file_size: Option<u64>,
    pub exclude_patterns: Vec<String>,
    pub compile_timeout_secs: u64,
    pub match_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub file_path: PathBuf,
    pub matches: Vec<YaraMatch>,
    pub scan_duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanReport {
    pub scan_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub files_scanned: usize,
    pub files_matched: usize,
    pub total_matches: usize,
    pub results: Vec<YaraScanResult>,
    pub errors: Vec<String>,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_paths: vec![PathBuf::from("/opt/duea/yara/rules")],
            scan_paths: vec![PathBuf::from("/"), PathBuf::from("/home")],
            scan_interval_secs: 3600,
            max_file_size: Some(100 * 1024 * 1024), // 100MB
            exclude_patterns: vec![
                "*.tmp".to_string(),
                "*.log".to_string(),
                "/proc/*".to_string(),
                "/sys/*".to_string(),
                "/dev/*".to_string(),
            ],
            compile_timeout_secs: 60,
            match_timeout_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_rules_path() {
        let config = YaraConfig::default();
        assert!(!config.rules_paths.is_empty());
        assert!(!config.scan_paths.is_empty());
        assert_eq!(config.scan_interval_secs, 3600);
    }
}