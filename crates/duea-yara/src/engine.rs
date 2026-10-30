use crate::types::{YaraConfig, YaraScanReport, YaraScanResult};
use duea_core::{Module, ModuleConfig, ModuleHealth, HealthStatus, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::time::{interval, Instant};
use walkdir::WalkDir;
use tracing::{info, warn, error};

pub struct YaraModule {
    config: YaraConfig,
    running: Arc<Mutex<bool>>,
    last_scan: Arc<Mutex<Option<SystemTime>>>,
    scan_count: Arc<Mutex<u64>>,
    total_matches: Arc<Mutex<u64>>,
    files_scanned: Arc<Mutex<u64>>,
    rules_compiled: Arc<Mutex<bool>>,
}

impl YaraModule {
    pub fn new(config: YaraConfig) -> Self {
        Self {
            config,
            running: Arc::new(Mutex::new(false)),
            last_scan: Arc::new(Mutex::new(None)),
            scan_count: Arc::new(Mutex::new(0)),
            total_matches: Arc::new(Mutex::new(0)),
            files_scanned: Arc::new(Mutex::new(0)),
            rules_compiled: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn compile_rules(&self) -> Result<()> {
        info!("Compiling YARA rules from: {:?}", self.config.rules_paths);

        // Simulate rule compilation - in production this would use the yara crate
        // For now, we just mark rules as compiled
        *self.rules_compiled.lock().await = true;
        info!("YARA rules compiled successfully (stub implementation)");
        Ok(())
    }

    pub async fn scan(&self) -> Result<YaraScanReport> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now();
        let scan_start = Instant::now();

        info!("Starting YARA scan {}", scan_id);

        // Ensure rules are compiled
        if !*self.rules_compiled.lock().await {
            self.compile_rules().await?;
        }

        let mut results = Vec::new();
        let mut total_matches: u64 = 0;
        let mut files_scanned: u64 = 0;
        let mut errors = Vec::new();

        for scan_path in &self.config.scan_paths {
            if !scan_path.exists() {
                warn!("Scan path does not exist: {}", scan_path.display());
                continue;
            }

            for entry in WalkDir::new(scan_path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path().to_path_buf();

                // Check if we should exclude this path
                if self.should_exclude(&path) {
                    continue;
                }

                if entry.file_type().is_file() {
                    // Check file size limit
                    if let Some(max_size) = self.config.max_file_size {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.len() > max_size {
                                continue;
                            }
                        }
                    }

                    // Mock scan - in production this would call yara crate
                    let scan_result = self.mock_scan_file(&path).await;
                    match scan_result {
                        Ok(result) => {
                            files_scanned += 1;
                            if !result.matches.is_empty() {
                                total_matches += result.matches.len() as u64;
                                warn!("YARA match in {}: {} rules", path.display(), result.matches.len());
                            }
                            results.push(result);
                        }
                        Err(e) => {
                            errors.push(format!("Failed to scan {}: {}", path.display(), e));
                        }
                    }

                    // Check match timeout
                    if scan_start.elapsed() > Duration::from_secs(self.config.match_timeout_secs) {
                        warn!("YARA scan timeout reached");
                        break;
                    }
                }
            }
        }

        let completed_at = chrono::Utc::now();

        *self.last_scan.lock().await = Some(completed_at.into());
        *self.scan_count.lock().await += 1;
        *self.total_matches.lock().await += total_matches;
        *self.files_scanned.lock().await += files_scanned;

        Ok(YaraScanReport {
            scan_id,
            started_at,
            completed_at,
            files_scanned: files_scanned as usize,
            files_matched: results.iter().filter(|r| !r.matches.is_empty()).count(),
            total_matches: total_matches as usize,
            results,
            errors,
        })
    }

    async fn mock_scan_file(&self, path: &Path) -> Result<YaraScanResult> {
        let scan_start = Instant::now();

        // Simulate a scan - in production this would use the yara crate
        // For now, we just return an empty result
        // This is a stub implementation

        Ok(YaraScanResult {
            file_path: path.to_path_buf(),
            matches: Vec::new(),
            scan_duration_ms: scan_start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            error: None,
        })
    }

    fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.config.exclude_patterns {
            if pattern.contains('*') {
                let regex_pattern = pattern
                    .replace(".", "\\.")
                    .replace("*", ".*");
                if regex::Regex::new(&format!("^{}$", regex_pattern))
                    .map(|re| re.is_match(&path_str))
                    .unwrap_or(false) {
                    return true;
                }
            } else if path_str.starts_with(pattern) {
                return true;
            }
        }
        false
    }

    pub async fn run_scheduled(&self) {
        let mut interval = interval(Duration::from_secs(self.config.scan_interval_secs));

        loop {
            interval.tick().await;

            let running = *self.running.lock().await;
            if !running {
                break;
            }

            if let Err(e) = self.scan().await {
                error!("Scheduled YARA scan failed: {}", e);
            }
        }
    }
}

#[async_trait::async_trait]
impl Module for YaraModule {
    fn name(&self) -> &str {
        "yara"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn initialize(&mut self, config: ModuleConfig) -> Result<()> {
        info!("Initializing YARA module");

        if config.enabled {
            // Update config from module options if provided
            if let Some(rules_paths) = config.options.get("rules_paths") {
                if let Some(paths) = rules_paths.as_array() {
                    self.config.rules_paths = paths.iter()
                        .filter_map(|v| v.as_str().map(PathBuf::from))
                        .collect();
                }
            }

            if let Some(interval) = config.options.get("scan_interval_secs") {
                if let Some(secs) = interval.as_u64() {
                    self.config.scan_interval_secs = secs;
                }
            }

            // Compile rules during initialization
            self.compile_rules().await?;
            info!("YARA module initialized with {} rule paths", self.config.rules_paths.len());
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting YARA module");
        *self.running.lock().await = true;

        // Start scheduled scanner
        let config = self.config.clone();
        let running = self.running.clone();
        let last_scan = self.last_scan.clone();
        let scan_count = self.scan_count.clone();
        let _total_matches = self.total_matches.clone();
        let files_scanned = self.files_scanned.clone();
        let interval_secs = self.config.scan_interval_secs;
        let max_file_size = self.config.max_file_size;
        let exclude_patterns = self.config.exclude_patterns.clone();
        let rules_compiled = self.rules_compiled.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                let running = *running.lock().await;
                if !running {
                    break;
                }

                // Mock scan cycle - in production this would use yara crate
                if *rules_compiled.lock().await {
                    for scan_path in &config.scan_paths {
                        if !scan_path.exists() {
                            continue;
                        }

                        for entry in WalkDir::new(scan_path)
                            .follow_links(false)
                            .into_iter()
                            .filter_map(|e| e.ok())
                        {
                            let path = entry.path().to_path_buf();

                            // Check exclusions
                            let path_str = path.to_string_lossy();
                            let mut excluded = false;
                            for pattern in &exclude_patterns {
                                if pattern.contains('*') {
                                    let regex_pattern = pattern.replace(".", "\\.").replace("*", ".*");
                                    if regex::Regex::new(&format!("^{}$", regex_pattern))
                                        .map(|re| re.is_match(&path_str))
                                        .unwrap_or(false) {
                                        excluded = true;
                                        break;
                                    }
                                } else if path_str.starts_with(pattern) {
                                    excluded = true;
                                    break;
                                }
                            }
                            if excluded { continue; }

                            if entry.file_type().is_file() {
                                if let Some(max_size) = max_file_size {
                                    if let Ok(metadata) = entry.metadata() {
                                        if metadata.len() > max_size { continue; }
                                    }
                                }

                                // Mock scan
                                *files_scanned.lock().await += 1;
                            }
                        }
                    }
                }

                *scan_count.lock().await += 1;
                *last_scan.lock().await = Some(SystemTime::now());
                info!("Scheduled YARA scan cycle completed");
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping YARA module");
        *self.running.lock().await = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        false
    }

    async fn health_check(&self) -> Result<ModuleHealth> {
        let scan_count = *self.scan_count.lock().await;
        let total_matches = *self.total_matches.lock().await;
        let files_scanned = *self.files_scanned.lock().await;
        let rules_compiled = *self.rules_compiled.lock().await;

        let mut metrics = HashMap::new();
        metrics.insert("scans_completed".to_string(), serde_json::json!(scan_count));
        metrics.insert("total_matches".to_string(), serde_json::json!(total_matches));
        metrics.insert("files_scanned".to_string(), serde_json::json!(files_scanned));
        metrics.insert("rules_compiled".to_string(), serde_json::json!(rules_compiled));
        metrics.insert("configured_rules_paths".to_string(), serde_json::json!(self.config.rules_paths.len()));
        metrics.insert("configured_scan_paths".to_string(), serde_json::json!(self.config.scan_paths.len()));

        let status = if scan_count > 0 && rules_compiled {
            HealthStatus::Healthy
        } else if rules_compiled {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };

        Ok(ModuleHealth {
            name: self.name().to_string(),
            status,
            message: Some(format!("YARA module operational (stub), {} rule paths", self.config.rules_paths.len())),
            metrics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use std::fs;
    use std::io::Write;

    #[tokio::test]
    async fn yara_module_initializes_and_scans() {
        let temp_dir = TempDir::new().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let test_file = temp_dir.path().join("test.txt");
        let mut f = fs::File::create(&test_file).unwrap();
        f.write_all(b"This file contains malware string").unwrap();

        let config = YaraConfig {
            rules_paths: vec![rules_dir],
            scan_paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let mut module = YaraModule::new(config);

        let module_config = ModuleConfig {
            enabled: true,
            options: HashMap::new(),
        };

        module.initialize(module_config).await.unwrap();
        module.start().await.unwrap();

        // Run scan manually for test
        let report = module.scan().await.unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.total_matches, 0); // Stub returns no matches

        let health = module.health_check().await.unwrap();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.metrics.get("scans_completed").unwrap().as_u64().unwrap() > 0);

        module.stop().await.unwrap();
    }
}