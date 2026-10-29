use crate::scanner::Scanner;
use crate::types::{FimConfig, ScanReport};
use duea_core::{Module, ModuleConfig, ModuleHealth, HealthStatus, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

pub struct FimModule {
    config: FimConfig,
    scanner: Scanner,
    running: Arc<Mutex<bool>>,
    last_scan: Arc<Mutex<Option<SystemTime>>>,
    scan_count: Arc<Mutex<u64>>,
    total_changes: Arc<Mutex<u64>>,
}

impl FimModule {
    pub fn new(config: FimConfig) -> Self {
        let scanner = Scanner::new(config.clone());
        Self {
            config,
            scanner,
            running: Arc::new(Mutex::new(false)),
            last_scan: Arc::new(Mutex::new(None)),
            scan_count: Arc::new(Mutex::new(0)),
            total_changes: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn run_scan(&self) -> Result<ScanReport> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let started_at = SystemTime::now();

        info!("Starting FIM scan {}", scan_id);

        let changes = self.scanner.detect_changes().await?;
        let changes_count = changes.len();

        if changes_count > 0 {
            warn!("FIM scan {} detected {} changes", scan_id, changes_count);
            for change in &changes {
                warn!("  {}: {} ({})",
                    match change.change_type {
                        crate::types::ChangeType::Created => "CREATED",
                        crate::types::ChangeType::Modified => "MODIFIED",
                        crate::types::ChangeType::Deleted => "DELETED",
                        crate::types::ChangeType::PermissionsChanged => "PERMS_CHANGED",
                        crate::types::ChangeType::Moved { .. } => "MOVED",
                    },
                    change.path.display(),
                    change.details
                );
            }
            self.scanner.update_baseline(&changes).await?;
        }

        self.scanner.update_baseline(&changes).await?;

        let completed_at = SystemTime::now();
        let files_scanned = {
            let baseline = self.scanner.baseline().lock().await;
            baseline.len()
        };

        *self.last_scan.lock().await = Some(completed_at);
        *self.scan_count.lock().await += 1;
        *self.total_changes.lock().await += changes_count as u64;

        Ok(ScanReport {
            scan_id,
            started_at,
            completed_at,
            files_scanned,
            changes_detected: changes_count,
            changes,
            errors: Vec::new(),
        })
    }

    pub async fn run_scheduled(&self) {
        let mut interval = interval(Duration::from_secs(self.config.scan_interval_secs));

        loop {
            interval.tick().await;

            let running = *self.running.lock().await;
            if !running {
                break;
            }

            if let Err(e) = self.run_scan().await {
                warn!("Scheduled FIM scan failed: {}", e);
            }
        }
    }
}

#[async_trait::async_trait]
impl Module for FimModule {
    fn name(&self) -> &str {
        "fim"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn initialize(&mut self, config: ModuleConfig) -> Result<()> {
        info!("Initializing FIM module");

        if config.enabled {
            self.config.paths = config.options
                .get("paths")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(PathBuf::from)).collect())
                .unwrap_or(self.config.paths.clone());

            self.config.exclude_patterns = config.options
                .get("exclude_patterns")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or(self.config.exclude_patterns.clone());

            self.config.scan_interval_secs = config.options
                .get("scan_interval_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(self.config.scan_interval_secs);

            self.config.real_time = config.options
                .get("real_time")
                .and_then(|v| v.as_bool())
                .unwrap_or(self.config.real_time);

            self.scanner.initialize_baseline().await?;
            info!("FIM module initialized with {} paths", self.config.paths.len());
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting FIM module");
        *self.running.lock().await = true;

        if self.config.real_time {
            let scanner = self.scanner.clone();
            let running = self.running.clone();

            tokio::spawn(async move {
                if let Ok(mut rx) = scanner.start_realtime_watcher().await {
                    while *running.lock().await {
                        if let Some(event) = rx.recv().await {
                            info!("Real-time FIM event: {:?}", event);
                        }
                    }
                }
            });
        }

        let scanner = self.scanner.clone();
        let running = self.running.clone();
        let interval_secs = self.config.scan_interval_secs;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            while *running.lock().await {
                interval.tick().await;
                if let Err(e) = scanner.detect_changes().await {
                    warn!("FIM scan error: {}", e);
                } else {
                    info!("Scheduled FIM scan completed");
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping FIM module");
        *self.running.lock().await = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        false
    }

    async fn health_check(&self) -> Result<ModuleHealth> {
        let last_scan = *self.last_scan.lock().await;
        let scan_count = *self.scan_count.lock().await;
        let total_changes = *self.total_changes.lock().await;
        let baseline_count = {
            let baseline = self.scanner.baseline().lock().await;
            baseline.len()
        };

        let mut metrics = HashMap::new();
        metrics.insert("baseline_files".to_string(), serde_json::json!(baseline_count));
        metrics.insert("scans_completed".to_string(), serde_json::json!(scan_count));
        metrics.insert("total_changes_detected".to_string(), serde_json::json!(total_changes));

        if let Some(last) = last_scan {
            if let Ok(duration) = last.duration_since(UNIX_EPOCH) {
                metrics.insert("last_scan_timestamp".to_string(), serde_json::json!(duration.as_secs()));
            }
        }

        let status = if scan_count > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        };

        Ok(ModuleHealth {
            name: self.name().to_string(),
            status,
            message: Some(format!("FIM module operational, {} files in baseline", baseline_count)),
            metrics,
        })
    }
}

use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    use std::io::Write;

    #[tokio::test]
    async fn fim_module_initializes_and_scans() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let mut f = fs::File::create(&test_file).unwrap();
        f.write_all(b"hello").unwrap();

        let config = FimConfig {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let mut module = FimModule::new(config);

        let module_config = ModuleConfig {
            enabled: true,
            options: HashMap::new(),
        };

        module.initialize(module_config).await.unwrap();
        module.start().await.unwrap();

        // Run a manual scan to ensure scan_count > 0 for healthy status
        module.run_scan().await.unwrap();

        let health = module.health_check().await.unwrap();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.metrics.get("baseline_files").unwrap().as_u64().unwrap() > 0);

        module.stop().await.unwrap();
    }
}