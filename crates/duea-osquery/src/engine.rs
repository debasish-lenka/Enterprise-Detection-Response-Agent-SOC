use crate::types::{OsqueryConfig, OsqueryResult, OsqueryQuery};
use duea_core::{Module, ModuleConfig, ModuleHealth, HealthStatus, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{info, error};

pub struct OsqueryModule {
    config: OsqueryConfig,
    running: Arc<Mutex<bool>>,
    last_query_results: Arc<Mutex<Vec<OsqueryResult>>>,
    query_count: Arc<Mutex<u64>>,
    total_rows: Arc<Mutex<u64>>,
}

impl OsqueryModule {
    pub fn new(config: OsqueryConfig) -> Self {
        Self {
            config,
            running: Arc::new(Mutex::new(false)),
            last_query_results: Arc::new(Mutex::new(Vec::new())),
            query_count: Arc::new(Mutex::new(0)),
            total_rows: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn run_queries(&self) -> Result<Vec<OsqueryResult>> {
        let mut results = Vec::new();

        for query in &self.config.queries {
            info!("Executing osquery: {}", query.name);

            let result = self.execute_query(query).await?;
            let row_count = result.rows.len();

            if row_count > 0 {
                info!("Query {} returned {} rows", query.name, row_count);
            }

            results.push(result);
        }

        *self.last_query_results.lock().await = results.clone();
        *self.query_count.lock().await += 1;
        *self.total_rows.lock().await += results.iter().map(|r| r.rows.len() as u64).sum::<u64>();

        Ok(results)
    }

    async fn execute_query(&self, query: &OsqueryQuery) -> Result<OsqueryResult> {
        // In a real implementation, this would connect to osquery via Thrift/extension socket
        // For now, we'll simulate with a mock implementation
        // TODO: Implement actual osquery Thrift client connection

        // Simulate query execution delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Return mock results for demonstration
        let mut rows = Vec::new();

        // Add some mock data based on query type
        match query.name.as_str() {
            "processes" => {
                rows.push({
                    let mut row = HashMap::new();
                    row.insert("pid".to_string(), serde_json::json!(1234));
                    row.insert("name".to_string(), serde_json::json!("example.exe"));
                    row.insert("path".to_string(), serde_json::json!("/usr/bin/example"));
                    row.insert("cmdline".to_string(), serde_json::json!("example --flag"));
                    row.insert("cwd".to_string(), serde_json::json!("/home/user"));
                    row.insert("uid".to_string(), serde_json::json!(1000));
                    row.insert("gid".to_string(), serde_json::json!(1000));
                    row
                });
            }
            "listening_ports" => {
                rows.push({
                    let mut row = HashMap::new();
                    row.insert("pid".to_string(), serde_json::json!(5678));
                    row.insert("port".to_string(), serde_json::json!(8080));
                    row.insert("address".to_string(), serde_json::json!("0.0.0.0"));
                    row.insert("protocol".to_string(), serde_json::json!(6));
                    row
                });
            }
            "users" => {
                rows.push({
                    let mut row = HashMap::new();
                    row.insert("uid".to_string(), serde_json::json!(1000));
                    row.insert("gid".to_string(), serde_json::json!(1000));
                    row.insert("username".to_string(), serde_json::json!("testuser"));
                    row.insert("description".to_string(), serde_json::json!("Test User"));
                    row.insert("directory".to_string(), serde_json::json!("/home/testuser"));
                    row.insert("shell".to_string(), serde_json::json!("/bin/bash"));
                    row
                });
            }
            _ => {}
        }

        let columns = if let Some(first_row) = rows.first() {
            first_row.keys().cloned().collect()
        } else {
            Vec::new()
        };

        Ok(OsqueryResult {
            name: query.name.clone(),
            columns,
            rows,
            timestamp: chrono::Utc::now(),
        })
    }

    pub async fn run_scheduled(&self) {
        let mut interval = interval(Duration::from_secs(self.config.query_interval_secs));

        loop {
            interval.tick().await;

            let running = *self.running.lock().await;
            if !running {
                break;
            }

            if let Err(e) = self.run_queries().await {
                error!("Scheduled osquery execution failed: {}", e);
            }
        }
    }
}

#[async_trait::async_trait]
impl Module for OsqueryModule {
    fn name(&self) -> &str {
        "osquery"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn initialize(&mut self, config: ModuleConfig) -> Result<()> {
        info!("Initializing Osquery module");

        if config.enabled {
            // Update config from module options if provided
            if let Some(socket_path) = config.options.get("socket_path") {
                if let Some(path_str) = socket_path.as_str() {
                    self.config.socket_path = PathBuf::from(path_str);
                }
            }

            if let Some(interval) = config.options.get("query_interval_secs") {
                if let Some(secs) = interval.as_u64() {
                    self.config.query_interval_secs = secs;
                }
            }

            info!("Osquery module initialized with socket: {}", self.config.socket_path.display());
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        info!("Starting Osquery module");
        *self.running.lock().await = true;

        // Start scheduled query executor
        let config = self.config.clone();
        let running = self.running.clone();
        let _last_results = self.last_query_results.clone();
        let query_count = self.query_count.clone();
        let _total_rows = self.total_rows.clone();
        let interval_secs = self.config.query_interval_secs;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                let running = *running.lock().await;
                if !running {
                    break;
                }

                // Execute queries
                for _query in &config.queries {
                    // Mock execution - in real implementation, connect to osquery
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                *query_count.lock().await += 1;
                info!("Scheduled osquery cycle completed");
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping Osquery module");
        *self.running.lock().await = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        false // Would need async to check properly
    }

    async fn health_check(&self) -> Result<ModuleHealth> {
        let last_results_len = self.last_query_results.lock().await.len();
        let query_count = *self.query_count.lock().await;
        let total_rows = *self.total_rows.lock().await;

        let mut metrics = HashMap::new();
        metrics.insert("queries_executed".to_string(), serde_json::json!(query_count));
        metrics.insert("total_rows_returned".to_string(), serde_json::json!(total_rows));
        metrics.insert("last_results_count".to_string(), serde_json::json!(last_results_len));
        metrics.insert("configured_queries".to_string(), serde_json::json!(self.config.queries.len()));

        let status = if query_count > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        };

        Ok(ModuleHealth {
            name: self.name().to_string(),
            status,
            message: Some(format!("Osquery module operational, {} queries configured", self.config.queries.len())),
            metrics,
        })
    }
}

use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn osquery_module_initializes_and_executes() {
        let config = OsqueryConfig::default();
        let mut module = OsqueryModule::new(config);

        let module_config = ModuleConfig {
            enabled: true,
            options: HashMap::new(),
        };

        module.initialize(module_config).await.unwrap();
        module.start().await.unwrap();

        // Run queries manually for test
        let results = module.run_queries().await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().any(|r| r.name == "processes"));
        assert!(results.iter().any(|r| r.name == "listening_ports"));
        assert!(results.iter().any(|r| r.name == "users"));

        let health = module.health_check().await.unwrap();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.metrics.get("queries_executed").unwrap().as_u64().unwrap() > 0);

        module.stop().await.unwrap();
    }
}