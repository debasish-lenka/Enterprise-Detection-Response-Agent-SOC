use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled: bool,
    #[serde(flatten)]
    pub options: HashMap<String, serde_json::Value>,
}

#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    async fn initialize(&mut self, config: ModuleConfig) -> crate::Result<()>;
    async fn start(&mut self) -> crate::Result<()>;
    async fn stop(&mut self) -> crate::Result<()>;
    fn is_running(&self) -> bool;
    async fn health_check(&self) -> crate::Result<ModuleHealth>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub metrics: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

pub struct ModuleRegistry {
    modules: HashMap<String, Box<dyn Module>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn register(&mut self, module: Box<dyn Module>) {
        self.modules.insert(module.name().to_string(), module);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Module> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut (dyn Module + '_)> {
        if let Some(module) = self.modules.get_mut(name) {
            Some(module.as_mut())
        } else {
            None
        }
    }

    pub async fn initialize_all(&mut self, configs: HashMap<String, ModuleConfig>) -> Result<()> {
        for (name, config) in configs {
            if let Some(module) = self.modules.get_mut(&name) {
                if config.enabled {
                    module.initialize(config).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn start_all(&mut self) -> Result<()> {
        for module in self.modules.values_mut() {
            if module.is_running() {
                continue;
            }
            module.start().await?;
        }
        Ok(())
    }

    pub async fn stop_all(&mut self) -> Result<()> {
        for module in self.modules.values_mut() {
            if module.is_running() {
                module.stop().await?;
            }
        }
        Ok(())
    }

    pub async fn health_check_all(&self) -> Result<Vec<ModuleHealth>> {
        let mut results = Vec::new();
        for module in self.modules.values() {
            results.push(module.health_check().await?);
        }
        Ok(results)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct TestModule {
        name: String,
        running: Arc<Mutex<bool>>,
    }

    impl TestModule {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                running: Arc::new(Mutex::new(false)),
            }
        }
    }

    #[async_trait]
    impl Module for TestModule {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        async fn initialize(&mut self, _config: ModuleConfig) -> Result<()> {
            Ok(())
        }

        async fn start(&mut self) -> Result<()> {
            *self.running.lock().await = true;
            Ok(())
        }

        async fn stop(&mut self) -> Result<()> {
            *self.running.lock().await = false;
            Ok(())
        }

        fn is_running(&self) -> bool {
            false
        }

        async fn health_check(&self) -> Result<ModuleHealth> {
            Ok(ModuleHealth {
                name: self.name.clone(),
                status: HealthStatus::Healthy,
                message: None,
                metrics: HashMap::new(),
            })
        }
    }

    #[tokio::test]
    async fn registry_registers_and_initializes_modules() {
        let mut registry = ModuleRegistry::new();
        registry.register(Box::new(TestModule::new("test-module")));

        let mut configs = HashMap::new();
        configs.insert(
            "test-module".to_string(),
            ModuleConfig {
                enabled: true,
                options: HashMap::new(),
            },
        );

        registry.initialize_all(configs).await.unwrap();
        registry.start_all().await.unwrap();

        let health = registry.health_check_all().await.unwrap();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].name, "test-module");
        assert_eq!(health[0].status, HealthStatus::Healthy);

        registry.stop_all().await.unwrap();
    }
}