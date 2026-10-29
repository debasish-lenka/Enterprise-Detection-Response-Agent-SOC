use anyhow::{Context, Result};
use clap::Parser;
use duea_core::{Config, ModuleConfig, ModuleRegistry};
use duea_fim::FimModule;
use duea_transport::MtlsClient;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "duea", version, about = "DUEA - Unified Endpoint Security Agent")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Run once and exit (no daemon mode)
    #[arg(short, long)]
    once: bool,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    fmt().with_env_filter(filter).init();

    // Load configuration
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config.display()))?;

    log::info!("Starting DUEA agent: {} (v{})", config.agent.name, env!("CARGO_PKG_VERSION"));
    log::info!("Environment: {}", config.agent.environment);

    // Initialize transport
    let mut transport = MtlsClient::new(config.clone())?;
    transport.connect().await?;
    log::info!("Connected to management server");

    // Initialize module registry
    let mut registry = ModuleRegistry::new();

    // Register FIM module
    let fim_config = duea_fim::FimConfig {
        paths: config.modules.fim.paths.iter().map(PathBuf::from).collect(),
        exclude_patterns: config.modules.fim.exclude_patterns.clone(),
        scan_interval_secs: config.modules.fim.scan_interval_secs,
        ..Default::default()
    };
    let fim_module = FimModule::new(fim_config);
    registry.register(Box::new(fim_module));

    // Initialize all modules
    let mut module_configs = HashMap::new();
    module_configs.insert("fim".to_string(), ModuleConfig {
        enabled: config.modules.fim.enabled,
        options: {
            let mut opts = HashMap::new();
            opts.insert("paths".to_string(), serde_json::json!(config.modules.fim.paths));
            opts.insert("exclude_patterns".to_string(), serde_json::json!(config.modules.fim.exclude_patterns));
            opts.insert("scan_interval_secs".to_string(), serde_json::json!(config.modules.fim.scan_interval_secs));
            opts
        },
    });
    registry.initialize_all(module_configs).await?;

    // Start all modules
    registry.start_all().await?;
    log::info!("All modules started");

    if args.once {
        // Run single scan cycle
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let health = registry.health_check_all().await?;
        for h in health {
            log::info!("Module {}: {:?} - {}", h.name, h.status, h.message.unwrap_or_default());
        }
    } else {
        // Run until interrupted
        log::info!("Agent running. Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
        log::info!("Shutdown signal received");
    }

    // Stop all modules
    registry.stop_all().await?;
    log::info!("All modules stopped");

    // Close transport
    transport.close().await?;
    log::info!("Transport closed");

    log::info!("DUEA agent stopped");
    Ok(())
}