use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod ai;
mod ai_explainer;
mod api;
mod capture;
mod cli;
mod config;
mod correlator;
mod dashboard;
mod detection;
mod dpi;
mod engine;
mod forensics;
mod logging;
mod models;
mod profiler;
mod response;
mod simulator;
mod soc;
mod ui;
mod utils;

use cli::{Cli, Commands};
use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "rustshield=info".to_string()),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::time());

    if cli.json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    info!("Starting RustShield IDS v{}", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Run {
            config,
            interface,
            dashboard,
            advanced,
            simulate,
        } => {
            cmd_run(config, interface, dashboard, advanced, simulate).await?;
        }
        Commands::Train {
            config,
            data_file,
            output_model,
        } => {
            cmd_train(config, data_file, output_model).await?;
        }
        Commands::Analyze {
            config,
            pcap_file,
            output,
        } => {
            cmd_analyze(config, pcap_file, output).await?;
        }
        Commands::Config { action } => {
            cmd_config(action).await?;
        }
        Commands::Serve { config, address } => {
            cmd_serve(config, address).await?;
        }
    }

    Ok(())
}

async fn cmd_run(
    config_path: Option<PathBuf>,
    interface: Option<String>,
    use_dashboard: bool,
    use_advanced: bool,
    simulate: bool,
) -> Result<()> {
    info!("Starting IDS in monitoring mode");

    let config = Config::load(config_path)?;

    // Use advanced dashboard if requested
    if use_advanced {
        let interface = interface.unwrap_or_else(|| "eth0".to_string());
        ui::dashboard::run_advanced_dashboard(config, interface, simulate).await?;
        return Ok(());
    }

    let interface = interface
        .or_else(|| config.capture.interface.clone())
        .ok_or_else(|| anyhow::anyhow!("No network interface specified"))?;

    if use_dashboard {
        dashboard::run_dashboard(config, interface).await?;
    } else {
        cli::run_monitoring(config, interface).await?;
    }

    Ok(())
}

async fn cmd_train(
    config_path: Option<PathBuf>,
    data_file: Option<PathBuf>,
    output_model: Option<PathBuf>,
) -> Result<()> {
    info!("Starting model training");

    let config = Config::load(config_path)?;
    let output_path = output_model.unwrap_or_else(|| PathBuf::from("baseline_model.bin"));

    ai::train_baseline_model(&config, data_file, &output_path).await?;

    info!("Model saved to {:?}", output_path);
    Ok(())
}

async fn cmd_analyze(
    config_path: Option<PathBuf>,
    pcap_file: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    info!("Analyzing PCAP file: {:?}", pcap_file);

    let config = Config::load(config_path)?;
    cli::analyze_pcap(config, pcap_file, output).await?;

    Ok(())
}

async fn cmd_config(action: cli::ConfigAction) -> Result<()> {
    match action {
        cli::ConfigAction::Init => {
            cli::generate_default_config().await?;
        }
        cli::ConfigAction::Validate { path } => {
            Config::load(Some(path))?;
            println!("Configuration is valid");
        }
        cli::ConfigAction::Example => {
            cli::print_config_example()?;
        }
    }
    Ok(())
}

async fn cmd_serve(config_path: Option<PathBuf>, address: String) -> Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    info!("Starting RustShield API server on {}", address);

    let config = Arc::new(Config::load(config_path)?);
    let addr: SocketAddr = address.parse()?;

    api::run_integrated(config, addr).await?;

    Ok(())
}
