use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod dashboard;
pub mod monitoring;

pub use monitoring::analyze_pcap;
pub use monitoring::run_monitoring;

#[derive(Parser)]
#[command(name = "rustshield")]
#[command(about = "AI-Assisted Intrusion Detection System")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output logs in JSON format
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the IDS in monitoring mode
    Run {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Network interface to monitor
        #[arg(short, long, value_name = "INTERFACE")]
        interface: Option<String>,

        /// Enable TUI dashboard
        #[arg(short, long)]
        dashboard: bool,

        /// Enable advanced TUI dashboard with 4-panel layout
        #[arg(short, long)]
        advanced: bool,

        /// Enable attack simulation mode (for testing)
        #[arg(short, long)]
        simulate: bool,
    },

    /// Train the anomaly detection model on baseline traffic
    Train {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Path to training data (PCAP or JSON features)
        #[arg(short, long, value_name = "FILE")]
        data_file: Option<PathBuf>,

        /// Output path for trained model
        #[arg(short, long, value_name = "FILE")]
        output_model: Option<PathBuf>,
    },

    /// Analyze a saved PCAP file
    Analyze {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Path to PCAP file to analyze
        #[arg(value_name = "PCAP_FILE")]
        pcap_file: PathBuf,

        /// Output file for analysis results
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Start the REST API server
    Serve {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Address to bind the API server
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        address: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Initialize default configuration file
    Init,

    /// Validate a configuration file
    Validate {
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },

    /// Print example configuration
    Example,
}

pub async fn generate_default_config() -> anyhow::Result<()> {
    let config_path = PathBuf::from("rustshield.yaml");

    if config_path.exists() {
        println!("Configuration file already exists at {:?}", config_path);
        return Ok(());
    }

    let default_config = include_str!("../../config/default.yaml");
    tokio::fs::write(&config_path, default_config).await?;

    println!("Created default configuration at {:?}", config_path);
    Ok(())
}

pub fn print_config_example() -> anyhow::Result<()> {
    let example = include_str!("../../config/example.yaml");
    println!("{}", example);
    Ok(())
}
