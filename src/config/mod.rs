use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub capture: CaptureConfig,
    pub detection: DetectionConfig,
    pub ai: AiConfig,
    pub logging: LoggingConfig,
    pub alerting: AlertingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub name: String,
    pub description: String,
    pub max_packet_queue: usize,
    pub worker_threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub buffer_size: i32,
    pub bpf_filter: Option<String>,
    pub exclude_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub rules_file: String,
    pub rules_refresh_interval_secs: u64,
    pub enable_rule_based: bool,
    pub enable_anomaly_detection: bool,
    pub port_scan_threshold: u32,
    pub port_scan_time_window_secs: u64,
    pub syn_flood_threshold: u32,
    pub syn_flood_time_window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub model_path: String,
    pub training_data_path: Option<String>,
    pub anomaly_threshold: f64,
    pub feature_window_secs: u64,
    pub min_samples_for_detection: usize,
    pub isolation_forest_contamination: f64,
    pub isolation_forest_n_estimators: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_file: String,
    pub log_format: LogFormat,
    pub max_file_size_mb: u64,
    pub max_backup_files: u32,
    pub console_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub min_severity: String,
    pub rate_limit_per_minute: u32,
    pub deduplication_window_secs: u64,
    pub webhook_url: Option<String>,
    pub email_notifications: bool,
    pub suppress_internal_traffic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "pretty")]
    Pretty,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                name: "RustShield IDS".to_string(),
                description: "AI-Assisted Intrusion Detection System".to_string(),
                max_packet_queue: 10000,
                worker_threads: 4,
            },
            capture: CaptureConfig {
                interface: None,
                promiscuous: true,
                snaplen: 65535,
                buffer_size: 67108864,
                bpf_filter: None,
                exclude_ips: vec![],
            },
            detection: DetectionConfig {
                rules_file: "rules/default.yaml".to_string(),
                rules_refresh_interval_secs: 300,
                enable_rule_based: true,
                enable_anomaly_detection: true,
                port_scan_threshold: 20,
                port_scan_time_window_secs: 60,
                syn_flood_threshold: 100,
                syn_flood_time_window_secs: 10,
            },
            ai: AiConfig {
                model_path: "models/baseline.bin".to_string(),
                training_data_path: None,
                anomaly_threshold: 0.7,
                feature_window_secs: 30,
                min_samples_for_detection: 10,
                isolation_forest_contamination: 0.1,
                isolation_forest_n_estimators: 100,
            },
            logging: LoggingConfig {
                log_file: "logs/rustshield.log".to_string(),
                log_format: LogFormat::Json,
                max_file_size_mb: 100,
                max_backup_files: 5,
                console_output: true,
            },
            alerting: AlertingConfig {
                min_severity: "LOW".to_string(),
                rate_limit_per_minute: 100,
                deduplication_window_secs: 300,
                webhook_url: None,
                email_notifications: false,
                suppress_internal_traffic: true,
            },
        }
    }
}

impl Config {
    pub fn load(path: Option<impl AsRef<Path>>) -> Result<Self> {
        if let Some(p) = path {
            let content = std::fs::read_to_string(p)?;
            let config: Config = serde_yaml::from_str(&content)?;
            return Ok(config);
        }

        // Try default locations
        let default_paths = ["rustshield.yaml", "config/rustshield.yaml", "/etc/rustshield/config.yaml"];
        
        for path in &default_paths {
            if std::path::Path::new(path).exists() {
                let content = std::fs::read_to_string(path)?;
                let config: Config = serde_yaml::from_str(&content)?;
                return Ok(config);
            }
        }

        // Return default config if no file found
        Ok(Config::default())
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
