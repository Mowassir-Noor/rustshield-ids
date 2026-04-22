use crate::models::{Alert, Severity};
use crate::config::LoggingConfig;
use anyhow::Result;
use chrono::Utc;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Alert logging and management system
pub struct AlertLogger {
    config: Arc<LoggingConfig>,
    log_file: Arc<RwLock<File>>,
    alert_count: Arc<RwLock<u64>>,
}

/// Statistics for dashboard and reporting
#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub alerts_by_severity: std::collections::HashMap<Severity, u64>,
    pub alerts_by_type: std::collections::HashMap<String, u64>,
    pub recent_alerts: Vec<Alert>,
    pub alerts_per_minute: f64,
}

impl AlertLogger {
    pub async fn new(config: Arc<LoggingConfig>) -> Result<Self> {
        // Create logs directory if needed
        if let Some(parent) = Path::new(&config.log_file).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.log_file)?;

        info!("Alert logger initialized: {}", config.log_file);

        Ok(Self {
            config,
            log_file: Arc::new(RwLock::new(file)),
            alert_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Log an alert to file and optionally console
    pub async fn log_alert(&self, alert: &Alert) -> Result<()> {
        // Update counter
        {
            let mut count = self.alert_count.write().await;
            *count += 1;
        }

        // Format based on configuration
        let log_entry = match self.config.log_format {
            crate::config::LogFormat::Json => {
                serde_json::to_string(&alert)?
            }
            crate::config::LogFormat::Pretty => {
                self.format_pretty(alert)
            }
        };

        // Write to file
        {
            let mut file = self.log_file.write().await;
            writeln!(file, "{}", log_entry)?;
            file.flush()?;
        }

        // Console output
        if self.config.console_output {
            self.print_console(alert);
        }

        debug!("Logged alert {}: {}", alert.id, alert.description);
        
        Ok(())
    }

    /// Export alerts to a file (for external analysis)
    pub async fn export_alerts(&self, output_path: &Path, alerts: &[Alert]) -> Result<()> {
        let json_data = serde_json::to_string_pretty(alerts)?;
        tokio::fs::write(output_path, json_data).await?;
        info!("Exported {} alerts to {:?}", alerts.len(), output_path);
        Ok(())
    }

    /// Get current alert count
    pub async fn get_alert_count(&self) -> u64 {
        *self.alert_count.read().await
    }

    /// Rotate log file if it exceeds max size
    pub async fn rotate_if_needed(&self) -> Result<()> {
        let metadata = std::fs::metadata(&self.config.log_file)?;
        let size_mb = metadata.len() / (1024 * 1024);

        if size_mb >= self.config.max_file_size_mb {
            self.rotate_log().await?;
        }

        Ok(())
    }

    fn format_pretty(&self, alert: &Alert) -> String {
        let severity_color = match alert.severity {
            Severity::Low => "\x1b[34m",      // Blue
            Severity::Medium => "\x1b[33m",   // Yellow
            Severity::High => "\x1b[35m",     // Magenta
            Severity::Critical => "\x1b[31m", // Red
        };
        let reset = "\x1b[0m";

        format!(
            "[{}{:>8}{}] {} - {} - {} - Score: {:.2}",
            severity_color,
            alert.severity.to_string(),
            reset,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
            alert.id,
            alert.description,
            alert.score
        )
    }

    fn print_console(&self, alert: &Alert) {
        let severity_emoji = match alert.severity {
            Severity::Low => "ℹ️",
            Severity::Medium => "⚠️",
            Severity::High => "🚨",
            Severity::Critical => "🔴",
        };

        println!(
            "{} [{}] {} - Score: {:.2}",
            severity_emoji,
            alert.severity,
            alert.description,
            alert.score
        );

        if !alert.details.feature_deviations.is_empty() {
            println!("  Feature deviations:");
            for deviation in &alert.details.feature_deviations {
                println!("    - {}: {:.2} (expected: {:.2})",
                    deviation.feature_name,
                    deviation.actual_value,
                    deviation.expected_value
                );
            }
        }

        println!("  Recommendation: {}", alert.details.recommendation);
    }

    async fn rotate_log(&self) -> Result<()> {
        // Close current file
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_file)?;

        // Rename old log files
        for i in (1..self.config.max_backup_files).rev() {
            let old_path = format!("{}.{}"
, self.config.log_file, i);
            let new_path = format!("{}.{}"
, self.config.log_file, i + 1);
            
            if Path::new(&old_path).exists() {
                tokio::fs::rename(&old_path, &new_path).await.ok();
            }
        }

        // Rename current log
        let backup_path = format!("{}.1"
, self.config.log_file);
        tokio::fs::rename(&self.config.log_file, &backup_path).await.ok();

        // Update file handle
        let mut file = self.log_file.write().await;
        *file = new_file;

        info!("Log file rotated");
        Ok(())
    }
}

/// Alert aggregation for deduplication and rate limiting
pub struct AlertAggregator {
    recent_alerts: std::collections::HashMap<String, chrono::DateTime<Utc>>,
    dedup_window_secs: i64,
    rate_limit_per_minute: u32,
    alert_times: Vec<chrono::DateTime<Utc>>,
}

impl AlertAggregator {
    pub fn new(dedup_window_secs: u64, rate_limit_per_minute: u32) -> Self {
        Self {
            recent_alerts: std::collections::HashMap::new(),
            dedup_window_secs: dedup_window_secs as i64,
            rate_limit_per_minute,
            alert_times: Vec::new(),
        }
    }

    /// Check if alert should be suppressed (duplicate or rate limit)
    pub fn should_suppress(&mut self, alert: &Alert) -> bool {
        let now = Utc::now();
        
        // Clean old entries
        self.recent_alerts.retain(|_, timestamp| {
            now.signed_duration_since(*timestamp).num_seconds() < self.dedup_window_secs
        });
        
        self.alert_times.retain(|t| {
            now.signed_duration_since(*t).num_minutes() < 1
        });

        // Check rate limit
        if self.alert_times.len() >= self.rate_limit_per_minute as usize {
            warn!("Rate limit reached, suppressing alert");
            return true;
        }

        // Check for duplicates (based on source IP and alert type)
        let dedup_key = format!("{:?}-{:?}-{:?}", 
            alert.source_ip, 
            alert.alert_type, 
            alert.description.chars().take(20).collect::<String>()
        );
        
        if self.recent_alerts.contains_key(&dedup_key) {
            return true;
        }

        // Record this alert
        self.recent_alerts.insert(dedup_key, now);
        self.alert_times.push(now);
        
        false
    }
}

/// Real-time alert stream for dashboards
pub struct AlertStream {
    tx: mpsc::Sender<Alert>,
    rx: mpsc::Receiver<Alert>,
}

impl AlertStream {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self { tx, rx }
    }

    pub fn sender(&self) -> mpsc::Sender<Alert> {
        self.tx.clone()
    }

    pub async fn recv(&mut self) -> Option<Alert> {
        self.rx.recv().await
    }
}
