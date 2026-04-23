//! Advanced Terminal UI Module for RustShield IDS
//!
//! Features:
//! - 4-panel layout (Stats, Alerts, Threats, Details)
//! - Real-time sparkline graphs
//! - Alert aggregation and deduplication
//! - Interactive keyboard controls
//! - Color-coded severity with flashing animations

pub mod aggregator;
pub mod dashboard;
pub mod sparkline;

pub use aggregator::{calculate_threat_score, AlertAggregator};
pub use dashboard::{run_advanced_dashboard, ActivePanel, AdvancedDashboard, DashboardMode};
pub use sparkline::{MultiSparkline, Sparkline};
