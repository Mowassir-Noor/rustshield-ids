use crate::config::Config;
use crate::models::{Alert, Severity};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

/// Dashboard state
struct DashboardState {
    alerts: VecDeque<Alert>,
    alert_counts: [u64; 4], // Low, Medium, High, Critical
    packets_per_second: f64,
    total_packets: u64,
    start_time: Instant,
    selected_tab: usize,
    running: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            alerts: VecDeque::with_capacity(100),
            alert_counts: [0, 0, 0, 0],
            packets_per_second: 0.0,
            total_packets: 0,
            start_time: Instant::now(),
            selected_tab: 0,
            running: true,
        }
    }
}

/// Run the TUI dashboard
pub async fn run_dashboard(config: Config, interface: String) -> Result<()> {
    info!("Starting TUI dashboard");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state = Arc::new(RwLock::new(DashboardState::default()));
    let (tx, mut rx) = mpsc::channel::<Alert>(100);

    // Start monitoring in background
    let config_clone = config.clone();
    let interface_clone = interface.clone();
    tokio::spawn(async move {
        if let Err(e) = run_monitoring_with_alerts(config_clone, interface_clone, tx).await {
            error!("Monitoring error: {}", e);
        }
    });

    // Update state with incoming alerts
    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Some(alert) = rx.recv().await {
            let mut state = state_clone.write().await;

            // Update counts
            match alert.severity {
                Severity::Low => state.alert_counts[0] += 1,
                Severity::Medium => state.alert_counts[1] += 1,
                Severity::High => state.alert_counts[2] += 1,
                Severity::Critical => state.alert_counts[3] += 1,
            }

            // Add to recent alerts
            if state.alerts.len() >= 100 {
                state.alerts.pop_back();
            }
            state.alerts.push_front(alert);
        }
    });

    // Main UI loop
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);

    loop {
        // Draw UI
        terminal.draw(|f| draw_ui(f, &state))?;

        // Handle events
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let mut state_guard = state.write().await;
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        state_guard.running = false;
                    }
                    KeyCode::Tab => {
                        state_guard.selected_tab = (state_guard.selected_tab + 1) % 3;
                    }
                    _ => {}
                }
            }
        }

        // Update timing
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        // Check if should exit
        if !state.read().await.running {
            break;
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut Frame, state: &Arc<RwLock<DashboardState>>) {
    let state_guard = match state.try_read() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer
        ])
        .split(f.size());

    // Header with title and tabs
    let header = Paragraph::new("RustShield IDS - AI-Assisted Intrusion Detection")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(header, chunks[0]);

    // Main content area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(chunks[1]);

    // Left sidebar - stats
    draw_stats_panel(f, main_chunks[0], &*state_guard);

    // Right panel - alerts or traffic
    match state_guard.selected_tab {
        0 => draw_alerts_panel(f, main_chunks[1], &*state_guard),
        1 => draw_traffic_panel(f, main_chunks[1], &*state_guard),
        _ => draw_alerts_panel(f, main_chunks[1], &*state_guard),
    }

    // Footer with help
    let footer = Paragraph::new("[q] Quit | [Tab] Switch View | Real-time Monitoring Active")
        .style(Style::default().fg(Color::Gray))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[2]);
}

fn draw_stats_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let stats_block = Block::default().title("Statistics").borders(Borders::ALL);

    let inner = stats_block.inner(area);

    let total_alerts: u64 = state.alert_counts.iter().sum();
    let uptime_secs = state.start_time.elapsed().as_secs();

    let text = vec![
        Line::from(vec![Span::styled(
            format!(
                "Uptime: {:02}:{:02}:{:02}",
                uptime_secs / 3600,
                (uptime_secs % 3600) / 60,
                uptime_secs % 60
            ),
            Style::default().fg(Color::White),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Alerts by Severity:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("  Critical: {}", state.alert_counts[3]),
            Style::default().fg(Color::Red),
        )]),
        Line::from(vec![Span::styled(
            format!("  High: {}", state.alert_counts[2]),
            Style::default().fg(Color::Magenta),
        )]),
        Line::from(vec![Span::styled(
            format!("  Medium: {}", state.alert_counts[1]),
            Style::default().fg(Color::Yellow),
        )]),
        Line::from(vec![Span::styled(
            format!("  Low: {}", state.alert_counts[0]),
            Style::default().fg(Color::Blue),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("Total Alerts: {}", total_alerts),
            Style::default().add_modifier(Modifier::BOLD),
        )]),
    ];

    let stats = Paragraph::new(text).block(stats_block);
    f.render_widget(stats, area);
}

fn _draw_stats_panel2(_f: &mut Frame, _area: Rect, _state: &DashboardState) {}

fn draw_alerts_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let alerts_block = Block::default()
        .title("Recent Alerts")
        .borders(Borders::ALL);

    let items: Vec<ListItem> = state
        .alerts
        .iter()
        .take(20)
        .map(|alert| {
            let severity_color = match alert.severity {
                Severity::Low => Color::Blue,
                Severity::Medium => Color::Yellow,
                Severity::High => Color::Magenta,
                Severity::Critical => Color::Red,
            };

            let content = format!(
                "[{}] {} - {} (Score: {:.2})",
                alert.timestamp.format("%H:%M:%S"),
                alert.severity,
                alert.description.chars().take(40).collect::<String>(),
                alert.score
            );

            ListItem::new(Line::from(vec![Span::styled(
                content,
                Style::default().fg(severity_color),
            )]))
        })
        .collect();

    let alerts_list = List::new(items).block(alerts_block);
    f.render_widget(alerts_list, area);
}

fn draw_traffic_panel(f: &mut Frame, area: Rect, state: &DashboardState) {
    let traffic_block = Block::default()
        .title("Traffic Overview")
        .borders(Borders::ALL);

    let text = vec![
        Line::from("Traffic monitoring visualization coming soon..."),
        Line::from(""),
        Line::from(format!("Current PPS: {:.1}", state.packets_per_second)),
        Line::from(format!("Total Packets: {}", state.total_packets)),
    ];

    let traffic = Paragraph::new(text).block(traffic_block);
    f.render_widget(traffic, area);
}

/// Wrapper to run monitoring and send alerts to the dashboard
async fn run_monitoring_with_alerts(
    config: Config,
    interface: String,
    alert_tx: mpsc::Sender<Alert>,
) -> Result<()> {
    // This is a simplified version - in production, you'd integrate directly
    use crate::ai::{AnomalyDetector, FeatureAggregator};
    use crate::capture::PacketCapture;
    use crate::detection::DetectionEngine;

    let config = Arc::new(config);
    let (packet_tx, mut packet_rx) = mpsc::channel(10000);

    let packet_capture = PacketCapture::new(config.clone(), packet_tx);
    let detection_engine = Arc::new(DetectionEngine::new(config.clone())?);

    let mut anomaly_detector = AnomalyDetector::new(config.clone());
    let model_path = std::path::Path::new(&config.ai.model_path);
    let _ = anomaly_detector.load_model(model_path);

    packet_capture.start_capture(interface).await?;

    let mut feature_aggregator = FeatureAggregator::new(config.ai.feature_window_secs);
    let mut last_feature_extraction = Instant::now();

    while let Some(packet) = packet_rx.recv().await {
        feature_aggregator.add_packet(&packet);

        // Rule-based detection
        let alerts = detection_engine.process_packet(&packet).await;
        for alert in alerts {
            let _ = alert_tx.send(alert).await;
        }

        // Periodic anomaly detection
        let now = Instant::now();
        if now.duration_since(last_feature_extraction).as_secs() >= config.ai.feature_window_secs {
            if let Some(features) = feature_aggregator.extract_features() {
                let (anomaly_score, deviations) = anomaly_detector.detect(&features);

                if anomaly_score >= config.ai.anomaly_threshold {
                    if let Some(alert) = detection_engine
                        .analyze_traffic_features(&features, anomaly_score, deviations)
                        .await
                    {
                        let _ = alert_tx.send(alert).await;
                    }
                }
            }
            last_feature_extraction = now;
        }
    }

    Ok(())
}
