//! Advanced TUI Dashboard for RustShield IDS
//!
//! 4-Panel Layout:
//! +----------------------+--------------------------+
//! | System Stats         | Live Alerts              |
//! +----------------------+--------------------------+
//! | Top Threats          | Alert Details (selected)   |
//! +----------------------+--------------------------+

use crate::engine::{create_default_engine, DetectionEngine};
use crate::models::{
    AggregatedAlert, EnrichedAlert, PacketInfo, Severity, SystemMetrics, TopThreat,
};
use crate::simulator::{AttackSimulator, AttackType, ScanIntensity};
use crate::ui::{calculate_threat_score, AlertAggregator, Sparkline};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

/// Active panel for navigation
#[derive(Debug, Clone, PartialEq)]
pub enum ActivePanel {
    Alerts,
    Threats,
    Details,
}

/// Dashboard mode
#[derive(Debug, Clone, PartialEq)]
pub enum DashboardMode {
    Normal,
    Simulation,
    Filtered(Severity),
    Search(String),
}

/// Advanced dashboard state
pub struct AdvancedDashboard {
    /// Alert aggregator for deduplication
    aggregator: AlertAggregator,
    /// Packet counter for metrics
    packet_count: u64,
    /// Alert counter
    alert_count: u64,
    /// Packets per second sparkline
    pps_sparkline: Sparkline,
    /// Alerts per second sparkline
    aps_sparkline: Sparkline,
    /// System metrics
    metrics: SystemMetrics,
    /// Active panel for keyboard navigation
    active_panel: ActivePanel,
    /// Dashboard mode
    mode: DashboardMode,
    /// Selected alert index
    selected_alert: usize,
    /// Selected threat index
    selected_threat: usize,
    /// Search query
    search_query: String,
    /// Show help overlay
    show_help: bool,
    /// Running state
    running: bool,
    /// Flash animation for high severity
    flash_state: bool,
    /// Last update time
    last_update: Instant,
    /// Detection engine
    engine: Arc<DetectionEngine>,
    /// Recent raw alerts (for details view)
    raw_alerts: VecDeque<EnrichedAlert>,
    /// Top threats list
    top_threats: Vec<TopThreat>,
}

impl AdvancedDashboard {
    pub fn new() -> Self {
        Self {
            aggregator: AlertAggregator::new(300),
            packet_count: 0,
            alert_count: 0,
            pps_sparkline: Sparkline::new(60),
            aps_sparkline: Sparkline::new(60),
            metrics: SystemMetrics::default(),
            active_panel: ActivePanel::Alerts,
            mode: DashboardMode::Normal,
            selected_alert: 0,
            selected_threat: 0,
            search_query: String::new(),
            show_help: false,
            running: true,
            flash_state: false,
            last_update: Instant::now(),
            engine: Arc::new(create_default_engine()),
            raw_alerts: VecDeque::with_capacity(100),
            top_threats: Vec::new(),
        }
    }

    /// Process a new packet through the detection engine
    pub async fn process_packet(&mut self, packet: PacketInfo) {
        self.packet_count += 1;

        // Process through detection engine
        let alerts = self.engine.process_packet(packet).await;

        for alert in alerts {
            self.alert_count += 1;
            self.aggregator.add_alert(alert.clone());

            // Keep recent raw alerts
            if self.raw_alerts.len() >= 100 {
                self.raw_alerts.pop_back();
            }
            self.raw_alerts.push_front(alert);
        }

        // Update sparklines every second
        if self.last_update.elapsed() >= Duration::from_secs(1) {
            let pps = self.packet_count as f64 / self.last_update.elapsed().as_secs_f64();
            let aps = self.alert_count as f64 / self.last_update.elapsed().as_secs_f64();

            self.pps_sparkline.push(pps);
            self.aps_sparkline.push(aps);

            self.last_update = Instant::now();
            self.packet_count = 0;
            self.alert_count = 0;
        }

        // Cleanup old aggregated alerts periodically
        self.aggregator.cleanup();
    }

    /// Handle keyboard input
    pub fn handle_input(&mut self, key: KeyCode) -> bool {
        if self.show_help {
            self.show_help = false;
            return true;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.running = false;
                return false;
            }
            KeyCode::Char('h') | KeyCode::Char('?') => {
                self.show_help = true;
            }
            KeyCode::Tab => {
                self.active_panel = match self.active_panel {
                    ActivePanel::Alerts => ActivePanel::Threats,
                    ActivePanel::Threats => ActivePanel::Details,
                    ActivePanel::Details => ActivePanel::Alerts,
                };
            }
            KeyCode::Up => match self.active_panel {
                ActivePanel::Alerts => {
                    if self.selected_alert > 0 {
                        self.selected_alert -= 1;
                    }
                }
                ActivePanel::Threats => {
                    if self.selected_threat > 0 {
                        self.selected_threat -= 1;
                    }
                }
                _ => {}
            },
            KeyCode::Down => match self.active_panel {
                ActivePanel::Alerts => {
                    let max = self.aggregator.get_aggregated_alerts().len();
                    if self.selected_alert < max.saturating_sub(1) {
                        self.selected_alert += 1;
                    }
                }
                ActivePanel::Threats => {
                    let max = self.top_threats.len();
                    if self.selected_threat < max.saturating_sub(1) {
                        self.selected_threat += 1;
                    }
                }
                _ => {}
            },
            KeyCode::Char('f') => {
                // Cycle through severity filters
                self.mode = match &self.mode {
                    DashboardMode::Normal => DashboardMode::Filtered(Severity::Critical),
                    DashboardMode::Filtered(Severity::Critical) => {
                        DashboardMode::Filtered(Severity::High)
                    }
                    DashboardMode::Filtered(Severity::High) => {
                        DashboardMode::Filtered(Severity::Medium)
                    }
                    DashboardMode::Filtered(Severity::Medium) => {
                        DashboardMode::Filtered(Severity::Low)
                    }
                    DashboardMode::Filtered(_) => DashboardMode::Normal,
                    DashboardMode::Search(q) => DashboardMode::Search(q.clone()),
                    DashboardMode::Simulation => DashboardMode::Simulation,
                };
            }
            KeyCode::Char('s') => {
                // Toggle simulation mode
                self.mode = if matches!(self.mode, DashboardMode::Simulation) {
                    DashboardMode::Normal
                } else {
                    DashboardMode::Simulation
                };
            }
            KeyCode::Char('/') => {
                // Enter search mode
                self.mode = DashboardMode::Search(String::new());
            }
            KeyCode::Enter => {
                // Expand selected alert details
                self.active_panel = ActivePanel::Details;
            }
            _ => {}
        }

        true
    }

    /// Get filtered alerts based on current mode
    fn get_filtered_alerts(&self) -> Vec<&AggregatedAlert> {
        let alerts = self.aggregator.get_aggregated_alerts();

        match &self.mode {
            DashboardMode::Filtered(severity) => alerts
                .into_iter()
                .filter(|a| a.severity == *severity)
                .collect(),
            DashboardMode::Search(query) if !query.is_empty() => {
                let query_lower = query.to_lowercase();
                alerts
                    .into_iter()
                    .filter(|a| {
                        a.description.to_lowercase().contains(&query_lower)
                            || a.alert_type.to_lowercase().contains(&query_lower)
                            || a.detection_result
                                .pattern
                                .to_lowercase()
                                .contains(&query_lower)
                    })
                    .collect()
            }
            _ => alerts,
        }
    }

    /// Get severity color
    fn get_severity_color(severity: Severity) -> Color {
        match severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::Magenta,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        }
    }

    /// Get severity style with optional flashing
    fn get_severity_style(&self, severity: Severity) -> Style {
        let color = Self::get_severity_color(severity);

        match severity {
            Severity::Critical if self.flash_state => Style::default()
                .fg(color)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
            Severity::Critical => Style::default().fg(color).add_modifier(Modifier::BOLD),
            Severity::High => Style::default().fg(color).add_modifier(Modifier::BOLD),
            _ => Style::default().fg(color),
        }
    }
}

impl Default for AdvancedDashboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the advanced dashboard
pub async fn run_advanced_dashboard(
    _config: crate::config::Config,
    _interface: String,
    simulate: bool,
) -> Result<()> {
    info!("Starting advanced TUI dashboard");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let dashboard = Arc::new(RwLock::new(AdvancedDashboard::new()));
    let (tx, mut rx) = mpsc::channel::<PacketInfo>(1000);

    // Start simulation if requested
    if simulate {
        let sim_tx = tx.clone();
        tokio::spawn(async move {
            crate::simulator::run_simulation(sim_tx).await;
        });
    }

    // Packet processing task
    let dash_clone = dashboard.clone();
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let mut dash = dash_clone.write().await;
            dash.process_packet(packet).await;
        }
    });

    // Main UI loop
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);
    let flash_rate = Duration::from_millis(500);
    let mut last_flash = Instant::now();

    loop {
        // Draw UI
        terminal.draw(|f| draw_dashboard(f, &dashboard).unwrap())?;

        // Handle events
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let mut dash = dashboard.write().await;
                    if !dash.handle_input(key.code) {
                        break;
                    }
                }
            }
        }

        // Update flash animation
        if last_flash.elapsed() >= flash_rate {
            let mut dash = dashboard.write().await;
            dash.flash_state = !dash.flash_state;
            last_flash = Instant::now();
        }

        // Update timing
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        // Check if should exit
        let dash = dashboard.read().await;
        if !dash.running {
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

/// Draw the complete dashboard
fn draw_dashboard(f: &mut Frame, dashboard: &Arc<RwLock<AdvancedDashboard>>) -> Result<()> {
    let dash = dashboard.try_read();
    if dash.is_err() {
        return Ok(());
    }
    let dash = dash.unwrap();

    let size = f.size();

    // Main layout: 2x2 grid
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_chunks[0]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_chunks[1]);

    // Draw panels
    draw_system_stats_panel(f, top_chunks[0], &dash);
    draw_live_alerts_panel(f, top_chunks[1], &dash);
    draw_top_threats_panel(f, bottom_chunks[0], &dash);
    draw_alert_details_panel(f, bottom_chunks[1], &dash);

    // Draw help overlay if enabled
    if dash.show_help {
        draw_help_overlay(f);
    }

    Ok(())
}

/// Draw system stats panel with sparklines
fn draw_system_stats_panel(f: &mut Frame, area: Rect, dash: &AdvancedDashboard) {
    let block = Block::default()
        .title("📊 System Stats")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout for sparklines and stats
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    // Packets per second
    let pps_line = dash
        .pps_sparkline
        .render(chunks[0].width as usize, Color::Green);
    let pps_text = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "Packets/sec: ",
            Style::default().fg(Color::Gray),
        )]),
        pps_line,
        Line::from(vec![Span::styled(
            format!(
                "Current: {:.1} | Peak: {:.1}",
                dash.pps_sparkline.current(),
                dash.pps_sparkline.peak()
            ),
            Style::default().fg(Color::White),
        )]),
    ]);
    f.render_widget(pps_text, chunks[0]);

    // Alerts per second
    let aps_line = dash
        .aps_sparkline
        .render_with_threshold(chunks[1].width as usize, 5.0);
    let aps_text = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "Alerts/sec: ",
            Style::default().fg(Color::Gray),
        )]),
        aps_line,
        Line::from(vec![Span::styled(
            format!(
                "Current: {:.1} | Average: {:.1}",
                dash.aps_sparkline.current(),
                dash.aps_sparkline.average()
            ),
            Style::default().fg(Color::White),
        )]),
    ]);
    f.render_widget(aps_text, chunks[1]);

    // Alert counts by severity
    let counts = dash.aggregator.get_severity_counts();
    let counts_text = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "Alert Counts:",
            Style::default().fg(Color::Gray),
        )]),
        Line::from(vec![
            Span::styled(
                format!(
                    "🔴 Crit: {}  ",
                    counts.get(&Severity::Critical).unwrap_or(&0)
                ),
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!("🟠 High: {}  ", counts.get(&Severity::High).unwrap_or(&0)),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(
                format!("🟡 Med: {}  ", counts.get(&Severity::Medium).unwrap_or(&0)),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("🔵 Low: {}", counts.get(&Severity::Low).unwrap_or(&0)),
                Style::default().fg(Color::Blue),
            ),
        ]),
    ]);
    f.render_widget(counts_text, chunks[2]);

    // Mode indicator
    let mode_text = match &dash.mode {
        DashboardMode::Normal => "Mode: Normal".to_string(),
        DashboardMode::Simulation => "Mode: 🎮 SIMULATION".to_string(),
        DashboardMode::Filtered(s) => format!("Mode: Filtered ({:?})", s),
        DashboardMode::Search(q) => format!("Mode: Search '{}'", q),
    };

    let mode_para = Paragraph::new(mode_text).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(mode_para, chunks[3]);
}

/// Draw live alerts panel
fn draw_live_alerts_panel(f: &mut Frame, area: Rect, dash: &AdvancedDashboard) {
    let is_active = matches!(dash.active_panel, ActivePanel::Alerts);
    let border_color = if is_active {
        Color::Yellow
    } else {
        Color::Gray
    };

    let block = Block::default()
        .title("🚨 Live Alerts")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let alerts = dash.get_filtered_alerts();
    let items: Vec<ListItem> = alerts
        .iter()
        .enumerate()
        .map(|(idx, alert)| {
            let style = if idx == dash.selected_alert && is_active {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                dash.get_severity_style(alert.severity)
            };

            let content = format!(
                "[{}] {} - {} (×{})",
                alert.severity,
                alert.detection_result.pattern,
                &alert.description[..alert.description.len().min(30)],
                alert.count
            );

            ListItem::new(content).style(style)
        })
        .collect();

    let alerts_list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(alerts_list, area);
}

/// Draw top threats panel
fn draw_top_threats_panel(f: &mut Frame, area: Rect, dash: &AdvancedDashboard) {
    let is_active = matches!(dash.active_panel, ActivePanel::Threats);
    let border_color = if is_active {
        Color::Yellow
    } else {
        Color::Gray
    };

    let block = Block::default()
        .title("⚠️ Top Threats")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    // Get top aggregated alerts as threats
    let threats = dash.aggregator.get_top_alerts(10);
    let threat_score = calculate_threat_score(&threats);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(inner);

    // Threat score gauge
    let gauge_color = if threat_score > 75.0 {
        Color::Red
    } else if threat_score > 50.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let gauge = Gauge::default()
        .block(Block::default().title(format!("Threat Score: {:.1}", threat_score)))
        .gauge_style(Style::default().fg(gauge_color).bg(Color::Black))
        .ratio((threat_score / 100.0).min(1.0));
    f.render_widget(gauge, chunks[0]);

    // Threat list
    let items: Vec<ListItem> = threats
        .into_iter()
        .enumerate()
        .map(|(idx, alert)| {
            let style = if idx == dash.selected_threat && is_active {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                dash.get_severity_style(alert.severity)
            };

            let content = format!(
                "{} - {} IPs, {} ports (×{})",
                alert.detection_result.pattern,
                alert.source_ips.len(),
                alert.destination_ports.len(),
                alert.count
            );

            ListItem::new(content).style(style)
        })
        .collect();

    let threat_list = List::new(items);
    f.render_widget(threat_list, chunks[1]);
}

/// Draw alert details panel
fn draw_alert_details_panel(f: &mut Frame, area: Rect, dash: &AdvancedDashboard) {
    let is_active = matches!(dash.active_panel, ActivePanel::Details);
    let border_color = if is_active {
        Color::Yellow
    } else {
        Color::Gray
    };

    let block = Block::default()
        .title("📋 Alert Details")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Get selected alert
    let alerts = dash.get_filtered_alerts();
    let content = if let Some(alert) = alerts.get(dash.selected_alert) {
        vec![
            Line::from(vec![Span::styled(
                format!("ID: {}", alert.group_id),
                Style::default().fg(Color::Gray),
            )]),
            Line::from(vec![Span::styled(
                format!("Type: {}", alert.alert_type),
                Style::default().fg(Color::White),
            )]),
            Line::from(vec![Span::styled(
                format!("Severity: {:?}", alert.severity),
                dash.get_severity_style(alert.severity),
            )]),
            Line::from(vec![Span::styled(
                format!("Pattern: {}", alert.detection_result.pattern),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                format!(
                    "Confidence: {:.1}%",
                    alert.detection_result.confidence * 100.0
                ),
                Style::default().fg(Color::White),
            )]),
            Line::from(vec![Span::styled(
                format!("Count: {} occurrences", alert.count),
                Style::default().fg(Color::White),
            )]),
            Line::from(vec![Span::styled(
                format!("Sources: {:?}", alert.source_ips),
                Style::default().fg(Color::Yellow),
            )]),
            Line::from(vec![Span::styled(
                format!("Ports: {:?}", alert.destination_ports),
                Style::default().fg(Color::Yellow),
            )]),
            Line::from(vec![Span::styled(
                "Indicators:",
                Style::default().fg(Color::Gray),
            )]),
            Line::from(vec![Span::styled(
                alert.detection_result.indicators.join(", "),
                Style::default().fg(Color::White),
            )]),
            Line::from(vec![Span::styled(
                format!("Reason: {}", alert.detection_result.reason),
                Style::default().fg(Color::White),
            )]),
            Line::from(vec![Span::styled(
                format!(
                    "Recommendation: {}",
                    alert.sample_alert.details.recommendation
                ),
                Style::default().fg(Color::Green),
            )]),
        ]
    } else {
        vec![Line::from("No alert selected")]
    };

    let paragraph = Paragraph::new(content).wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner);
}

/// Draw help overlay
fn draw_help_overlay(f: &mut Frame) {
    let block = Block::default()
        .title("Help - Keyboard Controls")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));

    let text = vec![
        Line::from(vec![Span::styled(
            "Navigation:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  ↑/↓     - Navigate alerts/threats"),
        Line::from("  Tab     - Switch panels"),
        Line::from("  Enter   - View details"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Controls:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  f       - Filter by severity (cycles)"),
        Line::from("  s       - Toggle simulation mode"),
        Line::from("  /       - Search alerts"),
        Line::from("  h/?     - Show this help"),
        Line::from("  q/Esc   - Quit"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Severity Colors:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            "  🔴 Critical",
            Style::default().fg(Color::Red),
        )]),
        Line::from(vec![Span::styled(
            "  🟠 High",
            Style::default().fg(Color::Magenta),
        )]),
        Line::from(vec![Span::styled(
            "  🟡 Medium",
            Style::default().fg(Color::Yellow),
        )]),
        Line::from(vec![Span::styled(
            "  🔵 Low",
            Style::default().fg(Color::Blue),
        )]),
    ];

    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);

    // Center the overlay
    let area = centered_rect(60, 70, f.size());
    f.render_widget(Clear, area);
    f.render_widget(paragraph, area);
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
