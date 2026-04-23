//! ASCII Sparkline Chart Implementation
//!
//! Renders time-series data as ASCII bar charts for TUI display.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Sparkline chart for rendering in TUI
pub struct Sparkline {
    data: Vec<f64>,
    max_data_points: usize,
    min_value: f64,
    max_value: f64,
}

impl Sparkline {
    pub fn new(max_points: usize) -> Self {
        Self {
            data: Vec::with_capacity(max_points),
            max_data_points: max_points,
            min_value: 0.0,
            max_value: 100.0,
        }
    }

    /// Add a new data point
    pub fn push(&mut self, value: f64) {
        self.data.push(value);
        
        if self.data.len() > self.max_data_points {
            self.data.remove(0);
        }
        
        // Update min/max for scaling
        self.min_value = self.data.iter().cloned().fold(f64::INFINITY, f64::min);
        self.max_value = self.data.iter().cloned().fold(0.0f64, f64::max).max(1.0);
    }

    /// Get the current value
    pub fn current(&self) -> f64 {
        self.data.last().copied().unwrap_or(0.0)
    }

    /// Get average value
    pub fn average(&self) -> f64 {
        if self.data.is_empty() {
            return 0.0;
        }
        self.data.iter().sum::<f64>() / self.data.len() as f64
    }

    /// Get peak value
    pub fn peak(&self) -> f64 {
        self.max_value
    }

    /// Render sparkline as a line of spans
    pub fn render(&self, width: usize, color: Color) -> Line {
        if self.data.is_empty() {
            return Line::from("─".repeat(width));
        }

        let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let step = self.data.len() as f64 / width as f64;
        let range = self.max_value - self.min_value;
        
        let mut spans = Vec::new();
        
        for i in 0..width {
            let idx = (i as f64 * step) as usize;
            let idx = idx.min(self.data.len() - 1);
            
            let value = self.data.get(idx).unwrap_or(&0.0);
            let normalized = if range > 0.0 {
                ((value - self.min_value) / range).max(0.0).min(1.0)
            } else {
                0.0
            };
            
            let char_idx = (normalized * (chars.len() - 1) as f64) as usize;
            let char_idx = char_idx.min(chars.len() - 1);
            
            spans.push(Span::styled(
                chars[char_idx].to_string(),
                Style::default().fg(color)
            ));
        }
        
        Line::from(spans)
    }

    /// Render with threshold coloring (red for high values)
    pub fn render_with_threshold(&self, width: usize, threshold: f64) -> Line {
        if self.data.is_empty() {
            return Line::from("─".repeat(width));
        }

        let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let step = self.data.len() as f64 / width as f64;
        let range = self.max_value - self.min_value;
        
        let mut spans = Vec::new();
        
        for i in 0..width {
            let idx = (i as f64 * step) as usize;
            let idx = idx.min(self.data.len() - 1);
            
            let value = self.data.get(idx).unwrap_or(&0.0);
            let normalized = if range > 0.0 {
                ((value - self.min_value) / range).max(0.0).min(1.0)
            } else {
                0.0
            };
            
            let char_idx = (normalized * (chars.len() - 1) as f64) as usize;
            let char_idx = char_idx.min(chars.len() - 1);
            
            // Color based on threshold
            let color = if *value >= threshold {
                Color::Red
            } else {
                Color::Green
            };
            
            spans.push(Span::styled(
                chars[char_idx].to_string(),
                Style::default().fg(color)
            ));
        }
        
        Line::from(spans)
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.data.clear();
        self.min_value = 0.0;
        self.max_value = 100.0;
    }

    /// Get data length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for Sparkline {
    fn default() -> Self {
        Self::new(60) // Default 60 data points
    }
}

/// Multi-series sparkline for comparing metrics
pub struct MultiSparkline {
    series: Vec<(String, Vec<f64>, Color)>,
    max_points: usize,
}

impl MultiSparkline {
    pub fn new(max_points: usize) -> Self {
        Self {
            series: Vec::new(),
            max_points,
        }
    }

    pub fn add_series(&mut self, name: &str, color: Color) {
        self.series.push((name.to_string(), Vec::new(), color));
    }

    pub fn push(&mut self, series_idx: usize, value: f64) {
        if let Some((_, data, _)) = self.series.get_mut(series_idx) {
            data.push(value);
            if data.len() > self.max_points {
                data.remove(0);
            }
        }
    }

    pub fn render(&self, width: usize) -> Vec<Line> {
        let mut lines = Vec::new();
        
        for (name, data, color) in &self.series {
            if data.is_empty() {
                lines.push(Line::from(format!("{}: ─", name)));
                continue;
            }

            let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
            let step = data.len() as f64 / width as f64;
            let min_val = data.iter().cloned().fold(f64::INFINITY, f64::min);
            let max_val = data.iter().cloned().fold(0.0f64, f64::max).max(1.0);
            let range = max_val - min_val;
            
            let mut spans = vec![Span::from(format!("{}: ", name))];
            
            for i in 0..width {
                let idx = (i as f64 * step) as usize;
                let idx = idx.min(data.len() - 1);
                
                let value = data.get(idx).unwrap_or(&0.0);
                let normalized = if range > 0.0 {
                    ((value - min_val) / range).max(0.0).min(1.0)
                } else {
                    0.0
                };
                
                let char_idx = (normalized * (chars.len() - 1) as f64) as usize;
                let char_idx = char_idx.min(chars.len() - 1);
                
                spans.push(Span::styled(
                    chars[char_idx].to_string(),
                    Style::default().fg(*color)
                ));
            }
            
            lines.push(Line::from(spans));
        }
        
        lines
    }
}
