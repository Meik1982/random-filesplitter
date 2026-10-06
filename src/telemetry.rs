//! High-Performance Telemetry & Visual Progress Engine (blkcp-Style).
//! Supports interactive ANSI terminal bars, dynamic ETA, throughput tracking,
//! and machine-readable NDJSON telemetry on stderr.

use std::io::{self, Write};
use std::time::Instant;

/// Betriebsmodus für Telemetrie und Fortschrittsanzeige
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryMode {
    /// Keine Ausgabe (außer fatale Fehler)
    Silent,
    /// Interaktiver Fortschrittsbalken mit ANSI-Escapes auf stderr
    Interactive,
    /// Maschinenlesbare NDJSON-Streams auf stderr
    Json,
}

/// Einheitliche Telemetrie-Instanz für Split- und Restore-Pipelines
pub struct Telemetry {
    mode: TelemetryMode,
    action: &'static str,
    total_bytes: Option<u64>,
    start_time: Instant,
    last_update: Instant,
}

impl Telemetry {
    pub fn new(mode: TelemetryMode, action: &'static str, total_bytes: Option<u64>) -> Self {
        let now = Instant::now();
        Self {
            mode,
            action,
            total_bytes,
            start_time: now,
            last_update: now,
        }
    }

    /// Liefert den aktiven Telemetrie-Modus
    #[allow(dead_code)]
    pub fn mode(&self) -> TelemetryMode {
        self.mode
    }

    /// Aktualisiert den Fortschritt (zeitlich gedrosselt auf max. 10 Hz / 100ms)
    pub fn update(&mut self, processed_bytes: u64) {
        if self.mode == TelemetryMode::Silent {
            return;
        }

        let now = Instant::now();
        if now.duration_since(self.last_update).as_millis() < 100 {
            return;
        }
        self.last_update = now;

        let elapsed_s = self.start_time.elapsed().as_secs_f64();
        let speed_bps = if elapsed_s > 0.0001 {
            processed_bytes as f64 / elapsed_s
        } else {
            0.0
        };

        match self.mode {
            TelemetryMode::Json => {
                self.print_json_progress(processed_bytes, elapsed_s, speed_bps);
            }
            TelemetryMode::Interactive => {
                self.print_interactive_progress(processed_bytes, elapsed_s, speed_bps);
            }
            TelemetryMode::Silent => {}
        }
    }

    /// Schließt den Vorgang ab und gibt Zusammenfassung / Abschluss-Event aus
    pub fn finish(&self, processed_bytes: u64, num_parts: usize, checksum: Option<(&str, &str)>) {
        if self.mode == TelemetryMode::Silent {
            return;
        }

        let elapsed_s = self.start_time.elapsed().as_secs_f64();
        let avg_speed_bps = if elapsed_s > 0.0001 {
            processed_bytes as f64 / elapsed_s
        } else {
            0.0
        };

        match self.mode {
            TelemetryMode::Json => {
                self.print_json_finished(
                    processed_bytes,
                    elapsed_s,
                    avg_speed_bps,
                    num_parts,
                    checksum,
                );
            }
            TelemetryMode::Interactive => {
                // Bei Interactive eine neue Zeile nach dem Fortschrittsbalken setzen
                eprintln!();
            }
            TelemetryMode::Silent => {}
        }
    }

    /// Gibt ein standardisiertes JSON-Fehler-Event aus (nur im JSON-Modus)
    pub fn error(&self, message: &str) {
        if self.mode == TelemetryMode::Json {
            let escaped = message.replace('"', "\\\"").replace('\n', " ");
            eprintln!(
                "{{\"event\":\"error\",\"action\":\"{}\",\"message\":\"{}\"}}",
                self.action, escaped
            );
            let _ = io::stderr().flush();
        }
    }

    fn print_json_progress(&self, processed: u64, elapsed_s: f64, speed_bps: f64) {
        if let Some(total) = self.total_bytes {
            if total > 0 {
                let pct = ((processed as f64 * 100.0) / total as f64).min(100.0);
                let eta_s = if speed_bps > 1.0 && processed < total {
                    (total - processed) as f64 / speed_bps
                } else {
                    0.0
                };
                eprintln!(
                    "{{\"event\":\"progress\",\"action\":\"{}\",\"processed_bytes\":{},\"total_bytes\":{},\"percent\":{:.2},\"speed_bps\":{:.0},\"elapsed_s\":{:.2},\"eta_s\":{:.1}}}",
                    self.action, processed, total, pct, speed_bps, elapsed_s, eta_s
                );
            } else {
                eprintln!(
                    "{{\"event\":\"progress\",\"action\":\"{}\",\"processed_bytes\":{},\"total_bytes\":0,\"percent\":100.0,\"speed_bps\":{:.0},\"elapsed_s\":{:.2},\"eta_s\":0.0}}",
                    self.action, processed, speed_bps, elapsed_s
                );
            }
        } else {
            eprintln!(
                "{{\"event\":\"progress\",\"action\":\"{}\",\"processed_bytes\":{},\"total_bytes\":null,\"percent\":null,\"speed_bps\":{:.0},\"elapsed_s\":{:.2},\"eta_s\":null}}",
                self.action, processed, speed_bps, elapsed_s
            );
        }
        let _ = io::stderr().flush();
    }

    fn print_json_finished(
        &self,
        processed: u64,
        elapsed_s: f64,
        avg_speed_bps: f64,
        num_parts: usize,
        checksum: Option<(&str, &str)>,
    ) {
        let chk_str = match checksum {
            Some((algo, dig)) => format!(
                "\"checksum\":{{\"algorithm\":\"{}\",\"digest\":\"{}\"}}",
                algo, dig
            ),
            None => "\"checksum\":null".to_string(),
        };

        eprintln!(
            "{{\"event\":\"finished\",\"action\":\"{}\",\"processed_bytes\":{},\"elapsed_s\":{:.4},\"avg_speed_bps\":{:.0},\"num_parts\":{},{}}}",
            self.action, processed, elapsed_s, avg_speed_bps, num_parts, chk_str
        );
        let _ = io::stderr().flush();
    }

    fn print_interactive_progress(&self, processed: u64, _elapsed_s: f64, speed_bps: f64) {
        let speed_str = format_speed(speed_bps);

        if let Some(total) = self.total_bytes {
            if total > 0 {
                let ratio = (processed as f64 / total as f64).clamp(0.0, 1.0);
                let pct = ratio * 100.0;
                let eta_s = if speed_bps > 1.0 && processed < total {
                    (total - processed) as f64 / speed_bps
                } else {
                    0.0
                };
                let bar = render_ansi_bar(ratio, 24);
                let proc_str = format_bytes(processed);
                let tot_str = format_bytes(total);

                eprint!(
                    "\r[RFS {}] {} {:5.1}% ({}/{}) {:>10}  ETA {:>4}",
                    self.action,
                    bar,
                    pct,
                    proc_str,
                    tot_str,
                    speed_str,
                    format_eta(eta_s)
                );
            } else {
                eprint!(
                    "\r[RFS {}] [========================] 100.0% ({}) {:>10}",
                    self.action,
                    format_bytes(processed),
                    speed_str
                );
            }
        } else {
            eprint!(
                "\r[RFS {} Stream] {} übertragen  {:>10}",
                self.action,
                format_bytes(processed),
                speed_str
            );
        }
        let _ = io::stderr().flush();
    }
}

/// Zeichnet einen 24-Zeichen breiten ANSI-Fortschrittsbalken
fn render_ansi_bar(ratio: f64, width: usize) -> String {
    let filled = (ratio * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut bar = String::with_capacity(width + 2);
    bar.push('[');
    for i in 0..width {
        if i < filled {
            bar.push('=');
        } else if i == filled && filled > 0 && filled < width {
            bar.push('>');
        } else {
            bar.push('-');
        }
    }
    bar.push(']');
    bar
}

/// Formatiert Bytes menschenlesbar (z. B. "12.4 MB", "1.25 GB")
fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;
    if b >= TB {
        format!("{:.2} TB", b / TB)
    } else if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Formatiert Durchsatz (z. B. "1.85 GB/s")
fn format_speed(speed_bps: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if speed_bps >= GB {
        format!("{:.2} GB/s", speed_bps / GB)
    } else if speed_bps >= MB {
        format!("{:.1} MB/s", speed_bps / MB)
    } else if speed_bps >= KB {
        format!("{:.1} KB/s", speed_bps / KB)
    } else {
        format!("{:.0} B/s", speed_bps)
    }
}

/// Formatiert die verbleibende Zeit (z. B. "12s", "1m 30s")
fn format_eta(eta_s: f64) -> String {
    if eta_s <= 0.0 {
        return "0s".to_string();
    }
    let total_secs = eta_s.round() as u64;
    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        let m = total_secs / 60;
        let s = total_secs % 60;
        format!("{}m{:02}s", m, s)
    } else {
        let h = total_secs / 3600;
        let m = (total_secs % 3600) / 60;
        format!("{}h{:02}m", h, m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(10 * 1024 * 1024), "10.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(500.0), "500 B/s");
        assert_eq!(format_speed(1024.0 * 1024.0 * 50.0), "50.0 MB/s");
        assert_eq!(format_speed(1024.0 * 1024.0 * 1024.0 * 2.5), "2.50 GB/s");
    }

    #[test]
    fn test_render_ansi_bar() {
        assert_eq!(render_ansi_bar(0.0, 10), "[----------]");
        assert_eq!(render_ansi_bar(0.5, 10), "[=====>----]");
        assert_eq!(render_ansi_bar(1.0, 10), "[==========]");
    }
}
