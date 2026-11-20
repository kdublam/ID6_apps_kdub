//! App-wide diagnostic log for triage. One file per launch under `<app data>/logs/app-<time>.log`.
//!
//! Records launches, panics, every SSH command (text, exit status, timing, stderr) and every operation
//! message. Passwords and uploaded file contents are never written.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const KEEP_FILES: usize = 60;
const MAX_FIELD: usize = 600;

static LOG: OnceLock<Mutex<(PathBuf, File)>> = OnceLock::new();

/// "2026-11-17 22:10:41Z" from unix seconds (UTC).
pub fn timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Shortens `s` for logging, keeping the start and noting how much was cut.
pub fn clip(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_FIELD {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX_FIELD).collect();
    format!("{head}... [{} more chars]", s.chars().count() - MAX_FIELD)
}

fn prune(dir: &Path) {
    let Ok(read) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<_> = read
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in files.into_iter().skip(KEEP_FILES) {
        let _ = std::fs::remove_file(path);
    }
}

/// Starts the log for this launch. Safe to call once; later calls are ignored.
pub fn init(dir: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    prune(dir);
    let path = dir.join(format!("app-{}.log", now()));
    let file = OpenOptions::new().create(true).append(true).open(&path).ok()?;
    let _ = LOG.set(Mutex::new((path.clone(), file)));
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        line(&format!("PANIC: {info}"));
        default_hook(info);
    }));
    line(&format!(
        "launch: id6-installer {} on {} {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    Some(path)
}

pub fn line(msg: &str) {
    if let Some(lock) = LOG.get() {
        if let Ok(mut guard) = lock.lock() {
            let _ = writeln!(guard.1, "{} {msg}", timestamp(now()));
            let _ = guard.1.flush();
        }
    }
}

/// Header plus the tail of the newest log files, as one text blob for a bug report.
pub fn diagnostics(dir: &Path) -> String {
    let mut out = format!(
        "ID6 Installer diagnostics\ncreated: {}\nversion: {}\nos: {} {}\nlog folder: {}\n",
        timestamp(now()),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        dir.display()
    );
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|r| r.filter_map(|e| e.ok()).filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect())
        .unwrap_or_default();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in files.into_iter().take(6) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let start = text.len().saturating_sub(200_000);
        let start = (start..text.len()).find(|i| text.is_char_boundary(*i)).unwrap_or(text.len());
        out.push_str(&format!("\n===== {} =====\n{}\n", path.display(), &text[start..]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(timestamp(1_794_981_929), "2026-11-18 06:05:29Z");
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00:00Z");
    }

    #[test]
    fn clips_long_fields() {
        assert_eq!(clip("  short  "), "short");
        let long = "x".repeat(MAX_FIELD + 10);
        assert!(clip(&long).ends_with("[10 more chars]"));
    }
}
