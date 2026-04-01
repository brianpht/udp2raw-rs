//! Custom logger matching C++ udp2raw log format.
//! "[YYYY-MM-DD HH:MM:SS][LEVEL]message"

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// ─── Log level constants (matching C++ values) ─────────────────────────────

pub const LOG_FATAL: u8 = 1;
pub const LOG_ERROR: u8 = 2;
pub const LOG_WARN: u8 = 3;
pub const LOG_INFO: u8 = 4;
pub const LOG_DEBUG: u8 = 5;
pub const LOG_TRACE: u8 = 6;

// ─── ANSI color codes ──────────────────────────────────────────────────────

const RED: &str = "\x1B[31m";
const YEL: &str = "\x1B[33m";
const GRN: &str = "\x1B[32m";
const MAG: &str = "\x1B[35m";
const RESET: &str = "\x1B[0m";

// ─── Global state ──────────────────────────────────────────────────────────

static ENABLE_COLOR: AtomicBool = AtomicBool::new(true);
static ENABLE_POSITION: AtomicBool = AtomicBool::new(false);
static LOG_LEVEL_VAL: AtomicU8 = AtomicU8::new(LOG_INFO);

pub fn set_log_color(enabled: bool) {
    ENABLE_COLOR.store(enabled, Ordering::Relaxed);
}

pub fn set_log_position(enabled: bool) {
    ENABLE_POSITION.store(enabled, Ordering::Relaxed);
}

pub fn set_log_level(level: u8) {
    LOG_LEVEL_VAL.store(level.min(LOG_TRACE), Ordering::Relaxed);
}

pub fn get_log_level() -> u8 {
    LOG_LEVEL_VAL.load(Ordering::Relaxed)
}

// ─── Logger implementation ─────────────────────────────────────────────────

/// Format current local time as "YYYY-MM-DD HH:MM:SS" using libc (Linux-only).
/// Uses a stack buffer — zero heap allocations per log call.
fn format_local_time(buf: &mut [u8; 19]) {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&tv.tv_sec, &mut tm) };
    // "YYYY-MM-DD HH:MM:SS" is exactly 19 bytes
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(buf.as_mut_slice());
    let _ = write!(
        cursor,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    );
}

struct Udp2rawLogger;

impl Log for Udp2rawLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let level = LOG_LEVEL_VAL.load(Ordering::Relaxed);
        let msg_level = rust_level_to_u8(metadata.level());
        msg_level <= level
    }

    fn log(&self, record: &Record) {
        let level = LOG_LEVEL_VAL.load(Ordering::Relaxed);
        let msg_level = rust_level_to_u8(record.level());
        if msg_level > level {
            return;
        }

        let color = ENABLE_COLOR.load(Ordering::Relaxed);
        let position = ENABLE_POSITION.load(Ordering::Relaxed);

        let mut ts_buf = [0u8; 19];
        format_local_time(&mut ts_buf);
        let timestamp = std::str::from_utf8(&ts_buf).unwrap_or("????-??-?? ??:??:??");

        let level_str = match record.level() {
            Level::Error => "FATAL", // We map Rust Error to our FATAL/ERROR
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };

        let color_code = if color {
            match record.level() {
                Level::Error => RED,
                Level::Warn => YEL,
                Level::Info => GRN,
                Level::Debug => MAG,
                Level::Trace => "",
            }
        } else {
            ""
        };

        let reset_code = if color && !color_code.is_empty() {
            RESET
        } else {
            ""
        };

        if position {
            println!(
                "{}[{}][{}][{}:{}]{}{}",
                color_code,
                timestamp,
                level_str,
                record.file().unwrap_or("?"),
                record.line().unwrap_or(0),
                record.args(),
                reset_code
            );
        } else {
            println!(
                "{}[{}][{}]{}{}",
                color_code,
                timestamp,
                level_str,
                record.args(),
                reset_code
            );
        }
    }

    fn flush(&self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

fn rust_level_to_u8(level: Level) -> u8 {
    match level {
        Level::Error => LOG_ERROR,
        Level::Warn => LOG_WARN,
        Level::Info => LOG_INFO,
        Level::Debug => LOG_DEBUG,
        Level::Trace => LOG_TRACE,
    }
}

/// Convert our u8 log level to Rust LevelFilter
fn u8_to_level_filter(level: u8) -> LevelFilter {
    match level {
        0 => LevelFilter::Off,
        1..=2 => LevelFilter::Error,
        3 => LevelFilter::Warn,
        4 => LevelFilter::Info,
        5 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

static LOGGER: Udp2rawLogger = Udp2rawLogger;

/// Initialize the global logger. Call once at startup.
pub fn init_logger(level: u8, color: bool, position: bool) {
    set_log_level(level);
    set_log_color(color);
    set_log_position(position);

    let filter = u8_to_level_filter(level);
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(filter))
        .expect("Failed to set logger");
}

