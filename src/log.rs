use std::io::Write;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub enum Level {
    Error,
    Warn,
    Info,
}

fn journal() -> bool {
    static JOURNAL: OnceLock<bool> = OnceLock::new();
    *JOURNAL.get_or_init(|| std::env::var_os("JOURNAL_STREAM").is_some())
}

pub fn emit(level: Level, msg: std::fmt::Arguments<'_>) {
    let (prio, name) = match level {
        Level::Error => (3, "error"),
        Level::Warn => (4, "warn"),
        Level::Info => (6, "info"),
    };
    let mut err = std::io::stderr().lock();
    let _ = if journal() {
        writeln!(err, "<{prio}>{msg}")
    } else {
        writeln!(err, "{name}: {msg}")
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Error, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Warn, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Info, format_args!($($arg)*)) };
}
