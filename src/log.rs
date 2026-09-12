//! Minimal logging to stderr.
//!
//! The daemon runs as a systemd service, so stderr is the journal. Lines are
//! prefixed with the syslog level markers sd-daemon(3) defines (`<3>` for
//! error, and so on); journald strips them and sets the priority, because
//! `SyslogLevelPrefix=` defaults to yes.
//!
//! Deliberately hand-rolled rather than pulling in `log` plus a backend: this
//! binary is bound for an initrd, where every dependency is closure size.

use std::io::Write;

pub const ERR: &str = "<3>";
pub const WARNING: &str = "<4>";
pub const NOTICE: &str = "<5>";
pub const INFO: &str = "<6>";

pub fn emit(level: &str, args: std::fmt::Arguments<'_>) {
	// A failed log write must never take down an unlock in progress.
	let mut err = std::io::stderr().lock();
	let _ = writeln!(err, "{level}{args}");
	let _ = err.flush();
}

macro_rules! error {
	($($arg:tt)*) => { $crate::log::emit($crate::log::ERR, format_args!($($arg)*)) };
}

macro_rules! warning {
	($($arg:tt)*) => { $crate::log::emit($crate::log::WARNING, format_args!($($arg)*)) };
}

macro_rules! notice {
	($($arg:tt)*) => { $crate::log::emit($crate::log::NOTICE, format_args!($($arg)*)) };
}

macro_rules! info {
	($($arg:tt)*) => { $crate::log::emit($crate::log::INFO, format_args!($($arg)*)) };
}

pub(crate) use {error, info, notice, warning};
