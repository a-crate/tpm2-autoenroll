//! Socket activation fd pickup, implementing the `sd_listen_fds(3)` protocol
//! directly rather than linking libsystemd.
//!
//! The protocol is small and stable: systemd passes `LISTEN_PID` (our pid),
//! `LISTEN_FDS` (a count), and optionally `LISTEN_FDNAMES`, with the fds
//! themselves occupying a contiguous run starting at 3.

use std::os::fd::{FromRawFd, OwnedFd};

use rustix::net::{AddressFamily, SocketType};

use crate::log::{error, warning};

/// `SD_LISTEN_FDS_START`.
const LISTEN_FDS_START: i32 = 3;

/// Take the listening sockets systemd passed us.
///
/// The environment variables are removed on the way out, for the reason
/// `sd_listen_fds(3)` removes them: the daemon spawns `systemd-ask-password`,
/// and a child that inherited `LISTEN_FDS` would believe it had been socket
/// activated.
pub fn take() -> Result<Vec<OwnedFd>, String> {
	let pid = std::env::var("LISTEN_PID");
	let count = std::env::var("LISTEN_FDS");

	std::env::remove_var("LISTEN_PID");
	std::env::remove_var("LISTEN_FDS");
	std::env::remove_var("LISTEN_FDNAMES");

	let pid = pid.map_err(|_| "LISTEN_PID is not set; not socket activated".to_string())?;
	let pid: u32 = pid
		.parse()
		.map_err(|_| format!("LISTEN_PID is not a number: {pid:?}"))?;
	if pid != std::process::id() {
		// The variables were meant for some other process in our ancestry.
		return Err(format!(
			"LISTEN_PID is {pid}, but we are {}",
			std::process::id()
		));
	}

	let count = count.map_err(|_| "LISTEN_FDS is not set; not socket activated".to_string())?;
	let count: i32 = count
		.parse()
		.map_err(|_| format!("LISTEN_FDS is not a number: {count:?}"))?;
	if count <= 0 {
		return Err(format!("LISTEN_FDS is {count}; no sockets to serve"));
	}

	let mut fds = Vec::with_capacity(count as usize);
	for raw in LISTEN_FDS_START..LISTEN_FDS_START + count {
		// SAFETY: systemd guarantees this contiguous run of fds is open and
		// owned by us, and we take each one exactly once.
		let fd = unsafe { OwnedFd::from_raw_fd(raw) };

		// Inherited fds arrive without FD_CLOEXEC. Set it so they do not reach
		// systemd-ask-password.
		if let Err(e) = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC) {
			warning!("fd {raw}: could not set FD_CLOEXEC: {e}");
		}

		match check_listening_unix_stream(&fd) {
			Ok(()) => fds.push(fd),
			Err(e) => {
				// Keep serving the rest: one malformed ListenStream= should not
				// cost every other volume its socket.
				error!("fd {raw}: not a listening AF_UNIX stream socket ({e}); ignoring it");
			}
		}
	}

	if fds.is_empty() {
		return Err("none of the passed fds were usable listening sockets".to_string());
	}
	Ok(fds)
}

/// Reject anything that is not what our `.socket` unit is supposed to hand us,
/// so a misconfigured unit fails loudly here instead of mysteriously later.
fn check_listening_unix_stream(fd: &OwnedFd) -> Result<(), String> {
	use rustix::net::sockopt;

	let domain = sockopt::socket_domain(fd).map_err(|e| format!("SO_DOMAIN: {e}"))?;
	if domain != AddressFamily::UNIX {
		return Err(format!("address family is {domain:?}, expected AF_UNIX"));
	}

	let kind = sockopt::socket_type(fd).map_err(|e| format!("SO_TYPE: {e}"))?;
	if kind != SocketType::STREAM {
		return Err(format!("socket type is {kind:?}, expected SOCK_STREAM"));
	}

	let listening = sockopt::socket_acceptconn(fd).map_err(|e| format!("SO_ACCEPTCONN: {e}"))?;
	if !listening {
		return Err("socket is not listening".to_string());
	}

	Ok(())
}
