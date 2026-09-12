//! tpm2-autoenrolld -- socket protocol core.
//!
//! Sits on the `/run/cryptsetup-keys.d/<volume>.key` key-discovery path that
//! systemd-cryptsetup consults on every iteration of its unlock loop, and
//! answers according to which phase of that loop it is being asked in.
//!
//! What this build does:
//!
//!   * TPM2 / FIDO2 / PKCS#11 phase -- reply with zero bytes and close. The
//!     empty reply leaves `iovec_is_set(key_data)` false, so the dispatch at
//!     cryptsetup.c:2044 falls through to the LUKS2 header token and ordinary
//!     TPM2 unlocking is untouched.
//!   * plain phase -- prompt for the passphrase and return it verbatim. Being
//!     asked here at all means every token type has already failed for this
//!     volume, which is the signal the re-enrollment logic will key off.
//!
//! What it does not do yet: anything to the LUKS2 header. There is no preflight,
//! no `systemd-cryptenroll`, no consent prompt. Installing this build changes no
//! boot outcome, which is precisely what makes the canary test meaningful.

mod askpw;
mod bindname;
mod listen_fds;
mod log;
mod secret;
mod volume;

use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::event::{PollFd, PollFlags};
use rustix::net::{SocketAddrAny, SocketAddrUnix};

use crate::bindname::Phase;
use crate::log::{error, info, notice, warning};

/// A listening socket together with the volume it serves.
struct Listener {
	fd: OwnedFd,
	volume: String,
}

fn main() -> std::process::ExitCode {
	if std::env::args().any(|a| a == "--version") {
		let mut out = std::io::stdout();
		let _ = writeln!(out, "{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
		return std::process::ExitCode::SUCCESS;
	}

	lock_memory();

	let listeners = match setup() {
		Ok(l) => l,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	for l in &listeners {
		info!("serving volume {:?}", l.volume);
	}

	serve(&listeners)
}

/// Pin our pages so key material cannot reach swap.
///
/// systemd-cryptsetup does exactly this (cryptsetup.c:2625) and calls it "a
/// delicious drop of snake oil", which is about right: it is worth doing and
/// not worth failing over, so a refusal is logged and the daemon continues.
fn lock_memory() {
	// SAFETY: mlockall has no memory-safety preconditions; it either pins the
	// address space or returns an error.
	let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) };
	if rc != 0 {
		warning!(
			"mlockall failed ({}); key material may reach swap",
			std::io::Error::last_os_error()
		);
	}
}

/// Take the listening fds and work out which volume each one serves.
fn setup() -> Result<Vec<Listener>, String> {
	let fds = listen_fds::take()?;

	let mut listeners = Vec::with_capacity(fds.len());
	for fd in fds {
		let path = match socket_path(fd.as_fd()) {
			Ok(p) => p,
			Err(e) => {
				error!("could not read a listening socket's path ({e}); ignoring it");
				continue;
			}
		};

		match volume::from_socket_path(&path) {
			Some(v) => listeners.push(Listener {
				fd,
				volume: String::from_utf8_lossy(v).into_owned(),
			}),
			None => error!(
				"listening socket {:?} is not named <volume>.key; ignoring it",
				String::from_utf8_lossy(&path)
			),
		}
	}

	if listeners.is_empty() {
		return Err("no usable listening sockets".to_string());
	}
	Ok(listeners)
}

/// The filesystem path a listening socket is bound to.
fn socket_path(fd: BorrowedFd<'_>) -> Result<Vec<u8>, String> {
	let addr = rustix::net::getsockname(fd).map_err(|e| format!("getsockname: {e}"))?;
	let unix = unix_addr(&addr).ok_or_else(|| "not an AF_UNIX address".to_string())?;
	let path = unix.path().ok_or_else(|| {
		"socket has no filesystem path; ListenStream= must name a path".to_string()
	})?;
	Ok(path.to_bytes().to_vec())
}

fn unix_addr(addr: &SocketAddrAny) -> Option<SocketAddrUnix> {
	SocketAddrUnix::try_from(addr.clone()).ok()
}

/// Accept and answer connections, one at a time, forever.
///
/// Serial handling is a requirement rather than a simplification: several
/// `systemd-cryptsetup@.service` instances can be unlocking in parallel, and
/// two console passphrase prompts interleaving would be unusable.
fn serve(listeners: &[Listener]) -> std::process::ExitCode {
	loop {
		let mut polls: Vec<PollFd> = listeners
			.iter()
			.map(|l| PollFd::new(&l.fd, PollFlags::IN))
			.collect();

		match rustix::event::poll(&mut polls, None) {
			Ok(_) => {}
			Err(rustix::io::Errno::INTR) => continue,
			Err(e) => {
				error!("poll failed: {e}");
				return std::process::ExitCode::FAILURE;
			}
		}

		let ready: Vec<usize> = polls
			.iter()
			.enumerate()
			.filter(|(_, p)| p.revents().intersects(PollFlags::IN))
			.map(|(i, _)| i)
			.collect();

		for i in ready {
			let l = &listeners[i];
			match rustix::net::accept(&l.fd) {
				Ok(conn) => handle(conn, &l.volume),
				Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
				Err(e) => error!("volume {:?}: accept failed: {e}", l.volume),
			}
		}
	}
}

/// Answer one connection.
///
/// Every path out of here that is not a deliberate reply drops `conn`, which
/// closes it having written nothing -- the zero-byte decline. That is the
/// fail-closed default: an unparseable peer name, an unrecognised phase, or a
/// volume that disagrees with the socket it arrived on all degrade to stock
/// systemd-cryptsetup behaviour rather than guessing.
fn handle(conn: OwnedFd, volume: &str) {
	// `None` means the peer never bound a name of its own. systemd-cryptsetup
	// always does, so this is not one of its connections.
	let peer = match rustix::net::getpeername(&conn) {
		Ok(Some(p)) => p,
		Ok(None) => {
			warning!("volume {volume:?}: peer is unnamed; declining");
			return;
		}
		Err(e) => {
			warning!("volume {volume:?}: getpeername failed ({e}); declining");
			return;
		}
	};

	let Some(unix) = unix_addr(&peer) else {
		warning!("volume {volume:?}: peer is not an AF_UNIX address; declining");
		return;
	};

	// systemd-cryptsetup binds its end to an abstract name. The bytes are not
	// NUL-terminated; rustix hands us the slice with its real length.
	let Some(name) = unix.abstract_name() else {
		warning!("volume {volume:?}: peer is not in the abstract namespace; declining");
		return;
	};

	let Some(peer_name) = bindname::parse(name) else {
		warning!(
			"volume {volume:?}: unparseable peer name {:?}; declining",
			String::from_utf8_lossy(name)
		);
		return;
	};

	if peer_name.volume != volume.as_bytes() {
		warning!(
			"volume {volume:?}: peer asked for volume {:?}; declining",
			String::from_utf8_lossy(peer_name.volume)
		);
		return;
	}

	match peer_name.phase {
		Phase::Plain => serve_passphrase(conn, volume),
		phase => {
			info!(
				"volume {volume:?}: {} phase, declining with zero bytes",
				phase.as_str()
			);
		}
	}
}

/// The plain phase: TPM2 has already failed for this volume.
fn serve_passphrase(conn: OwnedFd, volume: &str) {
	notice!("volume {volume:?}: plain phase, so every token type has already failed; prompting");

	let secret = match askpw::ask(volume) {
		Ok(s) => s,
		Err(e) => {
			// Declining hands the prompt back to systemd-cryptsetup, which asks
			// the user directly. The volume still unlocks.
			error!("volume {volume:?}: could not acquire a passphrase ({e}); declining");
			return;
		}
	};

	// Verbatim: these bytes go straight to crypt_activate_by_passphrase().
	match write_all(&conn, secret.as_bytes()) {
		Ok(()) => info!(
			"volume {volume:?}: returned a passphrase of {} bytes",
			secret.len()
		),
		Err(e) => error!("volume {volume:?}: could not write the passphrase ({e})"),
	}
}

fn write_all(fd: &OwnedFd, mut buf: &[u8]) -> Result<(), rustix::io::Errno> {
	while !buf.is_empty() {
		match rustix::io::write(fd, buf) {
			Ok(0) => return Err(rustix::io::Errno::PIPE),
			Ok(n) => buf = &buf[n..],
			Err(rustix::io::Errno::INTR) => {}
			Err(e) => return Err(e),
		}
	}
	Ok(())
}
