//! tpm2-autoenrolld -- the plain-phase passphrase path.
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
//!   * plain phase -- being asked here at all means every token type has already
//!     failed for this volume. Answer from the passphrase cache if one of its
//!     entries opens the volume, otherwise prompt, and in either case return a
//!     passphrase only once it has been checked against the volume's header.
//!     We get one attempt before systemd-cryptsetup reverts to prompting the
//!     user itself (DESIGN.md section 2.3), so a typo is retried here rather
//!     than spent there.
//!
//! What it does not do yet: anything to the LUKS2 header. There is no preflight,
//! no `systemd-cryptenroll`, no consent prompt. Installing this build still
//! changes no boot outcome, which is what keeps the canary test meaningful.

mod askpw;
mod bindname;
mod cache;
mod config;
mod drift;
mod listen_fds;
mod log;
mod luks;
mod memfd;
mod secret;
mod token;
mod tpm2;
mod volume;

use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::event::{PollFd, PollFlags};
use rustix::net::{SocketAddrAny, SocketAddrUnix};

use crate::askpw::Attempt;
use crate::bindname::Phase;
use crate::cache::Cache;
use crate::log::{error, info, notice, warning};
use crate::luks::Verdict;
use crate::secret::Secret;

/// How many times we ask before handing the prompt back to systemd-cryptsetup.
///
/// Matches `arg_tries` (cryptsetup.c:87), which is the number of tries a user
/// gets with us not installed.
const TRIES: usize = 3;

/// A listening socket together with the volume it serves.
struct Listener {
	fd: OwnedFd,
	volume: String,
	/// `None` for a volume the config file does not mention. Such a volume
	/// keeps its listener and declines every connection: not accepting at all
	/// would leave systemd-cryptsetup waiting on a connection sitting in the
	/// backlog, which is worse for the boot than falling back to stock
	/// behaviour.
	config: Option<config::Volume>,
}

fn main() -> std::process::ExitCode {
	let config_path = match parse_args() {
		Ok(Some(p)) => p,
		Ok(None) => return std::process::ExitCode::SUCCESS,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	lock_memory();

	// A config we cannot read is not a reason to exit. Every volume then
	// declines, which is the same outcome as not being installed.
	let config = match config::load(&config_path) {
		Ok(c) => {
			if c.is_empty() {
				warning!("{config_path} configures no volumes; every connection will be declined");
			}
			c
		}
		Err(e) => {
			error!("{e}; every connection will be declined");
			config::Config::default()
		}
	};

	let listeners = match setup(&config) {
		Ok(l) => l,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	for l in &listeners {
		match &l.config {
			Some(c) => info!("serving volume {:?} on {}", l.volume, c.device),
			None => error!(
				"volume {:?} has a socket but no configuration; declining its connections",
				l.volume
			),
		}
	}

	serve(&listeners)
}

/// Returns the config path to use, or `None` when the invocation was one that
/// only prints something.
fn parse_args() -> Result<Option<String>, String> {
	let mut path = config::DEFAULT_PATH.to_string();

	for arg in std::env::args().skip(1) {
		if arg == "--version" {
			let mut out = std::io::stdout();
			let _ = writeln!(out, "{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
			return Ok(None);
		} else if let Some(p) = arg.strip_prefix("--config=") {
			if p.is_empty() {
				return Err("--config= needs a path".to_string());
			}
			path = p.to_string();
		} else {
			return Err(format!("unrecognised argument {arg:?}"));
		}
	}

	Ok(Some(path))
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
fn setup(config: &config::Config) -> Result<Vec<Listener>, String> {
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
			Some(v) => {
				let volume = String::from_utf8_lossy(v).into_owned();
				let config = config.get(&volume).cloned();
				listeners.push(Listener { fd, volume, config });
			}
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
/// two console passphrase prompts interleaving would be unusable. It is also
/// what makes the cache worth having -- the second volume's connection is
/// handled after the first has produced a passphrase, not alongside it.
fn serve(listeners: &[Listener]) -> std::process::ExitCode {
	let mut cache = Cache::new();

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
				Ok(conn) => handle(conn, l, &mut cache),
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
/// fail-closed default: an unparseable peer name, an unrecognised phase, a
/// volume that disagrees with the socket it arrived on, or a volume we have no
/// configuration for all degrade to stock systemd-cryptsetup behaviour rather
/// than guessing.
fn handle(conn: OwnedFd, listener: &Listener, cache: &mut Cache) {
	let volume = listener.volume.as_str();

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
		Phase::Plain => match &listener.config {
			Some(config) => serve_passphrase(conn, volume, config, cache),
			None => error!("volume {volume:?}: plain phase, but it is not configured; declining"),
		},
		phase => {
			info!(
				"volume {volume:?}: {} phase, declining with zero bytes",
				phase.as_str()
			);
		}
	}
}

/// The plain phase: TPM2 has already failed for this volume.
fn serve_passphrase(conn: OwnedFd, volume: &str, config: &config::Volume, cache: &mut Cache) {
	notice!("volume {volume:?}: plain phase, so every token type has already failed");

	match acquire(volume, config, cache) {
		Some(secret) => {
			diagnose(volume, config);
			reply(conn, volume, &secret)
		}
		// Declining hands the prompt back to systemd-cryptsetup, which asks the
		// user directly on its next iteration. The volume still unlocks; we
		// have simply used up our turn.
		None => error!("volume {volume:?}: no passphrase to return; declining"),
	}
}

/// Work out *why* the TPM2 unlock failed, and say so.
///
/// DESIGN.md section 4.1's preflight, minus the acting on it: this build reports
/// its verdict and returns the passphrase regardless. Separating the diagnosis
/// from the repair is deliberate. Every one of these checks is a reason to
/// refuse to touch the header, so they are worth watching in a real boot before
/// anything is wired up to rewrite one.
fn diagnose(volume: &str, config: &config::Volume) {
	let device = config.device.as_str();

	let tokens = match token::read(device) {
		Ok(t) => t,
		Err(e) => {
			error!("volume {volume:?}: could not read the LUKS2 tokens ({e})");
			return;
		}
	};

	if tokens.is_empty() {
		// "Never enrolled", which section 4.1 keeps distinct from "drifted":
		// enrolling here would be creating a binding, not repairing one.
		notice!(
			"volume {volume:?}: carries no systemd-tpm2 token, so there is no TPM2 binding to repair"
		);
		return;
	}

	let mut tpm = match tpm2::Tpm::open(&config.tpm2_device) {
		Ok(t) => t,
		Err(e) => {
			// No TPM means a passphrase fallback is the expected state rather
			// than a fault, and wiping the token would be pure loss.
			notice!("volume {volume:?}: no usable TPM2 device ({e})");
			return;
		}
	};

	match tpm.lockout() {
		Ok(l) if l.in_lockout => {
			// Sealing would succeed and unsealing would keep failing, so we
			// would rewrite the header every boot and fix nothing. Not a case
			// to recover from -- a TPM in lockout is a bigger problem than a
			// stale PCR binding.
			error!(
				"volume {volume:?}: the TPM is in dictionary-attack lockout ({} of {} failures); refusing to touch the header",
				l.counter, l.max_auth_fail
			);
			return;
		}
		Ok(l) => info!(
			"volume {volume:?}: TPM responsive, lockout counter {} of {}",
			l.counter, l.max_auth_fail
		),
		Err(e) => {
			error!("volume {volume:?}: could not read the TPM's lockout state ({e})");
			return;
		}
	}

	for t in &tokens {
		let verdict = drift::check(&mut tpm, t);
		notice!(
			"volume {volume:?}: token {}: {}",
			t.index,
			verdict.describe()
		);

		if let drift::Drift::Drifted { .. } = verdict {
			log_pcrs(volume, &mut tpm, t);
		}
	}
}

/// The audit line section 6 asks for: what the machine measured at the moment we
/// were consulted, which is what a re-enrollment would seal against.
fn log_pcrs(volume: &str, tpm: &mut tpm2::Tpm, t: &token::Tpm2Token) {
	let bank = t
		.bank
		.as_deref()
		.and_then(tpm2::Bank::from_name)
		.unwrap_or(tpm2::Bank::SHA256);

	match tpm.read_pcrs(bank, &t.pcrs) {
		Ok(values) => {
			for (pcr, digest) in values {
				let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
				info!("volume {volume:?}: PCR {pcr} is now {hex}");
			}
		}
		Err(e) => warning!("volume {volume:?}: could not read the current PCR values ({e})"),
	}
}

/// Produce a passphrase that is known to open `config.device`.
///
/// The cache is consulted first (DESIGN.md section 5): with several volumes
/// sharing a passphrase, only the first of them prompts. Every candidate,
/// cached or freshly typed, is validated before it is returned -- which is
/// precisely what makes it safe to accept a secret we did not watch the user
/// type.
fn acquire(volume: &str, config: &config::Volume, cache: &mut Cache) -> Option<Secret> {
	let device = config.device.as_str();

	if !cache.is_empty() {
		// Worth a line: each trial is a full KDF pass, so this is where a
		// multi-second pause before the prompt comes from.
		info!(
			"volume {volume:?}: trying {} passphrase(s) seen earlier this boot",
			cache.len()
		);
	}

	for cached in cache.iter() {
		match luks::test_passphrase(device, cached) {
			Verdict::Correct => {
				info!("volume {volume:?}: answered from a passphrase seen earlier this boot");
				return Some(cached.clone());
			}
			Verdict::Wrong => {}
			Verdict::Unusable(why) => {
				error!("volume {volume:?}: cannot check passphrases against {device} ({why})");
				return None;
			}
		}
	}

	for attempt in 0..TRIES {
		let which = if attempt == 0 {
			Attempt::First
		} else {
			Attempt::Retry
		};

		let candidates = match askpw::ask(volume, device, which) {
			Ok(c) => c,
			Err(e) => {
				error!("volume {volume:?}: could not acquire a passphrase ({e})");
				return None;
			}
		};

		for candidate in candidates {
			match luks::test_passphrase(device, &candidate) {
				Verdict::Correct => {
					cache.insert(candidate.clone());
					return Some(candidate);
				}
				Verdict::Wrong => {}
				Verdict::Unusable(why) => {
					error!("volume {volume:?}: cannot check passphrases against {device} ({why})");
					return None;
				}
			}
		}

		notice!(
			"volume {volume:?}: passphrase did not unlock {device} (attempt {} of {TRIES})",
			attempt + 1
		);
	}

	None
}

/// Hand the passphrase back verbatim: these bytes go straight to
/// `crypt_activate_by_passphrase()`, so a stray newline is a rejected
/// passphrase.
fn reply(conn: OwnedFd, volume: &str, secret: &Secret) {
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
