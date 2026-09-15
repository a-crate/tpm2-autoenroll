//! tpm2-autoenrolld -- re-bind a TPM2-enrolled LUKS2 volume at the point of
//! unlock.
//!
//! Sits on the `/run/cryptsetup-keys.d/<volume>.key` key-discovery path that
//! systemd-cryptsetup consults on every iteration of its unlock loop, and
//! answers according to which phase of that loop it is being asked in.
//!
//!   * TPM2 / FIDO2 / PKCS#11 phase -- reply with zero bytes and close. The
//!     empty reply leaves `iovec_is_set(key_data)` false, so the dispatch at
//!     cryptsetup.c:2044 falls through to the LUKS2 header token and ordinary
//!     TPM2 unlocking is untouched.
//!   * plain phase -- every token type has already failed for this volume, so
//!     this is the fallback. Produce a passphrase known to open the volume,
//!     then preflight, ask a human, re-enroll and verify, all before replying,
//!     so nothing is half-done if the initrd goes away.
//!
//! The invariant underneath it is enroll at the point of unlock: the PCR values
//! read when we are consulted are, by construction, the values present the next
//! time this volume is unlocked at this same point in boot.
//!
//! The daemon exits once every configured volume is open or has been answered
//! in the plain phase, or after a stretch with no connections, taking the
//! passphrase cache and consent decisions with it. That bounds how long a
//! passphrase sits in memory where any root process that can reach the socket
//! might ask for it. A later `systemd-cryptsetup@` start pulls the daemon in
//! again through the `Wants=` drop-in, with both empty; that is intended.

mod askpw;
mod bindname;
mod cache;
mod config;
mod consent;
mod dm;
mod drift;
mod enroll;
mod log;
mod luks;
mod memfd;
mod notify;
mod peer;
mod preflight;
mod secret;
mod sockets;
mod token;
mod tpm2;

use std::collections::HashSet;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::net::{SocketAddrAny, SocketAddrUnix};

use crate::askpw::Attempt;
use crate::bindname::Phase;
use crate::cache::Cache;
use crate::config::Volume;
use crate::drift::Drift;
use crate::log::{error, info, notice, warning};
use crate::luks::Verdict;
use crate::secret::Secret;

/// How many times we ask before handing the prompt back to systemd-cryptsetup.
/// Matches `arg_tries` (cryptsetup.c:87).
const TRIES: usize = 3;

/// How long the accept loop sleeps before re-checking whether it is finished.
const TICK: Duration = Duration::from_secs(1);

/// Backstop for volumes that never report in: a `noauto` volume nobody starts,
/// or a config entry that matches no crypttab line.
const IDLE_LIMIT: Duration = Duration::from_secs(300);

struct Listener {
	fd: OwnedFd,
	path: String,
	volume: Volume,
}

/// Set from the SIGTERM handler; read by the accept loop.
static TERMINATE: AtomicBool = AtomicBool::new(false);

/// Every path defaults to what a NixOS system uses; the overrides exist so the
/// daemon can be driven by hand.
struct Args {
	config: String,
	socket_dir: String,
}

fn main() -> std::process::ExitCode {
	let args = match parse_args() {
		Ok(Some(a)) => a,
		Ok(None) => return std::process::ExitCode::SUCCESS,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	lock_memory();
	catch_sigterm();

	// No config means no sockets, and no sockets means stock behaviour: the
	// Wants= drop-in lets the boot go on without us.
	let volumes = match config::load(&args.config) {
		Ok(v) => v,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	if volumes.is_empty() {
		notice!("{}: no usable volumes to serve", args.config);
		notify::ready();
		return std::process::ExitCode::SUCCESS;
	}

	let listeners = match listen(&args.socket_dir, volumes) {
		Ok(l) => l,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	for l in &listeners {
		info!(
			"serving volume {:?} on {} via {}",
			l.volume.name, l.volume.device, l.path
		);
	}

	// Only now. The unit is ordered before the systemd-cryptsetup instances, and
	// with Type=notify this is the point at which that ordering starts to mean
	// "the socket is already there".
	notify::ready();

	let code = serve(&listeners);
	shutdown(&listeners);
	code
}

/// `None` when the invocation only printed something and should exit.
fn parse_args() -> Result<Option<Args>, String> {
	let mut args = Args {
		config: config::DEFAULT_PATH.to_string(),
		socket_dir: sockets::DEFAULT_DIR.to_string(),
	};

	for arg in std::env::args().skip(1) {
		if arg == "--version" {
			let mut out = std::io::stdout();
			let _ = writeln!(
				out,
				"{} {}",
				env!("CARGO_PKG_NAME"),
				env!("CARGO_PKG_VERSION")
			);
			return Ok(None);
		}

		let Some((name, value)) = arg.split_once('=') else {
			return Err(format!("unrecognised argument {arg:?}"));
		};
		if value.is_empty() {
			return Err(format!("{name}= needs a path"));
		}
		match name {
			"--config" => args.config = value.to_string(),
			"--socket-dir" => args.socket_dir = value.to_string(),
			_ => return Err(format!("unrecognised argument {arg:?}")),
		}
	}

	Ok(Some(args))
}

/// Bind one socket per volume.
///
/// A volume whose socket cannot be created is dropped rather than fatal: it
/// falls back to stock systemd-cryptsetup behaviour, and the rest are still
/// served.
fn listen(dir: &str, volumes: Vec<Volume>) -> Result<Vec<Listener>, String> {
	sockets::ensure_dir(dir)?;

	let mut listeners = Vec::with_capacity(volumes.len());
	for volume in volumes {
		let path = sockets::path(dir, &volume.name);
		match sockets::bind(&path) {
			Ok(fd) => listeners.push(Listener { fd, path, volume }),
			Err(e) => error!(
				"volume {:?}: could not listen on {path} ({e}); it will unlock as if we were not installed",
				volume.name
			),
		}
	}

	if listeners.is_empty() {
		return Err("no usable listening sockets".to_string());
	}
	Ok(listeners)
}

/// Take the sockets back out of the filesystem.
///
/// /run survives switch-root, so a socket left here is one stage 2's
/// systemd-cryptsetup will find, connect to, and get nothing from.
fn shutdown(listeners: &[Listener]) {
	for l in listeners {
		if let Err(e) = sockets::clear(&l.path) {
			warning!("could not remove {} ({e})", l.path);
		}
	}
}

/// Notice SIGTERM rather than dying on it, so `shutdown` gets to run.
///
/// poll(2) is never restarted after a handler runs, regardless of SA_RESTART
/// (signal(7)), so the accept loop finds out on its next trip round.
fn catch_sigterm() {
	extern "C" fn handler(_signal: libc::c_int) {
		TERMINATE.store(true, Ordering::Relaxed);
	}

	// SAFETY: the handler only stores to an atomic, which is async-signal-safe.
	unsafe {
		libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
		libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
	}
}

/// Pin our pages so key material cannot reach swap.
///
/// systemd-cryptsetup does the same (cryptsetup.c:2625) and calls it "a
/// delicious drop of snake oil": worth doing, not worth failing over.
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

fn unix_addr(addr: &SocketAddrAny) -> Option<SocketAddrUnix> {
	SocketAddrUnix::try_from(addr.clone()).ok()
}

/// Accept and answer connections, one at a time, until `finished` says the
/// daemon is no longer needed.
///
/// Serial handling is a requirement rather than a simplification: several
/// `systemd-cryptsetup@.service` instances can be unlocking in parallel, and two
/// console prompts interleaving would be unusable. It is also what makes the
/// cache worth having -- the second volume's connection is handled after the
/// first has produced a passphrase, not alongside it.
fn serve(listeners: &[Listener]) -> std::process::ExitCode {
	let mut cache = Cache::new();
	let mut decided = consent::Decisions::new();
	let mut served: HashSet<String> = HashSet::new();
	let mut last_contact = Instant::now();
	let tick = rustix::event::Timespec {
		tv_sec: TICK.as_secs() as _,
		tv_nsec: 0,
	};

	loop {
		let volumes = listeners.iter().map(|l| l.volume.name.as_str());
		let active = |v: &str| dm::is_active(Path::new(dm::SYS_BLOCK), v);
		if let Some(why) = finished(volumes, &served, active, last_contact.elapsed()) {
			notice!("{why}; removing the key sockets and exiting");
			return std::process::ExitCode::SUCCESS;
		}

		let mut polls: Vec<PollFd> = listeners
			.iter()
			.map(|l| PollFd::new(&l.fd, PollFlags::IN))
			.collect();

		let woken = rustix::event::poll(&mut polls, Some(&tick));

		if TERMINATE.load(Ordering::Relaxed) {
			notice!("asked to stop; removing the key sockets");
			return std::process::ExitCode::SUCCESS;
		}

		match woken {
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
				Ok(conn) => {
					if handle(conn, &l.volume, &mut cache, &mut decided) {
						served.insert(l.volume.name.clone());
					}
					last_contact = Instant::now();
				}
				Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
				Err(e) => error!("volume {:?}: accept failed: {e}", l.volume.name),
			}
		}
	}
}

/// Why the daemon can stop, if it can.
///
/// A volume is done once it is open, or once its plain-phase connection has
/// been handled -- whatever came of it, since systemd-cryptsetup does not ask
/// twice. A TPM-phase connection alone does not count: a plain-phase one may
/// follow.
fn finished<'a>(
	volumes: impl IntoIterator<Item = &'a str>,
	served: &HashSet<String>,
	active: impl Fn(&str) -> bool,
	idle: Duration,
) -> Option<String> {
	if volumes.into_iter().all(|v| served.contains(v) || active(v)) {
		return Some("every configured volume is open or has been answered".to_string());
	}
	if idle >= IDLE_LIMIT {
		return Some(format!(
			"no connection for {} seconds",
			IDLE_LIMIT.as_secs()
		));
	}
	None
}

/// Answer one connection.
///
/// Every path out of here that is not a deliberate reply drops `conn`, closing
/// it having written nothing -- the zero-byte decline. That is the fail-closed
/// default: anything we cannot make sense of degrades to stock
/// systemd-cryptsetup behaviour rather than being guessed at.
///
/// True when this was the volume's plain-phase connection and it was handled.
fn handle(
	conn: OwnedFd,
	managed: &Volume,
	cache: &mut Cache,
	decided: &mut consent::Decisions,
) -> bool {
	let volume = managed.name.as_str();

	// systemd-cryptsetup always binds a name of its own, so an unnamed peer is
	// not one of its connections.
	let peer = match rustix::net::getpeername(&conn) {
		Ok(Some(p)) => p,
		Ok(None) => {
			warning!("volume {volume:?}: peer is unnamed; declining");
			return false;
		}
		Err(e) => {
			warning!("volume {volume:?}: getpeername failed ({e}); declining");
			return false;
		}
	};

	let Some(unix) = unix_addr(&peer) else {
		warning!("volume {volume:?}: peer is not an AF_UNIX address; declining");
		return false;
	};

	// The abstract name's bytes are not NUL-terminated; rustix hands us the
	// slice with its real length.
	let Some(name) = unix.abstract_name() else {
		warning!("volume {volume:?}: peer is not in the abstract namespace; declining");
		return false;
	};

	let Some(peer_name) = bindname::parse(name) else {
		warning!(
			"volume {volume:?}: unparseable peer name {:?}; declining",
			String::from_utf8_lossy(name)
		);
		return false;
	};

	if peer_name.volume != volume.as_bytes() {
		warning!(
			"volume {volume:?}: peer asked for volume {:?}; declining",
			String::from_utf8_lossy(peer_name.volume)
		);
		return false;
	}

	match peer_name.phase {
		// Only the plain phase is ever answered with anything, so only it needs
		// to know who is asking. A failed check does not count as served.
		Phase::Plain => {
			if let Err(why) = peer::check(&conn, volume) {
				warning!("volume {volume:?}: {why}; declining");
				return false;
			}
			serve_passphrase(conn, managed, cache, decided);
			true
		}
		phase => {
			info!(
				"volume {volume:?}: {} phase, declining with zero bytes",
				phase.as_str()
			);
			false
		}
	}
}

/// The plain phase: TPM2 has already failed for this volume.
fn serve_passphrase(
	conn: OwnedFd,
	config: &Volume,
	cache: &mut Cache,
	decided: &mut consent::Decisions,
) {
	let volume = config.name.as_str();
	notice!("volume {volume:?}: plain phase, so every token type has already failed");

	match acquire(volume, config, cache) {
		Some(secret) => {
			maybe_reenroll(volume, config, &secret, decided);
			reply(conn, volume, &secret)
		}
		// Declining hands the prompt back to systemd-cryptsetup, which asks the
		// user directly. The volume still unlocks; we have used up our turn.
		None => error!("volume {volume:?}: no passphrase to return; declining"),
	}
}

/// Repair the TPM2 binding, if that is the right thing to do and a human agrees.
///
/// Synchronous and before the passphrase is returned: the user is already
/// stopped at a console prompt, so the latency is not on an unattended path,
/// and finishing before we reply removes any chance of the initrd tearing down
/// mid-enrollment. Every failure here is survivable and none stops the boot,
/// because the passphrase slot is never touched.
fn maybe_reenroll(
	volume: &str,
	config: &Volume,
	secret: &Secret,
	decided: &mut consent::Decisions,
) {
	let mut tpm = match tpm2::Tpm::open(&config.tpm2_device) {
		Ok(t) => t,
		Err(e) => {
			// With no TPM the passphrase fallback is the expected state rather
			// than a fault, and wiping the token would be pure loss.
			notice!("volume {volume:?}: leaving the header alone: no usable TPM2 device ({e})");
			return;
		}
	};

	let plan = match preflight::check(volume, config, &mut tpm) {
		preflight::Decision::Reenroll(plan) => plan,
		preflight::Decision::Leave(why) => {
			notice!("volume {volume:?}: leaving the header alone: {why}");
			return;
		}
	};

	// An auditable re-enrollment means saying what the policy was as well as
	// what it is about to become; log_state adds the PCR values behind it.
	if plan.enrolled.is_empty() {
		notice!("volume {volume:?}: no TPM2 binding yet, and one can be created");
	} else {
		notice!(
			"volume {volume:?}: the TPM2 binding has gone stale and can be repaired \
			 (policy {} -> {})",
			drift::short(&plan.enrolled),
			drift::short(&plan.state)
		);
	}
	preflight::log_state(volume, &mut tpm, config);

	// A decision carries across volumes sharing a boot state, so five volumes
	// bound to the same drifted PCRs ask once.
	if !plan.state.is_empty() && decided.declined(&plan.state) {
		notice!(
			"volume {volume:?}: leaving the header alone: re-enrollment was already declined for this boot state"
		);
		return;
	}

	if !decided.accepted(&plan.state) {
		match consent::ask(volume, &config.device, &config.pcrs, config.bank) {
			consent::Answer::No => {
				notice!("volume {volume:?}: leaving the header alone: re-enrollment was declined");
				if !plan.state.is_empty() {
					decided.decline(&plan.state);
				}
				return;
			}
			consent::Answer::Always => {
				notice!(
					"volume {volume:?}: automatically re-enrolling this PCR set for future volumes"
				);
				decided.accept(&plan.state);
			}
			consent::Answer::Yes => {}
		}
	}

	if let Err(e) = enroll::run(
		&config.device,
		&config.tpm2_device,
		&config.pcrs,
		config.bank,
		secret,
	) {
		// systemd-cryptenroll adds the new slot before wiping the old one and
		// never wipes the slot it just added, so a failure leaves the old
		// binding, the new one, or both -- and the passphrase either way.
		error!(
			"volume {volume:?}: re-enrollment failed ({e}); the volume still unlocks by passphrase"
		);
		return;
	}

	verify(volume, config, &plan, &mut tpm);
}

/// Check the new slot before trusting it. The old slot is gone by now, so a
/// failure is worth saying loudly -- though the passphrase slot was never
/// involved, so it is not a disaster.
fn verify(volume: &str, config: &Volume, plan: &preflight::Plan, tpm: &mut tpm2::Tpm) {
	let tokens = match token::read(&config.device) {
		Ok(t) => t,
		Err(e) => {
			error!("volume {volume:?}: re-enrolled, but the header could not be re-read ({e})");
			return;
		}
	};

	let Some(new) = enroll::find_new_token(&tokens, plan.old_token) else {
		error!(
			"volume {volume:?}: re-enrolled, but the new systemd-tpm2 token could not be identified"
		);
		return;
	};

	// The flags passed to systemd-cryptenroll should make this impossible;
	// checking the result means a systemd that stops honouring them is noticed.
	let wrong =
		preflight::token_refusal(new).or_else(|| preflight::same_selection(new, config).err());
	if let Some(why) = wrong {
		error!(
			"volume {volume:?}: re-enrolled as token {}, but {why}. The old binding is gone; \
			 the passphrase still works",
			new.index
		);
		return;
	}

	// --token-only refuses to fall back to a passphrase, so success here is a
	// TPM2 unseal and nothing else.
	match enroll::test_unseal(&config.device, new.index) {
		Ok(()) => {
			notice!(
				"volume {volume:?}: re-enrolled as token {} and verified by unsealing it",
				new.index
			);
			return;
		}
		Err(e) => info!(
			"volume {volume:?}: no token-plugin unseal available ({e}); verifying the policy instead"
		),
	}

	// Reached whenever libcryptsetup cannot load the systemd-tpm2 token plugin:
	// a trimmed initrd, or simply nixpkgs, which ships the plugin in systemd's
	// output rather than cryptsetup's plugin directory. Comparing the sealed
	// policy against the current PCRs is weaker -- it would not notice an
	// unusable SRK -- but it covers the failure this tool can cause, which is
	// sealing against the wrong state.
	match drift::check(tpm, new, &config.pcrs, config.bank) {
		Drift::Matches => notice!(
			"volume {volume:?}: re-enrolled as token {}, and its policy matches the current PCRs",
			new.index
		),
		other => error!(
			"volume {volume:?}: re-enrolled as token {}, but {}. The passphrase still works; \
			 re-run systemd-cryptenroll by hand",
			new.index,
			other.describe()
		),
	}
}

/// Produce a passphrase that is known to open `config.device`.
///
/// The cache is consulted first, so with several volumes sharing a passphrase
/// only the first prompts. Every candidate, cached or freshly typed, is
/// validated before it is returned -- which is what makes it safe to accept a
/// secret we did not watch the user type.
fn acquire(volume: &str, config: &Volume, cache: &mut Cache) -> Option<Secret> {
	let device = config.device.as_str();

	if !cache.is_empty() {
		// Each trial is a full KDF pass, so this line explains a multi-second
		// pause before the prompt.
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

/// Verbatim: these bytes go straight to `crypt_activate_by_passphrase()`, so a
/// stray newline is a rejected passphrase.
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

#[cfg(test)]
mod tests {
	use super::*;

	fn served(names: &[&str]) -> HashSet<String> {
		names.iter().map(|n| n.to_string()).collect()
	}

	#[test]
	fn finishes_once_every_volume_is_open_or_answered() {
		let volumes = ["root", "home", "swap"];
		let cases: [(&[&str], &[&str], bool); 5] = [
			(&[], &[], false),
			(&["root"], &[], false),
			(&["root", "home"], &["swap"], true),
			(&[], &["root", "home", "swap"], true),
			(&["root", "home", "swap"], &[], true),
		];
		for (answered, open, expected) in cases {
			let actual = finished(
				volumes,
				&served(answered),
				|v| open.contains(&v),
				Duration::ZERO,
			)
			.is_some();
			assert_eq!(
				actual, expected,
				"finished({volumes:?}, served = {answered:?}, open = {open:?}, idle = 0) returned {actual}, expected {expected}"
			);
		}
	}

	#[test]
	fn finishes_after_the_idle_limit() {
		let cases = [
			(IDLE_LIMIT - Duration::from_secs(1), false),
			(IDLE_LIMIT, true),
		];
		for (idle, expected) in cases {
			let actual = finished(["root"], &served(&[]), |_| false, idle).is_some();
			assert_eq!(
				actual, expected,
				"finished([\"root\"], served = [], open = [], idle = {idle:?}) returned {actual}, expected {expected}"
			);
		}
	}
}
