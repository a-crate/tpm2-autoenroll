//! tpm2-autoenrolld -- re-bind a TPM2-enrolled LUKS2 volume at the point of
//! unlock.
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
//! Having established that the volume really has fallen back and that we hold a
//! passphrase that really works, the plain phase then does what the tool exists
//! for: check that re-binding would actually help (`preflight`), ask a human
//! (`consent`), run `systemd-cryptenroll`, and verify the result -- all before
//! the passphrase is returned, so nothing is half-done if the initrd goes away.
//!
//! The invariant underneath all of it is **enroll at the point of unlock**. The
//! PCR values read when we are consulted are, by construction, the values that
//! will be present the next time this volume is unlocked at this same point in
//! boot. Nothing here knows or cares whether that point is in the initrd.

mod askpw;
mod bindname;
mod cache;
mod consent;
mod crypttab;
mod drift;
mod enroll;
mod ignore;
mod log;
mod luks;
mod memfd;
mod notify;
mod preflight;
mod secret;
mod sockets;
mod token;
mod tpm2;

use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::event::{PollFd, PollFlags};
use rustix::net::{SocketAddrAny, SocketAddrUnix};

use crate::askpw::Attempt;
use crate::bindname::Phase;
use crate::cache::Cache;
use crate::crypttab::Volume;
use crate::drift::Drift;
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
	path: String,
	volume: Volume,
}

/// Set from the SIGTERM handler; read by the accept loop.
///
/// The daemon is asked to stop at switch-root, and the sockets it leaves behind
/// in /run are still there when stage 2 looks for a discovered key. Unlinking
/// them is the whole reason we bother to notice the signal.
static TERMINATE: AtomicBool = AtomicBool::new(false);

/// The paths a run is configured with. Every one of them has a default that is
/// right on a NixOS system; the overrides exist so the daemon can be driven by
/// hand without a machine's real crypttab being involved.
struct Args {
	crypttab: String,
	ignore: String,
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

	let volumes = match discover(&args) {
		Ok(v) => v,
		Err(e) => {
			error!("{e}");
			return std::process::ExitCode::FAILURE;
		}
	};

	if volumes.is_empty() {
		// Not a failure: a machine with no TPM2-bound volume in this stage has
		// nothing for us to do, and saying so beats sitting on an empty poll.
		notice!("{}: no TPM2-bound volumes to serve", args.crypttab);
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

	// Only now: the unit is ordered before the systemd-cryptsetup instances, and
	// with Type=notify this is the point at which that ordering starts to mean
	// "the socket is already there".
	notify::ready();

	let code = serve(&listeners);
	shutdown(&listeners);
	code
}

/// Returns the paths to use, or `None` when the invocation was one that only
/// prints something.
fn parse_args() -> Result<Option<Args>, String> {
	let mut args = Args {
		crypttab: crypttab::DEFAULT_PATH.to_string(),
		ignore: ignore::DEFAULT_PATH.to_string(),
		socket_dir: sockets::DEFAULT_DIR.to_string(),
	};

	for arg in std::env::args().skip(1) {
		if arg == "--version" {
			let mut out = std::io::stdout();
			let _ = writeln!(out, "{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
			return Ok(None);
		}

		let Some((name, value)) = arg.split_once('=') else {
			return Err(format!("unrecognised argument {arg:?}"));
		};
		if value.is_empty() {
			return Err(format!("{name}= needs a path"));
		}
		match name {
			"--crypttab" => args.crypttab = value.to_string(),
			"--ignore" => args.ignore = value.to_string(),
			"--socket-dir" => args.socket_dir = value.to_string(),
			_ => return Err(format!("unrecognised argument {arg:?}")),
		}
	}

	Ok(Some(args))
}

/// Which volumes this run will manage: the TPM2-bound entries of the crypttab,
/// less the ones the user has opted out.
fn discover(args: &Args) -> Result<Vec<Volume>, String> {
	let volumes = match crypttab::load(&args.crypttab) {
		Ok(v) => v,
		// Nothing to serve rather than a fault: a stage with no crypttab has no
		// encrypted volumes in it.
		Err(e) if missing(&args.crypttab) => {
			notice!("{e}; nothing to serve");
			return Ok(Vec::new());
		}
		Err(e) => return Err(e),
	};

	let ignored = ignore::load(&args.ignore)?;
	if ignored.is_empty() {
		return Ok(volumes);
	}

	Ok(volumes
		.into_iter()
		.filter(|v| {
			let keep = !ignored.covers(v);
			if !keep {
				notice!(
					"volume {:?} is listed in {}; it will never be re-enrolled",
					v.name,
					args.ignore
				);
			}
			keep
		})
		.collect())
}

fn missing(path: &str) -> bool {
	!std::path::Path::new(path).exists()
}

/// Bind one socket per volume.
///
/// A volume whose socket cannot be created is dropped rather than fatal: it
/// falls back to stock systemd-cryptsetup behaviour, and the volumes that did
/// bind are still served.
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
	// Both of these live for the daemon's lifetime, which in the initrd is the
	// initrd: one passphrase typed once, and one refusal honoured once.
	let mut decided = consent::Decisions::new();

	loop {
		let mut polls: Vec<PollFd> = listeners
			.iter()
			.map(|l| PollFd::new(&l.fd, PollFlags::IN))
			.collect();

		let woken = rustix::event::poll(&mut polls, None);

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
				Ok(conn) => handle(conn, &l.volume, &mut cache, &mut decided),
				Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
				Err(e) => error!("volume {:?}: accept failed: {e}", l.volume.name),
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
fn handle(conn: OwnedFd, managed: &Volume, cache: &mut Cache, decided: &mut consent::Decisions) {
	let volume = managed.name.as_str();

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
		Phase::Plain => serve_passphrase(conn, managed, cache, decided),
		phase => {
			info!(
				"volume {volume:?}: {} phase, declining with zero bytes",
				phase.as_str()
			);
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
		// user directly on its next iteration. The volume still unlocks; we
		// have simply used up our turn.
		None => error!("volume {volume:?}: no passphrase to return; declining"),
	}
}

/// Repair the TPM2 binding, if that is the right thing to do and a human agrees.
///
/// Synchronous and before the passphrase is returned (DESIGN.md section 4): the
/// user is already stopped at a console prompt, so the latency is not on an
/// otherwise-unattended path, and finishing before we reply removes any chance
/// of the initrd tearing down mid-enrollment.
///
/// Every failure here is survivable, which is why none of them stops the boot.
/// The passphrase slot is never touched, so the worst outcome is a volume that
/// still needs its passphrase next time -- exactly where it was before we ran.
fn maybe_reenroll(
	volume: &str,
	config: &Volume,
	secret: &Secret,
	decided: &mut consent::Decisions,
) {
	let mut tpm = match tpm2::Tpm::open(&config.tpm2_device) {
		Ok(t) => t,
		Err(e) => {
			// No TPM means falling back to a passphrase is the expected state
			// rather than a fault, and wiping the token would be pure loss.
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

	// Section 6 wants every re-enrollment auditable after the fact, which means
	// saying what the policy was as well as what it is about to become. The PCR
	// values behind the new digest follow on the next lines.
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
	preflight::log_state(volume, &mut tpm, &plan);

	// Section 6: consent is mandatory and has no opt-out. Section 11 asked
	// whether a refusal should carry across volumes sharing a boot state; it
	// does, so five volumes bound to the same drifted PCRs ask once.
	if !plan.state.is_empty() && decided.declined(&plan.state) {
		notice!(
			"volume {volume:?}: leaving the header alone: re-enrollment was already declined for this boot state"
		);
		return;
	}

	if !decided.accepted(&plan.state) {
	    match consent::ask(volume, &config.device) {
	        consent::Answer::No => {
			    notice!("volume {volume:?}: leaving the header alone: re-enrollment was declined");
			    if !plan.state.is_empty() {
			        decided.decline(&plan.state);
			    }
			    return;
		    }
		    consent::Answer::Always => {
		        notice!("volume {volume:?}: automatically re-enrolling this PCR set for future volumes");
			    decided.accept(&plan.state);
		    }
		    _ => {}
	    }
	}

	if let Err(e) = enroll::run(
		&config.device,
		&config.tpm2_device,
		&plan.pcrs,
		plan.bank.as_deref(),
		secret,
	) {
		// systemd-cryptenroll adds the new slot before wiping the old one and
		// never wipes the slot it just added, so a failure here leaves the old
		// binding, the new one, or both -- and the passphrase either way.
		error!("volume {volume:?}: re-enrollment failed ({e}); the volume still unlocks by passphrase");
		return;
	}

	verify(volume, config, &plan, &mut tpm);
}

/// Section 4.3: check the new slot before trusting it.
///
/// The old slot is gone by now, so a failure here is worth saying loudly -- but
/// it is not a disaster, because the passphrase slot was never involved.
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

	// The real thing first: --token-only refuses to fall back to a passphrase,
	// so success is a TPM2 unseal and nothing else.
	match enroll::test_unseal(&config.device, new.index) {
		Ok(()) => {
			notice!("volume {volume:?}: re-enrolled as token {} and verified by unsealing it", new.index);
			return;
		}
		Err(e) => info!(
			"volume {volume:?}: no token-plugin unseal available ({e}); verifying the policy instead"
		),
	}

	// Reached whenever libcryptsetup cannot load the systemd-tpm2 token plugin:
	// an initrd trimmed of it, or simply nixpkgs, which ships the plugin in
	// systemd's output rather than in cryptsetup's plugin directory. Comparing
	// the sealed policy against the current PCRs is weaker -- it would not
	// notice an unusable SRK -- but it covers the failure this tool can actually
	// cause, which is sealing against the wrong state.
	match drift::check(tpm, new) {
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
/// The cache is consulted first (DESIGN.md section 5): with several volumes
/// sharing a passphrase, only the first of them prompts. Every candidate,
/// cached or freshly typed, is validated before it is returned -- which is
/// precisely what makes it safe to accept a secret we did not watch the user
/// type.
fn acquire(volume: &str, config: &Volume, cache: &mut Cache) -> Option<Secret> {
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
