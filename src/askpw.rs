//! Passphrase acquisition, delegating to `systemd-ask-password`.
//!
//! Going through the same tool systemd-cryptsetup uses means the prompt reaches
//! whichever agent owns the console (plymouth, the tty agent, a wall agent) with
//! no work on our part, and means the kernel keyring cache behaves identically.
//! See `get_password()`, src/cryptsetup/cryptsetup.c:911.

use std::process::{Command, Stdio};

use crate::secret::Secret;

const BINARY: &str = "systemd-ask-password";

/// Prompt for the passphrase of `volume`.
///
/// The passphrase is returned exactly as typed. `-n` suppresses the trailing
/// newline `systemd-ask-password` would otherwise add, which matters because
/// systemd-cryptsetup uses our reply verbatim: a stray newline is a rejected
/// passphrase.
pub fn ask(volume: &str) -> Result<Secret, String> {
	let mut cmd = Command::new(BINARY);
	cmd.arg("--icon=drive-harddisk")
		// systemd-cryptsetup uses the backing device here. We only learn the
		// volume name from the socket path in this slice; the id is used by
		// agents to recognise a repeated request, not for cache lookup, so the
		// difference is cosmetic until the config file lands.
		.arg(format!("--id=cryptsetup:{volume}"))
		// Both halves of the design's ACCEPT_CACHED | PUSH_CACHE live here:
		// --keyname= pushes collected passwords into the root keyring, and
		// with --accept-cached would also retrieve them.
		//
		// We push but deliberately do not accept yet. Retrieving a cached
		// passphrase we cannot check would spend our single attempt on a
		// secret that may belong to an entirely different volume, and the
		// validation step that makes accepting safe arrives with the
		// re-enrollment slice. Pushing costs nothing and already helps any
		// unmanaged volume unlocked later in the same boot.
		.arg("--keyname=cryptsetup")
		.arg("--credential=cryptsetup.passphrase")
		.arg("-n")
		.arg(format!("Please enter passphrase for disk {volume}:"))
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::inherit());

	let out = cmd
		.output()
		.map_err(|e| format!("could not run {BINARY}: {e}"))?;

	if !out.status.success() {
		return Err(format!("{BINARY} exited with {}", out.status));
	}

	let secret = Secret::new(out.stdout);
	if secret.is_empty() {
		return Err(format!("{BINARY} returned an empty passphrase"));
	}
	Ok(secret)
}
