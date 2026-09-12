//! The consent prompt, which DESIGN.md section 6 makes mandatory and section 6.1
//! explains at length why there is no way to switch off.
//!
//! Automatic re-enrollment blesses whatever boot chain is currently running.
//! Normally an unexpected passphrase prompt *is* the evil-maid signal, and this
//! tool removes it. A human at the console answering a question is the one
//! signal a modified boot chain cannot forge, so it is asked every time and the
//! answer is never inferred, remembered across boots, or configured away.
//!
//! Two details separate this from the passphrase prompt in `askpw`:
//!
//!   * `--echo=yes`. The answer is not a secret and the user should see what
//!     they typed.
//!   * no `--keyname=`. Pushing "y" into the `cryptsetup` keyring would leave it
//!     sitting there as a candidate passphrase for the next volume.

use std::collections::HashSet;
use std::process::{Command, Stdio};

const BINARY: &str = "systemd-ask-password";

/// Declines already given this boot, keyed by the boot state they were about.
///
/// Section 11 asked whether a decline should be remembered so a user with five
/// volumes sharing a passphrase is not asked five times. It is, and the key is
/// the policy digest the current PCRs produce: two volumes reach the same key
/// only when they are bound to the same registers holding the same values, so
/// "no, do not trust this boot state" answers all of them at once. The moment
/// the boot state differs, so does the key, and the question is asked again.
#[derive(Default)]
pub struct Declined {
	states: HashSet<Vec<u8>>,
}

impl Declined {
	pub fn new() -> Self {
		Declined::default()
	}

	pub fn contains(&self, state: &[u8]) -> bool {
		self.states.contains(state)
	}

	pub fn remember(&mut self, state: &[u8]) {
		self.states.insert(state.to_vec());
	}
}

/// Ask whether to re-enroll `volume`, and return what the human said.
///
/// Anything that is not an explicit yes is a no, including a timeout, a closed
/// prompt, or an agent that failed outright. The failure mode of declining is
/// that the volume stays in passphrase-only mode and the boot continues; the
/// failure mode of assuming yes is re-binding to an attacker's boot chain.
pub fn ask(volume: &str, device: &str) -> bool {
	let message = format!(
		"Boot measurements for {volume} have changed since TPM2 enrollment. \
		 Re-enroll TPM2 against the current state? [y/N]"
	);

	let out = Command::new(BINARY)
		.arg("--icon=drive-harddisk")
		// A distinct id from the passphrase prompt for the same disk, so an
		// agent cannot mistake one question for a repeat of the other.
		.arg(format!("--id=tpm2-autoenroll:{device}"))
		.arg("--echo=yes")
		.arg("-n")
		.arg(&message)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::inherit())
		.output();

	let out = match out {
		Ok(o) if o.status.success() => o,
		Ok(o) => {
			crate::log::notice!(
				"volume {volume:?}: the consent prompt exited with {}; treating that as a refusal",
				o.status
			);
			return false;
		}
		Err(e) => {
			crate::log::error!(
				"volume {volume:?}: could not run {BINARY} for consent ({e}); treating that as a refusal"
			);
			return false;
		}
	};

	is_yes(&out.stdout)
}

/// Only an explicit yes counts.
fn is_yes(answer: &[u8]) -> bool {
	let text = String::from_utf8_lossy(answer);
	// `--multiple` is not passed, but an agent may still terminate its reply
	// with a newline, and a user may well hit space before return.
	let first = text.lines().next().unwrap_or("").trim();
	matches!(first.to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn accepts_the_documented_answers() {
		for input in [
			b"y".as_slice(),
			b"Y".as_slice(),
			b"yes".as_slice(),
			b"YES".as_slice(),
			b"y\n".as_slice(),
			b"  y  ".as_slice(),
		] {
			let actual = is_yes(input);
			assert!(
				actual,
				"is_yes({input:?}) returned {actual}, expected true"
			);
		}
	}

	#[test]
	fn everything_else_is_a_refusal() {
		// The empty answer is the important one: it is what pressing return at
		// a "[y/N]" prompt produces, and the design says that means no.
		let cases: [(&[u8], &str); 7] = [
			(b"", "empty answer, i.e. a bare return"),
			(b"\n", "newline only"),
			(b"n", "explicit no"),
			(b"no", "explicit no"),
			(b"yeah", "not one of the accepted words"),
			(b"ye s", "not one of the accepted words"),
			(b"1", "not one of the accepted words"),
		];
		for (input, why) in cases {
			let actual = is_yes(input);
			assert!(
				!actual,
				"is_yes({input:?}) returned {actual}, expected false ({why})"
			);
		}
	}

	#[test]
	fn a_decline_covers_an_identical_boot_state() {
		// Two volumes bound to the same PCRs with the same values produce the
		// same key, so one refusal answers for both.
		let mut declined = Declined::new();
		declined.remember(&[0xaa; 32]);

		let actual = declined.contains(&[0xaa; 32]);
		assert!(
			actual,
			"Declined::remember([0xaa; 32]) then contains([0xaa; 32]) returned {actual}, expected true"
		);
	}

	#[test]
	fn a_decline_does_not_cover_a_different_boot_state() {
		let mut declined = Declined::new();
		declined.remember(&[0xaa; 32]);

		let actual = declined.contains(&[0xbb; 32]);
		assert!(
			!actual,
			"Declined::remember([0xaa; 32]) then contains([0xbb; 32]) returned {actual}, expected false: a different boot state is a different question"
		);
	}
}
