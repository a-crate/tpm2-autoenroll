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

/// Decision state for a given PCR set.
/// If the user says "don't enroll this", always skip enrollment.
/// If the user says "always enroll this", always do enrollemnt.
#[derive(Default)]
pub struct Decisions {
	declines: HashSet<Vec<u8>>,
	accepts: HashSet<Vec<u8>>,
}

impl Decisions {
	pub fn new() -> Self {
		Decisions::default()
	}

	pub fn declined(&self, state: &[u8]) -> bool {
		self.declines.contains(state)
	}

	pub fn decline(&mut self, state: &[u8]) {
		self.declines.insert(state.to_vec());
	}

	pub fn accepted(&self, state: &[u8]) -> bool {
		self.accepts.contains(state)
	}

	pub fn accept(&mut self, state: &[u8]) {
		self.accepts.insert(state.to_vec());
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Answer {
    No,
    Yes,
    Always,
}

/// Ask whether to re-enroll `volume`, and return what the human said.
///
/// Anything that is not an explicit yes is a no, including a timeout, a closed
/// prompt, or an agent that failed outright. The failure mode of declining is
/// that the volume stays in passphrase-only mode and the boot continues; the
/// failure mode of assuming yes is re-binding to an attacker's boot chain.
pub fn ask(volume: &str, device: &str) -> Answer {
	let message = format!(
		"Boot measurements for {volume} have changed since TPM2 enrollment. \
		 Re-enroll TPM2 against the current state? [y(es)/n(o)/a(lways)]"
	);

	let out = Command::new(BINARY)
		.arg("--icon=drive-harddisk")
		.arg("--emoji=yes")
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
			return Answer::No;
		}
		Err(e) => {
			crate::log::error!(
				"volume {volume:?}: could not run {BINARY} for consent ({e}); treating that as a refusal"
			);
			return Answer::No;
		}
	};

	classify_response(&out.stdout)
}

fn classify_response(answer: &[u8]) -> Answer {
	let text = String::from_utf8_lossy(answer);
	// `--multiple` is not passed, but an agent may still terminate its reply
	// with a newline, and a user may well hit space before return.
	let first = text.lines().next().unwrap_or("").trim();
	// The prompt spells the options out as "y(es)/n(o)/a(lways)", so both
	// spellings of each have to work. Nothing else does: an answer we do not
	// recognise is a refusal.
	match first.to_ascii_lowercase().as_str() {
		"y" | "yes" => Answer::Yes,
		"a" | "always" => Answer::Always,
		_ => Answer::No,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn classify_answers_correctly() {
	    let cases: [(&[u8], Answer); 17] = [
					(b"y".as_slice(), Answer::Yes),
					(b"Y".as_slice(), Answer::Yes),
					(b"yes".as_slice(), Answer::Yes),
					(b"YES".as_slice(), Answer::Yes),
					(b"a".as_slice(), Answer::Always),
					(b"A".as_slice(), Answer::Always),
					(b"always".as_slice(), Answer::Always),
					(b"y\n".as_slice(), Answer::Yes),
					(b"  y  ".as_slice(), Answer::Yes),
					(b"", Answer::No),
					(b"\n", Answer::No),
					(b"n", Answer::No),
					(b"no", Answer::No),
					(b"yeah", Answer::No),
					(b"ye s", Answer::No),
					(b"1", Answer::No),
					(b"all", Answer::No),
					];
		for (input, expect) in cases {
			let actual = classify_response(input);
			assert_eq!(
				actual, expect,
				"classify_response({input:?}) returned {actual:?}, expected {expect:?}"
			);
		}
	}

	#[test]
	fn a_decline_covers_an_identical_boot_state() {
		// Two volumes bound to the same PCRs with the same values produce the
		// same key, so one refusal answers for both.
		let mut declined = Decisions::new();
		declined.decline(&[0xaa; 32]);

		let actual = declined.declined(&[0xaa; 32]);
		assert!(
			actual,
			"Declined::decline([0xaa; 32]) then declined([0xaa; 32]) returned {actual}, expected true"
		);
	}

	#[test]
	fn a_decline_does_not_cover_a_different_boot_state() {
		let mut declined = Decisions::new();
		declined.decline(&[0xaa; 32]);

		let actual = declined.declined(&[0xbb; 32]);
		assert!(
			!actual,
			"Declined::decline([0xaa; 32]) then declined([0xbb; 32]) returned {actual}, expected false: a different boot state is a different question"
		);
	}

	#[test]
	fn an_accept_covers_an_identical_boot_state() {
		// Two volumes bound to the same PCRs with the same values produce the
		// same key, so one refusal answers for both.
		let mut accepted = Decisions::new();
		accepted.accept(&[0xaa; 32]);

		let actual = accepted.accepted(&[0xaa; 32]);
		assert!(
			actual,
			"accepted::accept([0xaa; 32]) then accepted([0xaa; 32]) returned {actual}, expected true"
		);
	}

	#[test]
	fn an_accept_does_not_cover_a_different_boot_state() {
		let mut accepted = Decisions::new();
		accepted.accept(&[0xaa; 32]);

		let actual = accepted.accepted(&[0xbb; 32]);
		assert!(
			!actual,
			"accepted::accept([0xaa; 32]) then accepted([0xbb; 32]) returned {actual}, expected false: a different boot state is a different question"
		);
	}
}
