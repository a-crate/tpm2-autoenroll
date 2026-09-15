//! The consent prompt. Mandatory, with no way to switch it off.
//!
//! Automatic re-enrollment blesses whatever boot chain is currently running.
//! Normally an unexpected passphrase prompt *is* the evil-maid signal, and this
//! tool removes it. A human at the console answering a question is the one
//! signal a modified boot chain cannot forge, so it is asked every time and the
//! answer is never inferred, remembered across boots, or configured away.
//!
//! Unlike the passphrase prompt in `askpw` this passes `--echo=yes`, since the
//! answer is not a secret, and no `--keyname=`, since pushing "y" into the
//! `cryptsetup` keyring would leave it there as a candidate passphrase.
//!
//! systemd-ask-password accepts a reply from any uid-0 sender on its socket, so
//! a root process watching `/run/systemd/ask-password` could answer this
//! question too. The daemon exiting once its volumes are served is what keeps
//! that window short.

use std::collections::HashSet;
use std::process::{Command, Stdio};

use crate::askpw;
use crate::child;
use crate::tpm2::Bank;

const BINARY: &str = "systemd-ask-password";

/// Answers already given, keyed by PCR set, so volumes sharing a boot state ask
/// once.
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

#[derive(Debug, PartialEq)]
pub enum Answer {
	No,
	Yes,
	Always,
}

/// Anything that is not an explicit yes is a no, including a timeout, a closed
/// prompt, or an agent that failed outright. Declining leaves the volume in
/// passphrase-only mode and the boot continues; assuming yes would re-bind to
/// an attacker's boot chain.
pub fn ask(volume: &str, device: &str, pcrs: &[u8], bank: Bank) -> Answer {
	// Naming the selection means the human approves a specific policy rather
	// than "whatever the tool decided".
	let message = format!(
		"Boot measurements for {volume} have changed since TPM2 enrollment. \
		 Re-enroll TPM2 for {volume} against PCRs {} ({}) in their current state? \
		 [y(es)/n(o)/a(lways)]",
		crate::config::pcr_list(pcrs),
		bank.name()
	);

	let mut cmd = Command::new(BINARY);
	cmd.arg("--icon=drive-harddisk")
		.arg("--emoji=yes")
		// Distinct from the passphrase prompt's id for the same disk, so an agent
		// cannot mistake one question for a repeat of the other.
		.arg(format!("--id=tpm2-autoenroll:{device}"))
		.arg("--echo=yes")
		.arg(format!("--timeout={}", askpw::PROMPT_TIMEOUT.as_secs()))
		.arg("-n")
		.arg(&message)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::inherit());

	// The answer is a word or two; anything longer is not an answer.
	let timeout = askpw::PROMPT_TIMEOUT + askpw::PROMPT_GRACE;
	let out = match child::run(&mut cmd, timeout, 4096) {
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
				"volume {volume:?}: the consent prompt failed ({e}); treating that as a refusal"
			);
			return Answer::No;
		}
	};

	classify_response(&out.stdout)
}

fn classify_response(answer: &[u8]) -> Answer {
	let text = String::from_utf8_lossy(answer);
	// An agent may terminate its reply with a newline, and a user may well hit
	// space before return.
	let first = text.lines().next().unwrap_or("").trim();
	// Both spellings of each option have to work; anything unrecognised is a
	// refusal.
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
