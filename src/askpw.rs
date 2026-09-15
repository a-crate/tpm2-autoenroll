//! Passphrase acquisition, delegating to `systemd-ask-password`.
//!
//! Going through the same tool systemd-cryptsetup uses means the prompt reaches
//! whichever agent owns the console (plymouth, the tty agent, a wall agent) with
//! no work on our part, and the kernel keyring cache behaves identically. See
//! `get_password()`, src/cryptsetup/cryptsetup.c:911.
//!
//! `--keyname=` pushes what we collect into the `cryptsetup` keyring and
//! `--accept-cached` takes what is already there. Accepting is only safe
//! because every candidate is checked against the volume before it is used
//! (`luks::test_passphrase`) -- a cached passphrase may well belong to some
//! unrelated volume unlocked earlier in the same boot.

use std::process::{Command, Stdio};
use std::time::Duration;

use crate::child;
use crate::secret::Secret;

const BINARY: &str = "systemd-ask-password";

/// `--timeout=` for this prompt and the consent prompt, pinned rather than
/// left to systemd-ask-password's default. Handling is serial, so this also
/// bounds how long other volumes wait behind an unanswered prompt.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(90);

/// Allowed on top of `PROMPT_TIMEOUT` before the process is killed, for an
/// agent that wedges rather than timing out.
pub const PROMPT_GRACE: Duration = Duration::from_secs(30);

/// Far more than `MAX_CANDIDATES` passphrases need. More than this is an
/// error rather than a reason to grow the buffer, which would leave an
/// unwiped copy behind.
const MAX_OUTPUT: usize = 64 * 1024;

/// How many candidates from one prompt we are willing to try.
///
/// `--multiple` can return every passphrase cached this boot, and each rejection
/// costs a full KDF pass -- seconds and up to a gigabyte with argon2id. Past a
/// handful, asking the user is cheaper than guessing.
const MAX_CANDIDATES: usize = 4;

/// A retry must *not* accept cached passphrases: the cached one is what we just
/// rejected, and asking for it again would spin the retry loop without the user
/// ever being given a chance to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
	First,
	Retry,
}

/// Every candidate the agent offered, in the order offered. The caller is
/// expected to validate them; nothing here knows whether any is right.
pub fn ask(volume: &str, device: &str, attempt: Attempt) -> Result<Vec<Secret>, String> {
	let friendly = friendly_name(volume, device);

	let mut cmd = Command::new(BINARY);
	cmd.arg("--icon=drive-harddisk")
		// systemd-cryptsetup identifies the request by the cescaped backing
		// device, not the volume name. Matching it exactly lets a console agent
		// recognise our request as being about the same disk.
		.arg(format!("--id=cryptsetup:{}", cescape(device)))
		.arg("--keyname=cryptsetup")
		.arg("--credential=cryptsetup.passphrase")
		// Without this, --accept-cached hands back one cached entry, and if that
		// one belongs to another volume it masks the entry that would have
		// worked.
		.arg("--multiple")
		.arg(format!("--timeout={}", PROMPT_TIMEOUT.as_secs()))
		.arg("-n");

	if attempt == Attempt::First {
		cmd.arg("--accept-cached");
	}

	cmd.arg(match attempt {
		Attempt::First => format!("Please enter passphrase for disk {friendly}:"),
		Attempt::Retry => format!("Passphrase did not unlock {friendly}, please try again:"),
	})
	.stdin(Stdio::null())
	.stdout(Stdio::piped())
	.stderr(Stdio::inherit());

	let out = child::run(&mut cmd, PROMPT_TIMEOUT + PROMPT_GRACE, MAX_OUTPUT)?;

	// A timeout is reported this way too, and declining on it is right: the
	// prompt reverts to systemd-cryptsetup, which applies its own timeout.
	if !out.status.success() {
		return Err(format!("{BINARY} exited with {}", out.status));
	}

	let candidates = parse_candidates(&out.stdout);
	if candidates.is_empty() {
		return Err(format!("{BINARY} returned no passphrase"));
	}
	Ok(candidates)
}

/// With `--multiple` the passphrases are newline-separated, and `-n` suppresses
/// only the final newline. Splitting is lossless because a passphrase cannot
/// contain a newline: agents deliver them as datagrams and the keyring stores
/// them NUL-separated, so there is nowhere for one to survive.
fn parse_candidates(stdout: &[u8]) -> Vec<Secret> {
	stdout
		.split(|&b| b == b'\n')
		.map(|line| Secret::new(line.to_vec()))
		.filter(|s| !s.is_empty())
		.take(MAX_CANDIDATES)
		.collect()
}

/// Cosmetic, unlike the id: this is the text a human reads.
fn friendly_name(volume: &str, device: &str) -> String {
	format!("{device} ({volume})")
}

/// systemd's `cescape()`, src/basic/escape.c.
///
/// A device path normally passes through untouched, but one whose name held a
/// quote or a control character would otherwise produce an id systemd would
/// never generate, defeating the point of matching systemd's id at all.
fn cescape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		match b {
			b'\x07' => out.push_str("\\a"),
			b'\x08' => out.push_str("\\b"),
			b'\x0c' => out.push_str("\\f"),
			b'\n' => out.push_str("\\n"),
			b'\r' => out.push_str("\\r"),
			b'\t' => out.push_str("\\t"),
			b'\x0b' => out.push_str("\\v"),
			b'\\' => out.push_str("\\\\"),
			b'"' => out.push_str("\\\""),
			b'\'' => out.push_str("\\'"),
			// Anything else, including every byte of a UTF-8 sequence, becomes
			// \xNN: systemd applies isprint(3) in the C locale byte by byte.
			0x20..=0x7e => out.push(b as char),
			_ => out.push_str(&format!("\\x{b:02x}")),
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn candidates(input: &[u8]) -> Vec<Vec<u8>> {
		parse_candidates(input)
			.iter()
			.map(|s| s.as_bytes().to_vec())
			.collect()
	}

	#[test]
	fn a_single_passphrase_survives_verbatim() {
		let input = b"correct horse".as_slice();
		let actual = candidates(input);
		let expected = vec![b"correct horse".to_vec()];
		assert_eq!(
			actual, expected,
			"parse_candidates({input:?}) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn splits_multiple_passphrases() {
		let input = b"one\ntwo\nthree".as_slice();
		let actual = candidates(input);
		let expected = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
		assert_eq!(
			actual, expected,
			"parse_candidates({input:?}) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn a_trailing_newline_does_not_become_an_empty_passphrase() {
		let input = b"only\n".as_slice();
		let actual = candidates(input);
		let expected = vec![b"only".to_vec()];
		assert_eq!(
			actual, expected,
			"parse_candidates({input:?}) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn caps_the_number_of_candidates() {
		let input = b"a\nb\nc\nd\ne\nf".as_slice();
		let actual = candidates(input).len();
		assert_eq!(
			actual, MAX_CANDIDATES,
			"parse_candidates({input:?}).len() returned {actual}, expected {MAX_CANDIDATES}"
		);
	}

	#[test]
	fn no_output_means_no_candidates() {
		for input in [b"".as_slice(), b"\n".as_slice(), b"\n\n".as_slice()] {
			let actual = candidates(input);
			assert!(
				actual.is_empty(),
				"parse_candidates({input:?}) returned {actual:?}, expected an empty vec"
			);
		}
	}

	#[test]
	fn a_device_path_escapes_to_itself() {
		let input = "/dev/disk/by-uuid/3f2a-4b1c";
		let actual = cescape(input);
		assert_eq!(
			actual, input,
			"cescape({input:?}) returned {actual:?}, expected {input:?} unchanged"
		);
	}

	#[test]
	fn escapes_what_systemd_escapes() {
		let cases = [
			("a\\b", "a\\\\b"),
			("a\"b", "a\\\"b"),
			("a'b", "a\\'b"),
			("a\tb", "a\\tb"),
			("a\nb", "a\\nb"),
			("a\u{1}b", "a\\x01b"),
			("dé", "d\\xc3\\xa9"),
		];
		for (input, expected) in cases {
			let actual = cescape(input);
			assert_eq!(
				actual, expected,
				"cescape({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn the_friendly_name_names_both_halves() {
		let actual = friendly_name("root", "/dev/vda2");
		assert_eq!(
			actual, "/dev/vda2 (root)",
			"friendly_name(\"root\", \"/dev/vda2\") returned {actual:?}, expected \"/dev/vda2 (root)\""
		);
	}
}
