//! Checking a passphrase against a LUKS2 volume.
//!
//! Validation is what makes everything else in the plain phase safe. DESIGN.md
//! section 2.3 gives us exactly one attempt before systemd-cryptsetup reverts to
//! its own prompt, so a passphrase we did not check -- one typed with a typo, or
//! one pulled from the kernel keyring where it was cached for some entirely
//! different volume -- would spend that attempt for nothing. Section 6 needs it
//! too: consent must be asked only after the passphrase is known to be right, so
//! a typo never produces a consent prompt.
//!
//! Done by running the `cryptsetup` CLI rather than linking libcryptsetup, which
//! would forfeit the static musl build section 9 asks for. The cost is one full
//! KDF pass per check (DESIGN.md section 4.4).

use std::process::{Command, Stdio};

use crate::memfd::SecretFile;
use crate::secret::Secret;

const BINARY: &str = "cryptsetup";

/// What a passphrase turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
	/// It opens the volume.
	Correct,
	/// It does not. A typo, or a passphrase belonging to another volume; either
	/// way, asking again is the right response.
	Wrong,
	/// We could not tell -- a missing device, a broken config, no permission.
	/// Distinct from `Wrong` because retrying would loop forever.
	Unusable(String),
}

/// Does `secret` unlock `device`?
pub fn test_passphrase(device: &str, secret: &Secret) -> Verdict {
	let key = match SecretFile::new(secret) {
		Ok(k) => k,
		Err(e) => return Verdict::Unusable(e),
	};

	let mut cmd = Command::new(BINARY);
	cmd.arg("open")
		// No device-mapper node is created and no name is needed; this only
		// runs the passphrase through the KDF and compares.
		.arg("--test-passphrase")
		.arg("--batch-mode")
		// Both of these keep the answer a statement about the passphrase
		// specifically. A LUKS2 token plugin, or a volume key already in the
		// kernel keyring, could otherwise open the volume and report success
		// for a passphrase that is in fact wrong -- and on this path the TPM2
		// token has just failed, so that is exactly the wrong thing to believe
		// at exactly the wrong moment.
		.arg("--disable-external-tokens")
		.arg("--disable-keyring")
		.arg(format!("--key-file={}", key.path()))
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	key.attach(&mut cmd);

	let out = match cmd.output() {
		Ok(o) => o,
		Err(e) => return Verdict::Unusable(format!("could not run {BINARY}: {e}")),
	};

	match verdict_from_code(out.status.code()) {
		Verdict::Unusable(reason) => {
			let stderr = String::from_utf8_lossy(&out.stderr);
			let stderr = stderr.trim();
			if stderr.is_empty() {
				Verdict::Unusable(reason)
			} else {
				Verdict::Unusable(format!("{reason}: {stderr}"))
			}
		}
		other => other,
	}
}

/// cryptsetup(8) RETURN CODES: 0 success, 1 wrong parameters, 2 no permission
/// (bad passphrase), 3 out of memory, 4 wrong device, 5 device busy.
///
/// Only 2 means "that passphrase is not one of this volume's". Everything else
/// is our problem rather than the user's, and must not be answered by prompting
/// again.
fn verdict_from_code(code: Option<i32>) -> Verdict {
	match code {
		Some(0) => Verdict::Correct,
		Some(2) => Verdict::Wrong,
		Some(1) => Verdict::Unusable("cryptsetup: wrong parameters".to_string()),
		Some(3) => Verdict::Unusable("cryptsetup: out of memory".to_string()),
		Some(4) => Verdict::Unusable("cryptsetup: wrong device".to_string()),
		Some(5) => Verdict::Unusable("cryptsetup: device already exists or is busy".to_string()),
		Some(n) => Verdict::Unusable(format!("cryptsetup exited with {n}")),
		None => Verdict::Unusable("cryptsetup was killed by a signal".to_string()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn maps_the_documented_return_codes() {
		let cases = [(Some(0), Verdict::Correct), (Some(2), Verdict::Wrong)];
		for (input, expected) in cases {
			let actual = verdict_from_code(input);
			assert_eq!(
				actual, expected,
				"verdict_from_code({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn everything_but_zero_and_two_is_unusable() {
		// The distinction that matters: Unusable must never be retried, because
		// a device that does not exist will not start existing because we asked
		// the user to type the passphrase again.
		for input in [Some(1), Some(3), Some(4), Some(5), Some(99), None] {
			let actual = verdict_from_code(input);
			assert!(
				matches!(actual, Verdict::Unusable(_)),
				"verdict_from_code({input:?}) returned {actual:?}, expected Verdict::Unusable(_)"
			);
		}
	}

	#[test]
	fn a_bad_passphrase_is_not_reported_as_a_broken_device() {
		// Confusing these two either loops forever on a typo or gives up
		// instantly on a correct passphrase.
		let actual = verdict_from_code(Some(2));
		assert_eq!(
			actual,
			Verdict::Wrong,
			"verdict_from_code(Some(2)) returned {actual:?}, expected Verdict::Wrong (cryptsetup's \"no permission (bad passphrase)\")"
		);
	}
}
