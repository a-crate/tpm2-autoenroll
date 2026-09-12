//! A byte buffer for key material.
//!
//! Passphrases are bytes, not text: nothing guarantees a user's passphrase is
//! valid UTF-8, and systemd-cryptsetup passes whatever it reads straight to
//! libcryptsetup. Keeping secrets in `Vec<u8>` rather than `String` avoids both
//! a lossy conversion and the reallocation a `String` would do to fix one up.

use std::fmt;

use zeroize::Zeroize;

/// Key material that is wiped when dropped and never rendered by `Debug`.
///
/// This is the only type a passphrase is allowed to live in. Introducing it up
/// front is deliberate: secret hygiene retrofitted later is how secrets end up
/// in log lines.
pub struct Secret(Vec<u8>);

impl Secret {
	pub fn new(bytes: Vec<u8>) -> Self {
		Secret(bytes)
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl Drop for Secret {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

/// Renders as a redaction, so a `Secret` reached by an accidental `{:?}` on some
/// enclosing struct cannot leak the passphrase into the journal.
impl fmt::Debug for Secret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Secret({} bytes)", self.0.len())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn debug_does_not_render_contents() {
		let s = Secret::new(b"hunter2".to_vec());
		let actual = format!("{s:?}");
		assert!(
			!actual.contains("hunter2"),
			"format!(\"{{:?}}\", Secret::new(b\"hunter2\")) returned {actual:?}, expected a redaction containing no passphrase bytes"
		);
		assert_eq!(
			actual, "Secret(7 bytes)",
			"format!(\"{{:?}}\", Secret::new(b\"hunter2\")) returned {actual:?}, expected \"Secret(7 bytes)\""
		);
	}

	#[test]
	fn as_bytes_round_trips() {
		let s = Secret::new(b"\xff\x00pass".to_vec());
		let actual = s.as_bytes();
		assert_eq!(
			actual,
			b"\xff\x00pass",
			"Secret::new(b\"\\xff\\x00pass\").as_bytes() returned {actual:?}, expected b\"\\xff\\x00pass\""
		);
	}
}
