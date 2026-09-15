//! Handing a secret to a child process without it appearing anywhere a third
//! party can read.
//!
//! Not argv, which is world-readable in `/proc`, and not the environment, which
//! anyone who can read `/proc/<pid>/environ` gets for the process's lifetime. A
//! memfd has no name in any filesystem, is reachable only through the holder's
//! own `/proc/self/fd`, and disappears when the last descriptor closes.
//!
//! `cryptsetup --key-file=` and `systemd-cryptenroll --unlock-key-file=` both
//! read the file verbatim -- cryptsetup(8) is explicit that newlines do not
//! terminate a key file -- so what the child reads is exactly the bytes
//! systemd-cryptsetup would have received from us.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::process::Command;

use crate::child;
use crate::secret::Secret;

pub struct SecretFile {
	fd: OwnedFd,
	len: usize,
}

impl SecretFile {
	pub fn new(secret: &Secret) -> Result<Self, String> {
		let fd = rustix::fs::memfd_create("tpm2-autoenroll-key", rustix::fs::MemfdFlags::CLOEXEC)
			.map_err(|e| format!("memfd_create: {e}"))?;

		let mut file = std::fs::File::from(fd);
		file.write_all(secret.as_bytes())
			.map_err(|e| format!("writing the key to a memfd: {e}"))?;
		file.flush()
			.map_err(|e| format!("flushing the key to a memfd: {e}"))?;

		Ok(SecretFile {
			fd: file.into(),
			len: secret.len(),
		})
	}

	/// The path to hand the child; see `child::fd_path`. Only this one child:
	/// the key must not leak into `systemd-ask-password`.
	pub fn path(&self) -> String {
		child::fd_path(&self.fd)
	}

	pub fn attach(&self, cmd: &mut Command) {
		child::inherit(cmd, &self.fd);
	}
}

/// A memfd's pages are not wiped when its last descriptor closes; they linger
/// in physical memory until reused. Overwriting them first means what lingers
/// is zeros. Errors are ignored: there is nothing left to do but close.
impl Drop for SecretFile {
	fn drop(&mut self) {
		let zeros = [0u8; 4096];
		let mut at = 0;
		while at < self.len {
			let n = (self.len - at).min(zeros.len());
			match rustix::io::pwrite(&self.fd, &zeros[..n], at as u64) {
				Ok(0) | Err(_) => break,
				Ok(written) => at += written,
			}
		}
		let _ = rustix::fs::ftruncate(&self.fd, 0);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Read;

	#[test]
	fn dropping_wipes_the_memfd() {
		// A second open of the procfs link is a separate file description on
		// the same memfd, so it outlives the SecretFile and sees what it left.
		let secret = Secret::new(b"correct-horse".to_vec());
		let file = SecretFile::new(&secret).expect("SecretFile::new returned Err, expected Ok");
		let mut reopened =
			std::fs::File::open(file.path()).expect("reopening the memfd path returned Err");
		drop(file);

		let mut actual = Vec::new();
		reopened
			.read_to_end(&mut actual)
			.expect("reading the reopened memfd returned Err");
		assert!(
			actual.is_empty(),
			"reading a SecretFile's memfd after dropping it returned {actual:?}, expected no bytes"
		);
	}

	#[test]
	fn the_path_reads_back_the_secret() {
		// Within our own process /proc/self/fd is our fd table, so this is the
		// same read the child performs.
		let secret = Secret::new(b"correct-horse".to_vec());
		let file = SecretFile::new(&secret).expect("SecretFile::new returned Err, expected Ok");
		let actual = std::fs::read(file.path()).expect("reading the memfd path returned Err");
		assert_eq!(
			actual,
			b"correct-horse",
			"std::fs::read(SecretFile::new(b\"correct-horse\").path()) returned {actual:?}, expected b\"correct-horse\""
		);
	}

	#[test]
	fn reading_twice_gives_the_same_bytes() {
		// If each open of the procfs link did not start at offset zero, the
		// second child handed the same SecretFile would read nothing and report
		// a wrong passphrase.
		let secret = Secret::new(b"hunter2".to_vec());
		let file = SecretFile::new(&secret).expect("SecretFile::new returned Err, expected Ok");
		let _ = std::fs::read(file.path()).expect("the first read returned Err");
		let actual = std::fs::read(file.path()).expect("the second read returned Err");
		assert_eq!(
			actual,
			b"hunter2",
			"the second std::fs::read of the same SecretFile path returned {actual:?}, expected b\"hunter2\""
		);
	}

	#[test]
	fn keeps_bytes_that_are_not_text() {
		let secret = Secret::new(b"\xff\x00\npass".to_vec());
		let file = SecretFile::new(&secret).expect("SecretFile::new returned Err, expected Ok");
		let actual = std::fs::read(file.path()).expect("reading the memfd path returned Err");
		assert_eq!(
			actual,
			b"\xff\x00\npass",
			"std::fs::read of a SecretFile holding b\"\\xff\\x00\\npass\" returned {actual:?}, expected the same bytes verbatim"
		);
	}
}
