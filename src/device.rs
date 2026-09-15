//! The backing device, opened once per plain-phase connection.
//!
//! Validation, the header read, enrollment and verification each run their own
//! subprocess. Handing each one the configured path would resolve it afresh
//! every time, and a `/dev/disk/by-*` symlink can change in between -- a USB
//! stick carrying a colliding UUID, say -- so the passphrase could be checked
//! against one disk and the enrollment written to another, with the consent
//! prompt holding that window open for as long as the human takes. Every child
//! instead gets `/proc/self/fd/<n>` for a descriptor opened here, which names
//! the same kernel device whatever happens to the symlinks.

use std::os::fd::OwnedFd;
use std::process::Command;

use rustix::fs::{FileType, Mode, OFlags};

use crate::child;

pub struct Device {
	fd: OwnedFd,
	/// The configured path, for messages. Never handed to a child.
	pub name: String,
}

impl Device {
	pub fn open(path: &str) -> Result<Device, String> {
		let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
			.map_err(|e| format!("{path}: {e}"))?;
		let stat = rustix::fs::fstat(&fd).map_err(|e| format!("{path}: {e}"))?;
		if FileType::from_raw_mode(stat.st_mode as u32) != FileType::BlockDevice {
			return Err(format!("{path} is not a block device"));
		}
		Ok(Device {
			fd,
			name: path.to_string(),
		})
	}

	/// Whatever `path` names, block device or not. For tests that never let a
	/// child near it.
	#[cfg(test)]
	pub fn unchecked(path: &str) -> Device {
		let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
			.unwrap_or_else(|e| panic!("opening {path} returned Err({e})"));
		Device {
			fd,
			name: path.to_string(),
		}
	}

	/// For a child's argv; see `child::inherit`.
	pub fn path(&self) -> String {
		child::fd_path(&self.fd)
	}

	pub fn attach(&self, cmd: &mut Command) {
		child::inherit(cmd, &self.fd);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn refuses_anything_but_a_block_device() {
		for path in ["/dev/null", "/proc/self/status"] {
			let actual = Device::open(path).map(|d| d.name);
			assert!(
				actual.is_err(),
				"Device::open({path:?}) returned {actual:?}, expected Err"
			);
		}
	}
}
