//! Putting a listening socket where systemd-cryptsetup will look for a key.
//!
//! `discover_key()` (cryptsetup.c:2562) searches `/etc/cryptsetup-keys.d` then
//! `/run/cryptsetup-keys.d` for `<volume>.key`, and connects to it if it is a
//! socket. We bind those sockets ourselves rather than having systemd do it
//! through `ListenStream=`, because the set of volumes is not known until the
//! crypttab has been read, and a socket unit's listen list is fixed at build
//! time.
//!
//! The daemon therefore owns the sockets' whole lifetime, including removing
//! them on the way out (`main::shutdown`). A socket file left behind in /run
//! outlives switch-root and sits exactly where stage 2's systemd-cryptsetup
//! looks, with nobody listening on it.

use std::os::fd::OwnedFd;

use rustix::fs::{FileType, Mode};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

/// Where the sockets go. /run rather than /etc because they exist only for as
/// long as the daemon does.
pub const DEFAULT_DIR: &str = "/run/cryptsetup-keys.d";

/// systemd-cryptsetup connects once per volume and we answer serially, so the
/// backlog only has to absorb several volumes unlocking at once.
const BACKLOG: i32 = 16;

pub fn path(dir: &str, volume: &str) -> String {
	format!("{dir}/{volume}.key")
}

/// Create the directory the sockets live in.
///
/// 0700: the sockets under it hand out passphrases, and the directory mode is
/// the cheap half of keeping that to root. An existing directory is left as it
/// is -- on a system-stage boot systemd-cryptsetup may have created it already,
/// and fighting over the mode of a directory we did not make is not our business.
pub fn ensure_dir(dir: &str) -> Result<(), String> {
	match rustix::fs::mkdir(dir, Mode::RWXU) {
		Ok(()) => {
			// mkdir's mode is masked by the umask, which we do not control.
			rustix::fs::chmod(dir, Mode::RWXU).map_err(|e| format!("chmod {dir}: {e}"))
		}
		Err(rustix::io::Errno::EXIST) => Ok(()),
		Err(e) => Err(format!("mkdir {dir}: {e}")),
	}
}

/// Bind and listen on one volume's key socket.
pub fn bind(path: &str) -> Result<OwnedFd, String> {
	clear(path)?;

	let addr = SocketAddrUnix::new(path).map_err(|e| format!("{path}: {e}"))?;
	let fd = rustix::net::socket_with(
		AddressFamily::UNIX,
		SocketType::STREAM,
		SocketFlags::CLOEXEC,
		None,
	)
	.map_err(|e| format!("socket: {e}"))?;

	rustix::net::bind(&fd, &addr).map_err(|e| format!("bind {path}: {e}"))?;
	// Again after the fact, because bind() applies the umask too.
	rustix::fs::chmod(path, Mode::RUSR | Mode::WUSR).map_err(|e| format!("chmod {path}: {e}"))?;
	rustix::net::listen(&fd, BACKLOG).map_err(|e| format!("listen {path}: {e}"))?;

	Ok(fd)
}

/// Remove a socket we are about to replace, or have finished with.
///
/// Only ever a socket. Anything else at that path is a real key file someone
/// put there deliberately -- systemd-cryptsetup reads those as well -- and
/// deleting it would destroy the very thing it is looking for.
pub fn clear(path: &str) -> Result<(), String> {
	let stat = match rustix::fs::lstat(path) {
		Ok(s) => s,
		Err(rustix::io::Errno::NOENT) => return Ok(()),
		Err(e) => return Err(format!("stat {path}: {e}")),
	};

	if FileType::from_raw_mode(stat.st_mode as u32) != FileType::Socket {
		return Err(format!(
			"{path} exists and is not a socket; leaving it alone"
		));
	}

	rustix::fs::unlink(path).map_err(|e| format!("unlink {path}: {e}"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn names_the_socket_after_the_volume() {
		let actual = path("/run/cryptsetup-keys.d", "root");
		assert_eq!(
			actual, "/run/cryptsetup-keys.d/root.key",
			"path(\"/run/cryptsetup-keys.d\", \"root\") returned {actual:?}, expected \"/run/cryptsetup-keys.d/root.key\""
		);
	}

	#[test]
	fn binds_listens_and_cleans_up() {
		let dir = format!("/tmp/tpm2-autoenroll-test-{}", std::process::id());
		let _ = std::fs::remove_dir_all(&dir);
		ensure_dir(&dir).expect("ensure_dir returned Err, expected Ok");

		let p = path(&dir, "root");
		let fd = bind(&p).unwrap_or_else(|e| panic!("bind({p:?}) returned Err({e}), expected Ok"));

		let mode = rustix::fs::lstat(&p)
			.expect("the socket was not created")
			.st_mode;
		assert_eq!(
			mode & 0o777,
			0o600,
			"bind({p:?}) left mode {:o}, expected 600",
			mode & 0o777
		);

		// Rebinding is what a second run of the daemon does, and it must not
		// need a hand-cleaned /run to work.
		drop(fd);
		bind(&p).unwrap_or_else(|e| panic!("rebinding {p:?} returned Err({e}), expected Ok"));

		clear(&p).expect("clear returned Err, expected Ok");
		let actual = std::fs::metadata(&p).is_err();
		assert!(
			actual,
			"clear({p:?}) left the socket in place, expected it gone"
		);

		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn refuses_to_delete_a_real_key_file() {
		let dir = format!("/tmp/tpm2-autoenroll-keyfile-{}", std::process::id());
		let _ = std::fs::remove_dir_all(&dir);
		ensure_dir(&dir).expect("ensure_dir returned Err, expected Ok");

		let p = path(&dir, "root");
		std::fs::write(&p, b"a real key").expect("could not write the test key file");

		let actual = clear(&p);
		assert!(
			actual.is_err(),
			"clear({p:?}) on a regular file returned {actual:?}, expected Err: it may be someone's key file"
		);
		assert!(
			std::fs::metadata(&p).is_ok(),
			"clear({p:?}) on a regular file deleted it, expected it left in place"
		);

		let _ = std::fs::remove_dir_all(&dir);
	}
}
