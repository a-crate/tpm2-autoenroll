//! Putting a listening socket where systemd-cryptsetup will look for a key.
//!
//! `discover_key()` (cryptsetup.c:2562) searches `/etc/cryptsetup-keys.d` then
//! `/run/cryptsetup-keys.d` for `<volume>.key`, and connects to it if it is a
//! socket. We bind those sockets ourselves rather than through `ListenStream=`,
//! so that a socket exists exactly as long as a daemon able to answer on it. The daemon therefore owns
//! their whole lifetime, including removing them on the way out
//! (`main::shutdown`).

use std::os::fd::OwnedFd;

use rustix::fs::{FileType, Mode};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

/// /run rather than /etc because the sockets exist only as long as the daemon.
pub const DEFAULT_DIR: &str = "/run/cryptsetup-keys.d";

/// We answer serially, so this only has to absorb several volumes unlocking at
/// once.
const BACKLOG: i32 = 16;

pub fn path(dir: &str, volume: &str) -> String {
	format!("{dir}/{volume}.key")
}

/// 0700, because the sockets under it hand out passphrases. An existing
/// directory is not re-moded -- on a system-stage boot something else may have
/// created it -- but it has to be one only root could have made and only root
/// can write to. Otherwise someone else could swap a socket of their own in
/// for ours and be handed systemd-cryptsetup's connection.
pub fn ensure_dir(dir: &str) -> Result<(), String> {
	match rustix::fs::mkdir(dir, Mode::RWXU) {
		Ok(()) => {
			// mkdir's mode is masked by the umask, which we do not control.
			rustix::fs::chmod(dir, Mode::RWXU).map_err(|e| format!("chmod {dir}: {e}"))
		}
		Err(rustix::io::Errno::EXIST) => check_existing(dir, 0),
		Err(e) => Err(format!("mkdir {dir}: {e}")),
	}
}

/// A real directory rather than a symlink to one, owned by `owner`, and
/// writable by nobody else.
fn check_existing(dir: &str, owner: u32) -> Result<(), String> {
	let stat = rustix::fs::lstat(dir).map_err(|e| format!("stat {dir}: {e}"))?;
	let mode = stat.st_mode as u32;
	if FileType::from_raw_mode(mode) != FileType::Directory {
		return Err(format!("{dir} exists and is not a directory"));
	}
	if stat.st_uid != owner {
		return Err(format!(
			"{dir} is owned by uid {}, expected {owner}",
			stat.st_uid
		));
	}
	if mode & 0o022 != 0 {
		return Err(format!(
			"{dir} has mode {:o}, which lets others write to it",
			mode & 0o7777
		));
	}
	Ok(())
}

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

/// Only ever a socket. Anything else at that path is a real key file someone put
/// there deliberately -- systemd-cryptsetup reads those too -- and deleting it
/// would destroy the very thing it is looking for.
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

		// A second run of the daemon must not need a hand-cleaned /run to work.
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
	fn an_existing_directory_must_be_private() {
		use std::os::unix::fs::PermissionsExt;

		let base = format!("/tmp/tpm2-autoenroll-existing-{}", std::process::id());
		let _ = std::fs::remove_dir_all(&base);
		std::fs::create_dir(&base).expect("could not create the test directory");
		let me = rustix::process::geteuid().as_raw();

		let private = format!("{base}/private");
		std::fs::create_dir(&private).expect("could not create the private directory");
		std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
			.expect("could not chmod the private directory");
		let writable = format!("{base}/writable");
		std::fs::create_dir(&writable).expect("could not create the writable directory");
		std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
			.expect("could not chmod the writable directory");
		let link = format!("{base}/link");
		std::os::unix::fs::symlink(&private, &link).expect("could not create the symlink");

		let cases = [
			(private.as_str(), me, true, "private and ours"),
			(writable.as_str(), me, false, "world-writable"),
			(link.as_str(), me, false, "a symlink to a private directory"),
			(private.as_str(), me + 1, false, "owned by someone else"),
		];
		for (dir, owner, expected, why) in cases {
			let actual = check_existing(dir, owner);
			assert_eq!(
				actual.is_ok(),
				expected,
				"check_existing({dir:?}, {owner}) returned {actual:?}, expected {} ({why})",
				if expected { "Ok" } else { "Err" }
			);
		}

		let _ = std::fs::remove_dir_all(&base);
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
