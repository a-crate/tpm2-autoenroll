//! Deriving the managed volume name from the path a listening socket is bound
//! to.
//!
//! One process holds one listening fd per managed volume, so the fd a
//! connection arrived on is what tells us which volume is being unlocked. The
//! path comes from `getsockname(2)` on that fd.
//!
//! systemd-cryptsetup's `discover_key()` (cryptsetup.c:2562) searches
//! `/etc/cryptsetup-keys.d` then `/run/cryptsetup-keys.d` for `<volume>.key`,
//! so only the basename carries meaning; we do not constrain the directory.

const SUFFIX: &str = ".key";

/// Extract the volume name from a key socket path.
///
/// `/run/cryptsetup-keys.d/root.key` yields `root`.
pub fn from_socket_path(path: &[u8]) -> Option<&[u8]> {
	let base = match path.iter().rposition(|&b| b == b'/') {
		Some(i) => &path[i + 1..],
		None => path,
	};
	let volume = base.strip_suffix(SUFFIX.as_bytes())?;
	if volume.is_empty() {
		return None;
	}
	Some(volume)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn call(input: &str) -> Option<String> {
		from_socket_path(input.as_bytes()).map(|v| String::from_utf8_lossy(v).into_owned())
	}

	#[test]
	fn strips_directory_and_suffix() {
		let cases = [
			("/run/cryptsetup-keys.d/root.key", Some("root")),
			("/etc/cryptsetup-keys.d/backup.key", Some("backup")),
			("data.key", Some("data")),
			("/run/cryptsetup-keys.d/luks-3f2a.key", Some("luks-3f2a")),
		];
		for (input, expected) in cases {
			let actual = call(input);
			assert_eq!(
				actual.as_deref(),
				expected,
				"from_socket_path({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn rejects_paths_without_the_key_suffix() {
		let cases = [
			("/run/cryptsetup-keys.d/root", "no .key suffix"),
			("/run/cryptsetup-keys.d/root.keyx", "suffix is not final"),
			("/run/cryptsetup-keys.d/.key", "empty volume"),
			("", "empty path"),
			("/run/cryptsetup-keys.d/", "directory, not a socket"),
		];
		for (input, why) in cases {
			let actual = call(input);
			assert_eq!(
				actual, None,
				"from_socket_path({input:?}) returned {actual:?}, expected None ({why})"
			);
		}
	}

	#[test]
	fn only_the_final_dot_key_is_stripped() {
		// A volume legitimately named "a.key" would live at "a.key.key"; we
		// must not eat both.
		let input = "/run/cryptsetup-keys.d/a.key.key";
		let actual = call(input);
		assert_eq!(
			actual.as_deref(),
			Some("a.key"),
			"from_socket_path({input:?}) returned {actual:?}, expected Some(\"a.key\")"
		);
	}
}
