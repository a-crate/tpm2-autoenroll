//! Who is on the other end of a key-socket connection.
//!
//! The abstract bind name says which phase systemd-cryptsetup is in, but any
//! process can bind any name. The cgroup is different: systemd puts each
//! `systemd-cryptsetup@<volume>.service` in its own, and a process cannot move
//! itself there without the privileges to rewrite the cgroup tree. So a
//! passphrase goes only to a uid-0 peer inside the unit for the volume the
//! socket belongs to. Root services with every capability dropped can still
//! reach `/run`, and this is what stops them.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// The executable a key-socket peer has to be running.
///
/// Set `TPM2_AUTOENROLL_SYSTEMD_CRYPTSETUP` at build time to override it.
pub const EXPECTED_SYSTEMD_BINARY: &str = match option_env!("TPM2_AUTOENROLL_SYSTEMD_CRYPTSETUP") {
	Some(path) => path,
	None => "/usr/bin/systemd-cryptsetup",
};

/// `Ok` when the peer of `conn` is systemd-cryptsetup working on `volume`.
pub fn check(conn: &OwnedFd, volume: &str) -> Result<(), String> {
	// This is probably forge-able by full root :(
	// mkdir /sys/fs/cgroup/evil/systemd-cryptsetup@root.service
	// write pid to croup.procs
	// take over EXPECTED_SYSTEMD_BINARY
	let cred =
		rustix::net::sockopt::socket_peercred(conn).map_err(|e| format!("SO_PEERCRED: {e}"))?;
	if cred.uid.as_raw() != 0 {
		return Err(format!("the peer runs as uid {}", cred.uid.as_raw()));
	}

	// SO_PEERPIDFD pins the peer process itself, so a pid recycled between
	// connect() and now cannot pass. Kernels before 6.5 lack it and get the
	// weaker pid-only check.
	let pidfd = peer_pidfd(conn)?;
	let pid = match &pidfd {
		Some(fd) => pidfd_pid(fd)?,
		None => cred.pid.as_raw_nonzero().get(),
	};

	let path = format!("/proc/{pid}/cgroup");
	let cgroup = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
	let unit = format!("systemd-cryptsetup@{}.service", unit_escape(volume));
	if !in_unit(&cgroup, &unit) {
		return Err(format!("the peer (pid {pid}) is not in {unit}"));
	}

	let path = format!("/proc/{pid}/exe");
	let exe = std::fs::read_link(&path).map_err(|e| format!("{path}: {e}"))?;
	if !is_expected_exe(&exe) {
		return Err(format!(
			"the peer (pid {pid}) runs {}, expected {EXPECTED_SYSTEMD_BINARY}",
			exe.display()
		));
	}

	// The cgroup and exe were read by pid. The pidfd still referring to a live
	// process means that pid was not recycled while we read them.
	if let Some(fd) = &pidfd {
		alive(fd)?;
	}
	Ok(())
}

fn peer_pidfd(conn: &OwnedFd) -> Result<Option<OwnedFd>, String> {
	let mut fd: libc::c_int = -1;
	let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
	// SAFETY: fd and len point to storage of the sizes passed.
	let rc = unsafe {
		libc::getsockopt(
			conn.as_raw_fd(),
			libc::SOL_SOCKET,
			libc::SO_PEERPIDFD,
			&mut fd as *mut libc::c_int as *mut libc::c_void,
			&mut len,
		)
	};
	if rc != 0 {
		let err = std::io::Error::last_os_error();
		if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
			return Ok(None);
		}
		return Err(format!("SO_PEERPIDFD: {err}"));
	}
	// SAFETY: the kernel just handed us this descriptor and nothing else owns it.
	Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// The pid behind a pidfd, from its fdinfo. -1 there means the process has
/// already exited.
fn pidfd_pid(fd: &OwnedFd) -> Result<i32, String> {
	let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
	let info = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
	let pid = info
		.lines()
		.find_map(|l| l.strip_prefix("Pid:"))
		.and_then(|v| v.trim().parse::<i32>().ok())
		.ok_or_else(|| format!("{path} has no Pid: line"))?;
	if pid <= 0 {
		return Err("the peer has exited".to_string());
	}
	Ok(pid)
}

fn alive(fd: &OwnedFd) -> Result<(), String> {
	// SAFETY: signal 0 delivers nothing; the call only checks the target exists.
	let rc = unsafe {
		libc::syscall(
			libc::SYS_pidfd_send_signal,
			fd.as_raw_fd(),
			0,
			std::ptr::null::<libc::siginfo_t>(),
			0,
		)
	};
	if rc != 0 {
		return Err(format!(
			"the peer is gone ({})",
			std::io::Error::last_os_error()
		));
	}
	Ok(())
}

/// Whether a `/proc/<pid>/exe` link target is the binary we expect.
fn is_expected_exe(link: &Path) -> bool {
	link == Path::new(EXPECTED_SYSTEMD_BINARY)
}

/// Whether the unified-hierarchy line of a `/proc/<pid>/cgroup` ends in `unit`.
fn in_unit(cgroup: &str, unit: &str) -> bool {
	cgroup
		.lines()
		.find_map(|l| l.strip_prefix("0::"))
		.is_some_and(|path| path.rsplit('/').next() == Some(unit))
}

/// systemd's `unit_name_escape()`, src/basic/unit-name.c.
fn unit_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for (i, b) in s.bytes().enumerate() {
		match b {
			// A leading dot would make a hidden unit name.
			b'.' if i == 0 => out.push_str("\\x2e"),
			b'/' => out.push('-'),
			b'-' | b'\\' => out.push_str(&format!("\\x{b:02x}")),
			b if b.is_ascii_alphanumeric() || b":_.".contains(&b) => out.push(b as char),
			_ => out.push_str(&format!("\\x{b:02x}")),
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn escapes_like_systemd() {
		let cases = [
			("root", "root"),
			("luks-3f2a", "luks\\x2d3f2a"),
			(".hidden", "\\x2ehidden"),
			("a.b", "a.b"),
			("a b", "a\\x20b"),
			("a/b", "a-b"),
			("a:b_c", "a:b_c"),
			("a\\b", "a\\x5cb"),
			("dé", "d\\xc3\\xa9"),
		];
		for (input, expected) in cases {
			let actual = unit_escape(input);
			assert_eq!(
				actual, expected,
				"unit_escape({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn matches_only_the_volumes_own_unit() {
		let unit = "systemd-cryptsetup@root.service";
		let cases = [
			(
				"0::/system.slice/system-systemd\\x2dcryptsetup.slice/systemd-cryptsetup@root.service\n",
				true,
			),
			(
				"0::/system.slice/system-systemd\\x2dcryptsetup.slice/systemd-cryptsetup@root2.service\n",
				false,
			),
			("0::/system.slice/evil.service\n", false),
			("0::/user.slice/user-0.slice/session-1.scope\n", false),
			("1:name=systemd:/systemd-cryptsetup@root.service\n", false),
			("", false),
		];
		for (cgroup, expected) in cases {
			let actual = in_unit(cgroup, unit);
			assert_eq!(
				actual, expected,
				"in_unit({cgroup:?}, {unit:?}) returned {actual}, expected {expected}"
			);
		}
	}

	#[test]
	fn the_expected_binary_is_an_absolute_path() {
		// /proc/<pid>/exe is always absolute, so a relative override could never
		// match and would cost the feature at boot with a confusing reason.
		let actual = Path::new(EXPECTED_SYSTEMD_BINARY).is_absolute();
		assert!(
			actual,
			"Path::new({EXPECTED_SYSTEMD_BINARY:?}).is_absolute() returned {actual}, expected true"
		);
	}

	#[test]
	fn matches_only_the_expected_binary() {
		let cases = [
			(EXPECTED_SYSTEMD_BINARY.to_string(), true),
			(format!("{EXPECTED_SYSTEMD_BINARY} (deleted)"), false),
			(format!("{EXPECTED_SYSTEMD_BINARY}-generator"), false),
			("/usr/bin/systemd-cryptenroll".to_string(), false),
			("/tmp/evil".to_string(), false),
		];
		for (link, expected) in cases {
			let actual = is_expected_exe(Path::new(&link));
			assert_eq!(
				actual, expected,
				"is_expected_exe({link:?}) returned {actual}, expected {expected}"
			);
		}
	}

	#[test]
	fn refuses_a_peer_outside_the_unit() {
		// The test process is not systemd-cryptsetup@root.service, whatever uid
		// it runs as.
		let (a, _b) = rustix::net::socketpair(
			rustix::net::AddressFamily::UNIX,
			rustix::net::SocketType::STREAM,
			rustix::net::SocketFlags::CLOEXEC,
			None,
		)
		.expect("socketpair failed");
		let actual = check(&a, "root");
		assert!(
			actual.is_err(),
			"check(<socketpair with ourselves>, \"root\") returned {actual:?}, expected Err"
		);
	}
}
