//! Running a child process with a deadline.
//!
//! Connections are handled one at a time, so a `cryptsetup` stuck on a wedged
//! device would otherwise hold every other volume's connection in the backlog,
//! healthy ones included -- and `Wants=` does not help, since the daemon started
//! fine. A timeout fails the step it belongs to, which every caller already
//! turns into a decline or a `Leave`.
//!
//! stdout can carry passphrases (`systemd-ask-password`), so it is read into a
//! buffer allocated once at a fixed capacity and wiped on drop. A growing
//! `Vec` would leave unwiped copies behind in every allocation it outgrew.

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::process::{Pid, PidfdFlags};
use zeroize::{Zeroize, Zeroizing};

/// stderr is only ever logged, but still has a bound.
const STDERR_CAP: usize = 64 * 1024;

/// How much one read may take.
const CHUNK: usize = 64 * 1024;

pub struct Output {
	pub status: ExitStatus,
	pub stdout: Zeroizing<Vec<u8>>,
	pub stderr: Vec<u8>,
}

/// Spawn `cmd`, collect whichever of stdout and stderr the caller piped, and
/// kill it if it is still running after `timeout`. More than `stdout_cap`
/// bytes on stdout is an error.
pub fn run(cmd: &mut Command, timeout: Duration, stdout_cap: usize) -> Result<Output, String> {
	let program = cmd.get_program().to_string_lossy().into_owned();
	let mut child = cmd
		.spawn()
		.map_err(|e| format!("could not run {program}: {e}"))?;

	let collected = collect(&mut child, timeout, stdout_cap);
	if !matches!(collected, Ok(Some(_))) {
		// Not yet reaped, so the pid is still this child's.
		let _ = child.kill();
		let _ = child.wait();
	}

	match collected {
		Ok(Some((stdout, stderr))) => {
			let status = child
				.wait()
				.map_err(|e| format!("waiting for {program}: {e}"))?;
			Ok(Output {
				status,
				stdout,
				stderr,
			})
		}
		Ok(None) => Err(format!(
			"{program} did not finish within {} seconds, so it was killed",
			timeout.as_secs()
		)),
		Err(e) => Err(format!("{program}: {e}")),
	}
}

/// `/proc/self/fd/<n>` for `fd`, for the argv of a child `inherit` was called
/// for. It resolves in the *child's* fd table, where the number is only valid
/// because `inherit` kept it open across the exec. Opening the link re-opens
/// the file itself at offset zero, so one descriptor can serve several
/// children in turn.
pub fn fd_path(fd: &OwnedFd) -> String {
	format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// Keep `fd` open across `cmd`'s exec. Clearing `FD_CLOEXEC` in the parent
/// would leak it into every later child, `systemd-ask-password` included;
/// doing it in the pre-exec hook confines it to this one.
pub fn inherit(cmd: &mut Command, fd: &OwnedFd) {
	let raw = fd.as_raw_fd();
	// SAFETY: the closure runs in the forked child between fork and exec,
	// where only async-signal-safe calls are permitted. fcntl is one, and it
	// allocates nothing.
	unsafe {
		cmd.pre_exec(move || {
			if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		});
	}
}

type Collected = (Zeroizing<Vec<u8>>, Vec<u8>);

/// `None` when the deadline passed first.
fn collect(
	child: &mut Child,
	timeout: Duration,
	stdout_cap: usize,
) -> Result<Option<Collected>, String> {
	let deadline = Instant::now() + timeout;
	let pid = Pid::from_raw(child.id() as i32).ok_or("the child has no pid")?;
	let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty())
		.map_err(|e| format!("pidfd_open: {e}"))?;

	let mut stdout_pipe = child.stdout.take();
	let mut stderr_pipe = child.stderr.take();
	let mut stdout = Zeroizing::new(Vec::with_capacity(stdout_cap));
	let mut stderr = Vec::with_capacity(STDERR_CAP);
	let mut exited = false;

	// Both pipes are drained while the child runs, not after it exits: a child
	// that fills a pipe nobody is reading blocks, and would look like a hang.
	while !exited || stdout_pipe.is_some() || stderr_pipe.is_some() {
		let left = deadline.saturating_duration_since(Instant::now());
		if left.is_zero() {
			return Ok(None);
		}

		let mut fds = Vec::with_capacity(3);
		if !exited {
			fds.push(PollFd::new(&pidfd, PollFlags::IN));
		}
		if let Some(p) = &stdout_pipe {
			fds.push(PollFd::new(p, PollFlags::IN));
		}
		if let Some(p) = &stderr_pipe {
			fds.push(PollFd::new(p, PollFlags::IN));
		}

		let wait = Timespec {
			tv_sec: left.as_secs() as _,
			tv_nsec: left.subsec_nanos() as _,
		};
		match rustix::event::poll(&mut fds, Some(&wait)) {
			Ok(_) => {}
			Err(rustix::io::Errno::INTR) => continue,
			Err(e) => return Err(format!("poll: {e}")),
		}

		// Walked in the order pushed above, skipping whatever was not pushed.
		let mut ready = fds.iter().map(|f| !f.revents().is_empty());
		let pid_ready = !exited && ready.next() == Some(true);
		let stdout_ready = stdout_pipe.is_some() && ready.next() == Some(true);
		let stderr_ready = stderr_pipe.is_some() && ready.next() == Some(true);
		drop(fds);

		if pid_ready {
			exited = true;
		}
		if stdout_ready {
			drain(&mut stdout_pipe, &mut stdout, stdout_cap)?;
		}
		if stderr_ready {
			drain(&mut stderr_pipe, &mut stderr, STDERR_CAP)?;
		}
	}

	Ok(Some((stdout, stderr)))
}

/// One read's worth, straight into `into`. It never grows past `cap`, which
/// its capacity already covers, so it never reallocates. End of file closes
/// the pipe.
fn drain<R: Read>(pipe: &mut Option<R>, into: &mut Vec<u8>, cap: usize) -> Result<(), String> {
	let Some(p) = pipe else {
		return Ok(());
	};

	let start = into.len();
	if start == cap {
		// Full, so any more is too much; one byte is enough to tell.
		let mut probe = [0u8; 1];
		let read = p.read(&mut probe);
		probe.zeroize();
		return match read {
			Ok(0) => {
				*pipe = None;
				Ok(())
			}
			Ok(_) => Err(format!("wrote more than {cap} bytes")),
			Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()),
			Err(e) => Err(format!("reading from the child: {e}")),
		};
	}

	into.resize(start + (cap - start).min(CHUNK), 0);
	let read = p.read(&mut into[start..]);
	match read {
		Ok(0) => {
			into.truncate(start);
			*pipe = None;
		}
		Ok(n) => into.truncate(start + n),
		Err(e) if e.kind() == std::io::ErrorKind::Interrupted => into.truncate(start),
		Err(e) => {
			into.truncate(start);
			return Err(format!("reading from the child: {e}"));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::process::Stdio;

	#[test]
	fn collects_output_and_status() {
		let mut cmd = Command::new("sh");
		cmd.args(["-c", "printf out; printf err >&2; exit 3"])
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		let out = run(&mut cmd, Duration::from_secs(10), 16)
			.unwrap_or_else(|e| panic!("run(sh -c ..., 10s, 16) returned Err({e}), expected Ok"));
		let actual = (out.status.code(), out.stdout.to_vec(), out.stderr);
		let expected = (Some(3), b"out".to_vec(), b"err".to_vec());
		assert_eq!(
			actual, expected,
			"run(sh -c 'printf out; printf err >&2; exit 3', 10s, 16) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn output_larger_than_a_pipe_does_not_deadlock() {
		// A pipe holds 64 KiB. Reading only after the child exits would leave
		// this child blocked on a full pipe until the deadline. Exactly at the
		// cap is still within it.
		let mut cmd = Command::new("sh");
		cmd.args(["-c", "head -c 1000000 /dev/zero"])
			.stdout(Stdio::piped());
		let actual = run(&mut cmd, Duration::from_secs(10), 1_000_000).map(|o| o.stdout.len());
		assert_eq!(
			actual,
			Ok(1_000_000),
			"run(head -c 1000000 /dev/zero, 10s, 1000000) returned stdout length {actual:?}, expected Ok(1000000)"
		);
	}

	#[test]
	fn stdout_past_the_cap_is_an_error() {
		let mut cmd = Command::new("sh");
		cmd.args(["-c", "head -c 1000 /dev/zero"])
			.stdout(Stdio::piped());
		let actual = run(&mut cmd, Duration::from_secs(10), 999).map(|o| o.stdout.len());
		assert!(
			actual.is_err(),
			"run(head -c 1000 /dev/zero, 10s, 999) returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn the_stdout_buffer_is_never_reallocated() {
		let mut cmd = Command::new("sh");
		cmd.args(["-c", "head -c 200000 /dev/zero"])
			.stdout(Stdio::piped());
		let out = run(&mut cmd, Duration::from_secs(10), 300_000)
			.unwrap_or_else(|e| panic!("run(head -c 200000, 10s, 300000) returned Err({e})"));
		let actual = out.stdout.capacity();
		assert_eq!(
			actual, 300_000,
			"run(head -c 200000, 10s, 300000) left stdout capacity {actual}, expected 300000: a different capacity means it was reallocated"
		);
	}

	#[test]
	fn kills_a_child_past_its_deadline() {
		let mut cmd = Command::new("sleep");
		cmd.arg("30");
		let started = Instant::now();
		let actual = run(&mut cmd, Duration::from_millis(200), 0).map(|o| o.status);
		let elapsed = started.elapsed();
		assert!(
			actual.is_err(),
			"run(sleep 30, 200ms, 0) returned {actual:?}, expected Err"
		);
		assert!(
			elapsed < Duration::from_secs(5),
			"run(sleep 30, 200ms, 0) took {elapsed:?}, expected well under 5s"
		);
	}
}
