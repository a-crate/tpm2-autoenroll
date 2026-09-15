//! Running a child process with a deadline.
//!
//! Connections are handled one at a time, so a `cryptsetup` stuck on a wedged
//! device would otherwise hold every other volume's connection in the backlog,
//! healthy ones included -- and `Wants=` does not help, since the daemon started
//! fine. A timeout fails the step it belongs to, which every caller already
//! turns into a decline or a `Leave`.

use std::io::Read;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::process::{Pid, PidfdFlags};

pub struct Output {
	pub status: ExitStatus,
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

/// Spawn `cmd`, collect whichever of stdout and stderr the caller piped, and
/// kill it if it is still running after `timeout`.
pub fn run(cmd: &mut Command, timeout: Duration) -> Result<Output, String> {
	let program = cmd.get_program().to_string_lossy().into_owned();
	let mut child = cmd
		.spawn()
		.map_err(|e| format!("could not run {program}: {e}"))?;

	let collected = collect(&mut child, timeout);
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

type Collected = (Vec<u8>, Vec<u8>);

/// `None` when the deadline passed first.
fn collect(child: &mut Child, timeout: Duration) -> Result<Option<Collected>, String> {
	let deadline = Instant::now() + timeout;
	let pid = Pid::from_raw(child.id() as i32).ok_or("the child has no pid")?;
	let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty())
		.map_err(|e| format!("pidfd_open: {e}"))?;

	let mut stdout_pipe = child.stdout.take();
	let mut stderr_pipe = child.stderr.take();
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
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
			drain(&mut stdout_pipe, &mut stdout)?;
		}
		if stderr_ready {
			drain(&mut stderr_pipe, &mut stderr)?;
		}
	}

	Ok(Some((stdout, stderr)))
}

/// One read's worth. End of file closes the pipe.
fn drain<R: Read>(pipe: &mut Option<R>, into: &mut Vec<u8>) -> Result<(), String> {
	let Some(p) = pipe else {
		return Ok(());
	};
	let mut buf = [0u8; 4096];
	match p.read(&mut buf) {
		Ok(0) => *pipe = None,
		Ok(n) => into.extend_from_slice(&buf[..n]),
		Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
		Err(e) => return Err(format!("reading from the child: {e}")),
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
		let out = run(&mut cmd, Duration::from_secs(10))
			.unwrap_or_else(|e| panic!("run(sh -c ..., 10s) returned Err({e}), expected Ok"));
		let actual = (out.status.code(), out.stdout, out.stderr);
		let expected = (Some(3), b"out".to_vec(), b"err".to_vec());
		assert_eq!(
			actual, expected,
			"run(sh -c 'printf out; printf err >&2; exit 3', 10s) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn output_larger_than_a_pipe_does_not_deadlock() {
		// A pipe holds 64 KiB. Reading only after the child exits would leave
		// this child blocked on a full pipe until the deadline.
		let mut cmd = Command::new("sh");
		cmd.args(["-c", "head -c 1000000 /dev/zero"])
			.stdout(Stdio::piped());
		let actual = run(&mut cmd, Duration::from_secs(10)).map(|o| o.stdout.len());
		assert_eq!(
			actual,
			Ok(1_000_000),
			"run(head -c 1000000 /dev/zero, 10s) returned stdout length {actual:?}, expected Ok(1000000)"
		);
	}

	#[test]
	fn kills_a_child_past_its_deadline() {
		let mut cmd = Command::new("sleep");
		cmd.arg("30");
		let started = Instant::now();
		let actual = run(&mut cmd, Duration::from_millis(200)).map(|o| o.status);
		let elapsed = started.elapsed();
		assert!(
			actual.is_err(),
			"run(sleep 30, 200ms) returned {actual:?}, expected Err"
		);
		assert!(
			elapsed < Duration::from_secs(5),
			"run(sleep 30, 200ms) took {elapsed:?}, expected well under 5s"
		);
	}
}
