//! The `sd_notify(3)` half of `Type=notify`, written out rather than linked.
//!
//! This is what makes "the socket is listening before systemd-cryptsetup runs"
//! true rather than merely likely. With `Type=exec` systemd considers the
//! service started the moment the binary is executed, which is some way before
//! it has read the crypttab and bound anything; ordering another unit after it
//! would then guarantee nothing at all.

use rustix::net::{AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType};

/// Tell the service manager we are listening.
///
/// Silent when there is nothing to tell: the daemon is perfectly runnable by
/// hand, and a missing NOTIFY_SOCKET only means nobody is waiting on us.
pub fn ready() {
	let Ok(socket) = std::env::var("NOTIFY_SOCKET") else {
		return;
	};

	if let Err(e) = send(&socket, b"READY=1\n") {
		// Not fatal, but it will look like a startup hang from the outside, so
		// it is worth a line saying otherwise.
		crate::log::warning!("could not notify {socket:?} that we are ready ({e})");
	}
}

fn send(socket: &str, message: &[u8]) -> Result<(), String> {
	// sd_notify(3): a leading '@' means the abstract namespace.
	let addr = match socket.strip_prefix('@') {
		Some(name) => SocketAddrUnix::new_abstract_name(name.as_bytes()),
		None => SocketAddrUnix::new(socket),
	}
	.map_err(|e| format!("{socket}: {e}"))?;

	let fd = rustix::net::socket_with(
		AddressFamily::UNIX,
		SocketType::DGRAM,
		SocketFlags::CLOEXEC,
		None,
	)
	.map_err(|e| format!("socket: {e}"))?;

	rustix::net::sendto(&fd, message, SendFlags::empty(), &addr)
		.map_err(|e| format!("sendto: {e}"))?;
	Ok(())
}
