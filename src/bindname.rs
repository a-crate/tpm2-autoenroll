//! Parsing of the abstract AF_UNIX peer name that systemd-cryptsetup binds to
//! its own end of the connection before talking to a key socket.
//!
//! crypttab(5) documents the format as
//!
//! ```text
//!     NUL RANDOM "/cryptsetup/" VOLUME
//! ```
//!
//! with RANDOM an alphanumeric string (a hex `u64` in practice). systemd varies
//! the infix according to what it is asking for, and that infix is the only
//! signal we get about which phase of the unlock loop we are being consulted
//! in. See `make_bindname()`, src/cryptsetup/cryptsetup.c:1373.
//!
//! The name is recovered with `getpeername(2)`, and the important property of
//! the bytes it returns is that they are *not* NUL-terminated: the leading NUL
//! marks the abstract namespace, and the length comes from the returned
//! `addrlen`. Reading them as a C string yields an empty name and mis-dispatches
//! every connection, so everything here works on byte slices with an explicit
//! length.

/// Which phase of systemd-cryptsetup's retry loop a connection belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
	/// The real passphrase is wanted. For a volume we manage this is reached
	/// only after the TPM2 attempt has already failed, which is what makes it
	/// our cue that the binding has drifted.
	Plain,
	/// The *encrypted* TPM2 blob is wanted. Declining here with zero bytes is
	/// what lets the LUKS2 header token be consulted normally.
	Tpm2,
	/// The FIDO2 salt is wanted.
	Fido2Salt,
	/// The PKCS#11 encrypted key is wanted.
	Pkcs11,
	/// An infix this build does not recognise. Treated exactly like the other
	/// non-plain phases: declined.
	Unknown,
}

impl Phase {
	pub fn as_str(self) -> &'static str {
		match self {
			Phase::Plain => "plain",
			Phase::Tpm2 => "tpm2",
			Phase::Fido2Salt => "fido2-salt",
			Phase::Pkcs11 => "pkcs11",
			Phase::Unknown => "unknown",
		}
	}
}

/// The infixes systemd uses, longest-distinguishing first. None is a prefix of
/// another, so match order is not load-bearing.
const INFIXES: &[(&[u8], Phase)] = &[
	(b"/cryptsetup/", Phase::Plain),
	(b"/cryptsetup-tpm2/", Phase::Tpm2),
	(b"/cryptsetup-fido2-salt/", Phase::Fido2Salt),
	(b"/cryptsetup-pkcs11/", Phase::Pkcs11),
];

/// A successfully parsed peer name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerName<'a> {
	pub phase: Phase,
	/// The volume component, which we cross-check against the volume the
	/// listening socket is bound for.
	pub volume: &'a [u8],
}

/// Parse an abstract socket name *without* its leading NUL byte.
///
/// Returns `None` when the name does not have the documented shape at all, as
/// distinct from having an unrecognised infix -- the latter parses fine and
/// yields [`Phase::Unknown`]. Both outcomes lead to a decline; they are kept
/// apart only so the logs say which happened.
pub fn parse(name: &[u8]) -> Option<PeerName<'_>> {
	// The random prefix runs up to the first slash.
	let slash = name.iter().position(|&b| b == b'/')?;
	let (random, rest) = name.split_at(slash);

	// crypttab(5) promises alphanumeric. Enforcing it means a name that does
	// not come from systemd-cryptsetup is rejected outright rather than being
	// coerced into a phase.
	if random.is_empty() || !random.iter().all(u8::is_ascii_alphanumeric) {
		return None;
	}

	for &(infix, phase) in INFIXES {
		if let Some(volume) = rest.strip_prefix(infix) {
			if volume.is_empty() {
				return None;
			}
			return Some(PeerName { phase, volume });
		}
	}

	// Unrecognised infix. Recover the volume for the log line: device-mapper
	// names cannot contain a slash, so the last component is the volume.
	let last = rest.iter().rposition(|&b| b == b'/')?;
	let volume = &rest[last + 1..];
	if volume.is_empty() {
		return None;
	}
	Some(PeerName { phase: Phase::Unknown, volume })
}

#[cfg(test)]
mod tests {
	use super::*;

	fn phase_of(input: &str) -> Option<Phase> {
		parse(input.as_bytes()).map(|p| p.phase)
	}

	fn volume_of(input: &str) -> Option<String> {
		parse(input.as_bytes()).map(|p| String::from_utf8_lossy(p.volume).into_owned())
	}

	#[test]
	fn recognises_every_documented_infix() {
		let cases = [
			("d7067f78d9827418/cryptsetup/myvol", Phase::Plain),
			("d7067f78d9827418/cryptsetup-tpm2/myvol", Phase::Tpm2),
			("d7067f78d9827418/cryptsetup-fido2-salt/myvol", Phase::Fido2Salt),
			("d7067f78d9827418/cryptsetup-pkcs11/myvol", Phase::Pkcs11),
		];
		for (input, expected) in cases {
			let actual = phase_of(input);
			assert_eq!(
				actual,
				Some(expected),
				"parse({input:?}).phase returned {actual:?}, expected {:?}",
				Some(expected)
			);
		}
	}

	#[test]
	fn extracts_the_volume_component() {
		let input = "d7067f78d9827418/cryptsetup-tpm2/root";
		let actual = volume_of(input);
		assert_eq!(
			actual.as_deref(),
			Some("root"),
			"parse({input:?}).volume returned {actual:?}, expected Some(\"root\")"
		);
	}

	#[test]
	fn tpm2_infix_is_not_read_as_plain() {
		// "/cryptsetup-tpm2/" shares a prefix with "/cryptsetup" but not with
		// "/cryptsetup/". Confusing the two would hand the passphrase to the
		// phase that wants an encrypted blob.
		let input = "abc123/cryptsetup-tpm2/root";
		let actual = phase_of(input);
		assert_eq!(
			actual,
			Some(Phase::Tpm2),
			"parse({input:?}).phase returned {actual:?}, expected Some(Tpm2)"
		);
	}

	#[test]
	fn unknown_infix_parses_as_unknown_not_plain() {
		let input = "abc123/cryptsetup-future-thing/root";
		let actual = phase_of(input);
		assert_eq!(
			actual,
			Some(Phase::Unknown),
			"parse({input:?}).phase returned {actual:?}, expected Some(Unknown)"
		);
	}

	#[test]
	fn rejects_malformed_names() {
		let cases = [
			("", "no slash at all"),
			("d7067f78d9827418", "no slash at all"),
			("/cryptsetup/root", "empty random prefix"),
			("not-alnum!/cryptsetup/root", "non-alphanumeric random prefix"),
			("abc123/cryptsetup/", "empty volume"),
			("abc123/cryptsetup-future-thing/", "empty volume, unknown infix"),
		];
		for (input, why) in cases {
			let actual = phase_of(input);
			assert_eq!(
				actual, None,
				"parse({input:?}).phase returned {actual:?}, expected None ({why})"
			);
		}
	}

	#[test]
	fn a_retained_leading_nul_fails_closed() {
		// Callers pass the abstract name with its leading NUL already removed.
		// If that ever stops being true -- rustix changing what
		// `abstract_name()` returns, say -- we want a decline, not a phase
		// guessed from a name we misread.
		let input = "\0abc123/cryptsetup/root";
		let actual = phase_of(input);
		assert_eq!(
			actual, None,
			"parse({input:?}) returned {actual:?}, expected None (leading NUL must be stripped by the caller)"
		);
	}

	#[test]
	fn trailing_nul_padding_fails_closed() {
		// Likewise if we were ever handed the fixed-size sun_path buffer rather
		// than addrlen bytes of it. A volume name with NULs glued on is not a
		// volume we serve, and declining is the safe reading.
		let input = "abc123/cryptsetup/root\0\0\0";
		let volume = volume_of(input);
		assert_ne!(
			volume.as_deref(),
			Some("root"),
			"parse({input:?}).volume returned {volume:?}, expected something other than Some(\"root\") so the volume cross-check rejects it"
		);
	}

	#[test]
	fn volume_may_contain_dashes_and_dots() {
		let input = "abc123/cryptsetup/luks-3f2a.backup";
		let actual = volume_of(input);
		assert_eq!(
			actual.as_deref(),
			Some("luks-3f2a.backup"),
			"parse({input:?}).volume returned {actual:?}, expected Some(\"luks-3f2a.backup\")"
		);
	}
}
