//! Talking to the TPM directly over `/dev/tpmrm0`.
//!
//! The alternatives were linking tpm2-tss, which gives up the static musl
//! build, or putting tpm2-tools in the initrd. We need four commands, none of
//! which takes a session or an authorization, so the wire format is small
//! enough to write out: a 10-byte header, a handle area, a parameter area. The
//! resource manager device is command/response oriented -- one `write(2)` is
//! one command, one `read(2)` is its response.
//!
//! References are to the TPM 2.0 Library Specification, Part 2 (Structures) and
//! Part 3 (Commands).

use std::fs::File;
use std::io::{Read, Write};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::FileType;

/// How long one command may take to answer. Connections are handled serially,
/// so a TPM that never answers would otherwise hold every other volume's
/// connection in the backlog, healthy ones included.
const RESPONSE_TIMEOUT: Timespec = Timespec {
	tv_sec: 30,
	tv_nsec: 0,
};

/// TPM_ST_NO_SESSIONS. Every command here is unauthenticated.
const ST_NO_SESSIONS: u16 = 0x8001;

const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_GET_CAPABILITY: u32 = 0x0000_017a;
const CC_PCR_READ: u32 = 0x0000_017e;
const CC_POLICY_PCR: u32 = 0x0000_017f;
const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;

const RH_NULL: u32 = 0x4000_0007;
const SE_TRIAL: u8 = 0x03;
const ALG_NULL: u16 = 0x0010;

const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
/// TPM_PT_PERMANENT, the first of the variable properties.
const PT_PERMANENT: u32 = 0x0000_0200;
const PT_LOCKOUT_COUNTER: u32 = 0x0000_020e;
const PT_MAX_AUTH_FAIL: u32 = 0x0000_020f;

/// TPMA_PERMANENT.inLockout, bit 9.
const PERMANENT_IN_LOCKOUT: u32 = 1 << 9;

/// The TPM's own maximum; real responses here are a few hundred bytes.
const MAX_RESPONSE: usize = 4096;

/// A PCR bank, i.e. which hash the PCRs were extended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bank(u16);

impl Bank {
	pub const SHA256: Bank = Bank(0x000b);

	/// Map the name systemd writes into the LUKS2 token.
	pub fn from_name(name: &str) -> Option<Bank> {
		match name {
			"sha1" => Some(Bank(0x0004)),
			"sha256" => Some(Bank(0x000b)),
			"sha384" => Some(Bank(0x000c)),
			"sha512" => Some(Bank(0x000d)),
			_ => None,
		}
	}

	pub fn name(self) -> &'static str {
		match self.0 {
			0x0004 => "sha1",
			0x000b => "sha256",
			0x000c => "sha384",
			0x000d => "sha512",
			_ => "unknown",
		}
	}
}

/// What the TPM says about its dictionary-attack state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockout {
	/// TPMA_PERMANENT.inLockout: the TPM is refusing authorizations outright.
	pub in_lockout: bool,
	pub counter: u32,
	pub max_auth_fail: u32,
}

pub struct Tpm {
	device: File,
}

impl Tpm {
	/// The resource manager device, not the raw one: `/dev/tpm0` admits a single
	/// user at a time, and something else in the initrd may well want it.
	pub const DEFAULT_DEVICE: &'static str = "/dev/tpmrm0";

	/// `device` is a path, or "auto" for the default, matching what
	/// `systemd-cryptenroll --tpm2-device=` accepts.
	pub fn open(device: &str) -> Result<Tpm, String> {
		let path = if device == "auto" {
			Self::DEFAULT_DEVICE
		} else {
			device
		};

		let file = File::options()
			.read(true)
			.write(true)
			.open(path)
			.map_err(|e| format!("{path}: {e}"))?;

		// Everything after this writes commands to the file, so a typo naming a
		// block device would put them over the start of a disk -- its LUKS
		// header, likely enough.
		let stat = rustix::fs::fstat(&file).map_err(|e| format!("{path}: {e}"))?;
		if FileType::from_raw_mode(stat.st_mode as u32) != FileType::CharacterDevice {
			return Err(format!("{path} is not a character device, so not a TPM"));
		}
		Ok(Tpm { device: file })
	}

	fn transact(&mut self, cc: u32, body: &[u8]) -> Result<Vec<u8>, String> {
		let cmd = command(cc, body);
		self.device
			.write_all(&cmd)
			.map_err(|e| format!("writing command {cc:#010x} to the TPM: {e}"))?;

		// poll writes revents into the array it is given, so the PollFd has to
		// be read back from there rather than from a copy.
		let mut fds = [PollFd::new(&self.device, PollFlags::IN)];
		match rustix::event::poll(&mut fds, Some(&RESPONSE_TIMEOUT)) {
			Ok(0) => {
				return Err(format!(
					"no response to command {cc:#010x} within {} seconds",
					RESPONSE_TIMEOUT.tv_sec
				))
			}
			Ok(_) => {}
			Err(e) => {
				return Err(format!(
					"waiting for the response to command {cc:#010x}: {e}"
				))
			}
		}

		let mut buf = vec![0u8; MAX_RESPONSE];
		let n = self
			.device
			.read(&mut buf)
			.map_err(|e| format!("reading the response to command {cc:#010x}: {e}"))?;
		buf.truncate(n);

		response_payload(&buf).map_err(|e| format!("command {cc:#010x}: {e}"))
	}

	/// Read the dictionary-attack state. Doubles as the "is there a responsive
	/// TPM here" probe: one that answers this answers anything we need.
	pub fn lockout(&mut self) -> Result<Lockout, String> {
		let mut body = Vec::new();
		put_u32(&mut body, CAP_TPM_PROPERTIES);
		put_u32(&mut body, PT_PERMANENT);
		// PT_PERMANENT through PT_MAX_AUTH_FAIL inclusive, in one round trip.
		put_u32(&mut body, PT_MAX_AUTH_FAIL - PT_PERMANENT + 1);

		let payload = self.transact(CC_GET_CAPABILITY, &body)?;
		parse_properties(&payload)
	}

	pub fn read_pcrs(&mut self, bank: Bank, indices: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
		let mut out = Vec::with_capacity(indices.len());
		let mut remaining: Vec<u8> = indices.to_vec();
		remaining.sort_unstable();
		remaining.dedup();

		// A TPM may return fewer digests than asked for -- eight is a common
		// limit -- and reports which ones it did in pcrSelectionOut.
		while !remaining.is_empty() {
			let mut body = Vec::new();
			put_pcr_selection(&mut body, bank, &remaining);

			let payload = self.transact(CC_PCR_READ, &body)?;
			absorb(&mut remaining, &mut out, parse_pcr_read(&payload)?)?;
		}

		out.sort_by_key(|(pcr, _)| *pcr);
		Ok(out)
	}

	/// Compute the policy digest that the *current* PCR values would produce.
	///
	/// The whole trick behind the drift check. Rather than reimplementing
	/// systemd's hashing and tracking it across versions, open a trial session
	/// -- which authorizes nothing and exists to compute exactly this -- and let
	/// the TPM build the policy from the PCRs as they are right now.
	///
	/// PolicyPCR alone, which is what `tpm2_calculate_sealing_policy()` builds
	/// for an enrollment with no PIN, public key or pcrlock -- the only kind the
	/// preflight lets through.
	pub fn pcr_policy_digest(&mut self, bank: Bank, indices: &[u8]) -> Result<Vec<u8>, String> {
		let session = self.start_trial_session()?;

		let result = self.build_policy(session, bank, indices);

		// The session occupies one of a small number of TPM slots, so release it
		// whether or not the policy worked out.
		if let Err(e) = self.flush(session) {
			warn_flush(session, &e);
		}

		result
	}

	fn build_policy(
		&mut self,
		session: u32,
		bank: Bank,
		indices: &[u8],
	) -> Result<Vec<u8>, String> {
		let mut body = Vec::new();
		put_u32(&mut body, session);
		// An empty pcrDigest tells the TPM to use the PCRs it currently holds
		// rather than checking ours against them, which is what makes this a
		// question about the machine's present state.
		put_u16(&mut body, 0);
		put_pcr_selection(&mut body, bank, indices);
		self.transact(CC_POLICY_PCR, &body)?;

		let mut body = Vec::new();
		put_u32(&mut body, session);
		let payload = self.transact(CC_POLICY_GET_DIGEST, &body)?;

		let mut r = Reader::new(&payload);
		let digest = r.tpm2b()?;
		Ok(digest.to_vec())
	}

	fn start_trial_session(&mut self) -> Result<u32, String> {
		let mut body = Vec::new();
		// Handle area: no salt key, no bind object.
		put_u32(&mut body, RH_NULL);
		put_u32(&mut body, RH_NULL);
		// nonceCaller must be at least the session hash's length. Its value
		// carries no weight here: nothing is authorized, so there is no replay
		// to prevent.
		put_tpm2b(&mut body, &[0u8; 32]);
		// encryptedSalt: none, since tpmKey is TPM_RH_NULL.
		put_tpm2b(&mut body, &[]);
		body.push(SE_TRIAL);
		// TPMT_SYM_DEF with TPM_ALG_NULL carries no further fields.
		put_u16(&mut body, ALG_NULL);
		put_u16(&mut body, Bank::SHA256.0);

		let payload = self.transact(CC_START_AUTH_SESSION, &body)?;
		let mut r = Reader::new(&payload);
		// StartAuthSession is the one command here with a response handle.
		r.u32()
	}

	fn flush(&mut self, handle: u32) -> Result<(), String> {
		// The odd one out: FlushContext's handle travels in the parameter area,
		// not the handle area, so a handle the TPM no longer tracks can still be
		// named.
		let mut body = Vec::new();
		put_u32(&mut body, handle);
		self.transact(CC_FLUSH_CONTEXT, &body)?;
		Ok(())
	}
}

fn warn_flush(session: u32, e: &str) {
	crate::log::warning!("could not flush TPM session {session:#010x}: {e}");
}

/// Build a command: header, then the caller's handle and parameter areas.
fn command(cc: u32, body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(10 + body.len());
	put_u16(&mut out, ST_NO_SESSIONS);
	put_u32(&mut out, (10 + body.len()) as u32);
	put_u32(&mut out, cc);
	out.extend_from_slice(body);
	out
}

/// Check a response header and return everything after it.
fn response_payload(buf: &[u8]) -> Result<Vec<u8>, String> {
	if buf.len() < 10 {
		return Err(format!(
			"response is {} bytes, expected at least 10",
			buf.len()
		));
	}

	let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
	if size != buf.len() {
		return Err(format!(
			"response declares {size} bytes but {} were read",
			buf.len()
		));
	}

	let rc = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
	if rc != 0 {
		return Err(format!("the TPM returned {}", describe_rc(rc)));
	}

	Ok(buf[10..].to_vec())
}

/// Enough of the response-code space to make a log line useful; most of the
/// full table cannot occur for unauthenticated commands.
fn describe_rc(rc: u32) -> String {
	let known = match rc {
		0x000_0100 => Some("TPM_RC_INITIALIZE (the TPM has not been started)"),
		0x000_0101 => Some("TPM_RC_FAILURE (the TPM is in failure mode)"),
		0x000_0120 => Some("TPM_RC_LOCKOUT (the TPM is in dictionary-attack lockout)"),
		0x000_0921 => Some("TPM_RC_SESSION_HANDLES (no session slot is free)"),
		0x000_0922 => Some("TPM_RC_OBJECT_HANDLES (no object slot is free)"),
		_ => None,
	};
	match known {
		Some(name) => format!("{rc:#010x}, {name}"),
		None => format!("{rc:#010x}"),
	}
}

fn parse_properties(payload: &[u8]) -> Result<Lockout, String> {
	let mut r = Reader::new(payload);
	let _more_data = r.u8()?;
	let capability = r.u32()?;
	if capability != CAP_TPM_PROPERTIES {
		return Err(format!(
			"the TPM answered with capability {capability:#010x}, expected {CAP_TPM_PROPERTIES:#010x}"
		));
	}

	let count = r.u32()?;
	let mut permanent = None;
	let mut counter = None;
	let mut max_auth_fail = None;

	for _ in 0..count {
		let property = r.u32()?;
		let value = r.u32()?;
		match property {
			PT_PERMANENT => permanent = Some(value),
			PT_LOCKOUT_COUNTER => counter = Some(value),
			PT_MAX_AUTH_FAIL => max_auth_fail = Some(value),
			_ => {}
		}
	}

	let permanent =
		permanent.ok_or_else(|| "the TPM did not report TPM_PT_PERMANENT".to_string())?;

	Ok(Lockout {
		in_lockout: permanent & PERMANENT_IN_LOCKOUT != 0,
		counter: counter.unwrap_or(0),
		max_auth_fail: max_auth_fail.unwrap_or(0),
	})
}

type PcrRead = (Vec<u8>, Vec<Vec<u8>>);

/// Fold one PCR_Read round into `out`.
///
/// Every round must answer for at least one outstanding PCR and for nothing
/// else. That is what guarantees `read_pcrs`' loop ends: a TPM answering with
/// PCRs nobody asked for would otherwise have it re-ask forever.
fn absorb(
	remaining: &mut Vec<u8>,
	out: &mut Vec<(u8, Vec<u8>)>,
	(returned, digests): PcrRead,
) -> Result<(), String> {
	if returned.is_empty() || digests.len() != returned.len() {
		return Err(format!(
			"the TPM returned {} digest(s) for {} PCR(s)",
			digests.len(),
			returned.len()
		));
	}
	if returned.windows(2).any(|w| w[0] == w[1]) {
		return Err(format!(
			"the TPM returned PCRs {returned:?}, which repeats one"
		));
	}
	if let Some(pcr) = returned.iter().find(|p| !remaining.contains(p)) {
		return Err(format!(
			"the TPM returned PCR {pcr}, which is not among the outstanding {remaining:?}"
		));
	}

	remaining.retain(|p| !returned.contains(p));
	out.extend(returned.into_iter().zip(digests));
	Ok(())
}

fn parse_pcr_read(payload: &[u8]) -> Result<PcrRead, String> {
	let mut r = Reader::new(payload);
	let _update_counter = r.u32()?;

	let selections = r.u32()?;
	let mut returned = Vec::new();
	for _ in 0..selections {
		let _hash = r.u16()?;
		let size = r.u8()? as usize;
		let bitmap = r.bytes(size)?;
		for (byte, bits) in bitmap.iter().enumerate() {
			for bit in 0..8 {
				if bits & (1 << bit) != 0 {
					let pcr = byte * 8 + bit;
					if pcr > 23 {
						return Err(format!("PCR {pcr} is out of range"));
					}
					returned.push(pcr as u8);
				}
			}
		}
	}

	let count = r.u32()?;
	let mut digests = Vec::with_capacity(count as usize);
	for _ in 0..count {
		digests.push(r.tpm2b()?.to_vec());
	}

	returned.sort_unstable();
	Ok((returned, digests))
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
	out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
	out.extend_from_slice(&v.to_be_bytes());
}

fn put_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
	put_u16(out, bytes.len() as u16);
	out.extend_from_slice(bytes);
}

/// TPML_PCR_SELECTION with a single bank.
///
/// The bitmap is little-endian by bit: PCR n lives in byte n/8 at bit n%8.
fn put_pcr_selection(out: &mut Vec<u8>, bank: Bank, indices: &[u8]) {
	let mut bitmap = [0u8; 3];
	for &pcr in indices {
		if (pcr as usize) < bitmap.len() * 8 {
			bitmap[pcr as usize / 8] |= 1 << (pcr % 8);
		}
	}

	put_u32(out, 1);
	put_u16(out, bank.0);
	out.push(bitmap.len() as u8);
	out.extend_from_slice(&bitmap);
}

/// Refuses to read past the end, so a short or malformed response is an error
/// rather than a panic.
struct Reader<'a> {
	buf: &'a [u8],
	at: usize,
}

impl<'a> Reader<'a> {
	fn new(buf: &'a [u8]) -> Self {
		Reader { buf, at: 0 }
	}

	fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
		let end = self.at.checked_add(n).ok_or("response length overflowed")?;
		if end > self.buf.len() {
			return Err(format!(
				"response ended after {} bytes, expected at least {end}",
				self.buf.len()
			));
		}
		let out = &self.buf[self.at..end];
		self.at = end;
		Ok(out)
	}

	fn u8(&mut self) -> Result<u8, String> {
		Ok(self.bytes(1)?[0])
	}

	fn u16(&mut self) -> Result<u16, String> {
		let b = self.bytes(2)?;
		Ok(u16::from_be_bytes([b[0], b[1]]))
	}

	fn u32(&mut self) -> Result<u32, String> {
		let b = self.bytes(4)?;
		Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
	}

	fn tpm2b(&mut self) -> Result<&'a [u8], String> {
		let size = self.u16()? as usize;
		self.bytes(size)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn builds_a_command_header() {
		let actual = command(CC_POLICY_GET_DIGEST, &[0x03, 0x00, 0x00, 0x00]);
		let expected = vec![
			0x80, 0x01, // TPM_ST_NO_SESSIONS
			0x00, 0x00, 0x00, 0x0e, // commandSize: 10 header + 4 body
			0x00, 0x00, 0x01, 0x89, // TPM_CC_PolicyGetDigest
			0x03, 0x00, 0x00, 0x00,
		];
		assert_eq!(
			actual, expected,
			"command(CC_POLICY_GET_DIGEST, [3,0,0,0]) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn selects_the_right_pcr_bits() {
		// Getting the bit order backwards would compute a policy over the wrong
		// registers and report drift on a machine that has not drifted.
		let cases: [(&[u8], [u8; 3]); 4] = [
			(&[0], [0x01, 0x00, 0x00]),
			(&[7], [0x80, 0x00, 0x00]),
			(&[16], [0x00, 0x00, 0x01]),
			(&[7, 11], [0x80, 0x08, 0x00]),
		];
		for (indices, expected_bitmap) in cases {
			let mut out = Vec::new();
			put_pcr_selection(&mut out, Bank::SHA256, indices);
			let actual = &out[7..10];
			assert_eq!(
				actual,
				&expected_bitmap[..],
				"put_pcr_selection(SHA256, {indices:?}) produced bitmap {actual:?}, expected {expected_bitmap:?}"
			);
		}
	}

	#[test]
	fn a_selection_names_one_bank_of_three_bytes() {
		let mut actual = Vec::new();
		put_pcr_selection(&mut actual, Bank::SHA256, &[16]);
		let expected = vec![
			0x00, 0x00, 0x00, 0x01, // count: one bank
			0x00, 0x0b, // TPM_ALG_SHA256
			0x03, // sizeofSelect
			0x00, 0x00, 0x01,
		];
		assert_eq!(
			actual, expected,
			"put_pcr_selection(SHA256, [16]) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn rejects_a_failed_response() {
		// Reading a failure as success would hand back a garbage digest and call
		// it a policy.
		let buf = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x20];
		let actual = response_payload(&buf);
		assert!(
			actual.is_err(),
			"response_payload(<rc=0x120>) returned {actual:?}, expected Err"
		);
		let message = actual.unwrap_err();
		assert!(
			message.contains("LOCKOUT"),
			"response_payload(<rc=0x120>) failed with {message:?}, expected a message naming TPM_RC_LOCKOUT"
		);
	}

	#[test]
	fn rejects_a_truncated_response() {
		let cases: [(&[u8], &str); 2] = [
			(&[0x80, 0x01, 0x00], "shorter than a header"),
			(
				&[0x80, 0x01, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00],
				"declares more bytes than were read",
			),
		];
		for (buf, why) in cases {
			let actual = response_payload(buf);
			assert!(
				actual.is_err(),
				"response_payload({buf:?}) returned {actual:?}, expected Err ({why})"
			);
		}
	}

	#[test]
	fn reads_the_lockout_properties() {
		let mut payload = vec![0x00]; // moreData
		put_u32(&mut payload, CAP_TPM_PROPERTIES);
		put_u32(&mut payload, 3);
		put_u32(&mut payload, PT_PERMANENT);
		put_u32(&mut payload, PERMANENT_IN_LOCKOUT | 0x04);
		put_u32(&mut payload, PT_LOCKOUT_COUNTER);
		put_u32(&mut payload, 7);
		put_u32(&mut payload, PT_MAX_AUTH_FAIL);
		put_u32(&mut payload, 32);

		let expected = Lockout {
			in_lockout: true,
			counter: 7,
			max_auth_fail: 32,
		};
		let actual = parse_properties(&payload);
		assert_eq!(
			actual,
			Ok(expected),
			"parse_properties(<inLockout set, counter 7, max 32>) returned {actual:?}, expected Ok({expected:?})"
		);
	}

	#[test]
	fn a_clear_permanent_word_is_not_lockout() {
		// lockoutAuthSet is bit 2 and must not be mistaken for inLockout at bit
		// 9, or every machine with a lockout password would be refused.
		let mut payload = vec![0x00];
		put_u32(&mut payload, CAP_TPM_PROPERTIES);
		put_u32(&mut payload, 1);
		put_u32(&mut payload, PT_PERMANENT);
		put_u32(&mut payload, 0x04);

		let actual = parse_properties(&payload).map(|l| l.in_lockout);
		assert_eq!(
			actual,
			Ok(false),
			"parse_properties(<lockoutAuthSet only>) returned in_lockout {actual:?}, expected Ok(false)"
		);
	}

	#[test]
	fn parses_a_pcr_read_response() {
		let mut payload = Vec::new();
		put_u32(&mut payload, 42); // pcrUpdateCounter
		put_pcr_selection(&mut payload, Bank::SHA256, &[7, 16]);
		put_u32(&mut payload, 2);
		put_tpm2b(&mut payload, &[0xaa; 32]);
		put_tpm2b(&mut payload, &[0xbb; 32]);

		let (returned, digests) = parse_pcr_read(&payload).expect("parse_pcr_read returned Err");
		assert_eq!(
			returned,
			vec![7, 16],
			"parse_pcr_read(<PCRs 7 and 16>) returned selection {returned:?}, expected [7, 16]"
		);
		let lengths: Vec<usize> = digests.iter().map(|d| d.len()).collect();
		assert_eq!(
			lengths,
			vec![32, 32],
			"parse_pcr_read(<two sha256 digests>) returned digest lengths {lengths:?}, expected [32, 32]"
		);
	}

	#[test]
	fn open_refuses_anything_but_a_character_device() {
		let path =
			std::env::temp_dir().join(format!("tpm2-autoenroll-not-a-tpm-{}", std::process::id()));
		std::fs::write(&path, b"").expect("could not create the test file");
		let path = path.to_str().expect("the temp path is not UTF-8");

		let actual = Tpm::open(path).map(|_| ());
		let _ = std::fs::remove_file(path);
		assert!(
			actual.is_err(),
			"Tpm::open({path:?}) on a regular file returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn a_round_answering_only_the_unasked_is_refused() {
		// Asked for 7, got 0 back: before, read_pcrs would re-ask for 7 forever.
		let mut remaining = vec![7];
		let mut out = Vec::new();
		let actual = absorb(&mut remaining, &mut out, (vec![0], vec![vec![0xaa; 32]]));
		assert!(
			actual.is_err(),
			"absorb(remaining = [7], returned = [0]) returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn a_partial_round_leaves_the_rest_outstanding() {
		let mut remaining: Vec<u8> = (0..10).collect();
		let mut out = Vec::new();
		let returned: Vec<u8> = (0..8).collect();
		let digests = vec![vec![0xaa; 32]; 8];
		let actual = absorb(&mut remaining, &mut out, (returned, digests));
		assert_eq!(
			actual,
			Ok(()),
			"absorb(remaining = 0..10, returned = 0..8) returned {actual:?}, expected Ok(())"
		);
		assert_eq!(
			remaining,
			vec![8, 9],
			"absorb(remaining = 0..10, returned = 0..8) left remaining {remaining:?}, expected [8, 9]"
		);
		assert_eq!(
			out.len(),
			8,
			"absorb(remaining = 0..10, returned = 0..8) produced {} digests, expected 8",
			out.len()
		);
	}

	#[test]
	fn a_selection_bitmap_past_pcr_23_is_refused() {
		// sizeofSelect 40 reaches bit 319. Casting that to u8 used to wrap it
		// onto a real PCR index.
		let mut bitmap = [0u8; 40];
		bitmap[37] = 0x10; // bit 300
		let mut payload = Vec::new();
		put_u32(&mut payload, 0);
		put_u32(&mut payload, 1);
		put_u16(&mut payload, Bank::SHA256.0);
		payload.push(bitmap.len() as u8);
		payload.extend_from_slice(&bitmap);
		put_u32(&mut payload, 1);
		put_tpm2b(&mut payload, &[0xaa; 32]);

		let actual = parse_pcr_read(&payload);
		assert!(
			actual.is_err(),
			"parse_pcr_read(<sizeofSelect 40, bit 300 set>) returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn a_reader_stops_at_the_end() {
		let mut r = Reader::new(&[0x00, 0x01]);
		let actual = r.u32();
		assert!(
			actual.is_err(),
			"Reader::new(&[0,1]).u32() returned {actual:?}, expected Err: a short response must not read past its end"
		);
	}

	#[test]
	fn maps_the_bank_names_systemd_writes() {
		let cases = [
			("sha256", Some(Bank(0x000b))),
			("sha1", Some(Bank(0x0004))),
			("sha512", Some(Bank(0x000d))),
			("md5", None),
		];
		for (input, expected) in cases {
			let actual = Bank::from_name(input);
			assert_eq!(
				actual, expected,
				"Bank::from_name({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}
}
