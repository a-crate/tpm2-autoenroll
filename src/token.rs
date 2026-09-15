//! Reading the `systemd-tpm2` token out of a LUKS2 header.
//!
//! This is where the enrollment's own parameters live: which PCRs it was sealed
//! against, in which bank, and the policy digest that sealing produced. Nothing
//! else knows them.
//!
//! Obtained from `cryptsetup luksDump --dump-json-metadata`, whose output is the
//! header's JSON verbatim. The field names below are systemd's, from
//! `tpm2_make_luks2_json()` in src/shared/tpm2-util.c. As the comment there
//! admits, the older fields use `-` and the newer ones `_`; both spellings are
//! live, so both appear here.

use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use crate::child;

const BINARY: &str = "cryptsetup";

/// Reading the header involves no KDF, so this is generous.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A `systemd-tpm2` token as it sits in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2Token {
	pub index: u32,
	/// May be empty: an enrollment against no PCRs at all is legal and unlocks
	/// unconditionally.
	pub pcrs: Vec<u8>,
	/// e.g. `sha256`. Absent in very old enrollments.
	pub bank: Option<String>,
	/// What a drift check compares against.
	pub policy_hash: Vec<u8>,
	pub pin: bool,
	/// Why the policy is more than a literal PCR policy: signed, pcrlock, or
	/// carrying a field this build does not know. We can neither judge nor
	/// reproduce these, and must not wipe them.
	pub advanced: Option<String>,
}

/// Every key `tpm2_make_luks2_json()` writes as of systemd 261.2. Anything else
/// is a policy element from a newer systemd, which would otherwise read as
/// drift and be silently dropped by a repair.
const KNOWN_KEYS: &[&str] = &[
	"type",
	"keyslots",
	"tpm2-blob",
	"tpm2-pcrs",
	"tpm2-pcr-bank",
	"tpm2-primary-alg",
	"tpm2-policy-hash",
	"tpm2-pin",
	"tpm2_pcrlock",
	"tpm2_pubkey_pcrs",
	"tpm2_pubkey",
	"tpm2_salt",
	"tpm2_srk",
	"tpm2_pcrlock_nv",
];

/// Every `systemd-tpm2` token in `device`'s header, in header order.
pub fn read(device: &str) -> Result<Vec<Tpm2Token>, String> {
	let mut cmd = Command::new(BINARY);
	cmd.arg("luksDump")
		.arg("--dump-json-metadata")
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let out = child::run(&mut cmd, TIMEOUT)?;

	if !out.status.success() {
		let stderr = String::from_utf8_lossy(&out.stderr);
		return Err(format!(
			"{BINARY} luksDump {device} exited with {} ({})",
			out.status,
			stderr.trim()
		));
	}

	parse(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse(json: &str) -> Result<Vec<Tpm2Token>, String> {
	let root: Value = serde_json::from_str(json).map_err(|e| format!("not valid JSON: {e}"))?;

	// A header with no tokens at all omits the object entirely.
	let Some(tokens) = root.get("tokens").and_then(Value::as_object) else {
		return Ok(Vec::new());
	};

	let mut out = Vec::new();
	for (index, value) in tokens {
		if value.get("type").and_then(Value::as_str) != Some("systemd-tpm2") {
			continue;
		}
		let index: u32 = index
			.parse()
			.map_err(|_| format!("token key {index:?} is not a number"))?;
		out.push(token(index, value)?);
	}

	out.sort_by_key(|t| t.index);
	Ok(out)
}

fn token(index: u32, value: &Value) -> Result<Tpm2Token, String> {
	let pcrs = match value.get("tpm2-pcrs") {
		Some(v) => pcr_list(v)?,
		None => Vec::new(),
	};

	let bank = value
		.get("tpm2-pcr-bank")
		.and_then(Value::as_str)
		.map(str::to_string);

	let policy_hash = match value.get("tpm2-policy-hash") {
		Some(v) => single_shard(v, "tpm2-policy-hash")?,
		None => return Err(format!("token {index} has no \"tpm2-policy-hash\"")),
	};

	// systemd writes tpm2-pin only when true, and a salt only exists alongside
	// a PIN, so either one is enough.
	let pin = value
		.get("tpm2-pin")
		.and_then(Value::as_bool)
		.unwrap_or(false)
		|| value.get("tpm2_salt").is_some();

	Ok(Tpm2Token {
		index,
		pcrs,
		bank,
		policy_hash,
		pin,
		advanced: advanced(value),
	})
}

/// Signed and pcrlock policies change how the policy is built in ways a PCR
/// trial session cannot reproduce: one authorizes over a public key, the other
/// against an NV index. Recognising them, and anything unrecognised, is how we
/// avoid mistaking "we cannot compute this" for "the PCRs drifted".
fn advanced(value: &Value) -> Option<String> {
	let obj = value.as_object()?;
	if let Some(key) = obj.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
		return Some(format!("a field this build does not recognise ({key:?})"));
	}
	if obj.contains_key("tpm2_pubkey") || obj.contains_key("tpm2_pubkey_pcrs") {
		return Some("a signed PCR policy".to_string());
	}
	if obj.contains_key("tpm2_pcrlock") || obj.contains_key("tpm2_pcrlock_nv") {
		return Some("a pcrlock policy".to_string());
	}
	None
}

fn pcr_list(value: &Value) -> Result<Vec<u8>, String> {
	let list = value.as_array().ok_or("\"tpm2-pcrs\" is not an array")?;
	let mut out = Vec::with_capacity(list.len());
	for item in list {
		let n = item
			.as_u64()
			.ok_or("\"tpm2-pcrs\" contains a non-integer")?;
		if n > 23 {
			return Err(format!(
				"\"tpm2-pcrs\" contains {n}, which is not a PCR index"
			));
		}
		out.push(n as u8);
	}
	out.sort_unstable();
	out.dedup();
	Ok(out)
}

/// A field systemd writes either as a hex string or as an array of them.
///
/// The array form is key sharding, where several policies each protect part of
/// the key. We have no business rewriting one of several shards, so more than
/// one is reported as an error rather than silently taking the first.
fn single_shard(value: &Value, field: &str) -> Result<Vec<u8>, String> {
	let text = match value {
		Value::String(s) => s.as_str(),
		Value::Array(items) => match items.len() {
			1 => items[0]
				.as_str()
				.ok_or_else(|| format!("{field:?} contains a non-string"))?,
			n => return Err(format!("{field:?} has {n} shards; only one is supported")),
		},
		_ => return Err(format!("{field:?} is neither a string nor an array")),
	};
	unhex(text).ok_or_else(|| format!("{field:?} is not valid hex"))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
	if !text.len().is_multiple_of(2) {
		return None;
	}
	let bytes = text.as_bytes();
	let mut out = Vec::with_capacity(text.len() / 2);
	for pair in bytes.chunks(2) {
		let hi = (pair[0] as char).to_digit(16)?;
		let lo = (pair[1] as char).to_digit(16)?;
		out.push((hi * 16 + lo) as u8);
	}
	Some(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	const ENROLLED: &str = r#"{
	  "keyslots": {"0": {"type": "luks2"}},
	  "tokens": {
	    "0": {
	      "type": "systemd-tpm2",
	      "keyslots": ["1"],
	      "tpm2-blob": "Zm9v",
	      "tpm2-pcrs": [7, 11],
	      "tpm2-pcr-bank": "sha256",
	      "tpm2-primary-alg": "ecc",
	      "tpm2-policy-hash": "abcdef0123456789"
	    }
	  }
	}"#;

	fn only(json: &str) -> Tpm2Token {
		let tokens = parse(json).expect("parse returned Err, expected Ok");
		assert_eq!(
			tokens.len(),
			1,
			"parse(<one systemd-tpm2 token>) returned {} tokens, expected 1",
			tokens.len()
		);
		tokens.into_iter().next().unwrap()
	}

	#[test]
	fn reads_an_ordinary_enrollment() {
		let expected = Tpm2Token {
			index: 0,
			pcrs: vec![7, 11],
			bank: Some("sha256".to_string()),
			policy_hash: vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
			pin: false,
			advanced: None,
		};
		let actual = only(ENROLLED);
		assert_eq!(
			actual, expected,
			"parse(ENROLLED) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn a_header_with_no_tokens_is_not_an_error() {
		// The "never enrolled" case, which section 4.1 treats as distinct from
		// a drifted one. It must not look like a parse failure.
		let actual = parse(r#"{"keyslots":{}}"#);
		assert_eq!(
			actual,
			Ok(vec![]),
			"parse(<header with no tokens>) returned {actual:?}, expected Ok([])"
		);
	}

	#[test]
	fn ignores_tokens_of_other_types() {
		let json = r#"{"tokens":{"0":{"type":"systemd-fido2","fido2-credential":"x"}}}"#;
		let actual = parse(json);
		assert_eq!(
			actual,
			Ok(vec![]),
			"parse(<a fido2 token>) returned {actual:?}, expected Ok([])"
		);
	}

	#[test]
	fn notices_a_pin() {
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2-pin": true"#,
		);
		let actual = only(&json).pin;
		assert!(
			actual,
			"parse(<token with tpm2-pin>) returned pin {actual}, expected true"
		);
	}

	#[test]
	fn notices_a_signed_policy() {
		// Section 6.2 calls signed policies the right answer for UKI systems.
		// They are also one we must not silently replace with a literal-PCR
		// enrollment, so they have to be recognised rather than treated as
		// ordinary.
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_pubkey": "Zm9v", "tpm2_pubkey_pcrs": [11]"#,
		);
		let actual = only(&json).advanced;
		let actual = actual.as_deref();
		assert_eq!(
			actual,
			Some("a signed PCR policy"),
			"parse(<token with tpm2_pubkey>) returned advanced {actual:?}, expected Some(\"a signed PCR policy\")"
		);
	}

	#[test]
	fn notices_pcrlock() {
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_pcrlock": true"#,
		);
		let actual = only(&json).advanced;
		let actual = actual.as_deref();
		assert_eq!(
			actual,
			Some("a pcrlock policy"),
			"parse(<token with tpm2_pcrlock>) returned advanced {actual:?}, expected Some(\"a pcrlock policy\")"
		);
	}

	#[test]
	fn a_salt_implies_a_pin() {
		// systemd only writes tpm2_salt for a PIN enrollment, so a header that
		// has lost tpm2-pin but kept the salt still needs one.
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_salt": "Zm9v""#,
		);
		let actual = only(&json).pin;
		assert!(
			actual,
			"parse(<token with tpm2_salt>) returned pin {actual}, expected true"
		);
	}

	#[test]
	fn notices_a_pcrlock_nv_index() {
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_pcrlock_nv": "Zm9v""#,
		);
		let actual = only(&json).advanced;
		assert_eq!(
			actual.as_deref(),
			Some("a pcrlock policy"),
			"parse(<token with tpm2_pcrlock_nv>) returned advanced {actual:?}, expected Some(\"a pcrlock policy\")"
		);
	}

	#[test]
	fn an_unrecognised_field_is_advanced() {
		// A policy element from a newer systemd would otherwise read as drift
		// and be dropped by the repair.
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_future_policy": "x""#,
		);
		let actual = only(&json).advanced;
		assert!(
			actual.as_deref().is_some_and(|a| a.contains("tpm2_future_policy")),
			"parse(<token with tpm2_future_policy>) returned advanced {actual:?}, expected Some naming the field"
		);
	}

	#[test]
	fn every_field_systemd_writes_for_a_plain_policy_is_ordinary() {
		let json = ENROLLED.replace(
			r#""tpm2-primary-alg": "ecc""#,
			r#""tpm2-primary-alg": "ecc", "tpm2_srk": "Zm9v""#,
		);
		let actual = only(&json).advanced;
		assert_eq!(
			actual, None,
			"parse(<token with tpm2_srk>) returned advanced {actual:?}, expected None"
		);
	}

	#[test]
	fn accepts_a_single_shard_array() {
		// Newer systemd writes these fields as arrays even when there is only
		// one shard.
		let json = ENROLLED.replace(
			r#""tpm2-policy-hash": "abcdef0123456789""#,
			r#""tpm2-policy-hash": ["abcdef0123456789"]"#,
		);
		let actual = only(&json).policy_hash;
		let expected = vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89];
		assert_eq!(
			actual, expected,
			"parse(<single-element shard array>) returned policy_hash {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn refuses_a_multi_shard_policy() {
		// Sharding means several policies each protect part of the key.
		// Rewriting one of them is not something this tool understands, and
		// taking the first would compare against a digest that only covers part
		// of the enrollment.
		let json = ENROLLED.replace(
			r#""tpm2-policy-hash": "abcdef0123456789""#,
			r#""tpm2-policy-hash": ["abcdef01", "23456789"]"#,
		);
		let actual = parse(&json);
		assert!(
			actual.is_err(),
			"parse(<two-shard policy hash>) returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn rejects_a_token_without_a_policy_hash() {
		let json = r#"{"tokens":{"0":{"type":"systemd-tpm2","tpm2-pcrs":[7]}}}"#;
		let actual = parse(json);
		assert!(
			actual.is_err(),
			"parse(<token with no policy hash>) returned {actual:?}, expected Err"
		);
	}

	#[test]
	fn decodes_hex() {
		let cases = [
			("00ff", Some(vec![0x00, 0xff])),
			("AbCd", Some(vec![0xab, 0xcd])),
			("abc", None),
			("zz", None),
		];
		for (input, expected) in cases {
			let actual = unhex(input);
			assert_eq!(
				actual, expected,
				"unhex({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}
}
