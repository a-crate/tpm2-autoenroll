//! Running `systemd-cryptenroll`, and checking afterwards that it worked.
//!
//! A single invocation does both halves of the update at once. Combining
//! `--wipe-slot=` with an enrollment is the documented update idiom, and
//! systemd-cryptenroll(1) states that wiping happens *after* the new slot is
//! added, with the new slot always excluded. That gives the safety property this
//! design wants: an interrupted run leaves the old slot, the new slot, or both,
//! never neither. The passphrase slot is untouched either way, which is what
//! makes every failure here recoverable.

use std::process::{Command, Stdio};

use crate::memfd::SecretFile;
use crate::secret::Secret;
use crate::token::Tpm2Token;

const BINARY: &str = "systemd-cryptenroll";

/// Re-bind `device` to the PCR state it is in right now. `pcrs` and `bank` are
/// already decided by the preflight.
pub fn run(
	device: &str,
	tpm2_device: &str,
	pcrs: &[u8],
	bank: Option<&str>,
	secret: &Secret,
) -> Result<(), String> {
	// Never argv, never the environment. $PASSWORD does work
	// (src/cryptenroll/cryptenroll-password.c:30) but is undocumented and leaves
	// the secret readable in /proc for the process's lifetime.
	let key = SecretFile::new(secret)?;

	let mut cmd = Command::new(BINARY);
	cmd.arg(format!("--unlock-key-file={}", key.path()))
		.arg("--wipe-slot=tpm2")
		.arg(format!("--tpm2-device={tpm2_device}"))
		.arg(format!("--tpm2-pcrs={}", pcr_spec(pcrs, bank)))
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	key.attach(&mut cmd);

	let out = cmd
		.output()
		.map_err(|e| format!("could not run {BINARY}: {e}"))?;

	if !out.status.success() {
		let stderr = String::from_utf8_lossy(&out.stderr);
		return Err(format!("{BINARY} exited with {} ({})", out.status, stderr.trim()));
	}

	Ok(())
}

/// The `--tpm2-pcrs=` argument: `PCR[:BANK][+PCR[:BANK]...]`.
///
/// The bank is pinned when the old token named one, so a repair reproduces the
/// enrollment it replaces rather than moving it to whatever systemd would pick
/// by default today.
fn pcr_spec(pcrs: &[u8], bank: Option<&str>) -> String {
	let mut parts = Vec::with_capacity(pcrs.len());
	for pcr in pcrs {
		match bank {
			Some(b) => parts.push(format!("{pcr}:{b}")),
			None => parts.push(pcr.to_string()),
		}
	}
	parts.join("+")
}

/// Does the freshly written token actually unlock the volume?
///
/// `--token-only` refuses to fall back to a passphrase, so success here is a
/// TPM2 unseal and nothing else. Without
/// `libcryptsetup-token-systemd-tpm2.so` this route is unavailable and the
/// caller falls back to comparing policy digests.
pub fn test_unseal(device: &str, token_index: u32) -> Result<(), String> {
	let out = Command::new("cryptsetup")
		.arg("open")
		.arg("--test-passphrase")
		.arg("--batch-mode")
		.arg("--token-only")
		.arg(format!("--token-id={token_index}"))
		.arg("--disable-keyring")
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped())
		.output()
		.map_err(|e| format!("could not run cryptsetup: {e}"))?;

	if out.status.success() {
		return Ok(());
	}

	let stderr = String::from_utf8_lossy(&out.stderr);
	Err(format!(
		"cryptsetup exited with {} ({})",
		out.status,
		stderr.trim()
	))
}

pub fn find_new_token(tokens: &[Tpm2Token], old_index: Option<u32>) -> Option<&Tpm2Token> {
	// --wipe-slot removes the old token, so ordinarily exactly one remains and
	// it is the new one. Excluding the old index defends against the interrupted
	// run where both survive.
	let mut candidates = tokens.iter().filter(|t| Some(t.index) != old_index);
	let first = candidates.next()?;
	match candidates.next() {
		None => Some(first),
		// Not a state we created, so decline to guess which is ours.
		Some(_) => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn token(index: u32) -> Tpm2Token {
		Tpm2Token {
			index,
			pcrs: vec![7],
			bank: Some("sha256".to_string()),
			policy_hash: vec![0xaa; 32],
			pin: false,
			advanced: None,
		}
	}

	#[test]
	fn builds_the_pcr_spec_systemd_documents() {
		let cases: [(&[u8], Option<&str>, &str); 4] = [
			(&[7], Some("sha256"), "7:sha256"),
			(&[7, 11], Some("sha256"), "7:sha256+11:sha256"),
			(&[7, 11], None, "7+11"),
			(&[16], None, "16"),
		];
		for (pcrs, bank, expected) in cases {
			let actual = pcr_spec(pcrs, bank);
			assert_eq!(
				actual, expected,
				"pcr_spec({pcrs:?}, {bank:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn an_empty_selection_produces_an_empty_spec() {
		// The caller must never get here -- enrolling against no PCRs would
		// produce a token that unlocks unconditionally -- so this records the
		// shape rather than endorsing it.
		let actual = pcr_spec(&[], Some("sha256"));
		assert_eq!(
			actual, "",
			"pcr_spec([], Some(\"sha256\")) returned {actual:?}, expected \"\""
		);
	}

	#[test]
	fn finds_the_one_token_left_after_a_wipe() {
		let tokens = vec![token(3)];
		let actual = find_new_token(&tokens, Some(1)).map(|t| t.index);
		assert_eq!(
			actual,
			Some(3),
			"find_new_token([token 3], old = Some(1)) returned {actual:?}, expected Some(3)"
		);
	}

	#[test]
	fn ignores_a_surviving_old_token() {
		// The interrupted-run case systemd's wipe-after-enroll ordering can leave
		// behind: both slots present.
		let tokens = vec![token(1), token(3)];
		let actual = find_new_token(&tokens, Some(1)).map(|t| t.index);
		assert_eq!(
			actual,
			Some(3),
			"find_new_token([token 1, token 3], old = Some(1)) returned {actual:?}, expected Some(3)"
		);
	}

	#[test]
	fn refuses_to_guess_between_two_new_tokens() {
		let tokens = vec![token(2), token(3)];
		let actual = find_new_token(&tokens, Some(1)).map(|t| t.index);
		assert_eq!(
			actual, None,
			"find_new_token([token 2, token 3], old = Some(1)) returned {actual:?}, expected None: with two unfamiliar tokens we cannot tell which one we wrote"
		);
	}

	#[test]
	fn no_tokens_at_all_is_a_failure_to_report() {
		let actual = find_new_token(&[], Some(1)).map(|t| t.index);
		assert_eq!(
			actual, None,
			"find_new_token([], old = Some(1)) returned {actual:?}, expected None"
		);
	}
}
