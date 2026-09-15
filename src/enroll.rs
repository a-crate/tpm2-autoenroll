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
use std::time::Duration;

use crate::child;
use crate::memfd::SecretFile;
use crate::secret::Secret;
use crate::token::Tpm2Token;
use crate::tpm2::Bank;

const BINARY: &str = "systemd-cryptenroll";

/// A KDF pass to unlock, another to add the new slot, and sealing, which on a
/// slow TPM takes seconds of its own.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(120);

/// One unseal and one KDF pass.
const UNSEAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Re-bind `device` to the PCR state it is in right now. `pcrs` and `bank` come
/// from the config.
pub fn run(
	device: &str,
	tpm2_device: &str,
	pcrs: &[u8],
	bank: Bank,
	secret: &Secret,
) -> Result<(), String> {
	// Config validation already refuses this. Checked again because the result
	// would be a token that unseals unconditionally.
	if pcrs.is_empty() {
		return Err("refusing to enroll against an empty PCR selection".to_string());
	}

	// Never argv, never the environment. $PASSWORD does work
	// (src/cryptenroll/cryptenroll-password.c:30) but is undocumented and leaves
	// the secret readable in /proc for the process's lifetime.
	let key = SecretFile::new(secret)?;

	let mut cmd = Command::new(BINARY);
	cmd.arg(format!("--unlock-key-file={}", key.path()))
		.arg("--wipe-slot=tpm2")
		.arg(format!("--tpm2-device={tpm2_device}"))
		.arg(format!("--tpm2-pcrs={}", pcr_spec(pcrs, bank.name())))
		// systemd-cryptenroll adds a signed policy on its own whenever it finds
		// tpm2-pcr-public-key.pem, and a pcrlock policy whenever it finds
		// pcrlock.json; the empty values switch both searches off. The preflight
		// already refuses when either file exists, so these make sure the policy
		// we write is exactly the one the preflight checked.
		.arg("--tpm2-public-key=")
		.arg("--tpm2-pcrlock=")
		.arg("--tpm2-with-pin=no")
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	key.attach(&mut cmd);

	let out = child::run(&mut cmd, ENROLL_TIMEOUT, 0)?;

	if !out.status.success() {
		let stderr = String::from_utf8_lossy(&out.stderr);
		return Err(format!(
			"{BINARY} exited with {} ({})",
			out.status,
			stderr.trim()
		));
	}

	Ok(())
}

/// The `--tpm2-pcrs=` argument: `PCR:BANK[+PCR:BANK...]`.
///
/// The bank is always pinned, so the enrollment uses the configured one rather
/// than whatever systemd would pick by default today.
fn pcr_spec(pcrs: &[u8], bank: &str) -> String {
	pcrs.iter()
		.map(|pcr| format!("{pcr}:{bank}"))
		.collect::<Vec<_>>()
		.join("+")
}

/// Does the freshly written token actually unlock the volume?
///
/// `--token-only` refuses to fall back to a passphrase, so success here is a
/// TPM2 unseal and nothing else. Without
/// `libcryptsetup-token-systemd-tpm2.so` this route is unavailable and the
/// caller falls back to comparing policy digests.
pub fn test_unseal(device: &str, token_index: u32) -> Result<(), String> {
	let mut cmd = Command::new("cryptsetup");
	cmd.arg("open")
		.arg("--test-passphrase")
		.arg("--batch-mode")
		.arg("--token-only")
		.arg(format!("--token-id={token_index}"))
		.arg("--disable-keyring")
		.arg(device)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	let out = child::run(&mut cmd, UNSEAL_TIMEOUT, 0)?;

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
		let cases: [(&[u8], &str, &str); 3] = [
			(&[7], "sha256", "7:sha256"),
			(&[7, 11], "sha256", "7:sha256+11:sha256"),
			(&[16], "sha384", "16:sha384"),
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
	fn refuses_an_empty_selection() {
		// Checked before anything is spawned, so no device or TPM is needed.
		let secret = Secret::new(b"unused".to_vec());
		let actual = run("/nonexistent", "auto", &[], Bank::SHA256, &secret);
		assert!(
			actual.is_err(),
			"run(\"/nonexistent\", \"auto\", [], SHA256, _) returned {actual:?}, expected Err"
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
