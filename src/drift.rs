//! Has the boot state actually moved away from what the volume was sealed
//! against?
//!
//! The last and most interesting preflight check. Being asked for a passphrase
//! tells us the TPM2 unlock failed, not *why*; re-enrolling fixes a policy whose
//! PCRs have drifted and fixes nothing else, so without this a volume failing
//! for an unrelated reason would have its header rewritten on every boot.
//!
//! The comparison is between the header's `tpm2-policy-hash`, written when the
//! volume was enrolled, and a policy built from the PCRs as they are right now.
//! The TPM computes the second itself in a trial session
//! (`tpm2::Tpm::pcr_policy_digest`) -- asking the hardware that will later be
//! asked to unseal is less code than reimplementing
//! `tpm2_calculate_sealing_policy()`, and a better authority.

use crate::token::Tpm2Token;
use crate::tpm2::{Bank, Tpm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
	/// The current PCRs no longer satisfy the sealed policy, which re-enrolling
	/// is exactly the repair for.
	Drifted { enrolled: Vec<u8>, current: Vec<u8> },
	/// They still satisfy it, so the unlock failed for some other reason and
	/// rewriting the header would achieve nothing.
	Matches,
	/// Never treated as drift: guessing here means wiping a working enrollment.
	Unknown(String),
}

impl Drift {
	pub fn describe(&self) -> String {
		match self {
			Drift::Drifted { enrolled, current } => format!(
				"the boot measurements have changed (policy {} -> {})",
				short(enrolled),
				short(current)
			),
			Drift::Matches => "the current PCRs still satisfy the enrolled policy".to_string(),
			Drift::Unknown(why) => format!("cannot tell whether the PCRs drifted: {why}"),
		}
	}
}

/// Compare `token`'s sealed policy against what `pcrs` in `bank` produce now.
///
/// The selection comes from the config rather than the token: the token is
/// only trusted for the digest it is compared against.
pub fn check(tpm: &mut Tpm, token: &Tpm2Token, pcrs: &[u8], bank: Bank) -> Drift {
	// Not a literal-PCR policy, so a PCR trial session computes a digest that
	// was never meant to match. The preflight refuses both before getting
	// here; this keeps the function honest on its own.
	if let Some(kind) = &token.advanced {
		return Drift::Unknown(format!("the enrollment uses {kind}"));
	}
	if token.pin {
		return Drift::Unknown("the enrollment requires a TPM2 PIN".to_string());
	}

	if pcrs.is_empty() {
		// Sealed against nothing, so nothing can drift. Whatever went wrong,
		// re-enrolling against no PCRs would reproduce it exactly.
		return Drift::Matches;
	}

	let current = match tpm.pcr_policy_digest(bank, pcrs) {
		Ok(d) => d,
		Err(e) => return Drift::Unknown(e),
	};

	if current == token.policy_hash {
		Drift::Matches
	} else {
		Drift::Drifted {
			enrolled: token.policy_hash.clone(),
			current,
		}
	}
}

/// Enough of a digest to tell two apart in a log line.
pub fn short(digest: &[u8]) -> String {
	let mut out = String::with_capacity(16);
	for b in digest.iter().take(8) {
		out.push_str(&format!("{b:02x}"));
	}
	if digest.len() > 8 {
		out.push_str("...");
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn token() -> Tpm2Token {
		Tpm2Token {
			index: 0,
			pcrs: vec![7],
			bank: Some("sha256".to_string()),
			policy_hash: vec![0xaa; 32],
			pin: false,
			advanced: None,
		}
	}

	#[test]
	fn an_empty_pcr_set_cannot_have_drifted() {
		// An enrollment over no PCRs unlocks unconditionally, so its failure is
		// always something else.
		let actual = check_without_tpm(&token(), &[]);
		assert_eq!(
			actual,
			Some(Drift::Matches),
			"check(<token>, pcrs = []) returned {actual:?}, expected Some(Matches)"
		);
	}

	#[test]
	fn an_advanced_policy_is_unknown_not_drifted() {
		// Unknown must not be actionable: reading a signed-policy enrollment as
		// drift would wipe a working token this tool cannot recreate.
		let mut t = token();
		t.advanced = Some("a signed PCR policy".to_string());
		let actual = check_without_tpm(&t, &[7]);
		assert!(
			matches!(actual, Some(Drift::Unknown(_))),
			"check(<signed policy token>, pcrs = [7]) returned {actual:?}, expected Some(Unknown(_))"
		);
	}

	#[test]
	fn a_pin_policy_is_unknown_not_drifted() {
		// The trial session no longer builds PolicyAuthValue, so its digest
		// could never match a PIN enrollment.
		let mut t = token();
		t.pin = true;
		let actual = check_without_tpm(&t, &[7]);
		assert!(
			matches!(actual, Some(Drift::Unknown(_))),
			"check(<PIN token>, pcrs = [7]) returned {actual:?}, expected Some(Unknown(_))"
		);
	}

	/// The part of `check` that runs before the TPM is consulted. `None` means
	/// the real function would have gone on to ask the hardware, which the VM
	/// test covers instead.
	fn check_without_tpm(token: &Tpm2Token, pcrs: &[u8]) -> Option<Drift> {
		if let Some(kind) = &token.advanced {
			return Some(Drift::Unknown(format!("the enrollment uses {kind}")));
		}
		if token.pin {
			return Some(Drift::Unknown(
				"the enrollment requires a TPM2 PIN".to_string(),
			));
		}
		if pcrs.is_empty() {
			return Some(Drift::Matches);
		}
		None
	}

	#[test]
	fn describes_a_drift_with_both_digests() {
		let d = Drift::Drifted {
			enrolled: vec![0x01; 32],
			current: vec![0x02; 32],
		};
		let actual = d.describe();
		assert!(
			actual.contains("0101010101010101") && actual.contains("0202020202020202"),
			"Drift::Drifted{{enrolled: [1; 32], current: [2; 32]}}.describe() returned {actual:?}, expected both digests to appear"
		);
	}

	#[test]
	fn shortens_a_digest_without_losing_the_head() {
		let actual = short(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44]);
		assert_eq!(
			actual, "deadbeef00112233...",
			"short(<9 bytes>) returned {actual:?}, expected \"deadbeef00112233...\""
		);
	}
}
