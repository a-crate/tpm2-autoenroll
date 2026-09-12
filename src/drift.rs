//! Has the boot state actually moved away from what the volume was sealed
//! against?
//!
//! This is the last and most interesting of DESIGN.md section 4.1's preflight
//! checks. Being asked for a passphrase tells us the TPM2 unlock failed; it does
//! not tell us *why*. Re-enrolling fixes a policy whose PCRs have drifted and
//! fixes nothing else, so without this check a volume failing for an unrelated
//! reason would have its header rewritten on every single boot.
//!
//! The comparison is between two digests:
//!
//!   * what the header says the policy is -- `tpm2-policy-hash` in the
//!     `systemd-tpm2` token, put there when the volume was enrolled.
//!   * what a policy built from the PCRs *as they are right now* would come out
//!     as.
//!
//! The second one is computed by the TPM itself, in a trial session
//! (`tpm2::Tpm::pcr_policy_digest`). The alternative was to reimplement
//! `tpm2_calculate_sealing_policy()` in software, which means owning a copy of
//! systemd's hashing and keeping it correct across systemd releases. Asking the
//! hardware that will later be asked to unseal is both less code and a better
//! authority.

use crate::token::Tpm2Token;
use crate::tpm2::{Bank, Tpm};

/// What we were able to conclude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
	/// The current PCRs no longer satisfy the sealed policy. Re-enrolling is
	/// exactly the repair for this.
	Drifted { enrolled: Vec<u8>, current: Vec<u8> },
	/// The current PCRs still satisfy it, so the unlock failed for some other
	/// reason and rewriting the header would achieve nothing.
	Matches,
	/// We could not work it out. Never treated as drift: guessing here means
	/// wiping a working enrollment.
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
			Drift::Matches => {
				"the current PCRs still satisfy the enrolled policy".to_string()
			}
			Drift::Unknown(why) => format!("cannot tell whether the PCRs drifted: {why}"),
		}
	}
}

/// Compare `token`'s sealed policy against the machine's present state.
pub fn check(tpm: &mut Tpm, token: &Tpm2Token) -> Drift {
	if let Some(kind) = token.advanced {
		// A signed or pcrlock policy is not a literal-PCR policy, so a PCR
		// trial session computes a digest that was never meant to match.
		// Section 6.2 puts these outside this tool's remit anyway.
		return Drift::Unknown(format!("the enrollment uses {kind}"));
	}

	if token.pcrs.is_empty() {
		// Sealed against nothing, so nothing can drift. Whatever went wrong,
		// re-enrolling against no PCRs would reproduce it exactly.
		return Drift::Matches;
	}

	let bank = match &token.bank {
		Some(name) => match Bank::from_name(name) {
			Some(b) => b,
			None => return Drift::Unknown(format!("unrecognised PCR bank {name:?}")),
		},
		// systemd omits the field only for enrollments old enough to predate
		// bank selection, which assumed sha256.
		None => Bank::SHA256,
	};

	let current = match tpm.pcr_policy_digest(bank, &token.pcrs, token.pin) {
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

/// Enough of a digest to tell two apart in a log line, which is all section 6's
/// audit requirement needs from it.
fn short(digest: &[u8]) -> String {
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
		// Reported without touching the TPM at all, which is what lets this be
		// a unit test: an enrollment over no PCRs unlocks unconditionally, so
		// its failure is always something else.
		let mut t = token();
		t.pcrs = vec![];
		let actual = check_without_tpm(&t);
		assert_eq!(
			actual,
			Some(Drift::Matches),
			"check(<token sealed against no PCRs>) returned {actual:?}, expected Some(Matches)"
		);
	}

	#[test]
	fn an_advanced_policy_is_unknown_not_drifted() {
		// The important half of this: Unknown must not be actionable. Reading a
		// signed-policy enrollment as drift would wipe a working token that
		// this tool cannot recreate.
		let mut t = token();
		t.advanced = Some("a signed PCR policy");
		let actual = check_without_tpm(&t);
		assert!(
			matches!(actual, Some(Drift::Unknown(_))),
			"check(<signed policy token>) returned {actual:?}, expected Some(Unknown(_))"
		);
	}

	#[test]
	fn an_unknown_bank_is_unknown() {
		let mut t = token();
		t.bank = Some("sha3-256".to_string());
		let actual = check_without_tpm(&t);
		assert!(
			matches!(actual, Some(Drift::Unknown(_))),
			"check(<token in an unrecognised bank>) returned {actual:?}, expected Some(Unknown(_))"
		);
	}

	/// The part of `check` that runs before the TPM is consulted.
	///
	/// `None` means the real function would have gone on to ask the hardware,
	/// which the VM test covers instead.
	fn check_without_tpm(token: &Tpm2Token) -> Option<Drift> {
		if let Some(kind) = token.advanced {
			return Some(Drift::Unknown(format!("the enrollment uses {kind}")));
		}
		if token.pcrs.is_empty() {
			return Some(Drift::Matches);
		}
		match &token.bank {
			Some(name) if Bank::from_name(name).is_none() => {
				Some(Drift::Unknown(format!("unrecognised PCR bank {name:?}")))
			}
			_ => None,
		}
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
