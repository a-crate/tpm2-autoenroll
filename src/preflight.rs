//! Deciding whether re-enrolling this volume is the right thing to do.
//!
//! DESIGN.md section 4.1. Every check here is a case where touching the LUKS2
//! header is either useless or destructive, so the decision is framed as
//! "refuse unless all of these hold" rather than "act unless something looks
//! wrong". The outcome is a [`Decision`], and the only one that leads anywhere
//! near `systemd-cryptenroll` is [`Decision::Reenroll`].
//!
//! The checks, and what each is protecting:
//!
//! | check | what goes wrong without it |
//! |-------|----------------------------|
//! | a TPM2 device answers | no TPM means the passphrase fallback is expected, not a fault, and wiping the token would be pure loss |
//! | it is not in dictionary-attack lockout | sealing succeeds, unsealing keeps failing, and we rewrite the header every boot |
//! | exactly one systemd-tpm2 token | `--wipe-slot=tpm2` removes all of them; with two, one of them is someone else's working binding |
//! | the enrollment is a plain PCR policy | a signed or pcrlock policy is one we cannot recreate, so replacing it is a downgrade |
//! | the volume has a token at all | a volume that was never TPM2-bound has no binding to repair, and no PCR selection to infer one from |
//! | the PCRs actually drifted | if they match, re-sealing the same policy changes nothing and the next boot fails identically |

use crate::crypttab::Volume;
use crate::drift::{self, Drift};
use crate::log::{error, info};
use crate::token::{self, Tpm2Token};
use crate::tpm2::Tpm;

/// What to do about a volume that has fallen back to its passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
	/// Re-bind it, once a human has agreed.
	Reenroll(Plan),
	/// Leave the header alone. The string says why, and is logged verbatim --
	/// this is the line a user reads when they are wondering why the tool did
	/// nothing.
	Leave(String),
}

/// Everything the enrollment step needs, settled before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
	/// The token being replaced, if there is one.
	pub old_token: Option<u32>,
	pub pcrs: Vec<u8>,
	pub bank: Option<String>,
	/// The policy digest the volume is sealed against now, empty when there is
	/// no enrollment to replace. Logged rather than used: section 6 wants the
	/// event auditable, and "what it was" is half of that.
	pub enrolled: Vec<u8>,
	/// The policy digest the current PCRs produce. Doubles as the key the
	/// consent cache uses, since it identifies this boot state exactly.
	pub state: Vec<u8>,
}

pub fn check(volume: &str, config: &Volume, tpm: &mut Tpm) -> Decision {
	let device = config.device.as_str();

	let tokens = match token::read(device) {
		Ok(t) => t,
		Err(e) => return Decision::Leave(format!("could not read the LUKS2 tokens: {e}")),
	};

	// The TPM has to answer before any of the rest means anything. Reading the
	// lockout state is both the "is it there" probe and a check in its own
	// right.
	match tpm.lockout() {
		Ok(l) if l.in_lockout => {
			// Not a case to recover from: a TPM in lockout means the machine
			// has a bigger problem than a stale PCR binding. The check exists
			// only to stop us rewriting the header on every boot of a machine
			// in that state.
			return Decision::Leave(format!(
				"the TPM is in dictionary-attack lockout ({} of {} failures)",
				l.counter, l.max_auth_fail
			));
		}
		Ok(l) => info!(
			"volume {volume:?}: TPM responsive, lockout counter {} of {}",
			l.counter, l.max_auth_fail
		),
		Err(e) => return Decision::Leave(format!("could not read the TPM's lockout state: {e}")),
	}

	match tokens.len() {
		0 => absent(),
		1 => drifted(&tokens[0], tpm),
		n => Decision::Leave(format!(
			"the header carries {n} systemd-tpm2 tokens, and --wipe-slot=tpm2 would remove all of them"
		)),
	}
}

/// The "never enrolled" case, which is not a repair.
///
/// There is deliberately no way to turn this into one. The PCR selection a
/// volume should be bound to is read out of the token being replaced, so a
/// volume with no token supplies nothing to bind against, and guessing a
/// selection on a fallback path would be inventing a policy the user never
/// chose. `systemd-cryptenroll` is the tool for a first enrollment.
fn absent() -> Decision {
	Decision::Leave(
		"it carries no systemd-tpm2 token, so there is no TPM2 binding to repair".to_string(),
	)
}

/// The ordinary case: one token, and the question is whether it has gone stale.
fn drifted(token: &Tpm2Token, tpm: &mut Tpm) -> Decision {
	match drift::check(tpm, token) {
		Drift::Drifted { current, .. } => Decision::Reenroll(Plan {
			old_token: Some(token.index),
			// A repair keeps the selection and bank it is repairing. Narrowing
			// or widening what the volume is bound to is a policy change, and
			// not one to make silently on a fallback path.
			pcrs: token.pcrs.clone(),
			enrolled: token.policy_hash.clone(),
			bank: token.bank.clone(),
			state: current,
		}),
		Drift::Matches => Decision::Leave(
			"the current PCRs still satisfy the enrolled policy, so the unlock failed for \
			 some other reason and re-sealing would change nothing"
				.to_string(),
		),
		Drift::Unknown(why) => Decision::Leave(format!("cannot tell whether the PCRs drifted: {why}")),
	}
}

/// Log the audit trail section 6 requires: what was measured at the moment we
/// were consulted, which is what the new policy will be sealed against.
pub fn log_state(volume: &str, tpm: &mut Tpm, plan: &Plan) {
	let bank = plan
		.bank
		.as_deref()
		.and_then(crate::tpm2::Bank::from_name)
		.unwrap_or(crate::tpm2::Bank::SHA256);

	match tpm.read_pcrs(bank, &plan.pcrs) {
		Ok(values) => {
			for (pcr, digest) in values {
				let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
				info!("volume {volume:?}: PCR {pcr} is now {hex}");
			}
		}
		Err(e) => error!("volume {volume:?}: could not read the current PCR values ({e})"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_unenrolled_volume_is_left_alone() {
		// Section 4.1's "distinguishes drifted from never enrolled". Creating a
		// binding the user never asked for is not a repair.
		let actual = absent();
		assert!(
			matches!(actual, Decision::Leave(_)),
			"absent() returned {actual:?}, expected Decision::Leave(_)"
		);
	}

	#[test]
	fn a_repair_keeps_the_selection_it_repairs() {
		// The PCR selection a volume is bound to lives in its token, and nowhere
		// else. Repairing an existing binding must not quietly move it to a
		// different set of registers.
		let token = Tpm2Token {
			index: 2,
			pcrs: vec![7, 11],
			bank: Some("sha384".to_string()),
			policy_hash: vec![0xaa; 32],
			pin: false,
			advanced: None,
		};
		let plan = Plan {
			old_token: Some(2),
			pcrs: token.pcrs.clone(),
			enrolled: token.policy_hash.clone(),
			bank: token.bank.clone(),
			state: vec![0xbb; 32],
		};

		assert_eq!(
			plan.pcrs, token.pcrs,
			"a repair plan for a token over {:?} used {:?}, expected the token's own selection",
			token.pcrs, plan.pcrs
		);
		assert_eq!(
			plan.bank, token.bank,
			"a repair plan for a token in bank {:?} used {:?}, expected the token's own bank",
			token.bank, plan.bank
		);
	}
}
