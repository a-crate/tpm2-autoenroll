//! Deciding whether re-enrolling this volume is the right thing to do.
//!
//! Every check here is a case where touching the LUKS2 header is either useless
//! or destructive, so the decision is framed as "refuse unless all of these
//! hold" rather than "act unless something looks wrong".
//!
//! | check | what goes wrong without it |
//! |-------|----------------------------|
//! | a TPM2 device answers | wiping the token when there is no TPM is pure loss |
//! | it is not in dictionary-attack lockout | sealing succeeds, unsealing keeps failing, and we rewrite the header every boot |
//! | exactly one systemd-tpm2 token | `--wipe-slot=tpm2` removes all of them; with two, one is someone else's working binding |
//! | no PIN | a repair would silently drop it, making the volume TPM-only |
//! | the enrollment is a plain PCR policy | a signed or pcrlock policy is one we cannot recreate, so replacing it is a downgrade |
//! | the header's selection and bank match the config | the header is unauthenticated; a mismatch is a manual re-enrollment or tampering |
//! | no host public key or pcrlock.json | the machine uses a policy this tool does not produce, so a literal-PCR repair is the wrong one |
//! | the volume has a token at all | nothing to repair |
//! | the PCRs actually drifted | if they match, re-sealing changes nothing and the next boot fails identically |

use crate::config::{self, Volume};
use crate::device::Device;
use crate::drift::{self, Drift};
use crate::log::{error, info};
use crate::token::{self, Tpm2Token};
use crate::tpm2::Tpm;

/// What to do about a volume that has fallen back to its passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
	/// Re-bind it, once a human has agreed.
	Reenroll(Plan),
	/// The string is logged verbatim: it is the line a user reads when they are
	/// wondering why the tool did nothing.
	Leave(String),
}

/// Everything the enrollment step needs beyond the volume's own config, settled
/// before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
	pub old_token: Option<u32>,
	/// What the volume is sealed against now. Logged rather than used, so the
	/// event is auditable.
	pub enrolled: Vec<u8>,
	/// The policy digest the current PCRs produce. Doubles as the consent
	/// cache's key, since it identifies this boot state exactly.
	pub state: Vec<u8>,
}

pub fn check(volume: &str, config: &Volume, device: &Device, tpm: &mut Tpm) -> Decision {
	let tokens = match token::read(device) {
		Ok(t) => t,
		Err(e) => return Decision::Leave(format!("could not read the LUKS2 tokens: {e}")),
	};

	// The TPM has to answer before any of the rest means anything. Reading the
	// lockout state is both the "is it there" probe and a check in its own right.
	match tpm.lockout() {
		Ok(l) if l.in_lockout => {
			// Not a case to recover from: a machine in lockout has a bigger
			// problem than a stale PCR binding. This check only stops us
			// rewriting its header on every boot.
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
		1 => drifted(&tokens[0], config, tpm),
		n => Decision::Leave(format!(
			"the header carries {n} systemd-tpm2 tokens, and --wipe-slot=tpm2 would remove all of them"
		)),
	}
}

/// The "never enrolled" case, which is not a repair. `systemd-cryptenroll` is
/// the tool for a first enrollment.
fn absent() -> Decision {
	Decision::Leave(
		"it carries no systemd-tpm2 token, so there is no TPM2 binding to repair".to_string(),
	)
}

/// `systemd-cryptenroll`'s search path for the signed-policy public key.
const PUBLIC_KEY_PATHS: [&str; 4] = [
	"/etc/systemd/tpm2-pcr-public-key.pem",
	"/run/systemd/tpm2-pcr-public-key.pem",
	"/usr/local/lib/systemd/tpm2-pcr-public-key.pem",
	"/usr/lib/systemd/tpm2-pcr-public-key.pem",
];

/// `tpm2_pcrlock_search_file()`'s search path.
const PCRLOCK_PATHS: [&str; 2] = ["/run/systemd/pcrlock.json", "/var/lib/systemd/pcrlock.json"];

/// The ordinary case: one token, and the question is whether it has gone stale.
fn drifted(token: &Tpm2Token, config: &Volume, tpm: &mut Tpm) -> Decision {
	if let Some(why) = token_refusal(token) {
		return Decision::Leave(why);
	}
	if let Err(why) = same_selection(token, config) {
		return Decision::Leave(format!(
			"{why}; refusing: this is a manual re-enrollment or tampering"
		));
	}
	if let Some(why) = host_policy(|p| std::fs::symlink_metadata(p).is_ok()) {
		return Decision::Leave(why);
	}

	match drift::check(tpm, token, &config.pcrs, config.bank) {
		Drift::Drifted { current, .. } => Decision::Reenroll(Plan {
			old_token: Some(token.index),
			enrolled: token.policy_hash.clone(),
			state: current,
		}),
		Drift::Matches => Decision::Leave(
			"the current PCRs still satisfy the enrolled policy, so the unlock failed for \
			 some other reason and re-sealing would change nothing"
				.to_string(),
		),
		Drift::Unknown(why) => {
			Decision::Leave(format!("cannot tell whether the PCRs drifted: {why}"))
		}
	}
}

/// A policy element a literal-PCR repair would drop. Also used to check the
/// token a repair wrote.
pub fn token_refusal(token: &Tpm2Token) -> Option<String> {
	if token.pin {
		return Some(
			"the enrollment requires a TPM2 PIN, which a repair would silently drop".to_string(),
		);
	}
	token
		.advanced
		.as_ref()
		.map(|kind| format!("the enrollment uses {kind}, which this tool cannot recreate"))
}

/// Whether the machine is set up for a signed or pcrlock policy. Either means
/// the literal-PCR policy we would write is not the one the user wants, even
/// though `enroll::run` stops systemd-cryptenroll picking the files up.
fn host_policy(exists: impl Fn(&str) -> bool) -> Option<String> {
	PUBLIC_KEY_PATHS
		.iter()
		.chain(PCRLOCK_PATHS.iter())
		.find(|p| exists(p))
		.map(|p| format!("{p} exists, so this machine expects a policy this tool does not produce"))
}

/// Does the token's selection agree with the config?
///
/// The header is not a source of policy, but a disagreement is still worth
/// refusing over rather than silently overriding: either someone re-enrolled
/// by hand against a selection the config does not know about, or the header
/// has been rewritten offline to get the next repair sealed somewhere weaker.
pub fn same_selection(token: &Tpm2Token, config: &Volume) -> Result<(), String> {
	// systemd omits the bank only for enrollments old enough to predate bank
	// selection, which assumed sha256.
	let header_bank = token.bank.as_deref().unwrap_or("sha256");
	if token.pcrs == config.pcrs && header_bank == config.bank.name() {
		return Ok(());
	}

	let header_pcrs = if token.pcrs.is_empty() {
		"(none)".to_string()
	} else {
		config::pcr_list(&token.pcrs)
	};
	Err(format!(
		"the header's PCR selection {header_pcrs} ({header_bank}) differs from the configured {} ({})",
		config::pcr_list(&config.pcrs),
		config.bank.name()
	))
}

/// What was measured at the moment we were consulted, which is what the new
/// policy will be sealed against.
pub fn log_state(volume: &str, tpm: &mut Tpm, config: &Volume) {
	match tpm.read_pcrs(config.bank, &config.pcrs) {
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
	use crate::tpm2::Bank;

	fn config(pcrs: &[u8], bank: &str) -> Volume {
		Volume {
			name: "root".to_string(),
			device: "/dev/vda2".to_string(),
			tpm2_device: "auto".to_string(),
			pcrs: pcrs.to_vec(),
			bank: Bank::from_name(bank).unwrap(),
		}
	}

	fn token(pcrs: &[u8], bank: Option<&str>) -> Tpm2Token {
		Tpm2Token {
			index: 0,
			pcrs: pcrs.to_vec(),
			bank: bank.map(str::to_string),
			policy_hash: vec![0xaa; 32],
			pin: false,
			advanced: None,
		}
	}

	#[test]
	fn an_unenrolled_volume_is_left_alone() {
		// Creating a binding the user never asked for is not a repair.
		let actual = absent();
		assert!(
			matches!(actual, Decision::Leave(_)),
			"absent() returned {actual:?}, expected Decision::Leave(_)"
		);
	}

	#[test]
	fn refuses_a_pin_or_an_advanced_policy() {
		let mut pin = token(&[7], None);
		pin.pin = true;
		let mut signed = token(&[7], None);
		signed.advanced = Some("a signed PCR policy".to_string());
		for (t, why) in [(pin, "PIN"), (signed, "signed policy")] {
			let actual = token_refusal(&t);
			assert!(
				actual.is_some(),
				"token_refusal({t:?}) returned None, expected Some ({why})"
			);
		}

		let plain = token(&[7], None);
		let actual = token_refusal(&plain);
		assert_eq!(
			actual, None,
			"token_refusal({plain:?}) returned {actual:?}, expected None"
		);
	}

	#[test]
	fn refuses_when_the_host_has_a_public_key_or_pcrlock_policy() {
		for path in PUBLIC_KEY_PATHS.iter().chain(PCRLOCK_PATHS.iter()) {
			let actual = host_policy(|p| p == *path);
			assert!(
				actual.as_deref().is_some_and(|a| a.contains(path)),
				"host_policy(<only {path} exists>) returned {actual:?}, expected Some naming it"
			);
		}
		let actual = host_policy(|_| false);
		assert_eq!(
			actual, None,
			"host_policy(<nothing exists>) returned {actual:?}, expected None"
		);
	}

	#[test]
	fn a_matching_selection_passes() {
		let cases = [
			(token(&[0, 1, 7], Some("sha256")), "explicit bank"),
			(token(&[0, 1, 7], None), "absent bank means sha256"),
		];
		let cfg = config(&[0, 1, 7], "sha256");
		for (t, why) in cases {
			let actual = same_selection(&t, &cfg);
			assert_eq!(
				actual,
				Ok(()),
				"same_selection({t:?}, <0+1+7 sha256>) returned {actual:?}, expected Ok(()) ({why})"
			);
		}
	}

	#[test]
	fn a_differing_selection_is_refused() {
		// The evil-maid case: the header was rewritten to name a register every
		// boot resets, or a weaker bank.
		let cases = [
			(token(&[16], Some("sha256")), "PCR 16 instead of 0+1+7"),
			(token(&[0, 1], Some("sha256")), "a narrower selection"),
			(token(&[0, 1, 7, 16], Some("sha256")), "a wider selection"),
			(token(&[], Some("sha256")), "no PCRs at all"),
			(token(&[0, 1, 7], Some("sha1")), "a downgraded bank"),
		];
		let cfg = config(&[0, 1, 7], "sha256");
		for (t, why) in cases {
			let actual = same_selection(&t, &cfg);
			assert!(
				actual.is_err(),
				"same_selection({t:?}, <0+1+7 sha256>) returned {actual:?}, expected Err ({why})"
			);
		}
	}

	#[test]
	fn a_refusal_names_both_selections() {
		let t = token(&[16], None);
		let actual = same_selection(&t, &config(&[0, 1, 7], "sha256")).unwrap_err();
		assert!(
			actual.contains("selection 16 (sha256)") && actual.contains("configured 0+1+7 (sha256)"),
			"same_selection(<16>, <0+1+7 sha256>) returned Err({actual:?}), expected it to name both selections"
		);
	}
}
