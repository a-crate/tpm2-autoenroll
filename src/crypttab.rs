//! Where the daemon learns which volumes exist, from the same file
//! systemd-cryptsetup is driven by.
//!
//! Reading crypttab(5) directly means there is no second list to keep in sync,
//! and no way to be configured for a volume systemd is not actually unlocking.
//! A line is ours when its options carry `tpm2-device=`, which is exactly what
//! makes systemd-cryptsetup attempt a TPM2 unlock and so exactly the set of
//! volumes that can fall back from one.
//!
//! Field 3 -- the key file -- gets a warning and nothing more. Setting it leaves
//! `try_discover_key` false, so the volume will most likely never reach us --
//! most likely, not certainly, since field 3 may name this daemon's socket.
//! Serving it and being ignored costs one fd, which is cheaper than deciding on
//! the user's behalf that their crypttab is wrong.

use crate::log::warning;

pub const DEFAULT_PATH: &str = "/etc/crypttab";

const TPM2_DEVICE: &str = "tpm2-device";

/// A volume we are prepared to manage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
	/// crypttab field 1. Also what our socket is named after and what
	/// systemd-cryptsetup puts in its bindname.
	pub name: String,
	/// The backing block device, resolved to a path.
	pub device: String,
	pub tpm2_device: String,
}

pub fn load(path: &str) -> Result<Vec<Volume>, String> {
	let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
	Ok(parse(&text))
}

/// Every TPM2-bound volume in a crypttab, in the order it appears.
///
/// A line we cannot use costs that line and nothing else: the file is shared
/// with systemd, so it may hold volumes that are none of our business and
/// options this build has never heard of.
pub fn parse(text: &str) -> Vec<Volume> {
	let mut out = Vec::new();
	for line in text.lines() {
		match entry(line) {
			Ok(Some(managed)) => {
				if let Some(caveat) = managed.caveat {
					warning!("crypttab: {caveat}");
				}
				out.push(managed.volume);
			}
			Ok(None) => {}
			Err(e) => warning!("crypttab: {e}; ignoring that entry"),
		}
	}
	out
}

/// A volume we will serve, plus anything about its entry that is likely to stop
/// it ever reaching us.
struct Managed {
	volume: Volume,
	caveat: Option<String>,
}

/// `Ok(None)` for a line that is simply not ours -- a comment, a blank, or a
/// volume with no TPM2 binding. `Err` is reserved for a line we cannot read.
fn entry(line: &str) -> Result<Option<Managed>, String> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') {
		return Ok(None);
	}

	let mut fields = line.split_whitespace();
	let name = fields.next().ok_or("empty entry")?;
	let Some(device) = fields.next() else {
		return Err(format!("{name:?} has no device field"));
	};
	let key_file = fields.next().unwrap_or("-");
	let options = fields.next().unwrap_or("");

	let Some(tpm2_device) = option(options, TPM2_DEVICE) else {
		return Ok(None);
	};
	if tpm2_device.is_empty() {
		return Err(format!("{name:?} has an empty {TPM2_DEVICE}="));
	}

	let caveat = (!matches!(key_file, "-" | "none" | "")).then(|| {
		format!(
			"{name:?} names the key file {key_file:?}; with field 3 set, \
			 systemd-cryptsetup does not search for a discovered key, so it will only \
			 reach us if that path is our own socket"
		)
	});

	Ok(Some(Managed {
		volume: Volume {
			name: name.to_string(),
			device: resolve(device),
			tpm2_device: tpm2_device.to_string(),
		},
		caveat,
	}))
}

fn option<'a>(options: &'a str, name: &str) -> Option<&'a str> {
	options.split(',').find_map(|o| {
		let (key, value) = o.split_once('=')?;
		(key.trim() == name).then_some(value)
	})
}

/// Turn an fstab-style device spec into a path. systemd resolves these itself;
/// we need the path because the passphrase is validated against the header and
/// systemd-cryptenroll is pointed at it.
pub fn resolve(spec: &str) -> String {
	let tags = [
		("UUID=", "by-uuid"),
		("PARTUUID=", "by-partuuid"),
		("LABEL=", "by-label"),
		("PARTLABEL=", "by-partlabel"),
	];
	for (tag, dir) in tags {
		if let Some(value) = spec.strip_prefix(tag) {
			return format!("/dev/disk/{dir}/{value}");
		}
	}
	spec.to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn volume(name: &str, device: &str, tpm2_device: &str) -> Volume {
		Volume {
			name: name.to_string(),
			device: device.to_string(),
			tpm2_device: tpm2_device.to_string(),
		}
	}

	#[test]
	fn takes_the_tpm2_bound_entries_only() {
		let input = "\
# a comment

root /dev/vda2 - tpm2-device=auto,tpm2-measure-pcr=yes
data /dev/vdb - none
swap /dev/vdc - tpm2-device=/dev/tpmrm0,noauto
";
		let expected = vec![
			volume("root", "/dev/vda2", "auto"),
			volume("swap", "/dev/vdc", "/dev/tpmrm0"),
		];
		let actual = parse(input);
		assert_eq!(
			actual, expected,
			"parse(<a crypttab with one unbound volume>) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn resolves_device_specs() {
		let cases = [
			("UUID=abc", "/dev/disk/by-uuid/abc"),
			("PARTUUID=abc", "/dev/disk/by-partuuid/abc"),
			("LABEL=abc", "/dev/disk/by-label/abc"),
			("PARTLABEL=abc", "/dev/disk/by-partlabel/abc"),
			("/dev/vda2", "/dev/vda2"),
		];
		for (input, expected) in cases {
			let actual = resolve(input);
			assert_eq!(
				actual, expected,
				"resolve({input:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}

	#[test]
	fn a_key_file_is_a_warning_rather_than_a_disqualification() {
		// Field 3 usually means we are never consulted, but the socket is cheap
		// and the path may even be ours.
		let input = "root /dev/vda2 /etc/keys/root.key tpm2-device=auto";
		let expected = vec![volume("root", "/dev/vda2", "auto")];
		let actual = parse(input);
		assert_eq!(
			actual, expected,
			"parse({input:?}) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn a_key_file_is_the_only_thing_warned_about() {
		let cases = [
			("root /dev/vda2 - tpm2-device=auto", false, "no key file"),
			("root /dev/vda2 none tpm2-device=auto", false, "\"none\""),
			(
				"root /dev/vda2 /etc/keys/root.key tpm2-device=auto",
				true,
				"a key file",
			),
		];
		for (input, expected, why) in cases {
			let actual = entry(input)
				.unwrap_or_else(|e| panic!("entry({input:?}) returned Err({e}), expected Ok"))
				.map(|m| m.caveat.is_some());
			assert_eq!(
				actual,
				Some(expected),
				"entry({input:?}).caveat.is_some() returned {actual:?}, expected {:?} ({why})",
				Some(expected)
			);
		}
	}

	#[test]
	fn a_missing_option_field_is_not_an_error() {
		// Three-field and two-field entries are both legal crypttab.
		let input = "root /dev/vda2 -\nswap /dev/vdc\n";
		let actual = parse(input);
		assert!(
			actual.is_empty(),
			"parse({input:?}) returned {actual:?}, expected no volumes"
		);
	}

	#[test]
	fn one_bad_line_does_not_cost_the_others_theirs() {
		let input = "\
broken
root /dev/vda2 - tpm2-device=auto
";
		let expected = vec![volume("root", "/dev/vda2", "auto")];
		let actual = parse(input);
		assert_eq!(
			actual, expected,
			"parse(<a crypttab with a one-field line>) returned {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn finds_an_option_anywhere_in_the_list() {
		let cases = [
			("tpm2-device=auto", Some("auto")),
			("noauto,tpm2-device=auto", Some("auto")),
			("tpm2-device=auto,noauto", Some("auto")),
			("noauto,tpm2-device=auto,discard", Some("auto")),
			("noauto,discard", None),
			("", None),
			// A prefix match would find this one, and it is a different option.
			("tpm2-device-key=/x", None),
		];
		for (input, expected) in cases {
			let actual = option(input, TPM2_DEVICE);
			assert_eq!(
				actual, expected,
				"option({input:?}, {TPM2_DEVICE:?}) returned {actual:?}, expected {expected:?}"
			);
		}
	}
}
