//! The opt-out list: volumes that are TPM2-bound but must never be re-enrolled.
//!
//! There is no positive configuration to balance this against -- the crypttab
//! decides what exists -- so the only thing a user can say is "not that one".
//! Written as one entry per line rather than as structured configuration
//! because that is the entire vocabulary.
//!
//! An entry matches either the volume (mapper) name or the backing device, and
//! device specs are resolved the same way crypttab's are, so `UUID=...` in this
//! file means what it means there.

use std::collections::BTreeSet;

use crate::crypttab::{self, Volume};

pub const DEFAULT_PATH: &str = "/etc/tpm2-autoenroll/ignore";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ignore {
	entries: BTreeSet<String>,
}

/// Read the ignore list.
///
/// A missing file is an empty list rather than an error: not having opted any
/// volume out is the ordinary case, and the module only writes the file when it
/// has something to put in it.
pub fn load(path: &str) -> Result<Ignore, String> {
	match std::fs::read_to_string(path) {
		Ok(text) => Ok(parse(&text)),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ignore::default()),
		Err(e) => Err(format!("{path}: {e}")),
	}
}

pub fn parse(text: &str) -> Ignore {
	let entries = text
		.lines()
		.map(str::trim)
		.filter(|l| !l.is_empty() && !l.starts_with('#'))
		.map(crypttab::resolve)
		.collect();
	Ignore { entries }
}

impl Ignore {
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	pub fn covers(&self, volume: &Volume) -> bool {
		self.entries.contains(&volume.name) || self.entries.contains(&volume.device)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn volume(name: &str, device: &str) -> Volume {
		Volume {
			name: name.to_string(),
			device: device.to_string(),
			tpm2_device: "auto".to_string(),
		}
	}

	#[test]
	fn matches_a_name_or_a_device() {
		let list = parse("swap\n/dev/vdc\n");
		let cases = [
			(volume("swap", "/dev/vdb"), true, "the name is listed"),
			(volume("data", "/dev/vdc"), true, "the device is listed"),
			(volume("root", "/dev/vda2"), false, "neither is listed"),
		];
		for (input, expected, why) in cases {
			let actual = list.covers(&input);
			assert_eq!(
				actual, expected,
				"parse(\"swap\\n/dev/vdc\\n\").covers({input:?}) returned {actual}, expected {expected} ({why})"
			);
		}
	}

	#[test]
	fn resolves_device_specs_like_crypttab_does() {
		// The user copies the spec out of their crypttab; it has to mean the
		// same thing in both files.
		let list = parse("UUID=abc\n");
		let input = volume("data", "/dev/disk/by-uuid/abc");
		let actual = list.covers(&input);
		assert!(
			actual,
			"parse(\"UUID=abc\\n\").covers({input:?}) returned false, expected true"
		);
	}

	#[test]
	fn skips_blanks_and_comments() {
		let input = "\n# swap\n  \nroot\n";
		let list = parse(input);
		let actual = list.covers(&volume("swap", "/dev/vdb"));
		assert!(
			!actual,
			"parse({input:?}).covers(<swap>) returned true, expected false: a commented-out entry is not an entry"
		);
		let actual = list.covers(&volume("root", "/dev/vda2"));
		assert!(
			actual,
			"parse({input:?}).covers(<root>) returned false, expected true"
		);
	}

	#[test]
	fn an_empty_list_covers_nothing() {
		let list = parse("");
		assert!(
			list.is_empty(),
			"parse(\"\").is_empty() returned false, expected true"
		);
		let actual = list.covers(&volume("root", "/dev/vda2"));
		assert!(
			!actual,
			"parse(\"\").covers(<root>) returned {actual}, expected false"
		);
	}
}
