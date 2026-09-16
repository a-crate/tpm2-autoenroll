//! The volumes this daemon may act on, and the policy each is enrolled against.
//!
//! ```json
//! {
//!   "volumes": {
//!     "root": {
//!       "device": "/dev/disk/by-uuid/...",
//!       "tpm2_device": "auto",
//!       "pcrs": [0, 1, 7],
//!       "pcr_bank": "sha256"
//!     }
//!   }
//! }
//! ```
//!
//! This file is the only source of the PCR selection and bank a re-enrollment
//! uses. The `systemd-tpm2` token in the LUKS2 header carries the same fields,
//! but nothing authenticates them: `cryptsetup token import` needs no key, so
//! anyone with the disk can rewrite them, and a header that says "PCR 16" would
//! otherwise be re-sealed to a register every boot resets. The config is trusted
//! because of where it lives -- the measured initrd in stage 1, the encrypted
//! root in stage 2 -- and the header is only ever compared against it.
//! `--config=` exists for manual runs.
//!
//! Anything unrecognised rejects the volume it appears in rather than being
//! skipped: this is security configuration, so a key this build does not
//! understand is one whose intent it cannot honour.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::log::{error, warning};
use crate::tpm2::Bank;

pub const DEFAULT_PATH: &str = "/etc/tpm2-autoenroll/config.json";

const MAX_PCR: u64 = 23;

/// PCRs userspace can reset without a reboot. Warned about rather than refused,
/// because the VM tests enroll against 16.
const RESETTABLE: [u8; 2] = [16, 23];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
	/// The mapper name. Also what our socket is named after and what
	/// systemd-cryptsetup puts in its bindname.
	pub name: String,
	/// The backing block device, i.e. what holds the LUKS2 header.
	pub device: String,
	/// "auto" or an absolute path, as `systemd-cryptenroll --tpm2-device=`
	/// accepts.
	pub tpm2_device: String,
	/// Sorted, deduplicated, never empty.
	pub pcrs: Vec<u8>,
	pub bank: Bank,
}

/// What a file amounts to: the volumes that passed validation, and why each
/// rejected one did not.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Loaded {
	pub volumes: Vec<Volume>,
	/// One message per rejected volume, each naming it.
	pub rejected: Vec<String>,
}

/// Read and validate, reporting rejections rather than acting on them.
///
/// `check-config` refuses a file with any, which is what lets a Nix build catch
/// a key this build does not know (see `nix/module.nix`). At boot the same key
/// would cost that volume the feature and say so only in the journal.
pub fn read(path: &str) -> Result<Loaded, String> {
	let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
	parse(&text).map_err(|e| format!("{path}: {e}"))
}

/// Every volume that passed validation. A file that cannot be read or parsed at
/// all is an `Err`; a single bad volume costs only itself.
pub fn load(path: &str) -> Result<Vec<Volume>, String> {
	let loaded = read(path)?;
	for why in &loaded.rejected {
		error!("config: {why}; it will not be served");
	}
	Ok(loaded.volumes)
}

pub fn parse(text: &str) -> Result<Loaded, String> {
	let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
	let obj = root.as_object().ok_or("top level is not an object")?;

	if let Some(key) = obj.keys().find(|k| k.as_str() != "volumes") {
		return Err(format!("unrecognised top-level key {key:?}"));
	}

	let volumes = obj
		.get("volumes")
		.ok_or("no \"volumes\" key")?
		.as_object()
		.ok_or("\"volumes\" is not an object")?;

	let mut out = Loaded::default();
	for (name, value) in volumes {
		match volume(name, value) {
			Ok(v) => out.volumes.push(v),
			Err(e) => out.rejected.push(format!("volume {name:?}: {e}")),
		}
	}
	Ok(out)
}

fn volume(name: &str, value: &Value) -> Result<Volume, String> {
	// The name becomes a path component under the socket directory.
	if name.is_empty() || name.contains('/') || name == "." || name == ".." {
		return Err("not a usable volume name".to_string());
	}

	let obj = value.as_object().ok_or("not an object")?;
	if let Some(key) = obj
		.keys()
		.find(|k| !matches!(k.as_str(), "device" | "tpm2_device" | "pcrs" | "pcr_bank"))
	{
		return Err(format!("unrecognised key {key:?}"));
	}

	let device = string(obj, "device")?.ok_or("no \"device\"")?;
	if !device.starts_with('/') {
		return Err(format!("\"device\" {device:?} is not an absolute path"));
	}

	let tpm2_device = string(obj, "tpm2_device")?.unwrap_or("auto");
	if tpm2_device != "auto" && !tpm2_device.starts_with('/') {
		return Err(format!(
			"\"tpm2_device\" {tpm2_device:?} is neither \"auto\" nor an absolute path"
		));
	}

	let pcrs = pcrs(obj.get("pcrs").ok_or("no \"pcrs\"")?)?;
	for pcr in pcrs.iter().filter(|p| RESETTABLE.contains(p)) {
		warning!("config: volume {name:?} binds to PCR {pcr}, which can be reset without a reboot");
	}

	let bank = match string(obj, "pcr_bank")? {
		Some(b) => Bank::from_name(b).ok_or_else(|| format!("unrecognised \"pcr_bank\" {b:?}"))?,
		None => Bank::SHA256,
	};

	Ok(Volume {
		name: name.to_string(),
		device: device.to_string(),
		tpm2_device: tpm2_device.to_string(),
		pcrs,
		bank,
	})
}

fn string<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
	match obj.get(key) {
		None => Ok(None),
		Some(v) => v
			.as_str()
			.map(Some)
			.ok_or_else(|| format!("{key:?} is not a string")),
	}
}

fn pcrs(value: &Value) -> Result<Vec<u8>, String> {
	let list = value.as_array().ok_or("\"pcrs\" is not an array")?;
	let mut out = BTreeSet::new();
	for item in list {
		let n = item.as_u64().ok_or("\"pcrs\" contains a non-integer")?;
		if n > MAX_PCR {
			return Err(format!("\"pcrs\" contains {n}, which is not a PCR index"));
		}
		out.insert(n as u8);
	}
	if out.is_empty() {
		// A policy over no PCRs unseals unconditionally.
		return Err("\"pcrs\" is empty".to_string());
	}
	Ok(out.into_iter().collect())
}

/// `0+1+7`, the way systemd writes a selection.
pub fn pcr_list(pcrs: &[u8]) -> String {
	pcrs.iter().map(u8::to_string).collect::<Vec<_>>().join("+")
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeMap;

	use super::*;

	fn only(input: &str) -> Option<Volume> {
		let loaded = parse(input)
			.unwrap_or_else(|e| panic!("parse({input:?}) returned Err({e}), expected Ok"));
		let by_name: BTreeMap<_, _> = loaded
			.volumes
			.into_iter()
			.map(|v| (v.name.clone(), v))
			.collect();
		by_name.get("root").cloned()
	}

	#[test]
	fn parses_a_full_volume() {
		let input = r#"{"volumes":{"root":{
			"device": "/dev/disk/by-uuid/abc",
			"tpm2_device": "/dev/tpmrm0",
			"pcrs": [7, 0, 1],
			"pcr_bank": "sha384"
		}}}"#;
		let expected = Volume {
			name: "root".to_string(),
			device: "/dev/disk/by-uuid/abc".to_string(),
			tpm2_device: "/dev/tpmrm0".to_string(),
			pcrs: vec![0, 1, 7],
			bank: Bank::from_name("sha384").unwrap(),
		};
		let actual = only(input);
		assert_eq!(
			actual,
			Some(expected.clone()),
			"parse({input:?}) returned {actual:?}, expected {:?}",
			Some(expected)
		);
	}

	#[test]
	fn defaults_the_tpm_device_and_bank() {
		let input = r#"{"volumes":{"root":{"device":"/dev/vda2","pcrs":[7]}}}"#;
		let actual = only(input).map(|v| (v.tpm2_device, v.bank));
		let expected = Some(("auto".to_string(), Bank::SHA256));
		assert_eq!(
			actual, expected,
			"parse({input:?}) returned (tpm2_device, bank) {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn sorts_and_dedupes_pcrs() {
		let input = r#"{"volumes":{"root":{"device":"/dev/vda2","pcrs":[7,1,7,0]}}}"#;
		let actual = only(input).map(|v| v.pcrs);
		assert_eq!(
			actual,
			Some(vec![0, 1, 7]),
			"parse({input:?}) returned pcrs {actual:?}, expected Some([0, 1, 7])"
		);
	}

	#[test]
	fn rejects_a_volume_missing_or_mistyping_a_required_field() {
		let cases = [
			(r#"{"pcrs":[7]}"#, "no device"),
			(r#"{"device":"","pcrs":[7]}"#, "empty device"),
			(r#"{"device":"vda2","pcrs":[7]}"#, "relative device"),
			(r#"{"device":"/dev/vda2"}"#, "no pcrs"),
			(r#"{"device":"/dev/vda2","pcrs":[]}"#, "empty pcrs"),
			(r#"{"device":"/dev/vda2","pcrs":[7,24]}"#, "PCR 24"),
			(r#"{"device":"/dev/vda2","pcrs":[-1]}"#, "negative PCR"),
			(r#"{"device":"/dev/vda2","pcrs":"7"}"#, "pcrs is a string"),
			(
				r#"{"device":"/dev/vda2","pcrs":[7],"tpm2_device":"tpmrm0"}"#,
				"relative tpm2_device",
			),
			(
				r#"{"device":"/dev/vda2","pcrs":[7],"pcr_bank":"md5"}"#,
				"unknown bank",
			),
			(
				r#"{"device":"/dev/vda2","pcrs":[7],"tpm2_pcrs":[16]}"#,
				"unknown key",
			),
			(r#""/dev/vda2""#, "not an object"),
		];
		for (volume, why) in cases {
			let input = format!(r#"{{"volumes":{{"root":{volume}}}}}"#);
			let actual = only(&input);
			assert_eq!(
				actual, None,
				"parse({input:?}) returned {actual:?}, expected the volume to be rejected ({why})"
			);
		}
	}

	#[test]
	fn a_rejected_volume_does_not_take_its_neighbours_with_it() {
		let input = r#"{"volumes":{
			"bad": {"device": "/dev/vdb", "pcrs": [7], "extra": true},
			"root": {"device": "/dev/vda2", "pcrs": [7]}
		}}"#;
		let loaded = parse(input).expect("parse returned Err, expected Ok");
		let actual: Vec<String> = loaded.volumes.into_iter().map(|v| v.name).collect();
		assert_eq!(
			actual,
			vec!["root".to_string()],
			"parse(<bad+root>) returned volumes {actual:?}, expected [\"root\"]"
		);
	}

	#[test]
	fn a_rejected_volume_is_reported_rather_than_only_dropped() {
		// What check-config refuses over: at boot this volume would just be
		// dropped, and the only sign would be a journal line.
		let input = r#"{"volumes":{"root":{"device":"/dev/vda2","pcrs":[7],"extra":true}}}"#;
		let actual = parse(input)
			.expect("parse returned Err, expected Ok")
			.rejected;
		assert_eq!(
			actual.len(),
			1,
			"parse({input:?}) returned rejected {actual:?}, expected one entry"
		);
		assert!(
			actual[0].contains("root") && actual[0].contains("extra"),
			"parse({input:?}) returned rejected {actual:?}, expected it to name the volume and the key"
		);
	}

	#[test]
	fn rejects_unusable_volume_names() {
		for name in ["", "a/b", ".", ".."] {
			let input =
				format!(r#"{{"volumes":{{"{name}":{{"device":"/dev/vda2","pcrs":[7]}}}}}}"#);
			let actual = parse(&input)
				.expect("parse returned Err, expected Ok")
				.volumes;
			assert!(
				actual.is_empty(),
				"parse({input:?}) returned {actual:?}, expected the volume named {name:?} to be rejected"
			);
		}
	}

	#[test]
	fn rejects_structurally_wrong_files() {
		let cases = [
			("", "empty file"),
			("[]", "top level is an array"),
			("{}", "no volumes key"),
			(r#"{"volumes":[]}"#, "volumes is an array"),
			(r#"{"volumes":{},"extra":1}"#, "unknown top-level key"),
			("{\"volumes\":{},", "truncated JSON"),
		];
		for (input, why) in cases {
			let actual = parse(input);
			assert!(
				actual.is_err(),
				"parse({input:?}) returned {actual:?}, expected Err ({why})"
			);
		}
	}

	#[test]
	fn formats_a_selection_the_way_systemd_does() {
		let actual = pcr_list(&[0, 1, 7]);
		assert_eq!(
			actual, "0+1+7",
			"pcr_list([0, 1, 7]) returned {actual:?}, expected \"0+1+7\""
		);
	}
}
