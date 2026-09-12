//! The volume configuration the NixOS module (DESIGN.md section 7) writes for
//! us.
//!
//! The daemon learns three things it cannot learn from the socket: which volumes
//! it is allowed to act on, the backing device behind each one, and the TPM2
//! parameters to enroll with. Only the backing device is used in this build --
//! for passphrase validation and for the ask-password id -- but the whole schema
//! is parsed and type-checked so the module/daemon contract is settled in one
//! go rather than drifting a field at a time.
//!
//! ```json
//! {
//!   "volumes": {
//!     "root": {
//!       "device": "/dev/disk/by-uuid/...",
//!       "tpm2Device": "auto",
//!       "tpm2Pcrs": [7, 11],
//!       "enrollIfAbsent": false
//!     }
//!   }
//! }
//! ```
//!
//! Per-volume values arrive already resolved: the module merges its global
//! defaults before writing the file, so there is exactly one place that knows
//! what a default is.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::log::warning;

/// Where the module puts the file. `--config=` overrides it.
pub const DEFAULT_PATH: &str = "/etc/tpm2-autoenroll/config.json";

/// Everything the daemon is allowed to act on, keyed by volume (mapper) name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
	volumes: BTreeMap<String, Volume>,
}

/// One volume's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
	/// The backing block device, i.e. what holds the LUKS2 header.
	pub device: String,
	/// `--tpm2-device=` for systemd-cryptenroll. Unused until the enrollment
	/// slice; parsed now so the schema does not change under the module.
	pub tpm2_device: String,
	/// `--tpm2-pcrs=`, as PCR indices.
	pub tpm2_pcrs: Vec<u8>,
	/// Whether a volume carrying no systemd-tpm2 token may be enrolled from
	/// scratch, as opposed to only having a drifted binding repaired.
	pub enroll_if_absent: bool,
}

/// The highest PCR index a TPM2 exposes. 16 is the debug PCR the tier 1 test
/// uses, 23 the last of them.
const MAX_PCR: u64 = 23;

impl Config {
	pub fn get(&self, volume: &str) -> Option<&Volume> {
		self.volumes.get(volume)
	}

	pub fn is_empty(&self) -> bool {
		self.volumes.is_empty()
	}
}

/// Read and parse the config file.
///
/// The caller is expected to treat an error as "manage nothing" rather than as
/// a reason to exit: a daemon that refuses to start leaves systemd-cryptsetup
/// connecting to a socket nobody accepts on, which is worse for the boot than
/// declining every connection.
pub fn load(path: &str) -> Result<Config, String> {
	let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
	parse(&text).map_err(|e| format!("{path}: {e}"))
}

pub fn parse(text: &str) -> Result<Config, String> {
	let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;

	let obj = root.as_object().ok_or("top level is not an object")?;
	for key in obj.keys() {
		if key != "volumes" {
			warning!("config: ignoring unrecognised top-level key {key:?}");
		}
	}

	let volumes = obj.get("volumes").ok_or("no \"volumes\" key")?;
	let volumes = volumes
		.as_object()
		.ok_or("\"volumes\" is not an object")?;

	let mut out = BTreeMap::new();
	for (name, value) in volumes {
		match volume(value) {
			Ok(v) => {
				out.insert(name.clone(), v);
			}
			// One malformed entry must not cost every other volume its
			// configuration, for the same reason one malformed ListenStream=
			// does not (listen_fds.rs).
			Err(e) => warning!("config: volume {name:?}: {e}; ignoring it"),
		}
	}
	Ok(Config { volumes: out })
}

fn volume(value: &Value) -> Result<Volume, String> {
	let obj = value.as_object().ok_or("not an object")?;

	for key in obj.keys() {
		if !matches!(
			key.as_str(),
			"device" | "tpm2Device" | "tpm2Pcrs" | "enrollIfAbsent"
		) {
			// A warning rather than an error, so a config from a newer module
			// still configures the fields this build does understand.
			warning!("config: ignoring unrecognised key {key:?}");
		}
	}

	let device = obj.get("device").ok_or("no \"device\"")?;
	let device = device.as_str().ok_or("\"device\" is not a string")?;
	if device.is_empty() {
		return Err("\"device\" is empty".to_string());
	}

	let tpm2_device = match obj.get("tpm2Device") {
		Some(v) => v.as_str().ok_or("\"tpm2Device\" is not a string")?.to_string(),
		None => "auto".to_string(),
	};

	let tpm2_pcrs = match obj.get("tpm2Pcrs") {
		Some(v) => pcrs(v)?,
		None => Vec::new(),
	};

	let enroll_if_absent = match obj.get("enrollIfAbsent") {
		Some(v) => v
			.as_bool()
			.ok_or("\"enrollIfAbsent\" is not a boolean")?,
		None => false,
	};

	Ok(Volume {
		device: device.to_string(),
		tpm2_device,
		tpm2_pcrs,
		enroll_if_absent,
	})
}

fn pcrs(value: &Value) -> Result<Vec<u8>, String> {
	let list = value.as_array().ok_or("\"tpm2Pcrs\" is not an array")?;
	let mut out = Vec::with_capacity(list.len());
	for item in list {
		let n = item
			.as_u64()
			.ok_or("\"tpm2Pcrs\" contains a non-integer")?;
		if n > MAX_PCR {
			return Err(format!("\"tpm2Pcrs\" contains {n}, which is not a PCR index"));
		}
		out.push(n as u8);
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	const FULL: &str = r#"{
	  "volumes": {
	    "root": {
	      "device": "/dev/disk/by-uuid/abc",
	      "tpm2Device": "/dev/tpmrm0",
	      "tpm2Pcrs": [7, 11],
	      "enrollIfAbsent": true
	    }
	  }
	}"#;

	#[test]
	fn parses_a_full_volume() {
		let expected = Volume {
			device: "/dev/disk/by-uuid/abc".to_string(),
			tpm2_device: "/dev/tpmrm0".to_string(),
			tpm2_pcrs: vec![7, 11],
			enroll_if_absent: true,
		};
		let cfg = parse(FULL).expect("parse(FULL) returned Err, expected Ok");
		let actual = cfg.get("root");
		assert_eq!(
			actual,
			Some(&expected),
			"parse(FULL).get(\"root\") returned {actual:?}, expected {:?}",
			Some(&expected)
		);
	}

	#[test]
	fn defaults_every_field_but_device() {
		let input = r#"{"volumes":{"data":{"device":"/dev/vdb"}}}"#;
		let expected = Volume {
			device: "/dev/vdb".to_string(),
			tpm2_device: "auto".to_string(),
			tpm2_pcrs: vec![],
			enroll_if_absent: false,
		};
		let cfg = parse(input).expect("parse of a device-only volume returned Err, expected Ok");
		let actual = cfg.get("data");
		assert_eq!(
			actual,
			Some(&expected),
			"parse({input:?}).get(\"data\") returned {actual:?}, expected {:?}",
			Some(&expected)
		);
	}

	#[test]
	fn a_malformed_volume_does_not_take_its_neighbours_with_it() {
		let input = r#"{"volumes":{
			"bad": {"tpm2Pcrs": [7]},
			"good": {"device": "/dev/vdc"}
		}}"#;
		let cfg = parse(input).expect("parse with one bad volume returned Err, expected Ok");

		let bad = cfg.get("bad");
		assert_eq!(
			bad, None,
			"parse(<bad+good>).get(\"bad\") returned {bad:?}, expected None (no \"device\" key)"
		);

		let good = cfg.get("good").map(|v| v.device.as_str());
		assert_eq!(
			good,
			Some("/dev/vdc"),
			"parse(<bad+good>).get(\"good\").device returned {good:?}, expected Some(\"/dev/vdc\")"
		);
	}

	#[test]
	fn unknown_keys_are_tolerated() {
		// A config written by a newer module must still configure the fields
		// this build understands.
		let input = r#"{"future":1,"volumes":{"root":{"device":"/dev/vda","futureKey":"x"}}}"#;
		let actual = parse(input).ok().and_then(|c| c.get("root").cloned());
		assert_eq!(
			actual.as_ref().map(|v| v.device.as_str()),
			Some("/dev/vda"),
			"parse({input:?}).get(\"root\") returned {actual:?}, expected a volume with device \"/dev/vda\""
		);
	}

	#[test]
	fn rejects_structurally_wrong_files() {
		let cases = [
			("", "empty file"),
			("[]", "top level is an array"),
			("{}", "no volumes key"),
			(r#"{"volumes":[]}"#, "volumes is an array"),
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
	fn rejects_out_of_range_pcrs() {
		let input = r#"{"volumes":{"root":{"device":"/dev/vda","tpm2Pcrs":[7,24]}}}"#;
		let cfg = parse(input).expect("parse returned Err, expected Ok with the volume dropped");
		let actual = cfg.get("root");
		assert_eq!(
			actual, None,
			"parse({input:?}).get(\"root\") returned {actual:?}, expected None (24 is not a PCR index)"
		);
	}

	#[test]
	fn an_empty_volume_map_is_not_an_error() {
		// Distinct from a broken file: "manage nothing" is a legitimate,
		// if useless, configuration, and the daemon logs the difference.
		let cfg = parse(r#"{"volumes":{}}"#).expect("parse of an empty volume map returned Err");
		assert!(
			cfg.is_empty(),
			"parse(r#\"{{\"volumes\":{{}}}}\"#).is_empty() returned false, expected true"
		);
	}
}
