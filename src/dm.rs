//! Whether a volume is already open.
//!
//! A volume unlocked on the token-plugin route never contacts the daemon, so
//! the only way to learn it no longer needs us is to look for its mapping.

use std::path::Path;

pub const SYS_BLOCK: &str = "/sys/block";

/// True when `/sys/block/dm-*/dm/name` names `volume` and the mapping is a
/// LUKS2 one. Anything unreadable counts as not open, which only costs the
/// daemon staying around until its idle limit.
pub fn is_active(sys_block: &Path, volume: &str) -> bool {
	let Ok(entries) = std::fs::read_dir(sys_block) else {
		return false;
	};
	entries
		.flatten()
		.filter(|e| e.file_name().to_string_lossy().starts_with("dm-"))
		.any(|e| {
			let dm = e.path().join("dm");
			let name = std::fs::read_to_string(dm.join("name")).unwrap_or_default();
			let uuid = std::fs::read_to_string(dm.join("uuid")).unwrap_or_default();
			name.trim_end_matches('\n') == volume && uuid.starts_with("CRYPT-LUKS2-")
		})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fake_sysfs(tag: &str, mappings: &[(&str, &str, &str)]) -> std::path::PathBuf {
		let root =
			std::env::temp_dir().join(format!("tpm2-autoenroll-dm-{tag}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&root);
		for (dev, name, uuid) in mappings {
			let dm = root.join(dev).join("dm");
			std::fs::create_dir_all(&dm).expect("could not create the fake sysfs");
			std::fs::write(dm.join("name"), format!("{name}\n")).unwrap();
			std::fs::write(dm.join("uuid"), format!("{uuid}\n")).unwrap();
		}
		std::fs::create_dir_all(root.join("vda")).unwrap();
		root
	}

	#[test]
	fn finds_an_open_luks2_mapping() {
		let root = fake_sysfs(
			"open",
			&[
				("dm-0", "swap", "LVM-abc"),
				("dm-1", "root", "CRYPT-LUKS2-0123-root"),
			],
		);
		let cases = [
			("root", true),
			("swap", false),
			("data", false),
			("roo", false),
		];
		for (volume, expected) in cases {
			let actual = is_active(&root, volume);
			assert_eq!(
				actual, expected,
				"is_active(<dm-0 swap LVM, dm-1 root LUKS2>, {volume:?}) returned {actual}, expected {expected}"
			);
		}
		let _ = std::fs::remove_dir_all(&root);
	}

	#[test]
	fn a_missing_sysfs_means_nothing_is_open() {
		let actual = is_active(Path::new("/nonexistent/sys/block"), "root");
		assert!(
			!actual,
			"is_active(\"/nonexistent/sys/block\", \"root\") returned {actual}, expected false"
		);
	}
}
