//! The passphrases this boot has already seen.
//!
//! Every managed volume opens its own connection, so five volumes sharing one
//! passphrase would produce five prompts unless we remember. Discovery runs
//! before systemd's own keyring lookup (cryptsetup.c:2742 is reachable only once
//! discovery has produced nothing), so for a managed volume the keyring cannot
//! answer on our behalf. Scope is the daemon's lifetime, which in the initrd is
//! the initrd; keyring interop lives in `askpw` instead.

use crate::secret::Secret;

/// Insertion-ordered and deduplicated. Order matters a little: the passphrase
/// that unlocked the previous volume is the one most likely to unlock the next,
/// and every miss costs a KDF pass.
#[derive(Default)]
pub struct Cache {
	entries: Vec<Secret>,
}

impl Cache {
	pub fn new() -> Self {
		Cache::default()
	}

	/// Only validated secrets belong here. A wrong one would be tried against
	/// every later volume, costing a KDF pass each time and teaching us nothing.
	pub fn insert(&mut self, secret: Secret) {
		if !self.entries.contains(&secret) {
			self.entries.push(secret);
		}
	}

	pub fn iter(&self) -> impl Iterator<Item = &Secret> {
		self.entries.iter()
	}

	pub fn len(&self) -> usize {
		self.entries.len()
	}

	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn secrets(cache: &Cache) -> Vec<Vec<u8>> {
		cache.iter().map(|s| s.as_bytes().to_vec()).collect()
	}

	#[test]
	fn keeps_insertion_order() {
		let mut cache = Cache::new();
		cache.insert(Secret::new(b"first".to_vec()));
		cache.insert(Secret::new(b"second".to_vec()));

		let actual = secrets(&cache);
		let expected = vec![b"first".to_vec(), b"second".to_vec()];
		assert_eq!(
			actual, expected,
			"Cache::insert(\"first\") then insert(\"second\"), iter() yielded {actual:?}, expected {expected:?}"
		);
	}

	#[test]
	fn ignores_a_repeat() {
		// Two copies would make the third volume pay two KDF passes to learn one
		// thing.
		let mut cache = Cache::new();
		cache.insert(Secret::new(b"shared".to_vec()));
		cache.insert(Secret::new(b"shared".to_vec()));

		let actual = cache.len();
		assert_eq!(
			actual, 1,
			"Cache::insert(\"shared\") twice, len() returned {actual}, expected 1"
		);
	}

	#[test]
	fn starts_empty() {
		let actual = Cache::new().is_empty();
		assert!(
			actual,
			"Cache::new().is_empty() returned {actual}, expected true"
		);
	}
}
