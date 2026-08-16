//! BYO-key manager: an easy, operator-local credential store with no .env editing.
//!
//! Keys are kept in the same flat `credentials.json` file consumed by
//! [`crate::credentials::load_credentials`], so adding a key here has exactly the
//! same effect as editing that file by hand — but the operator never has to.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::credentials::load_credentials;

/// A small handle for adding, listing, and removing operator credentials in the
/// attachment's `credentials.json` file.
///
/// The attachment is stored, not the file itself, so the path can be recreated
/// (or the attachment directory created) lazily on first write.
pub struct KeyStore {
    attachment: PathBuf,
}

impl KeyStore {
    /// Open the key store rooted at `attachment`.
    pub fn open(attachment: &Path) -> Self {
        Self {
            attachment: attachment.to_path_buf(),
        }
    }

    fn path(&self) -> PathBuf {
        self.attachment.join("credentials.json")
    }

    /// Insert or replace a credential named `name` with `value`.
    ///
    /// The update is read-modify-write against the existing credentials file and
    /// is persisted atomically (temp file + rename), so a crash cannot leave a
    /// half-written `credentials.json`.
    pub fn add(&self, name: &str, value: &str) -> Result<()> {
        let mut credentials = load_credentials(&self.attachment)?;
        credentials.insert(name.to_owned(), value.to_owned());
        crate::atomic_json(&self.path(), &credentials)
    }

    /// List credential names only. Values are never returned.
    pub fn list(&self) -> Result<Vec<String>> {
        let credentials = load_credentials(&self.attachment)?;
        let mut names: Vec<String> = credentials.into_keys().collect();
        names.sort();
        Ok(names)
    }

    /// Remove the credential named `name`.
    ///
    /// Returns `true` when the credential existed and was removed, or `false`
    /// when there was nothing to remove. A missing credentials file is treated
    /// as empty, so removal from an empty store simply returns `false`.
    pub fn remove(&self, name: &str) -> Result<bool> {
        let mut credentials = load_credentials(&self.attachment)?;
        if credentials.remove(name).is_none() {
            return Ok(false);
        }
        crate::atomic_json(&self.path(), &credentials)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_remove_round_trip_and_list_never_leaks_values() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open(dir.path());

        let secret = "sk-super-secret-value";
        store.add("OPENAI_API_KEY", secret).unwrap();

        // The same file format as crate::credentials, with the value present.
        let stored = load_credentials(dir.path()).unwrap();
        assert_eq!(
            stored.get("OPENAI_API_KEY").map(String::as_str),
            Some(secret)
        );

        // list() returns names only and must never leak a value.
        let names = store.list().unwrap();
        assert_eq!(names, vec!["OPENAI_API_KEY".to_owned()]);
        assert!(!names.iter().any(|name| name.contains("sk-")));
        assert!(!names.iter().any(|name| name == secret));

        // Removing an existing key reports true and persists the removal.
        assert!(store.remove("OPENAI_API_KEY").unwrap());
        assert!(store.list().unwrap().is_empty());
        assert!(load_credentials(dir.path()).unwrap().is_empty());

        // Removing a key that no longer exists reports false.
        assert!(!store.remove("OPENAI_API_KEY").unwrap());
    }

    #[test]
    fn add_updates_existing_credentials_without_dropping_others() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open(dir.path());

        store.add("FIRST_KEY", "first-value").unwrap();
        store.add("SECOND_KEY", "second-value").unwrap();
        store.add("FIRST_KEY", "replacement-value").unwrap();

        let stored = load_credentials(dir.path()).unwrap();
        assert_eq!(
            stored.get("FIRST_KEY").map(String::as_str),
            Some("replacement-value")
        );
        assert_eq!(
            stored.get("SECOND_KEY").map(String::as_str),
            Some("second-value")
        );
        assert_eq!(store.list().unwrap(), vec!["FIRST_KEY", "SECOND_KEY"]);
    }
}
