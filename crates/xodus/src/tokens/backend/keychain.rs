use crate::tokens::store::{TokenBackend, TokenStoreError};

pub struct KeychainBackend;

impl TokenBackend for KeychainBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
        let entry = crate::secrets::get_entry(key)?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
        Ok(crate::secrets::get_entry(key)?.set_secret(value)?)
    }

    fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
        match crate::secrets::get_entry(key)?.delete_credential() {
            // An absent entry is the state the caller asked for. `MemoryBackend`, the other
            // implementation of this trait, has always treated it that way; the keychain
            // reporting it as an error made `remove_persistent` give up partway through a
            // logout the first time it reached a key that had already been cleared.
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
