use std::time::Instant;

pub trait TokenBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError>;
    /// Removes `key`, and succeeds whether or not it was there - callers want the key gone,
    /// and it already being gone is that, not a failure.
    fn remove(&self, key: &str) -> Result<(), TokenStoreError>;
}

pub trait ExpiringTokenBackend: TokenBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring_core::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry not found")]
    NotFound,
    #[error("stored proof key is not a valid P-256 private key: {0}")]
    InvalidProofKey(String),
}
