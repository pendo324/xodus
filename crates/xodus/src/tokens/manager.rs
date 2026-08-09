use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use xal::RequestSigner;

use crate::{
    models::{
        secrets::{Device, Token, TokenStore, User},
        xbox::XstsResponse,
    },
    tokens::{
        backend::{KeychainBackend, MemoryBackend},
        store::{ExpiringTokenBackend, TokenBackend, TokenStoreError},
    },
};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
    pub const XBL_DEVICE_IDENTITY: &str = "xbl-device-identity";
    pub const SESSION_COOKIES: &str = "session-cookies";
    pub const SESSION_STORAGE: &str = "session-storage";
}

/// A browser cookie set without its own expiry - `xodus-cli`'s webview keeps the
/// requesting site's own session (e.g. minecraft.net's, layered on top of the separately
/// persistent Microsoft sign-in) alive across process launches by saving these here at
/// window close and replaying them into the next window's cookie jar before it navigates,
/// rather than relying on the browser engine's own on-disk cookie store, which only
/// persists cookies that carry their own expiry.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCookie {
    pub domain: String,
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
}

/// A `window.sessionStorage` entry for one origin. Real browsers keep `sessionStorage`
/// entirely in memory - it's never written to disk, even by an on-disk browsing profile -
/// so a library like MSAL.js that caches its sign-in state there loses that state every
/// time the hosting process exits, regardless of [`StoredCookie`] mirroring or a shared
/// profile directory. `xodus-cli`'s webview reads this out via `evaluate_script_with_callback`
/// at window close and replays it with a `with_initialization_script` before the next
/// window's page scripts run, standing in for what a browser's own long-lived tab would
/// have kept for free.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredStorageItem {
    pub host: String,
    pub key: String,
    pub value: String,
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// This device's Xbox Live identity. See [`TokenManager::get_xbl_device_identity`].
#[derive(Clone)]
pub struct XblDeviceIdentity {
    /// Sent as `Properties.Id` during device authentication.
    pub device_id: uuid::Uuid,
    /// Presents the `ProofKey` and signs requests bound to it.
    pub signer: RequestSigner,
}

#[derive(Serialize, Deserialize)]
struct StoredXblDeviceIdentity {
    device_id: uuid::Uuid,
    /// Raw big-endian P-256 private scalar.
    proof_key: Vec<u8>,
}

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_memory() -> Self {
        Self::new(
            Arc::new(MemoryBackend::default()),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Clears everything that identifies the signed-in *user*: the tokens themselves, and the
    /// webview session that could silently mint new ones without anybody typing a password.
    ///
    /// The device's own identity ([`keys::DEV_LICENSE`], [`keys::XBL_DEVICE_IDENTITY`]) is
    /// deliberately left alone - it is not a user, and re-earning it costs a device
    /// authentication for no benefit.
    ///
    /// Every key is attempted even if an earlier one fails, because stopping at the first
    /// failure leaves a half-signed-out store: the part that decides whether the next launch
    /// can skip the sign-in screen is at the end of the list, not the start.
    pub fn remove_persistent(&self) -> Result<(), TokenStoreError> {
        let mut first_err = None;
        for key in [
            keys::DEVICE_TOKENS,
            keys::USER_TOKENS,
            keys::USER_INFO,
            keys::SESSION_COOKIES,
            keys::SESSION_STORAGE,
        ] {
            if let Err(err) = self.persistent.remove(key)
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::DEV_LICENSE, &serde_json::to_vec(device)?)
    }

    pub fn remove_device_license(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEV_LICENSE)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_device_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::USER_TOKENS, address)
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::USER_TOKENS, address, token)
    }

    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_user_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- Xbox Live device identity -------------------------------------------

    /// This device's Xbox Live identity: the id it authenticates as, and the ES256
    /// keypair whose public half it presents as `ProofKey`.
    ///
    /// Both halves have to be persisted, and persisted *together*. Xbox Live binds
    /// issued tokens to the proof key presented at issuance, so a regenerated key
    /// cannot sign for tokens from a previous run; and a regenerated device id is a
    /// different device, which invalidates them just as thoroughly.
    ///
    /// This is deliberately independent of the MSA device credentials
    /// ([`TokenManager::get_device_license`]) - that identity is a different namespace
    /// and its `device_id` is a license binding id, not a UUID.
    ///
    /// Returns `Ok(None)` when no identity has been generated yet.
    pub fn get_xbl_device_identity(&self) -> Result<Option<XblDeviceIdentity>, TokenStoreError> {
        let Some(bytes) = self.persistent.get(keys::XBL_DEVICE_IDENTITY)? else {
            return Ok(None);
        };
        let stored: StoredXblDeviceIdentity = serde_json::from_slice(&bytes)?;

        let signer = RequestSigner::from_key_bytes(&stored.proof_key)
            .map_err(|e| TokenStoreError::InvalidProofKey(e.to_string()))?;

        Ok(Some(XblDeviceIdentity {
            device_id: stored.device_id,
            signer,
        }))
    }

    pub fn save_xbl_device_identity(
        &self,
        identity: &XblDeviceIdentity,
    ) -> Result<(), TokenStoreError> {
        let stored = StoredXblDeviceIdentity {
            device_id: identity.device_id,
            proof_key: identity.signer.to_key_bytes(),
        };
        self.persistent
            .set(keys::XBL_DEVICE_IDENTITY, &serde_json::to_vec(&stored)?)
    }

    /// Load the stored identity, generating and persisting one on first use.
    ///
    /// Call this once at startup - alongside
    /// [`crate::tokens::device::ensure_device_credentials`] - rather than per request:
    /// concurrent callers on an empty store would each generate an identity and the
    /// last write would win, invalidating tokens bound to the others.
    pub fn get_or_create_xbl_device_identity(&self) -> Result<XblDeviceIdentity, TokenStoreError> {
        if let Some(identity) = self.get_xbl_device_identity()? {
            return Ok(identity);
        }

        let identity = XblDeviceIdentity {
            device_id: uuid::Uuid::new_v4(),
            signer: RequestSigner::new(),
        };
        self.save_xbl_device_identity(&identity)?;
        Ok(identity)
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::USER_INFO)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::USER_INFO, &serde_json::to_vec(user)?)
    }

    // ---- Mirrored session-only webview cookies --------------------------------

    /// Keyed by `"{domain}|{name}"` so callers can merge in updates for one domain
    /// without clobbering cookies saved for another.
    pub fn get_session_cookies(&self) -> Result<HashMap<String, StoredCookie>, TokenStoreError> {
        match self.persistent.get(keys::SESSION_COOKIES)? {
            Some(bytes) if !bytes.is_empty() => Ok(serde_json::from_slice(&bytes)?),
            _ => Ok(HashMap::new()),
        }
    }

    pub fn save_session_cookies(
        &self,
        cookies: &HashMap<String, StoredCookie>,
    ) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::SESSION_COOKIES, &serde_json::to_vec(cookies)?)
    }

    // ---- Mirrored session-only webview storage ---------------------------------

    /// Keyed by `"{host}|{key}"`, same reasoning as [`Self::get_session_cookies`].
    pub fn get_session_storage(
        &self,
    ) -> Result<HashMap<String, StoredStorageItem>, TokenStoreError> {
        match self.persistent.get(keys::SESSION_STORAGE)? {
            Some(bytes) if !bytes.is_empty() => Ok(serde_json::from_slice(&bytes)?),
            _ => Ok(HashMap::new()),
        }
    }

    pub fn save_session_storage(
        &self,
        items: &HashMap<String, StoredStorageItem>,
    ) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::SESSION_STORAGE, &serde_json::to_vec(items)?)
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- shared TokenStore read/modify/write helper ---------------------------

    fn read_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: &str,
    ) -> Result<Option<Token>, TokenStoreError> {
        let Some(bytes) = backend.get(key)? else {
            return Ok(None);
        };
        let store: TokenStore = serde_json::from_slice(&bytes)?;
        Ok(store.tokens.get(address).cloned())
    }

    fn write_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: String,
        token: Token,
    ) -> Result<(), TokenStoreError> {
        let mut tokens: HashMap<String, Token> = match backend.get(key)? {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice::<TokenStore>(&bytes)?.tokens
            }
            _ => HashMap::new(),
        };
        tokens.insert(address, token);
        backend.set(key, &serde_json::to_vec(&TokenStore { tokens })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two managers sharing a backend stand in for two runs of the process. The second
    /// has to come back with the same device id *and* proof key: a new key cannot sign
    /// for tokens the first run was issued, and a new device id is a different device.
    #[test]
    fn xbl_device_identity_survives_reload() {
        let persistent = Arc::new(MemoryBackend::default());
        let manager = |persistent: Arc<MemoryBackend>| {
            TokenManager::new(persistent, Arc::new(MemoryBackend::default()))
        };

        let first = manager(persistent.clone())
            .get_or_create_xbl_device_identity()
            .expect("failed creating identity");
        let second = manager(persistent)
            .get_or_create_xbl_device_identity()
            .expect("failed reloading identity");

        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.signer.get_proof_key(), second.signer.get_proof_key());
    }

    #[test]
    fn no_xbl_device_identity_until_created() {
        let manager = TokenManager::with_memory();

        assert!(
            manager
                .get_xbl_device_identity()
                .expect("read failed")
                .is_none()
        );
        manager
            .get_or_create_xbl_device_identity()
            .expect("failed creating identity");
        assert!(
            manager
                .get_xbl_device_identity()
                .expect("read failed")
                .is_some()
        );
    }
}
