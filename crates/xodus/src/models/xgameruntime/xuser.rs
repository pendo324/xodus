use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
}

/// XUserGetTokenAndSignature: the relying party is not supplied by the caller (the real
/// GDK entry point doesn't take one either) - the handler looks it up from Xbox Live's
/// title-management endpoint table using `url`, the same way the real title-managed SDK
/// would. `body` is base64 because it's an arbitrary byte buffer, not XML-safe text.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub body: String,
    /// No caching layer exists yet to refresh, so this is accepted but currently a
    /// no-op - every request already fetches a fresh token.
    #[serde(default)]
    #[allow(dead_code)]
    pub force_refresh: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenResponse {
    pub token: String,
    /// XBL3.0 Authorization header value, e.g. "XBL3.0 x=...;<token>".
    pub authorization: String,
    /// ES256 request signature header, empty when no signature policy covers `url` or
    /// no device proof key has been provisioned yet (`xodus-cli device-auth`).
    #[serde(default)]
    pub signature: String,
    pub expiry: i64,
}

/// XUserGetGamertag / XUserGetId / age group - the identity claims off an
/// `http://xboxlive.com`-scoped XSTS token. No request fields: this always answers for
/// whichever user's credentials are on this connection, matching `XUserAddAsync`'s silent
/// path (there is no per-request user selection at the GDK layer either).
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserInfoRequest {}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserInfoResponse {
    pub xuid: String,
    pub gamertag: String,
    /// Empty when Xbox Live's `mgt` claim isn't present for this account.
    #[serde(default)]
    pub gamertag_modern: String,
    /// Xbox Live's raw `agg` claim (`"Adult"`/`"Teen"`/`"Child"`) - callers map this to
    /// `XUserAgeGroup` themselves.
    pub age_group: String,
}
