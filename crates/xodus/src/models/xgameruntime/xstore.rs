use serde::{Deserialize, Serialize};

/// `XStoreQueryGameLicenseAsync` - `content_id` is the package's `ContentId` (from its XVD
/// header), published to the game process by `xodus-cli run` via `xodus::ipc::ENV_CONTENT_ID`.
/// No user field: like `UserInfoRequest`, this always answers for whichever account's
/// credentials are on this connection.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseRequest {
    pub content_id: String,
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseResponse {
    pub is_active: bool,
    /// Zero for a license with no expiration (the common case for an outright purchase).
    #[serde(default)]
    pub expiration_date: i64,
}
