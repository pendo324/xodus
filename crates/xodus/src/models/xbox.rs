pub mod subscriptions;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthRequest {
    pub relying_party: String,
    pub token_type: String,
    pub properties: UserAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthProperties {
    pub auth_method: String,
    pub site_name: String,
    pub rps_ticket: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DisplayClaims {
    #[serde(default)]
    xui: Vec<XuiClaim>,
    #[serde(default)]
    xti: Vec<XtiClaim>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XuiClaim {
    uhs: String,
    gtg: Option<String>,
    xid: Option<String>,
    mgt: Option<String>,
    agg: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XtiClaim {
    tid: Option<String>,
}

impl XstsResponse {
    pub fn user_hash(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .map(|claim| claim.uhs.as_str())
    }

    pub fn xuid(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.xid.as_deref())
    }

    pub fn gamertag(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.gtg.as_deref())
    }

    /// The "modern" (suffix-free) gamertag, when Xbox Live's `mgt` claim is present.
    pub fn gamertag_modern(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.mgt.as_deref())
    }

    /// Xbox Live's `agg` claim as-is (`"Adult"`/`"Teen"`/`"Child"`), not yet mapped to
    /// `XUserAgeGroup` - that mapping is a GDK-shaped concern for callers to make.
    pub fn age_group(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.agg.as_deref())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsPropertyBag {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_tokens: Option<Vec<String>>,

    /// The `device.auth.xboxlive.com` device token, when the caller has one.
    ///
    /// A request carrying this must also be signed by the proof key the device token is
    /// bound to. On its own it does not change what the minted token can do - see
    /// [`Self::title_token`], which is the claim endpoints phrased in terms of "current"
    /// actually need.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,

    /// The title token, which is what puts a *title* claim on the minted XSTS token.
    ///
    /// Endpoints that resolve a title from the token - notably presence's
    /// `/devices/current/titles/current` - answer `400 {"code":"ArgumentError"}` without
    /// one, because "the current title" is unresolvable. Measured directly: the same
    /// presence write returns `ArgumentError` with a user-only token and `200 OK` once a
    /// title token is in the chain, regardless of request body or contract version.
    ///
    /// Note this cannot be obtained from `title.auth.xboxlive.com` - that endpoint
    /// answers 403 to both its RPS and proof-key flows here. It comes from the SISU
    /// flow, which authenticates as the title itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_token: Option<String>,

    #[serde(rename = "SandboxId", skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relying_party: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    pub properties: XstsPropertyBag,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtResponse {
    pub end_points: Vec<TitleMgtEndPoint>,
    pub signature_policies: Vec<TitleMgtSignaturePolicy>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtEndPoint {
    pub protocol: String,
    pub host: String,
    #[serde(default)]
    pub host_type: Option<String>,
    #[serde(default)]
    pub relying_party: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub signature_policy_index: Option<u8>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtSignaturePolicy {
    pub version: u16,
    pub supported_algorithms: Vec<String>,
    pub max_body_bytes: u64,
    pub supported_signature_types: Vec<String>,
}
