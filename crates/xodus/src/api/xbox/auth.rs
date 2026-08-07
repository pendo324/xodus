use crate::models::xbox::{
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
) -> reqwest::Result<XstsResponse> {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket,
        },
    };

    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

const XSTS_AUTHORIZE_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";

#[derive(Debug, thiserror::Error)]
pub enum XstsError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("failed to sign the XSTS request: {0}")]
    Signing(#[from] crate::auth::AuthError),
    #[error("failed to serialize the XSTS request: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    relying_party: &str,
) -> reqwest::Result<XstsResponse> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
            device_token: None,
            title_token: None,
        },
    };

    let resp = client
        .post(XSTS_AUTHORIZE_URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

/// [`request_xsts_token`], additionally carrying this device's and title's claims.
///
/// The title claim is the one that matters for endpoints phrased in terms of "the
/// current title"; see [`XstsPropertyBag::title_token`]. The device token accompanies it
/// because the same SISU flow issues both and `xsts/authorize` expects them together.
///
/// `xsts/authorize` only honors a `DeviceToken` on a request signed by the proof key
/// that token is bound to, so unlike the unsigned user-only path this one signs, using
/// the same persisted device identity [`crate::auth::get_device_token`] authenticated
/// with.
///
/// The signature is computed over the exact bytes sent, so the body is serialized once
/// here and handed to `reqwest` as raw bytes rather than re-serialized via `.json()`.
pub async fn request_xsts_token_for_title(
    client: &reqwest::Client,
    tokens: &crate::tokens::TokenManager,
    user_token: String,
    device_token: String,
    title_token: String,
    relying_party: &str,
) -> Result<XstsResponse, XstsError> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![user_token]),
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
            device_token: Some(device_token),
            title_token: Some(title_token),
        },
    };
    let body = serde_json::to_vec(&body)?;

    let mut request = client
        .post(XSTS_AUTHORIZE_URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");

    // `xsts/authorize` is covered by a signature policy, so this is expected to be
    // `Some`. A `None` (no policy matched the URL) is not worth failing the request
    // over - send it unsigned and let the service render its own verdict.
    if let Some(signature) =
        crate::auth::sign_header_for_url(tokens, XSTS_AUTHORIZE_URL, "POST", "", &body).await?
    {
        request = request.header("Signature", signature);
    }

    let resp = request
        .body(body)
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.json().await?)
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> String {
    let uhs = xsts.user_hash().expect("XSTS response missing xui claim");
    format!("XBL3.0 x={uhs};{}", xsts.token)
}
