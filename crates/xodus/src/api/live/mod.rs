use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
mod utils;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> reqwest::Result<DeviceAddResponse> {
    let data = quick_xml::se::to_string(&data).unwrap();

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text).expect("Failed to de xml");
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client).await?;

    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection) => {
            let token = collection.security_tokens.remove(0);
            Ok(token)
        }
        b => unimplemented!("Exchange token supports only singular token right now {b:?}"),
    }
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeUserTokenOutcome::Fault(envelope.header.pp),
        body => ExchangeUserTokenOutcome::Issued(body),
    })
}

#[derive(thiserror::Error, Debug)]
pub enum ExchangeCompactTokenError {
    #[error(transparent)]
    Rst(#[from] rst::RSTError),
    #[error("Xbox Live authentication returned a fault instead of a token")]
    Fault,
    #[error("Expected a security token response (collection) but got a different body")]
    UnexpectedResponseShape,
    #[error("Expected a compact token but got a different token type")]
    UnexpectedTokenType,
    #[error("Failed to parse token expiry: {0}")]
    InvalidExpiry(#[from] chrono::ParseError),
}

pub struct CompactUserToken {
    pub token: String,
    pub expiry: i64,
    /// A second, refreshed STS token Xbox Live sometimes returns alongside the compact
    /// token - callers that want to keep the caller's STS token fresh should persist this
    /// under the returned address; callers that don't care about refresh can ignore it.
    pub refreshed_sts: Option<(String, Token)>,
}

/// Shared by every caller that needs a compact Xbox Live user token out of
/// [`exchange_user_token`] - unwraps the [`ExchangeUserTokenOutcome`], pulls the token
/// lifetime, and downcasts to [`Token::Compact`], so callers don't each hand-roll the same
/// match/unwrap.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token_compact(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<CompactUserToken, ExchangeCompactTokenError> {
    let outcome = exchange_user_token(
        client,
        user_token,
        username,
        device_token,
        inline_token,
        inline_ux,
        hosting_app,
        scope_policies,
    )
    .await?;

    match outcome {
        ExchangeUserTokenOutcome::Fault(_) => Err(ExchangeCompactTokenError::Fault),
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let refreshed_sts = collection.security_tokens.pop().map(|sts| {
                let address = sts.applies_to.endpoint_reference.address.clone();
                let sts: Token = sts.into();
                let address = if let Token::Legacy(legacy) = &sts {
                    legacy.key_name.clone().unwrap_or(address)
                } else {
                    address
                };
                (address, sts)
            });
            if collection.security_tokens.is_empty() {
                return Err(ExchangeCompactTokenError::UnexpectedResponseShape);
            }
            let token = collection.security_tokens.remove(0);
            let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
            let token: Token = token.into();
            let Token::Compact(token) = token else {
                return Err(ExchangeCompactTokenError::UnexpectedTokenType);
            };
            Ok(CompactUserToken {
                token,
                expiry: expiry.timestamp(),
                refreshed_sts,
            })
        }
        _ => Err(ExchangeCompactTokenError::UnexpectedResponseShape),
    }
}

#[cfg(test)]
mod test {
    use crate::api::live::exchange_device_token;
    use crate::models::secrets::Token;
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await;

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.into();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
