use std::collections::HashMap;

use base64::prelude::*;
use xal::cvlib::CorrelationVector;
use xal::extensions::CorrelationVectorReqwestBuilder;

use crate::licensing::splicense::{DeviceKey, SPLicense};
use crate::licensing::utils;
use crate::models::devicecredential::License;
use crate::models::licensing::{
    DeviceContext, LicenseContentRequest, LicenseContentResponse, LicenseUserIdentity,
};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::Token;
use crate::models::soap;
use crate::tokens::TokenManager;

pub async fn get_license_content(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    content_id: String,
    market: String,
) -> reqwest::Result<(LicenseContentResponse, License)> {
    let mut cv = CorrelationVector::new();
    let response = client
        .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header("user-agent", "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe")
        .json(&LicenseContentRequest {
            content_id,
            market,
            client_challenge: "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+PENsaWVudENoYWxsZW5nZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vbmVzdG9yZS9zZWN1cml0eS9ta21zL0xpY1JlcS92MSIgVmVyc2lvbj0iMiI+PExpY2Vuc2VQcm90b2NvbFZlcnNpb24+NTwvTGljZW5zZVByb3RvY29sVmVyc2lvbj48U2lnbmluZ0tleVZlcnNpb24+MTwvU2lnbmluZ0tleVZlcnNpb24+PENsaWVudFZlcnNpb24+MjwvQ2xpZW50VmVyc2lvbj48L0NsaWVudENoYWxsZW5nZT4=".into(),
            concurrency_mode: "Rude".into(),
            license_version: 4,
            need_key: true,
            key_only: true,
            device_context: DeviceContext::default(),
            users: HashMap::from_iter(
                [(utils::generate_suid(),
                vec![LicenseUserIdentity {
                    identity_type: "Msa".to_string(),
                    identity_value: user_ms_token,
                    local_ticket_reference: ticket_reference,
                }])],
            ),
        })
        .add_cv(&mut cv)
        .unwrap()
        .send()
        .await?;

    let content_res = response.json::<LicenseContentResponse>().await?;
    let license = &content_res.license.keys[0].value;
    let license = BASE64_STANDARD.decode(license).unwrap();
    let license = quick_xml::de::from_str::<License>(&String::from_utf8(license).unwrap()).unwrap();
    Ok((content_res, license))
}

/// Compact MSA tokens (`www.microsoft.com` / `MBI_SSL` policy) for this device and user,
/// via the same device-token-exchange -> user-RST-exchange dance every `*.microsoft.com`
/// endpoint in this file needs. Shared by [`get_full_license`] (needs both) and
/// `api::xbox::services::get_library` callers (needs only the user token, as its bearer
/// `Authorization` header).
pub struct MsCompactTokens {
    pub device: String,
    pub user: String,
}

pub async fn get_ms_compact_tokens(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<MsCompactTokens, String> {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens.get_user().unwrap();
    let user_token = tokens.get_user_sts_token().unwrap();
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = crate::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .unwrap();

    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };

    Ok(MsCompactTokens {
        device: ms_device_token,
        user: user_token,
    })
}

/// `XStoreGetUserCollectionsIdAsync`'s real backing. `service_ticket`/`publisher_user_id`
/// are the caller's own values (opaque to xodus) - forwarded verbatim, mirroring the exact
/// `BodyTemplate` embedded in the real `xgameruntime.dll`'s service-configuration blob
/// (its OneCoreStore REST table, index #8: `POST /v7.0/beneficiaries/me/keys
/// {serviceTicket, publisherUserId}`). The response is an opaque signed blob the title's
/// own backend is meant to verify - returned as raw text rather than guessing at a field
/// name to extract, since no response schema was recovered from static analysis.
pub async fn get_collections_id(
    client: &reqwest::Client,
    user_ms_token: String,
    service_ticket: String,
    publisher_user_id: String,
) -> reqwest::Result<String> {
    let response = client
        .post("https://collections.mp.microsoft.com/v7.0/beneficiaries/me/keys")
        .header("Authorization", user_ms_token)
        .json(&serde_json::json!({
            "serviceTicket": service_ticket,
            "publisherUserId": publisher_user_id,
        }))
        .send()
        .await?;
    let response = response.error_for_status()?;
    response.text().await
}

/// `XStoreQueryLicenseTokenAsync`'s real backing, via the same service-configuration
/// blob's purchase-flow table, index #6: `POST licensing.mp.microsoft.com/v8.0/licenseToken
/// {parentProductId, enforceSellableBy, relatedProductIds, customDeveloperString,
/// beneficiaries}`. `product_ids[0]` becomes `parentProductId`, the rest
/// `relatedProductIds`. `beneficiaries`' wire shape is not recovered from the config blob
/// (it only names the field's type as `beneficiaryArray`) - this reuses the same
/// `LicenseUserIdentity` shape `get_license_content`'s `users` map already sends to the
/// sibling `/v7.0/licenses/content` endpoint, the only other precedent in this codebase
/// for identifying a license beneficiary to a `*.mp.microsoft.com` endpoint. Like
/// `get_collections_id`, the response is opaque and returned as raw text.
pub async fn get_license_token(
    client: &reqwest::Client,
    user_ms_token: String,
    local_ticket_reference: String,
    product_ids: &[String],
    custom_developer_string: String,
) -> reqwest::Result<String> {
    let (parent_product_id, related_product_ids) = match product_ids.split_first() {
        Some((first, rest)) => (first.clone(), rest.to_vec()),
        None => (String::new(), Vec::new()),
    };
    let response = client
        .post("https://licensing.mp.microsoft.com/v8.0/licenseToken")
        .header("Authorization", user_ms_token.clone())
        .json(&serde_json::json!({
            "parentProductId": parent_product_id,
            "enforceSellableBy": true,
            "relatedProductIds": related_product_ids,
            "customDeveloperString": custom_developer_string,
            "beneficiaries": [LicenseUserIdentity {
                identity_type: "Msa".to_string(),
                identity_value: user_ms_token,
                local_ticket_reference,
            }],
        }))
        .send()
        .await?;
    let response = response.error_for_status()?;
    response.text().await
}

/// The full MSA -> device/user token exchange -> `get_license_content` -> device-key
/// derivation pipeline for a given `ContentId`. Shared by `xodus-cli`'s `run`/`license`
/// commands (package decryption) and `xodus-service`'s `LicenseRequest` XML handler
/// (answering `XStoreQueryGameLicenseAsync` for the Wine-hosted DLL) - both need exactly
/// this sequence, just for different reasons (decrypting content vs. reporting whether a
/// license was obtainable at all).
pub async fn get_full_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> Result<(DeviceKey, SPLicense), String> {
    let user = tokens.get_user().unwrap();
    let ms_tokens = get_ms_compact_tokens(client, tokens).await?;

    let (_response, game_license) = get_license_content(
        client,
        ms_tokens.device,
        ms_tokens.user,
        user.puid,
        content_id,
        market,
    )
    .await
    .expect("failed to get license");

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .expect("could not parse base64 game SPLicense");

    let dev_license = tokens.get_device_license().unwrap();
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .expect("could not parse base64 device SPLicense");
    let key = device_license
        .encrypted_device_key
        .unwrap()
        .derive_device_key();
    Ok((key, game_splicense))
}
