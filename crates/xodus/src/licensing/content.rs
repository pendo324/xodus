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
use crate::models::secrets::{LegacyToken, Token};
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

/// The MSA -> Xbox Live user-token exchange shared by `xodus-service`'s `MsaTokenRequest`
/// (hands the compact token straight back to the game), `XstsTokenRequest` (feeds it on
/// into the XSTS chain), and `EntitledProductsRequest` (same chain, `MP_RELYING_PARTY`
/// XSTS) - and by any other caller (e.g. `xodus-cli`) that needs the same compact ticket
/// without going through a live `xodus-service` connection. Distinct from
/// [`get_ms_compact_tokens`]'s `www.microsoft.com`/`MBI_SSL` exchange - this one targets
/// whatever `client_id`/`scope` the caller passes (Xbox Live's own client id and
/// `xboxlive.signin`, for the callers above).
pub async fn exchange_msa_user_token(
    client: &reqwest::Client,
    tokens: &TokenManager,
    device_token: LegacyToken,
    client_id: &str,
    scope: &str,
) -> Result<crate::api::live::CompactUserToken, String> {
    let Token::Legacy(user_token) = tokens.get_user_sts_token().map_err(|err| err.to_string())?
    else {
        return Err("no legacy user STS token available".to_string());
    };

    let result = crate::api::live::exchange_user_token_compact(
        client,
        user_token,
        "USERNAME".to_string(),
        device_token,
        None,
        Some("Silent".to_string()),
        client_id.to_string(),
        &[
            (
                format!("scope={scope}&api-version=2.0&clientid={client_id}"),
                Some(soap::PolicyReference::token_broker()),
            ),
            ("http://Passport.NET/tb".to_string(), None),
        ],
    )
    .await
    .map_err(|err| err.to_string())?;

    if let Some((address, sts)) = &result.refreshed_sts {
        if let Err(err) = tokens.save_user_token(address.clone(), sts.clone()) {
            log::warn!("Failed to persist refreshed STS token: {err}");
        }
    }

    Ok(result)
}

/// `XStoreGetUserCollectionsIdAsync`'s real backing. `service_ticket`/`publisher_user_id`
/// are the caller's own values (opaque to xodus) - forwarded verbatim in the body the endpoint
/// expects: `POST /v7.0/beneficiaries/me/keys {serviceTicket, publisherUserId}`.
/// The response is `{"key": "..."}` wrapping an opaque
/// signed blob the title's own backend is meant to verify; [`read_store_key`] unwraps it.
///
/// `authorization` is an `XBL3.0` header for the `http://mp.microsoft.com/` relying party;
/// see [`get_purchase_id`] for why that and not an MSA ticket.
pub async fn get_collections_id(
    client: &reqwest::Client,
    authorization: String,
    service_ticket: String,
    publisher_user_id: String,
) -> Result<String, String> {
    let response = client
        .post("https://collections.mp.microsoft.com/v7.0/beneficiaries/me/keys")
        .header("Authorization", authorization)
        .json(&serde_json::json!({
            "serviceTicket": service_ticket,
            "publisherUserId": publisher_user_id,
        }))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    read_store_key(response).await
}

/// `XStoreGetUserPurchaseIdAsync`'s backing - the purchase-side twin of
/// [`get_collections_id`], same body, same opaque response. The two services do *not* mirror each
/// other's route: `purchase.mp.microsoft.com` answers on `users/me/keys` and 404s on the
/// collections spelling `beneficiaries/me/keys`, which is exactly inverted on
/// `collections.mp.microsoft.com`.
/// Each service names itself in its error bodies (`PurchaseFD` vs `CollectionsFD`), which is
/// what confirms the route is reached rather than merely existing.
///
/// Both this and [`get_collections_id`] authenticate with an **XSTS** token, not an MSA
/// ticket: `Authorization: XBL3.0 x=<uhs>;<token>` minted for the `http://mp.microsoft.com/`
/// relying party. An MSA compact ticket is refused as `UnexpectedTicketType` no matter how
/// it is framed - these services want a `Compact_Delegation` ticket, which MSA only issues
/// to the Windows identity broker - but that path is simply not the one in use here. The
/// `serviceTicket` in the body is the *service* half (an AAD token whose audience is
/// `https://onestore.microsoft.com/b2b/keys/create/{collections,purchase}`, which the title
/// obtains from PlayFab and hands us), and the `Authorization` header is the *user* half.
/// Getting those two the wrong way round is what produced the long-standing 401.
///
/// The relying party is not guessable from the hostname and is the same for both halves;
/// `licensing.xboxlive.com` satisfies collections but leaves purchase unable to decrypt the
/// token, since an XToken is encrypted to its relying party's key. See
/// `examples/collections_b2b_probe.rs` for the sweep that established it.
pub async fn get_purchase_id(
    client: &reqwest::Client,
    authorization: String,
    service_ticket: String,
    publisher_user_id: String,
) -> Result<String, String> {
    let response = client
        .post("https://purchase.mp.microsoft.com/v7.0/users/me/keys")
        .header("Authorization", authorization)
        .json(&serde_json::json!({
            "serviceTicket": service_ticket,
            "publisherUserId": publisher_user_id,
        }))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    read_store_key(response).await
}

/// Reads a store endpoint's opaque response, keeping the server's own error text on a
/// non-success status. Neither endpoint below is publicly documented, so when one rejects a
/// request the body is the only thing that says which field it disliked - `error_for_status`
/// throws exactly that away and leaves a bare "400 Bad Request" to debug from. Truncated because these bodies are unbounded, and the useful
/// part (an error code and field name) is always at the front.
async fn read_opaque_body(response: reqwest::Response) -> Result<String, String> {
    let status = response.status();
    let body = response.text().await.map_err(|err| err.to_string())?;
    if status.is_success() {
        // Names and sizes, never values: these bodies carry the store-ID keys themselves.
        // Whether the response is the bare key or an object wrapping it is the difference
        // between the title getting a usable key and getting a JSON blob, and the field
        // names alone settle that.
        log::debug!("Store response shape: {}", describe_json_shape(&body));
        return Ok(body);
    }

    let mut detail = body;
    detail.truncate(512);
    Err(format!("HTTP {status}: {detail}"))
}

/// Reads a store-ID key response, unwrapping the `{"key": "..."}` object both endpoints
/// answer with.
///
/// The title passes whatever it gets straight on as its `CollectionsMsIdKey`/
/// `PurchaseMsIdKey`, so handing it the enclosing JSON instead of the key is not a cosmetic
/// difference: Minecraft's entitlement service forwards it to PlayFab, which answers
/// `400 PlayFabError "Failed to validate CollectionsMsIdKey"` and the plan picker shows
/// "Couldn't access platform store".
///
/// A response without a `key` field is passed through whole rather than discarded - it is
/// the only way anything downstream can report what did arrive - but it is logged, since it
/// means the schema moved.
async fn read_store_key(response: reqwest::Response) -> Result<String, String> {
    let body = read_opaque_body(response).await?;
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(serde_json::Value::Object(mut fields)) => match fields.remove("key") {
            Some(serde_json::Value::String(key)) => Ok(key),
            _ => {
                log::warn!(
                    "Store key response has no string `key` field: {}",
                    describe_json_shape(&body)
                );
                Ok(body)
            }
        },
        _ => Ok(body),
    }
}

/// Describes a response body as `field=<value length>` pairs, or its own length when it is
/// not a JSON object.
///
/// Deliberately value-free - see the call site in [`read_opaque_body`].
fn describe_json_shape(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(fields)) => fields
            .iter()
            .map(|(name, value)| {
                let kind = match value {
                    serde_json::Value::String(text) => format!("{} chars", text.len()),
                    serde_json::Value::Object(inner) => format!("object, {} fields", inner.len()),
                    serde_json::Value::Array(items) => format!("array, {} items", items.len()),
                    serde_json::Value::Null => "null".to_string(),
                    // Numbers and bools are not credentials on this path, but naming the
                    // type rather than printing it keeps the rule "values never appear"
                    // true without exception.
                    serde_json::Value::Number(_) => "number".to_string(),
                    serde_json::Value::Bool(_) => "bool".to_string(),
                };
                format!("{name}=<{kind}>")
            })
            .collect::<Vec<_>>()
            .join(" "),
        Ok(_) => format!("<non-object JSON, {} bytes>", body.len()),
        Err(_) => format!("<not JSON, {} bytes>", body.len()),
    }
}

/// `XStoreQueryLicenseTokenAsync`'s real backing: `POST licensing.mp.microsoft.com/v8.0/licenseToken
/// {parentProductId, enforceSellableBy, relatedProductIds, customDeveloperString,
/// beneficiaries}`. `product_ids[0]` becomes `parentProductId`, the rest
/// `relatedProductIds`. `beneficiaries`' wire shape is undocumented beyond the field's type
/// name (`beneficiaryArray`) - this reuses the same
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
) -> Result<String, String> {
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
        .await
        .map_err(|err| err.to_string())?;
    read_opaque_body(response).await
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

#[cfg(test)]
mod tests {
    use super::*;

}
