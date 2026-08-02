use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use xodus::{
    api::xbox::{
        auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token},
        title::{get_endpoint, get_title_management},
    },
    models::{
        secrets::Token,
        soap,
        xgameruntime::{
            xstore::{
                AssociatedProductEntry, AssociatedProductsRequest, AssociatedProductsResponse,
                CollectionsIdRequest, CollectionsIdResponse, EntitledProduct,
                EntitledProductsRequest, EntitledProductsResponse, LicenseRequest, LicenseResponse,
                LicenseTokenRequest, LicenseTokenResponse, ResolveProductIdRequest,
                ResolveProductIdResponse,
            },
            xuser::{
                MSATokenRequest, MSATokenResponse, UserInfoRequest, UserInfoResponse,
                XstsTokenRequest, XstsTokenResponse,
            },
        },
    },
    proto::xodus::XodusMessageType,
};

use crate::{connection::Framing, simple_context::SimpleContext};

/// Xbox Live's own MSA app registration id - shared infrastructure, not a per-title
/// identity, so using it here doesn't run afoul of "never hardcode the title identity".
const XBOX_LIVE_CLIENT_ID: &str = "000000004424da1f";

/// Relying party used when Xbox Live's title-management endpoint table has no entry for
/// the requested URL - covers most everyday `*.xboxlive.com` calls.
const DEFAULT_RELYING_PARTY: &str = "http://xboxlive.com";

/// Relying party for `beige.xboxservices.com`'s "My games" library
/// (`XStoreQueryEntitledProductsAsync`) - its `x-ms-authorization-social` header wants an
/// XSTS token issued against this party, distinct from the Xbox Live one used everywhere
/// else in this file.
const MP_RELYING_PARTY: &str = "http://mp.microsoft.com/";

/// The MSA -> Xbox Live user-token exchange shared by `MsaTokenRequest` (which hands the
/// compact token straight back to the game) and `XstsTokenRequest` (which feeds it on
/// into the XSTS chain). Returns the compact RPS-ticket-shaped token used by both.
async fn exchange_msa_user_token(
    context: &SimpleContext,
    client_id: &str,
    scope: &str,
) -> Result<(String, i64), Box<dyn std::error::Error + Send + Sync>> {
    let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
        return Err("no legacy user STS token available".into());
    };
    let device_token = context
        .device_token
        .as_ref()
        .ok_or("no device token on this connection")?;

    let result = xodus::api::live::exchange_user_token_compact(
        &context.client,
        token,
        "USERNAME".to_string(),
        device_token.clone(),
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
    .await?;

    if let Some((address, sts)) = result.refreshed_sts {
        if let Err(err) = context.tokens().save_user_token(address, sts) {
            log::warn!("Failed to persist refreshed STS token: {err}");
        }
    }

    Ok((result.token, result.expiry))
}

pub async fn handle<S>(
    socket: &mut S,
    context: &mut SimpleContext,
    framing: Framing,
) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    log::debug!("Parsing XML");
    let (message_type, buffer) = super::read_message(socket, framing).await?;
    let message_type = XodusMessageType::try_from(message_type as i32).unwrap_or_default();

    let out_buf = match parse_message(context, message_type, buffer).await {
        Ok(buf) => buf,
        Err(err) => {
            log::error!("Failed parsing message: {err}");
            vec![]
        }
    };

    // Reply in the framing the client asked in, so a v1 client is never handed a
    // header it cannot parse.
    let data = super::encode_message(
        framing.xml_magic(),
        message_type as u16 + 1,
        framing,
        out_buf,
    )?;
    socket.write_all(&data).await
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::MsaTokenRequest => {
            log::debug!("Raw buffer: {buffer:?}");
            let string_buf = std::str::from_utf8(&buffer)?;
            log::debug!("String buffer: {string_buf:?}");
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL"
            } else {
                "xboxlive.signin"
            };
            let device_token = context
                .device_token
                .as_ref()
                .ok_or("no device token on this connection")?
                .clone();
            let device_token_resp = xodus::api::live::exchange_device_token(
                &context.client,
                device_token,
                "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
                "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
                Some(soap::PolicyReference::token_broker()),
            )
            .await;

            let ms_device_rps_token = if let Some((Token::Compact(ms_device_token), Ok(lifetime))) =
                device_token_resp.ok().map(|t| {
                    let expiry = chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires);
                    (t.into(), expiry)
                }) {
                Some((ms_device_token, lifetime.timestamp()))
            } else {
                None
            };

            let (token, expiry) = exchange_msa_user_token(context, &req.client_id, scope).await?;
            let payload = MSATokenResponse {
                token,
                expiry,
                device_expiry: ms_device_rps_token.as_ref().map(|(_, r)| *r).unwrap_or(0),
                device_rps: ms_device_rps_token
                    .map(|(t, _)| t)
                    .unwrap_or_else(String::new),
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::XstsTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<XstsTokenRequest>(string_buf)?;

            let (rps_ticket, _) =
                exchange_msa_user_token(context, XBOX_LIVE_CLIENT_ID, "xboxlive.signin").await?;
            let ms_user_token = authenticate_xbox_user(&context.client, rps_ticket).await?;

            let relying_party = match get_title_management(&context.client).await {
                Ok(endpoints) => get_endpoint(&req.url, &endpoints)
                    .and_then(|e| e.relying_party.clone())
                    .unwrap_or_else(|| DEFAULT_RELYING_PARTY.to_string()),
                Err(err) => {
                    log::warn!(
                        "Failed to fetch title-management endpoints, falling back to {DEFAULT_RELYING_PARTY}: {err}"
                    );
                    DEFAULT_RELYING_PARTY.to_string()
                }
            };

            let xsts =
                request_xsts_token(&context.client, ms_user_token.token, &relying_party).await?;
            let expiry = xsts.not_after.timestamp();
            let token = xsts.token.clone();
            let authorization = get_xsts_auth_header(xsts);

            // Only sign if a device identity already exists - creating one here, on a
            // request path that can run concurrently, would race the "generate once at
            // startup" contract `get_or_create_xbl_device_identity` documents.
            let signature = if context.tokens().get_xbl_device_identity()?.is_some() {
                use base64::prelude::*;
                let body = BASE64_STANDARD.decode(&req.body).unwrap_or_default();
                match xodus::auth::sign_header_for_url(
                    context.tokens(),
                    &req.url,
                    &req.method,
                    &authorization,
                    &body,
                )
                .await
                {
                    Ok(sig) => sig.unwrap_or_default(),
                    Err(err) => {
                        log::warn!("Failed to sign request for {}: {err}", req.url);
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            let payload = XstsTokenResponse {
                token,
                authorization,
                signature,
                expiry,
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::UserInfoRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let _req = quick_xml::de::from_str::<UserInfoRequest>(string_buf)?;

            let (rps_ticket, _) =
                exchange_msa_user_token(context, XBOX_LIVE_CLIENT_ID, "xboxlive.signin").await?;
            let ms_user_token = authenticate_xbox_user(&context.client, rps_ticket).await?;
            let xsts =
                request_xsts_token(&context.client, ms_user_token.token, DEFAULT_RELYING_PARTY)
                    .await?;

            let payload = UserInfoResponse {
                xuid: xsts.xuid().unwrap_or_default().to_string(),
                gamertag: xsts.gamertag().unwrap_or_default().to_string(),
                gamertag_modern: xsts.gamertag_modern().unwrap_or_default().to_string(),
                age_group: xsts.age_group().unwrap_or_default().to_string(),
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::LicenseRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<LicenseRequest>(string_buf)?;
            let market = if req.market.is_empty() {
                "neutral".to_string()
            } else {
                req.market
            };

            // A failed license fetch means "not entitled", not "request failed" - the
            // caller (XStoreQueryGameLicenseAsync) only has an isActive bool to report,
            // same honest-absence-over-fabricated-success stance as the rest of this file.
            let payload = match xodus::licensing::content::get_full_license(
                &context.client,
                context.tokens(),
                req.content_id,
                market,
            )
            .await
            {
                Ok((_key, splicense)) => LicenseResponse {
                    is_active: true,
                    expiration_date: splicense.license_expiration_time as i64,
                },
                Err(err) => {
                    log::warn!("License check failed: {err}");
                    LicenseResponse {
                        is_active: false,
                        expiration_date: 0,
                    }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::EntitledProductsRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<EntitledProductsRequest>(string_buf)?;
            let market = if req.market.is_empty() {
                "US".to_string()
            } else {
                req.market
            };

            let xsts = if let Some(cached) = context.tokens().get_cached_xsts(MP_RELYING_PARTY) {
                cached
            } else {
                let (rps_ticket, _) =
                    exchange_msa_user_token(context, XBOX_LIVE_CLIENT_ID, "xboxlive.signin")
                        .await?;
                let ms_user_token = authenticate_xbox_user(&context.client, rps_ticket).await?;
                let xsts =
                    request_xsts_token(&context.client, ms_user_token.token, MP_RELYING_PARTY)
                        .await?;
                context.tokens().cache_xsts(MP_RELYING_PARTY, &xsts);
                xsts
            };
            let xsts_header = get_xsts_auth_header(xsts);

            let ms_tokens =
                xodus::licensing::content::get_ms_compact_tokens(&context.client, context.tokens())
                    .await?;

            // Same honest-absence-over-fabricated-success stance as `LicenseRequest`: a
            // failed library fetch reports an empty entitlement list, not a request error.
            let payload = match xodus::api::xbox::services::get_library(
                &context.client,
                ms_tokens.user,
                xsts_header,
                market,
            )
            .await
            {
                Ok(library) => {
                    let products = library
                        .result
                        .product_ids
                        .iter()
                        .filter_map(|id| {
                            library
                                .product_summaries
                                .get(id)
                                .map(|summary| EntitledProduct {
                                    store_id: id.clone(),
                                    title: summary.title.clone(),
                                    product_kind: summary.product_kind.clone(),
                                    included_in_game_pass: summary.included_in_ultimate
                                        || summary.included_in_pcgp,
                                })
                        })
                        .collect();
                    EntitledProductsResponse { products }
                }
                Err(err) => {
                    log::warn!("Entitled products fetch failed: {err}");
                    EntitledProductsResponse { products: vec![] }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::CollectionsIdRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<CollectionsIdRequest>(string_buf)?;

            let ms_tokens =
                xodus::licensing::content::get_ms_compact_tokens(&context.client, context.tokens())
                    .await?;

            // Honest-absence-over-fabricated-success, same stance as LicenseRequest: a
            // failed fetch reports an empty key rather than a request error, since the
            // caller (XStoreGetUserCollectionsIdAsync) only has an opaque string to report.
            let payload = match xodus::licensing::content::get_collections_id(
                &context.client,
                ms_tokens.user,
                req.service_ticket,
                req.publisher_user_id,
            )
            .await
            {
                Ok(key) => CollectionsIdResponse { key },
                Err(err) => {
                    log::warn!("Collections id fetch failed: {err}");
                    CollectionsIdResponse { key: String::new() }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::LicenseTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<LicenseTokenRequest>(string_buf)?;

            let ms_tokens =
                xodus::licensing::content::get_ms_compact_tokens(&context.client, context.tokens())
                    .await?;
            let user = context.tokens().get_user()?;

            let payload = match xodus::licensing::content::get_license_token(
                &context.client,
                ms_tokens.user,
                user.puid,
                &req.product_ids,
                req.custom_developer_string,
            )
            .await
            {
                Ok(token) => LicenseTokenResponse { token },
                Err(err) => {
                    log::warn!("License token fetch failed: {err}");
                    LicenseTokenResponse {
                        token: String::new(),
                    }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::AssociatedProductsRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<AssociatedProductsRequest>(string_buf)?;
            let market = if req.market.is_empty() {
                "neutral".to_string()
            } else {
                req.market
            };
            let languages = vec!["en".to_string(), "neutral".to_string()];
            let max_items = if req.max_items == 0 {
                25
            } else {
                req.max_items
            };

            // Honest-absence-over-fabricated-success, same stance as EntitledProductsRequest:
            // no PFN (manifest not found/parsed by xodus-cli run), no resolvable ProductId, or
            // a failed catalog fetch all report an empty product list, never a request error -
            // there is no launch decision riding on this answer.
            let payload = if req.package_family_name.is_empty() {
                AssociatedProductsResponse { products: vec![] }
            } else {
                match xodus::api::displaycatalog::find_product_id_by_package_family_name(
                    &context.client,
                    &req.package_family_name,
                    &market,
                    &languages,
                )
                .await
                {
                    Ok(Some(parent_product_id)) => {
                        match xodus::api::displaycatalog::get_associated_products(
                            &context.client,
                            &parent_product_id,
                            &market,
                            &languages,
                            max_items,
                        )
                        .await
                        {
                            Ok(products) => AssociatedProductsResponse {
                                products: products
                                    .into_iter()
                                    .map(|p| AssociatedProductEntry {
                                        store_id: p.product_id,
                                        title: p.title,
                                        product_kind: p.product_kind,
                                    })
                                    .collect(),
                            },
                            Err(err) => {
                                log::warn!("Associated products fetch failed: {err}");
                                AssociatedProductsResponse { products: vec![] }
                            }
                        }
                    }
                    Ok(None) => {
                        log::warn!(
                            "No ProductId found for PackageFamilyName {}",
                            req.package_family_name
                        );
                        AssociatedProductsResponse { products: vec![] }
                    }
                    Err(err) => {
                        log::warn!("PackageFamilyName -> ProductId lookup failed: {err}");
                        AssociatedProductsResponse { products: vec![] }
                    }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::ResolveProductIdRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<ResolveProductIdRequest>(string_buf)?;
            let market = if req.market.is_empty() {
                "neutral".to_string()
            } else {
                req.market
            };
            let languages = vec!["en".to_string(), "neutral".to_string()];

            // Same honest-absence stance as AssociatedProductsRequest: no PFN, no match, or a
            // failed lookup all report an empty ProductId, never a request error.
            let payload = if req.package_family_name.is_empty() {
                ResolveProductIdResponse {
                    product_id: String::new(),
                }
            } else {
                match xodus::api::displaycatalog::find_product_id_by_package_family_name(
                    &context.client,
                    &req.package_family_name,
                    &market,
                    &languages,
                )
                .await
                {
                    Ok(product_id) => ResolveProductIdResponse {
                        product_id: product_id.unwrap_or_default(),
                    },
                    Err(err) => {
                        log::warn!("PackageFamilyName -> ProductId lookup failed: {err}");
                        ResolveProductIdResponse {
                            product_id: String::new(),
                        }
                    }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        _ => Err("Unimplemented".into()),
    }
}
