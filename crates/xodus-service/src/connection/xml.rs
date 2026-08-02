use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use xodus::{
    api::xbox::{
        auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token},
        title::{get_endpoint, get_title_management},
    },
    models::{
        secrets::Token,
        soap,
        xgameruntime::xuser::{
            MSATokenRequest, MSATokenResponse, XstsTokenRequest, XstsTokenResponse,
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
        _ => Err("Unimplemented".into()),
    }
}
