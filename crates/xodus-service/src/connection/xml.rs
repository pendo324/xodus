use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use xodus::{
    api::xbox::{
        auth::{
            authenticate_xbox_user, get_xsts_auth_header, request_xsts_token,
            request_xsts_token_for_title,
        },
        profile::get_gamer_picture,
        title::{get_endpoint, get_title_management},
    },
    models::{
        secrets::Token,
        soap,
        xbox::XstsResponse,
        xgameruntime::{
            xstore::{
                AssociatedProductsRequest, AssociatedProductsResponse, CatalogProductEntry,
                CollectionsIdRequest, CollectionsIdResponse, EntitledProduct,
                EntitledProductsRequest, EntitledProductsResponse, LicenseRequest, LicenseResponse,
                LicenseTokenRequest, LicenseTokenResponse, ProductsRequest, ProductsResponse,
                PurchaseIdRequest, PurchaseIdResponse, ResolveProductIdRequest,
                ResolveProductIdResponse,
            },
            xuser::{
                GamerPictureRequest, GamerPictureResponse, InteractiveSignInRequest,
                InteractiveSignInResponse, MSATokenRequest, MSATokenResponse, UserInfoRequest,
                UserInfoResponse, XstsTokenRequest, XstsTokenResponse,
            },
        },
    },
    proto::xodus::XodusMessageType,
};

use crate::{connection::Framing, simple_context::SimpleContext};

/// Xbox Live's own MSA app registration id - shared infrastructure, not a per-title
/// identity, so using it here doesn't run afoul of "never hardcode the title identity".
/// Used as the fallback in [`effective_client_id`] when a request didn't carry a real
/// per-title one.
const XBOX_LIVE_CLIENT_ID: &str = "000000004424da1f";

/// The `client_id` to use for a request's MSA/Xbox Live token exchange: the caller's own
/// `MSAAppId` (`xgameruntime-rs` reads it from the launched title's `MicrosoftGame.config`)
/// when it sent one, falling back to the shared [`XBOX_LIVE_CLIENT_ID`] for older clients or
/// titles with no `MicrosoftGame.config` to read one from.
fn effective_client_id(client_id: &str) -> &str {
    if client_id.is_empty() {
        XBOX_LIVE_CLIENT_ID
    } else {
        client_id
    }
}

/// Relying party used when Xbox Live's title-management endpoint table has no entry for
/// the requested URL - covers most everyday `*.xboxlive.com` calls.
const DEFAULT_RELYING_PARTY: &str = "http://xboxlive.com";

/// Relying party for the marketplace services, distinct from the Xbox Live one used
/// everywhere else in this file. Three callers want it:
///
/// - `beige.xboxservices.com`'s "My games" library (`XStoreQueryEntitledProductsAsync`),
///   whose `x-ms-authorization-social` header is issued against this party;
/// - `collections.mp.microsoft.com` and `purchase.mp.microsoft.com`'s store-ID keys
///   (`XStoreGetUserCollectionsIdAsync`/`XStoreGetUserPurchaseIdAsync`).
///
/// The trailing slash is load-bearing: `http://mp.microsoft.com` without it is not an entry
/// in Xbox Live's relying-party table and `xsts/authorize` refuses it with 400.
const MP_RELYING_PARTY: &str = "http://mp.microsoft.com/";

/// Relying party for PlayFab's `LoginWithXbox` (Minecraft's Marketplace, catalog, and
/// account-linking all sit behind it). The title-management endpoint table Xbox Live
/// serves does list `playfabapi.com` with this relying party, but only as a bare `fqdn`
/// entry with no wildcard - it never matches the per-title subdomains
/// (`<titleid>.playfabapi.com`) titles actually call, so `get_endpoint` falls through to
/// `DEFAULT_RELYING_PARTY` and PlayFab rejects the resulting token's audience with 400.
/// Special-cased here rather than widening `get_endpoint`'s matching, since that would
/// change matching semantics for every other bare-fqdn entry in the table too.
const PLAYFAB_RELYING_PARTY: &str = "http://playfab.xboxlive.com/";

/// Relying party for Minecraft Realms. Neither the host the title names when it asks for a
/// token (`pocket.realms.minecraft.net`) nor the one it actually calls
/// (`bedrock.frontendlegacy.realms.minecraft-services.net`) appears anywhere in the
/// title-management endpoint table, so `get_endpoint` finds nothing and the fallback
/// `DEFAULT_RELYING_PARTY` token is rejected by Realms with 401 on every request - no
/// worlds, no invites, no trial. Established by sweeping the plausible relying parties
/// against a real Realms endpoint; see `xodus/examples/realms_probe.rs`.
const REALMS_RELYING_PARTY: &str = "https://pocket.realms.minecraft.net/";

/// A catalog product in the shape the DLL reads it. Shared by `AssociatedProductsRequest` and
/// `ProductsRequest`, which differ only in how the products were chosen. The catalog's `MSRP` is
/// the wire's `base_price` and its `ListPrice` the `price`, matching the GDK's `XStorePrice`.
fn catalog_entry(product: xodus::models::displaycatalog::CatalogProduct) -> CatalogProductEntry {
    // Catalog listings, not credentials. An empty currency here is the difference between a
    // store page that shows a price and one that shows a blank, so it is worth naming.
    log::debug!(
        "catalog entry: store_id={} currency={:?} list_price={} msrp={}",
        product.product_id,
        product.price.currency_code,
        product.price.list_price,
        product.price.msrp
    );
    CatalogProductEntry {
        store_id: product.product_id,
        title: product.title,
        product_kind: product.product_kind,
        currency_code: product.price.currency_code,
        base_price: product.price.msrp,
        price: product.price.list_price,
        recurrence_price: product.price.recurrence_price,
        sale_end_date: product.price.sale_end_date,
    }
}

/// The MSA -> Xbox Live user-token exchange shared by `MsaTokenRequest` (which hands the
/// compact token straight back to the game) and `XstsTokenRequest` (which feeds it on
/// into the XSTS chain). Returns the compact RPS-ticket-shaped token used by both. Thin
/// wrapper over `xodus::licensing::content::exchange_msa_user_token` - the connection-scoped
/// device token is the only thing specific to a live `xodus-service` connection.
async fn exchange_msa_user_token(
    context: &SimpleContext,
    client_id: &str,
    scope: &str,
) -> Result<(String, i64), Box<dyn std::error::Error + Send + Sync>> {
    let device_token = context
        .device_token
        .as_ref()
        .ok_or("no device token on this connection")?;

    let result = xodus::licensing::content::exchange_msa_user_token(
        &context.client,
        context.tokens(),
        device_token.clone(),
        client_id,
        scope,
    )
    .await?;

    Ok((result.token, result.expiry))
}

/// The device and title tokens for `(client_id, title_id)`, or `None` if unavailable.
///
/// This runs the SISU flow, which authenticates as the title itself and hands back a
/// device token and a title token together. It is the only route to a title token: asking
/// `title.auth.xboxlive.com` directly answers 403 on both its RPS and proof-key flows.
///
/// Failure is reported as `None` rather than an error, and the caller falls back to the
/// plain user-only token. A token without a title claim still serves every endpoint that
/// does not resolve "the current title", which is nearly all of them - so a SISU outage
/// should cost presence only, not sign-in, the friends list, or the player's profile.
async fn title_claim(
    context: &SimpleContext,
    client_id: &str,
    title_id: &str,
) -> Option<crate::token_cache::TitleClaim> {
    // SISU takes the title id as a number; a title that sent something else can't be
    // authenticated as, so fall back rather than guessing at one.
    let parsed_title_id = match title_id.parse::<i64>() {
        Ok(title_id) => title_id,
        Err(_) => return None,
    };

    let result = crate::token_cache::title_claim(client_id, title_id, || async {
        // `do_sisu` boxes a plain `dyn Error`, which isn't `Send`; render it here so the
        // failure can cross the await boundary as a message.
        let (_, response, device) =
            xodus::auth::do_sisu(&context.client, context.tokens(), client_id, parsed_title_id)
                .await
                .map_err(|err| err.to_string())?;
        let expiry = response.title_token.not_after.min(device.not_after);
        Ok::<_, String>((
            crate::token_cache::TitleClaim {
                device_token: device.token,
                title_token: response.title_token.token,
            },
            expiry,
        ))
    })
    .await;

    match result {
        Ok(claim) => Some(claim),
        Err(err) => {
            log::warn!(
                "SISU title authentication failed for client {client_id} title {title_id}, \
                 minting XSTS tokens without a title claim - presence will not update: {err}"
            );
            None
        }
    }
}

/// The XSTS token for one relying party, served from [`crate::token_cache`] whenever a
/// live one is already in hand. Both the MSA -> user-token half of the chain and the XSTS
/// half are cached, so a warm relying party costs no network at all and a cold one costs
/// only the `xsts/authorize` call.
///
/// When the title told us its id, the minted token also carries a title claim. Endpoints
/// that resolve "the current title" from the token - presence's
/// `/devices/current/titles/current` above all - answer `ArgumentError` to a user-only
/// token, which is why the player showed as offline while playing.
async fn xsts_token(
    context: &SimpleContext,
    client_id: &str,
    title_id: &str,
    relying_party: &str,
    force_refresh: bool,
) -> Result<XstsResponse, Box<dyn std::error::Error + Send + Sync>> {
    let client_id = effective_client_id(client_id);

    crate::token_cache::xsts_token(client_id, relying_party, force_refresh, || async {
        let user_token = crate::token_cache::user_token(client_id, || async {
            let (rps_ticket, _) =
                exchange_msa_user_token(context, client_id, "xboxlive.signin").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                authenticate_xbox_user(&context.client, rps_ticket).await?,
            )
        })
        .await?;

        // No title id (an older client, or a title with no `MicrosoftGame.config`) means
        // no title claim is obtainable, so don't spend a SISU round trip finding out.
        let claim = if title_id.is_empty() {
            None
        } else {
            title_claim(context, client_id, title_id).await
        };

        match claim {
            Some(claim) => Ok(request_xsts_token_for_title(
                &context.client,
                context.tokens(),
                user_token.token,
                claim.device_token,
                claim.title_token,
                relying_party,
            )
            .await?),
            None => Ok(request_xsts_token(&context.client, user_token.token, relying_party).await?),
        }
    })
    .await
}

/// An `XBL3.0` header for the [`MP_RELYING_PARTY`] marketplace services, cached.
///
/// A user-only token, with no title claim: none of the three callers resolve "the current
/// title" from it the way presence does, and the store-ID key endpoints were verified to
/// accept one.
async fn mp_xsts_header(
    context: &SimpleContext,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let xsts = if let Some(cached) = context.tokens().get_cached_xsts(MP_RELYING_PARTY) {
        cached
    } else {
        let (rps_ticket, _) =
            exchange_msa_user_token(context, XBOX_LIVE_CLIENT_ID, "xboxlive.signin").await?;
        let ms_user_token = authenticate_xbox_user(&context.client, rps_ticket).await?;
        let xsts = request_xsts_token(&context.client, ms_user_token.token, MP_RELYING_PARTY)
            .await?;
        context.tokens().cache_xsts(MP_RELYING_PARTY, &xsts);
        xsts
    };
    Ok(get_xsts_auth_header(xsts))
}

/// The relying party for hosts the title-management endpoint table cannot resolve, or
/// `None` to consult the table as usual.
///
/// Both entries here are services Xbox Live authenticates for but does not list, so the
/// table's answer would be the `DEFAULT_RELYING_PARTY` fallback and the service would
/// reject the token's audience. Matching on the host rather than widening `get_endpoint`
/// keeps the table's matching semantics unchanged for every entry that *is* listed.
fn unlisted_relying_party(host: &str) -> Option<&'static str> {
    let host = host.to_ascii_lowercase();
    if host == "playfabapi.com" || host.ends_with(".playfabapi.com") {
        return Some(PLAYFAB_RELYING_PARTY);
    }
    // `pocket.realms.minecraft.net` is the host the title names in its token request;
    // the `minecraft-services.net` one is where the requests actually go, covered too in
    // case a title ever asks for a token against it directly.
    if host == "pocket.realms.minecraft.net" || host.ends_with(".realms.minecraft-services.net") {
        return Some(REALMS_RELYING_PARTY);
    }
    None
}

/// The relying party to mint a token for, given the URL the title wants to call.
async fn relying_party_for(context: &SimpleContext, url: &str) -> String {
    let unlisted = reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().and_then(unlisted_relying_party));
    if let Some(relying_party) = unlisted {
        return relying_party.to_string();
    }

    let endpoints =
        crate::token_cache::title_endpoints(|| get_title_management(&context.client)).await;
    match endpoints {
        Ok(endpoints) => get_endpoint(url, &endpoints)
            .and_then(|e| e.relying_party.clone())
            .unwrap_or_else(|| DEFAULT_RELYING_PARTY.to_string()),
        Err(err) => {
            log::warn!(
                "Failed to fetch title-management endpoints, falling back to {DEFAULT_RELYING_PARTY}: {err}"
            );
            DEFAULT_RELYING_PARTY.to_string()
        }
    }
}

/// The `UserInfoRequest` lookup (whichever user's credentials are on this connection),
/// shared with `InteractiveSignInRequest`'s post-sign-in lookup so both answer from the
/// exact same MSA -> XSTS chain.
async fn build_user_info(
    context: &SimpleContext,
    client_id: &str,
    title_id: &str,
) -> Result<UserInfoResponse, Box<dyn std::error::Error + Send + Sync>> {
    // The identity claims read below need no title claim, but this is the first token a
    // title asks for, and it is cached under `DEFAULT_RELYING_PARTY` for every later Xbox
    // Live call - presence included. Minting it claimless here is enough to leave presence
    // answering `ArgumentError` for the rest of the session.
    let xsts = xsts_token(context, client_id, title_id, DEFAULT_RELYING_PARTY, false).await?;

    Ok(UserInfoResponse {
        xuid: xsts.xuid().unwrap_or_default().to_string(),
        gamertag: xsts.gamertag().unwrap_or_default().to_string(),
        gamertag_modern: xsts.gamertag_modern().unwrap_or_default().to_string(),
        age_group: xsts.age_group().unwrap_or_default().to_string(),
    })
}

/// Locates the `xodus-cli` binary to spawn for interactive sign-in: an explicit override
/// (useful for dev/test setups where the two binaries aren't installed side by side),
/// then the sibling of this process's own executable (the normal installed layout), then
/// falling back to bare `PATH` lookup.
fn resolve_xodus_cli_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("XODUS_CLI_PATH") {
        return path.into();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(if cfg!(windows) {
                "xodus-cli.exe"
            } else {
                "xodus-cli"
            });
            if candidate.exists() {
                return candidate;
            }
        }
    }
    "xodus-cli".into()
}

/// Spawns `xodus-cli login` and waits for it to exit. That subcommand is fully
/// self-sufficient (it initializes its own secrets store and device credentials before
/// showing the webview, same as running it directly from a terminal) and already persists
/// whatever it signs in to the same keychain-backed `TokenManager` this service uses, so
/// there is nothing else to wire up here beyond waiting for it to finish.
async fn run_interactive_sign_in() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli_path = resolve_xodus_cli_path();
    let status = tokio::process::Command::new(cli_path)
        .arg("login")
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err("xodus-cli login exited with a failure status".into())
    }
}

/// Reply type sent instead of `message_type + 1` when [`parse_message`] fails. Every
/// real `XodusMessageType` is a small enum discriminant, so this value can never collide
/// with a legitimate `request_type + 1`. The body is the error's `Display` text, UTF-8,
/// unencoded - this is diagnostic-only and never carries credential data (the errors it
/// wraps are plumbing failures: connection/serialization/HTTP-status, not token bodies).
///
/// Without this, a transient failure partway through a request (e.g. a token exchange
/// that fails against a real Microsoft endpoint) was indistinguishable on the wire from
/// "legitimately empty success", which callers on the other end could not tell apart from
/// their own deserialization errors.
pub const ERROR_REPLY_TYPE: u16 = 0xFFFF;

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

    let (reply_type, out_buf) = match parse_message(context, message_type, buffer).await {
        Ok(buf) => (message_type as u16 + 1, buf),
        Err(err) => {
            log::error!("Failed parsing message: {err}");
            (ERROR_REPLY_TYPE, err.to_string().into_bytes())
        }
    };

    // Reply in the framing the client asked in, so a v1 client is never handed a
    // header it cannot parse.
    let data = super::encode_message(framing.xml_magic(), reply_type, framing, out_buf)?;
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

            let relying_party = relying_party_for(context, &req.url).await;
            let xsts =
                xsts_token(
                    context,
                    &req.client_id,
                    &req.title_id,
                    &relying_party,
                    req.force_refresh,
                )
                .await?;
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
            let req = quick_xml::de::from_str::<UserInfoRequest>(string_buf)?;

            let payload = build_user_info(context, &req.client_id, &req.title_id).await?;
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::InteractiveSignInRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<InteractiveSignInRequest>(string_buf)?;

            let payload = match run_interactive_sign_in().await {
                Ok(()) => {
                    // Whoever just signed in may not be who the cached tokens belong to.
                    crate::token_cache::invalidate_user_tokens();
                    match build_user_info(context, &req.client_id, &req.title_id).await {
                        Ok(info) => InteractiveSignInResponse {
                            success: true,
                            xuid: info.xuid,
                            gamertag: info.gamertag,
                            gamertag_modern: info.gamertag_modern,
                            age_group: info.age_group,
                        },
                        Err(err) => {
                            log::warn!(
                                "Interactive sign-in completed but the user info lookup failed: {err}"
                            );
                            InteractiveSignInResponse {
                                success: false,
                                xuid: String::new(),
                                gamertag: String::new(),
                                gamertag_modern: String::new(),
                                age_group: String::new(),
                            }
                        }
                    }
                }
                Err(err) => {
                    log::warn!("Interactive sign-in did not complete: {err}");
                    InteractiveSignInResponse {
                        success: false,
                        xuid: String::new(),
                        gamertag: String::new(),
                        gamertag_modern: String::new(),
                        age_group: String::new(),
                    }
                }
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::GamerPictureRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<GamerPictureRequest>(string_buf)?;

            let (rps_ticket, _) = exchange_msa_user_token(
                context,
                effective_client_id(&req.client_id),
                "xboxlive.signin",
            )
            .await?;
            let ms_user_token = authenticate_xbox_user(&context.client, rps_ticket).await?;
            let xsts =
                request_xsts_token(&context.client, ms_user_token.token, DEFAULT_RELYING_PARTY)
                    .await?;
            let xsts_header = get_xsts_auth_header(xsts);

            let picture = get_gamer_picture(&context.client, &xsts_header).await?;

            use base64::prelude::*;
            let payload = GamerPictureResponse {
                picture: picture
                    .map(|bytes| BASE64_STANDARD.encode(bytes))
                    .unwrap_or_default(),
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

            let xsts_header = mp_xsts_header(context).await?;

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

            // Sizes, not values: `service_ticket` is a caller-supplied credential. Whether
            // the title sent one at all is the first thing to check when the endpoint 400s,
            // and that much is safe to write to a log.
            log::debug!(
                "Collections id request: service_ticket {} bytes, publisher_user_id {} bytes",
                req.service_ticket.len(),
                req.publisher_user_id.len()
            );

            // Honest-absence-over-fabricated-success, same stance as LicenseRequest: a
            // failed fetch reports an empty key rather than a request error, since the
            // caller (XStoreGetUserCollectionsIdAsync) only has an opaque string to report.
            let payload = match xodus::licensing::content::get_collections_id(
                &context.client,
                mp_xsts_header(context).await?,
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
        XodusMessageType::PurchaseIdRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<PurchaseIdRequest>(string_buf)?;

            // Sizes, not values - same reasoning as CollectionsIdRequest above.
            log::debug!(
                "Purchase id request: service_ticket {} bytes, publisher_user_id {} bytes",
                req.service_ticket.len(),
                req.publisher_user_id.len()
            );

            let payload = match xodus::licensing::content::get_purchase_id(
                &context.client,
                mp_xsts_header(context).await?,
                req.service_ticket,
                req.publisher_user_id,
            )
            .await
            {
                Ok(key) => PurchaseIdResponse { key },
                Err(err) => {
                    log::warn!("Purchase id fetch failed: {err}");
                    PurchaseIdResponse { key: String::new() }
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
                                    .map(catalog_entry)
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
        XodusMessageType::ProductsRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<ProductsRequest>(string_buf)?;
            let market = if req.market.is_empty() {
                "neutral".to_string()
            } else {
                req.market
            };
            let languages = vec!["en".to_string(), "neutral".to_string()];

            // Same honest-absence stance as AssociatedProductsRequest: no ids to look up or a
            // failed catalog fetch report an empty list, never a request error. An in-game
            // storefront that gets nothing back shows no prices, which is what it should do -
            // fabricating one would be quoting the player a number we made up.
            let products = if req.store_ids.is_empty() {
                vec![]
            } else {
                match xodus::api::displaycatalog::get_products_by_id(
                    &context.client,
                    &req.store_ids,
                    &market,
                    &languages,
                )
                .await
                {
                    Ok(products) => products,
                    Err(err) => {
                        log::warn!("Products fetch failed: {err}");
                        vec![]
                    }
                }
            };
            let payload = ProductsResponse {
                products: products.into_iter().map(catalog_entry).collect(),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xodus::{models::secrets::LegacyToken, tokens::TokenManager};

    use super::*;
    use crate::connection::{self, Framing};

    #[test]
    fn unlisted_hosts_get_their_own_relying_party() {
        // The per-title subdomain, which is the form titles actually call.
        assert_eq!(
            unlisted_relying_party("b980a380.minecraft.playfabapi.com"),
            Some(PLAYFAB_RELYING_PARTY)
        );
        assert_eq!(
            unlisted_relying_party("pocket.realms.minecraft.net"),
            Some(REALMS_RELYING_PARTY)
        );
        assert_eq!(
            unlisted_relying_party("bedrock.frontendlegacy.realms.minecraft-services.net"),
            Some(REALMS_RELYING_PARTY)
        );
        // A suffix match must not be fooled by a host that merely ends the same way.
        assert_eq!(unlisted_relying_party("notplayfabapi.com"), None);
        // Anything the endpoint table does list has to keep falling through to it.
        assert_eq!(unlisted_relying_party("userpresence.xboxlive.com"), None);
    }

    fn dummy_context() -> SimpleContext {
        let device_token = LegacyToken {
            key_name: None,
            token: "unused-by-this-test".into(),
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: "2026-01-01T00:00:00Z".into(),
                expires: "2036-01-01T00:00:00Z".into(),
            },
        };
        SimpleContext::new(device_token, Arc::new(TokenManager::with_memory()))
    }

    /// A message type `parse_message` has no handler for hits its catch-all `Err`, without
    /// any network I/O - the cheapest way to deterministically exercise `handle()`'s error
    /// branch. Before the fix, this reply was indistinguishable on the wire from a
    /// legitimately empty success (empty body at `msg_type + 1`); now it must come back as
    /// `ERROR_REPLY_TYPE` with the error text as the body.
    #[tokio::test]
    async fn handle_reports_a_distinguishable_error_instead_of_a_silent_empty_success() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut context = dummy_context();

        const PONG: u16 = XodusMessageType::Pong as u16;
        let magic = Framing::V2.xml_magic();
        let full_request =
            connection::encode_message(magic, PONG, Framing::V2, vec![]).expect("encodes");
        // `handle()` expects the magic already stripped, same as `router::route` does
        // before dispatching to it.
        let request = &full_request[4..];

        let task =
            tokio::spawn(async move { handle(&mut server, &mut context, Framing::V2).await });
        client.write_all(request).await.expect("send request");

        let mut reply_magic = [0u8; 4];
        client
            .read_exact(&mut reply_magic)
            .await
            .expect("read magic");
        assert_eq!(u32::from_le_bytes(reply_magic), magic);

        let (reply_type, body) = connection::read_message(&mut client, Framing::V2)
            .await
            .expect("reads reply");

        assert_eq!(
            reply_type, ERROR_REPLY_TYPE,
            "an internal error must not be reported as a bare success at msg_type + 1"
        );
        assert_ne!(
            reply_type,
            PONG + 1,
            "must not collide with a legitimate success reply type"
        );
        assert!(
            !body.is_empty(),
            "the error text should be forwarded, not silently dropped"
        );

        task.await.expect("handle task").expect("handle io");
    }
}
