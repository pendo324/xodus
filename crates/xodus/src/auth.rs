use reqwest::Client;
use xal::client_params::CLIENT_WINDOWS;
use xal::oauth2::basic::BasicTokenType;
use xal::oauth2::{EmptyExtraTokenFields, RedirectUrl, Scope, StandardTokenResponse};
use xal::response::{
    XADDisplayClaims, XATDisplayClaims, XAUDisplayClaims, XSTSDisplayClaims, XTokenResponse,
};
use xal::{
    AuthPromptCallback, Constants, DeviceType, Flows, TokenStore, XalAppParameters,
    XalAuthenticator,
};

use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::Token;
use crate::models::soap;
use crate::tokens::TokenManager;

/// The MSA app and Xbox Live title a request authenticates as.
///
/// GDK titles carry their own `TitleId`/`ServiceConfigId` in `MicrosoftGame.config` and
/// Xbox Live scopes tokens to them, so this is per-caller rather than a constant. Use
/// [`TitleIdentity::xodus`] for xodus' own requests.
#[derive(Debug, Clone)]
pub struct TitleIdentity {
    pub client_id: String,
    pub title_id: Option<String>,
}

impl TitleIdentity {
    /// The identity xodus itself authenticates as, for requests not made on behalf of
    /// a specific title (licensing, package downloads, the CLI).
    pub fn xodus() -> Self {
        Self {
            client_id: "000000004424da1f".to_string(),
            title_id: Some("704208617".into()),
        }
    }

    pub fn new(client_id: impl Into<String>, title_id: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            title_id,
        }
    }

    pub fn app_params(&self) -> XalAppParameters {
        XalAppParameters {
            client_id: self.client_id.clone(),
            title_id: self.title_id.clone(),
            auth_scopes: vec![Scope::new(
                xal::Constants::SCOPE_SERVICE_USER_AUTH.to_owned(),
            )],
            redirect_uri: Some(
                RedirectUrl::new(xal::Constants::OAUTH20_DESKTOP_REDIRECT_URL.into()).unwrap(),
            ),
            client_secret: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("credential store error: {0}")]
    TokenStore(#[from] crate::tokens::store::TokenStoreError),
    #[error(transparent)]
    Xal(#[from] xal::Error),
}

/// Build an authenticator bound to this device's persisted Xbox Live identity.
///
/// [`XalAuthenticator::new`] generates a fresh proof key and device id per instance,
/// which makes every instance a different device as far as Xbox Live is concerned and
/// leaves issued tokens unsignable afterwards. Everything that talks to Xbox Live
/// should go through here so it presents the one stored identity.
pub fn authenticator(
    tokens: &TokenManager,
    identity: &TitleIdentity,
) -> Result<XalAuthenticator, AuthError> {
    authenticator_with_client_params(tokens, identity, CLIENT_WINDOWS())
}

/// [`authenticator`] with non-default client parameters.
pub fn authenticator_with_client_params(
    tokens: &TokenManager,
    identity: &TitleIdentity,
    client_params: xal::XalClientParameters,
) -> Result<XalAuthenticator, AuthError> {
    let device = tokens.get_or_create_xbl_device_identity()?;

    let mut authenticator = XalAuthenticator::with_device_id(
        identity.app_params(),
        client_params,
        "RETAIL".into(),
        device.device_id,
    );
    authenticator.set_request_signer(device.signer);

    Ok(authenticator)
}

pub async fn start_new_session(
    tokens: &TokenManager,
    identity: &TitleIdentity,
    cb: impl AuthPromptCallback,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let mut authenticator = authenticator(tokens, identity)?;
    let ts = Flows::ms_authorization_flow(&mut authenticator, cb, true).await?;
    let ts = Flows::xbox_live_authorization_traditional_flow(
        &mut authenticator,
        ts.live_token,
        Constants::RELYING_PARTY_XBOXLIVE.to_string(),
        xal::AccessTokenPrefix::None,
        false,
    )
    .await?;
    Ok(ts)
}

/// Request an Xbox Live device token, proving possession of the persisted proof key.
///
/// The resulting token - and any XSTS token minted from it - is bound to that key, so
/// only [`sign_header_for_url`] using the same [`TokenManager`] can sign for it.
pub async fn get_device_token(
    tokens: &TokenManager,
    identity: &TitleIdentity,
) -> Result<XTokenResponse<XADDisplayClaims>, AuthError> {
    Ok(authenticator(tokens, identity)?.get_device_token().await?)
}

pub async fn get_xsts_token(
    tokens: &TokenManager,
    identity: &TitleIdentity,
    device_token: Option<&XTokenResponse<XADDisplayClaims>>,
    title_token: Option<&XTokenResponse<XATDisplayClaims>>,
    user_token: Option<&XTokenResponse<XAUDisplayClaims>>,
    relying_party: &str,
) -> Result<XTokenResponse<XSTSDisplayClaims>, AuthError> {
    Ok(authenticator(tokens, identity)?
        .get_xsts_token(device_token, title_token, user_token, relying_party)
        .await?)
}

/// The signature policies for every Xbox Live endpoint, fetched once per process.
///
/// Despite its name [`xal::SignaturePolicyCache`] caches nothing across calls - it is a
/// wrapper over one already-fetched document, and [`xal::get_endpoints`] behind it is an
/// unconditional HTTPS GET on a *freshly constructed* `reqwest::Client`, so it cannot even
/// reuse a connection. Building one per signature put a full DNS+TLS+request round trip
/// (~130ms here) in front of every signed request, which is most of them: with the XSTS
/// token chain cached, this was ~97% of the latency the title saw on a token call, and a
/// title that makes a few hundred of them spent the better part of a minute on it.
///
/// Caching for the life of the process is what the document is for. It is a static
/// manifest of which URL prefixes require a signature and at what policy version - it
/// describes the service's shape, not any session or credential of ours - and Microsoft's
/// own clients persist it across runs. A process-lifetime cache is strictly less stale
/// than that, and the failure mode of a policy that changed mid-session is a request
/// signed under the previous version, which the service accepts.
async fn signature_policies() -> Result<&'static xal::SignaturePolicyCache, AuthError> {
    static POLICIES: tokio::sync::OnceCell<xal::SignaturePolicyCache> =
        tokio::sync::OnceCell::const_new();
    POLICIES
        .get_or_try_init(|| async {
            Ok(xal::SignaturePolicyCache::new(xal::get_endpoints().await?))
        })
        .await
}

/// Compute the `Signature` header for a request to a signature-policy-covered endpoint.
///
/// Returns `Ok(None)` when no policy covers `url`, i.e. when the request is sent
/// unsigned. This is the entry point `XUserGetTokenAndSignature` is built on: it hands
/// over the request parts and expects a header value back.
///
/// [`xal::RequestSigner`] resolves policies from its own `signature_policy_cache`, which
/// starts empty on a freshly loaded/created identity - without populating it here every
/// call would silently report "no policy covers this URL" and send requests unsigned,
/// even for endpoints (e.g. PlayFab) that reject unsigned ones.
pub async fn sign_header_for_url(
    tokens: &TokenManager,
    url: &str,
    method: &str,
    authorization: &str,
    body: &[u8],
) -> Result<Option<String>, AuthError> {
    let mut identity = tokens.get_or_create_xbl_device_identity()?;
    identity.signer.signature_policy_cache = signature_policies().await?.clone();
    Ok(identity
        .signer
        .sign_header_for_url(url, method, authorization, body, None)
        .await?)
}

pub async fn refresh_tokens(
    authenticator: &mut XalAuthenticator,
    live_token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let ts = Flows::xbox_live_sisu_authorization_flow(authenticator, live_token).await?;
    Ok(ts)
}

pub async fn do_sisu(
    client: &Client,
    manager: &TokenManager,
    client_id: &str,
    title_id: i64,
) -> Result<
    (
        XalAuthenticator,
        xal::response::SisuRPSAuthorizationResponse,
        xal::response::DeviceToken,
    ),
    Box<dyn std::error::Error>,
> {
    let Token::Legacy(token) = manager.get_user_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let scope = "xboxlive.signin";
    let Token::Legacy(device_token) = manager.get_device_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let device_token_resp: soap::RequestSecurityTokenResponse =
        crate::api::live::exchange_device_token(
            client,
            device_token.clone(),
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await?;

    let Token::Compact(ms_device_token) = device_token_resp.into() else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let user_token = crate::api::live::exchange_user_token(
        client,
        token,
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
    .await?;

    let ExchangeUserTokenOutcome::Issued(
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
    ) = user_token
    else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    if let Some(sts) = collection.security_tokens.pop() {
        let address = sts.applies_to.endpoint_reference.address.clone();
        let sts: Token = sts.into();
        let address = if let Token::Legacy(legacy) = &sts {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        if let Err(err) = manager.save_user_token(address, sts) {
            log::warn!("Failed to persist refreshed STS token: {err}");
        }
    }
    let token: soap::RequestSecurityTokenResponse = collection.security_tokens.remove(0);
    let token: Token = token.into();
    let Token::Compact(user_token) = token else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let mut auth = authenticator_with_client_params(
        manager,
        &TitleIdentity::new(client_id, Some(title_id.to_string())),
        xal::XalClientParameters {
            user_agent: "XAL GRTS 2025.11.20251105.000".to_string(),
            device_type: DeviceType::WIN32,
            client_version: "10.0.22621".to_string(),
            query_display: String::new(),
        },
    )?;

    let data = auth
        .get_device_token_rps(ms_device_token.to_owned())
        .await?;
    let resp = auth
        .sisu_authorize_rps(&user_token, &data.token, None)
        .await
        .expect("ok");
    Ok((auth, resp, data))
}

#[ignore]
#[tokio::test]
async fn test_minecraft_win_auth() {
    let client = reqwest::Client::new();
    crate::secrets::init_secrets().expect("Unable to initialize credentials");
    let tokens = TokenManager::with_keychain_and_memory();

    let (_, resp, _) = do_sisu(&client, &tokens, "0000000040159362", 896928775)
        .await
        .expect("ok");

    println!("title {}", resp.title_token.token);
    println!("user {}", resp.user_token.token);
    println!("webpage {}", resp.web_page);
}
