//! Diagnostic probe for the "player shows offline while playing" bug.
//!
//! Presence's `POST /users/xuid({xuid})/devices/current/titles/current` answers
//! `400 {"code":"ArgumentError"}` for us. The endpoint resolves *which* device and
//! *which* title from claims carried by the XSTS token rather than from the request
//! body, and our token chain is user-token -> XSTS, so it only ever carries `xui`.
//!
//! This walks the token chain three ways - user only, user+device, user+device+title -
//! prints the display claims each one comes back with, and then attempts the real
//! presence write with each. The point is to find out which claim the service is
//! actually missing before changing any production path.
//!
//! Run with: cargo run -p xodus --example presence_probe

use xodus::{
    api::xbox::auth::authenticate_xbox_user,
    auth::{self, TitleIdentity},
    licensing::content::exchange_msa_user_token,
    models::secrets::Token,
    tokens::TokenManager,
};

/// Xbox Live's own MSA app registration id, as used by `xodus-service` and the CLI.
const XBOX_LIVE_CLIENT_ID: &str = "000000004424da1f";

/// Minecraft Bedrock, from `MicrosoftGame.Config`'s `<TitleId>35760C07`.
const MINECRAFT_TITLE_ID: i64 = 0x35760C07;

/// What `relying_party_for` resolves userpresence.xboxlive.com to.
const RELYING_PARTY: &str = "http://xboxlive.com";

const XSTS_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";

/// The exact body the title sends, captured from `XUserGetTokenAndSignatureAsync`.
const PRESENCE_BODY: &str =
    r#"{"state":"active","activity":{"richPresence":{"id":"Menus","scid":"4fc10100-5f7a-4470-899b-280835760c07"}}}"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    xodus::secrets::init_secrets()?;
    let tokens = TokenManager::with_keychain_and_memory();
    xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;
    let identity = TitleIdentity::new(XBOX_LIVE_CLIENT_ID, Some(MINECRAFT_TITLE_ID.to_string()));

    // --- user token: the one leg we already have in production ---
    let Token::Legacy(msa_device_token) = tokens.get_device_sts_token()? else {
        return Err("invalid device STS token".into());
    };
    let rps = exchange_msa_user_token(
        &client,
        &tokens,
        msa_device_token,
        XBOX_LIVE_CLIENT_ID,
        "xboxlive.signin",
    )
    .await?;
    let rps_ticket = rps.token.clone();
    let user_token = authenticate_xbox_user(&client, rps.token).await?.token;
    println!("user token:   ok ({} bytes)", user_token.len());

    // --- device token: proof-of-possession against the persisted device key ---
    let device_token = match auth::get_device_token(&tokens, &identity).await {
        Ok(token) => {
            println!("device token: ok (valid until {})", token.not_after);
            Some(token.token)
        }
        Err(err) => {
            println!("device token: FAILED: {err}");
            None
        }
    };

    // --- title token: needs the device token and the title id, but no user token ---
    let title_token = match (&device_token, auth::authenticator(&tokens, &identity)) {
        (Some(device), Ok(mut authenticator)) => {
            match authenticator
                .get_title_token_win(device, MINECRAFT_TITLE_ID)
                .await
            {
                Ok(token) => {
                    println!("title token:  ok (valid until {})", token.not_after);
                    Some(token.token)
                }
                Err(err) => {
                    println!("title token:  FAILED: {err}");
                    None
                }
            }
        }
        (_, Err(err)) => {
            println!("title token:  FAILED to build authenticator: {err}");
            None
        }
        _ => {
            println!("title token:  skipped (no device token)");
            None
        }
    };

    // xal only reports "JSON Deserialization" when title auth fails, which hides the
    // service's actual complaint. Repeat the request by hand to see the real body.
    if let Some(device) = &device_token {
        raw_title_token(&client, &tokens, device).await;
        raw_title_token_rps(&client, &tokens, device, &rps_ticket).await;
    }

    let cases: Vec<(&str, Option<&String>, Option<&String>)> = vec![
        ("user only (what production does today)", None, None),
        ("user + device", device_token.as_ref(), None),
        (
            "user + device + title",
            device_token.as_ref(),
            title_token.as_ref(),
        ),
    ];

    for (label, device, title) in cases {
        println!("\n=== {label} ===");
        match mint_xsts(&client, &tokens, &user_token, device, title).await {
            Ok((token, uhs, claims)) => {
                println!("  claims: {claims}");
                presence_write(&client, &tokens, &token, &uhs).await;
            }
            Err(err) => println!("  xsts FAILED: {err}"),
        }
    }

    sisu_case(&client, &tokens).await;

    Ok(())
}

/// Minecraft's own MSA client id, from the `test_minecraft_win_auth` prototype.
const MINECRAFT_CLIENT_ID: &str = "0000000040159362";

/// The SISU flow, which issues device, title and user tokens together.
///
/// `title/authenticate` refuses us outright (403) on both its RPS and proof-key flows,
/// so this is the only route to a title claim. It authenticates as the *title* rather
/// than as the Xbox app, which is presumably why the service is willing.
async fn sisu_case(client: &reqwest::Client, tokens: &TokenManager) {
    println!("\n=== SISU (title-authenticated) ===");
    let (_auth, resp, device) =
        match auth::do_sisu(client, tokens, MINECRAFT_CLIENT_ID, MINECRAFT_TITLE_ID).await {
            Ok(result) => result,
            Err(err) => return println!("  do_sisu FAILED: {err}"),
        };
    println!("  title token: ok ({} bytes)", resp.title_token.token.len());
    println!("  user token:  ok ({} bytes)", resp.user_token.token.len());

    // SISU hands back a ready-made XSTS token; try it as-is first.
    let xsts = &resp.authorization_token;
    let uhs = xsts
        .display_claims
        .as_ref()
        .and_then(|claims| claims.xui.first())
        .and_then(|claim| claim.get("uhs"))
        .cloned()
        .unwrap_or_default();
    println!("  sisu xsts claims: {:?}", xsts.display_claims);
    if uhs.is_empty() {
        return println!("  no uhs in SISU authorization token; cannot build XBL3.0 header");
    }
    presence_write(client, tokens, &xsts.token, &uhs).await;

    // And mint one ourselves with all three claims, in case the SISU-issued token is
    // scoped to a relying party presence does not accept.
    println!("  -- self-minted XSTS with device+title+user --");
    match mint_xsts(
        client,
        tokens,
        &resp.user_token.token,
        Some(&device.token),
        Some(&resp.title_token.token),
    )
    .await
    {
        Ok((token, uhs, claims)) => {
            println!("  claims: {claims}");
            presence_write(client, tokens, &token, &uhs).await;
        }
        Err(err) => println!("  xsts FAILED: {err}"),
    }
}

/// Issue `title/authenticate` directly and print the raw status and body.
async fn raw_title_token(client: &reqwest::Client, tokens: &TokenManager, device_token: &str) {
    const URL: &str = "https://title.auth.xboxlive.com/title/authenticate";

    let identity = match tokens.get_or_create_xbl_device_identity() {
        Ok(identity) => identity,
        Err(err) => return println!("\ntitle auth: no device identity: {err}"),
    };
    let body = match serde_json::to_vec(&serde_json::json!({
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "ProofKey": identity.signer.get_proof_key(),
            "DeviceToken": device_token,
            "TitleId": MINECRAFT_TITLE_ID,
        },
    })) {
        Ok(body) => body,
        Err(err) => return println!("\ntitle auth: serialize failed: {err}"),
    };

    let mut request = client
        .post(URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");
    if let Ok(Some(signature)) = auth::sign_header_for_url(tokens, URL, "POST", "", &body).await {
        request = request.header("Signature", signature);
    }

    match request.body(body).send().await {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let text: String = text.chars().take(400).collect();
            println!("\ntitle auth: HTTP {status} {text}");
        }
        Err(err) => println!("\ntitle auth: request failed: {err}"),
    }
}

/// `title/authenticate` via the RPS flow rather than the proof-key/`TitleId` one, using
/// the same MSA ticket the user-token leg already gets.
async fn raw_title_token_rps(
    client: &reqwest::Client,
    tokens: &TokenManager,
    device_token: &str,
    rps_ticket: &str,
) {
    const URL: &str = "https://title.auth.xboxlive.com/title/authenticate";

    let body = match serde_json::to_vec(&serde_json::json!({
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": rps_ticket,
            "DeviceToken": device_token,
        },
    })) {
        Ok(body) => body,
        Err(err) => return println!("title auth (RPS): serialize failed: {err}"),
    };

    let mut request = client
        .post(URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");
    if let Ok(Some(signature)) = auth::sign_header_for_url(tokens, URL, "POST", "", &body).await {
        request = request.header("Signature", signature);
    }

    match request.body(body).send().await {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let text: String = text.chars().take(400).collect();
            println!("title auth (RPS): HTTP {status} {text}");
        }
        Err(err) => println!("title auth (RPS): request failed: {err}"),
    }
}

/// Mint an XSTS token with the given optional device/title claims, returning the token,
/// the user hash, and the raw display claims so the caller can see what landed in it.
async fn mint_xsts(
    client: &reqwest::Client,
    tokens: &TokenManager,
    user_token: &str,
    device_token: Option<&String>,
    title_token: Option<&String>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let mut properties = serde_json::Map::new();
    properties.insert("UserTokens".into(), serde_json::json!([user_token]));
    properties.insert("SandboxId".into(), serde_json::json!("RETAIL"));
    if let Some(device) = device_token {
        properties.insert("DeviceToken".into(), serde_json::json!(device));
    }
    if let Some(title) = title_token {
        properties.insert("TitleToken".into(), serde_json::json!(title));
    }
    let body = serde_json::to_vec(&serde_json::json!({
        "RelyingParty": RELYING_PARTY,
        "TokenType": "JWT",
        "Properties": properties,
    }))?;

    let mut request = client
        .post(XSTS_URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");
    // A DeviceToken is only honored on a request signed by the key it is bound to.
    if let Some(signature) = auth::sign_header_for_url(tokens, XSTS_URL, "POST", "", &body).await? {
        request = request.header("Signature", signature);
    }

    let response = request.body(body).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {text}").into());
    }

    let json: serde_json::Value = serde_json::from_str(&text)?;
    let token = json["Token"].as_str().unwrap_or_default().to_string();
    let uhs = json["DisplayClaims"]["xui"][0]["uhs"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok((token, uhs, json["DisplayClaims"].to_string()))
}

/// Sweep the presence write across contract versions and body shapes.
///
/// The token may not be the problem at all: `ArgumentError` is equally consistent with
/// the service rejecting the request *shape*, so vary that too rather than assuming.
async fn presence_write(
    client: &reqwest::Client,
    tokens: &TokenManager,
    xsts_token: &str,
    uhs: &str,
) {
    let title_id = MINECRAFT_TITLE_ID.to_string();
    let with_title_id = format!(
        r#"{{"titleId":"{title_id}","state":"active","activity":{{"richPresence":{{"id":"Menus","scid":"4fc10100-5f7a-4470-899b-280835760c07"}}}}}}"#
    );
    let state_only = r#"{"state":"active"}"#;

    let bodies = [
        ("captured body", PRESENCE_BODY),
        ("+ titleId", with_title_id.as_str()),
        ("state only", state_only),
    ];

    for version in ["1", "3"] {
        for (label, body) in &bodies {
            let status =
                presence_attempt(client, tokens, xsts_token, uhs, version, body, None).await;
            println!("  v{version:<2} {label:<14} -> {status}");
        }
    }

    // If the failure is really "current title/device can't be resolved without a title
    // claim", then addressing them explicitly should behave differently.
    let xuid = "2533274793373868";
    let paths = [
        format!("users/xuid({xuid})/devices/current/titles/{title_id}"),
        format!("users/xuid({xuid})/devices/Win32/titles/{title_id}"),
        format!("users/xuid({xuid})/devices/WindowsOneCore/titles/{title_id}"),
    ];
    for path in &paths {
        let status = presence_attempt(
            client,
            tokens,
            xsts_token,
            uhs,
            "3",
            &with_title_id,
            Some(path),
        )
        .await;
        let shown = path.split("/devices/").nth(1).unwrap_or(path);
        println!("  explicit {shown:<30} -> {status}");
    }
}

/// One presence write; returns a printable status + body summary.
async fn presence_attempt(
    client: &reqwest::Client,
    tokens: &TokenManager,
    xsts_token: &str,
    uhs: &str,
    contract_version: &str,
    body: &str,
    path: Option<&str>,
) -> String {
    let xuid = "2533274793373868";
    let path = path.map(str::to_owned).unwrap_or_else(|| {
        format!("users/xuid({xuid})/devices/current/titles/current")
    });
    let url = format!("https://userpresence.xboxlive.com/{path}");
    let authorization = format!("XBL3.0 x={uhs};{xsts_token}");
    let body = body.as_bytes();

    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", contract_version)
        .header("Authorization", &authorization);
    match auth::sign_header_for_url(tokens, &url, "POST", &authorization, body).await {
        Ok(Some(signature)) => request = request.header("Signature", signature),
        Ok(None) => return "no signature policy covers presence".to_string(),
        Err(err) => return format!("signing failed: {err}"),
    }

    match request.body(body.to_vec()).send().await {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let text: String = text.chars().take(200).collect();
            format!("{status} {text}")
        }
        Err(err) => format!("request failed: {err}"),
    }
}
