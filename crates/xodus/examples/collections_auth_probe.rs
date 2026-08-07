//! Probe: how does one authenticate to `collections.mp.microsoft.com/v7.0/beneficiaries/me/keys`,
//! the endpoint behind `XStoreGetUserCollectionsIdAsync`, and its purchase-side sibling
//! `purchase.mp.microsoft.com/v7.0/users/me/keys` behind `XStoreGetUserPurchaseIdAsync`? (The two
//! take the same request and give the same answer, but not on the same path - each 404s on the
//! other's spelling.)
//!
//! Superseded: both keys are minted today through the B2B route with relying party
//! `http://mp.microsoft.com/`, which needs none of what follows. This is kept as the record of
//! why the obvious route does not work, so it does not get retried.
//!
//! What this probe established about the direct route:
//!
//!   * The scheme must be `Bearer`. A raw ticket gets `NoAuthorizationHeaders` ("No
//!     authorization header provided"), and `WLID1.0=...` gets a generic
//!     `AuthenticationTokenInvalid`. Only `Bearer` produces a specific complaint.
//!   * The value must be a bare base64 ticket. Any `&`-joined pair (`t=<user>&p=<device>`
//!     and friends) fails as `InvalidBase64Ticket`.
//!   * Our ticket is the wrong *kind*. With `Bearer`, both the user and device compact
//!     tickets get:
//!     `RpsExceptionCode: UnexpectedTicketType` / "The ticket that was provided is not a
//!     Compact_Delegation ticket".
//!
//! So the endpoint wants a `urn:passport:delegationcompact` ticket (the `d=` variant
//! `models::secrets::Token` already knows how to represent), and no RST parameter selects one.
//! The delegation grant is a property of *who is asking*: the Windows identity broker requests
//! it under the caller's registered app identity, and MSA issues `Compact_Delegation` to that
//! brokered principal where it issues a plain compact to a raw SOAP caller. Nothing this probe
//! can vary changes that - the store's own auth target and policy (`www.microsoft.com` /
//! `mbi_ssl`) are target-for-target and policy-for-policy what it already asks MSA for directly,
//! and directly MSA answers with a plain `t=` every time.
//!
//! Never prints token material - only lengths, the `t=`/`d=` kind prefix, and the service's
//! own error text.

use xodus::models::secrets::Token;
use xodus::models::soap;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .user_agent("xodus-cli/0.1.0")
        .build()
        .unwrap();

    xodus::secrets::init_secrets().expect("Unable to initialize credentials");
    let tokens = xodus::tokens::TokenManager::with_keychain_and_memory();
    xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;

    let ms = xodus::licensing::content::get_ms_compact_tokens(&client, &tokens)
        .await
        .expect("compact tokens");
    println!(
        "user ticket: {} ({} bytes)\ndevice ticket: {} ({} bytes)",
        kind_of(&ms.user),
        ms.user.len(),
        kind_of(&ms.device),
        ms.device.len()
    );

    println!("\n-- header scheme, with the user compact ticket --");
    for (name, value) in [
        ("raw", ms.user.clone()),
        ("WLID1.0=<tok>", format!("WLID1.0={}", ms.user)),
        ("Bearer <tok>", format!("Bearer {}", ms.user)),
        ("XBL3.0 x=-;<tok>", format!("XBL3.0 x=-;{}", ms.user)),
    ] {
        try_call(&client, name, value).await;
    }

    println!("\n-- ticket shape, all under Bearer --");
    let user_body = ms.user.strip_prefix("t=").unwrap_or(&ms.user);
    let device_body = ms.device.strip_prefix("t=").unwrap_or(&ms.device);
    for (name, token) in [
        ("device ticket", ms.device.clone()),
        ("d=<user>", format!("d={user_body}")),
        ("t=<user>&p=<device>", format!("t={user_body}&p={device_body}")),
    ] {
        try_call(&client, name, format!("Bearer {token}")).await;
    }

    println!("\n-- can MSA issue a delegation ticket for the store hosts? --");
    // `DELEGATION` is a real policy name, not a guess - it is the policy paired with `MBI_SSL`
    // in the `service::<target>::<policy>` scopes the store auth path uses, against the store's
    // own auth target `www.microsoft.com`.
    let delegation = || soap::PolicyReference {
        uri: "DELEGATION".to_string(),
        val: String::default(),
    };
    for host in [
        "collections.mp.microsoft.com",
        "licensing.mp.microsoft.com",
        "purchase.mp.microsoft.com",
        "www.microsoft.com",
    ] {
        for (label, scope, policy) in [
            ("AppliesTo/MBI_SSL", host.to_string(), Some(soap::PolicyReference::mbi_ssl())),
            ("AppliesTo/DELEGATION", host.to_string(), Some(delegation())),
            (
                "token-broker",
                format!("scope=service::{host}::MBI_SSL&api-version=2.0"),
                Some(soap::PolicyReference::token_broker()),
            ),
            (
                "token-broker/DELEGATION",
                format!("scope=service::{host}::DELEGATION&api-version=2.0"),
                Some(soap::PolicyReference::token_broker()),
            ),
        ] {
            match fetch_compact(&client, &tokens, &scope, policy).await {
                Ok(token) => println!("  {host} [{label}] -> {}", kind_of(&token)),
                Err(err) => {
                    println!("  {host} [{label}] -> refused: {}", first_line(&err));
                }
            }
        }
    }
}

fn kind_of(token: &str) -> &'static str {
    match token.split_once('=') {
        Some(("t", _)) => "plain compact (t=)",
        Some(("d", _)) => "DELEGATION compact (d=)",
        _ => "unrecognized",
    }
}

fn first_line(text: &str) -> String {
    text.chars().take(160).collect()
}

async fn fetch_compact(
    client: &reqwest::Client,
    tokens: &xodus::tokens::TokenManager,
    scope: &str,
    policy: Option<soap::PolicyReference>,
) -> Result<String, String> {
    let Token::Legacy(dev_token) = tokens.get_device_sts_token().map_err(|e| e.to_string())? else {
        return Err("no legacy device token".to_string());
    };
    let Token::Legacy(user_token) = tokens.get_user_sts_token().map_err(|e| e.to_string())? else {
        return Err("no legacy user token".to_string());
    };
    let user = tokens.get_user().map_err(|e| e.to_string())?;

    let outcome = xodus::api::live::exchange_user_token(
        client,
        user_token,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        std::env::var("PROBE_CLIENT_ID")
            .unwrap_or_else(|_| "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string()),
        &[(scope.to_string(), policy)],
    )
    .await
    .map_err(|err| err.to_string())?;

    let token: Token = match outcome {
        xodus::models::live::ExchangeUserTokenOutcome::Fault(fault) => {
            let status = fault
                .as_ref()
                .and_then(|pp| pp.req_status.clone())
                .unwrap_or_else(|| "unknown".to_string());
            return Err(format!("MSA {status}"));
        }
        xodus::models::live::ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => collection.security_tokens.remove(0).into(),
        xodus::models::live::ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponse(token),
        ) => (*token).into(),
        _ => return Err("unexpected response".to_string()),
    };

    match token {
        Token::Compact(compact) => Ok(compact),
        Token::Legacy(_) => Err("legacy token, not compact".to_string()),
    }
}

async fn try_call(client: &reqwest::Client, name: &str, authorization: String) {
    let response = client
        .post("https://collections.mp.microsoft.com/v7.0/beneficiaries/me/keys")
        .header("Authorization", authorization)
        .json(&serde_json::json!({
            // Auth is rejected before the body is looked at, so placeholders are enough.
            "serviceTicket": "probe",
            "publisherUserId": "probe",
        }))
        .send()
        .await;

    match response {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let code = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .ok_or(())
                .and_then(|json| {
                    // `innererror.data` is where the useful part lives - `code` alone is a
                    // generic `AuthenticationTokenInvalid` for three quite different causes.
                    let code = json
                        .pointer("/innererror/code")
                        .and_then(|v| v.as_str())
                        .ok_or(())?
                        .to_owned();
                    let detail = json
                        .pointer("/innererror/data")
                        .and_then(|v| v.as_array())
                        .and_then(|data| data.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    Ok(if detail.is_empty() {
                        code
                    } else {
                        format!("{code} ({detail})")
                    })
                })
                .ok()
                .unwrap_or_else(|| first_line(&body));
            println!("  {name:>20} -> {status} {code}");
        }
        Err(err) => println!("  {name:>20} -> send failed: {err}"),
    }
}
