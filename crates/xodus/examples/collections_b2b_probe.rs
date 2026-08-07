//! Diagnostic probe for the B2B route to a Microsoft Store ID key.
//!
//! `collections_auth_probe` established that `POST collections.mp.microsoft.com/v7.0/
//! beneficiaries/me/keys` refuses a plain compact MSA ticket with `UnexpectedTicketType`,
//! wanting a `Compact_Delegation` ticket that MSA only issues to a WAM-brokered caller.
//!
//! That is not the only way in. The endpoint also accepts an `XBL3.0` Authorization
//! header - an ordinary XSTS token, which we can already mint - provided the body carries
//! a `serviceTicket`: an AAD token whose audience is
//! `https://onestore.microsoft.com/b2b/keys/create/collections`. Minecraft obtains exactly
//! that from PlayFab (`<titleid>.playfabapi.com/inventory/GetAccessTokens`, which answers
//! with a `Collections` and a `Purchase` token, both AAD, both ~1h).
//!
//! That pair works, and walks around the delegation-ticket wall entirely: with an XSTS
//! token for `http://mp.microsoft.com/` this probe gets a 1754-byte collections key and a
//! 1856-byte purchase key. What is left here is the sweep that established which relying
//! party, since it is not guessable from the hostname.
//!
//! The `serviceTicket` is passed in via `XODUS_SERVICE_TICKET`, since it is a bearer
//! credential with a short life and does not belong in the source tree.
//!
//! Run with: XODUS_SERVICE_TICKET=<aad token> cargo run -p xodus --example collections_b2b_probe

use xodus::{
    api::xbox::{auth::get_xsts_auth_header, request_xsts_token_for_title},
    auth, tokens::TokenManager,
};

/// Minecraft's own MSA client id and title id, as in the other probes.
const MINECRAFT_CLIENT_ID: &str = "0000000040159362";
const MINECRAFT_TITLE_ID: i64 = 0x35760C07;

const COLLECTIONS_URL: &str = "https://collections.mp.microsoft.com/v7.0/beneficiaries/me/keys";
const PURCHASE_URL: &str = "https://purchase.mp.microsoft.com/v7.0/users/me/keys";

/// Relying parties worth trying for the XSTS half. The store hosts are the obvious
/// guesses; `http://xboxlive.com` is the default we already send everywhere else and acts
/// as the control.
/// `http://licensing.xboxlive.com` is the one that works, established by sweeping the
/// obvious store hosts against it: the store hosts are not in Xbox Live's relying-party
/// table at all (`xsts/authorize` 400s before the request leaves), and the default
/// `http://xboxlive.com` we send everywhere else is refused with `InvalidXToken`.
/// `http://mp.microsoft.com/` is the answer - it is the marketplace relying party, and it
/// produces both keys. The others are kept as the controls that establish it is the only
/// one that does:
///
/// - `licensing.xboxlive.com` yields a collections key, but `PurchaseFD` answers
///   `Unable to decrypt` - an XToken is encrypted to its relying party's key, so the wrong
///   audience fails at decryption rather than at validation.
/// - `xboxlive.com` (our default everywhere else) is refused by both.
/// - the trailing slash matters: `http://mp.microsoft.com` without it is not in Xbox
///   Live's table and 400s at `xsts/authorize`.
///
/// Guessing `purchase.xboxlive.com`-shaped names is wasted effort; Xbox Live has no such
/// entries and refuses them before a store request is ever made.
const CANDIDATES: &[&str] = &[
    "http://mp.microsoft.com/",
    "http://mp.microsoft.com",
    "http://licensing.xboxlive.com",
    "http://xboxlive.com",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let collections_ticket = std::env::var("XODUS_COLLECTIONS_TICKET")
        .map_err(|_| "set XODUS_COLLECTIONS_TICKET to a PlayFab-issued collections AAD token")?;
    let purchase_ticket = std::env::var("XODUS_PURCHASE_TICKET")
        .map_err(|_| "set XODUS_PURCHASE_TICKET to a PlayFab-issued purchase AAD token")?;

    let client = reqwest::Client::new();
    xodus::secrets::init_secrets()?;
    let tokens = TokenManager::with_keychain_and_memory();
    xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;

    let (_auth, sisu, device) =
        auth::do_sisu(&client, &tokens, MINECRAFT_CLIENT_ID, MINECRAFT_TITLE_ID).await?;
    println!("sisu: title+user+device tokens ok\n");

    for relying_party in CANDIDATES {
        print!("{relying_party:<44} ");
        let xsts = request_xsts_token_for_title(
            &client,
            &tokens,
            sisu.user_token.token.clone(),
            device.token.clone(),
            sisu.title_token.token.clone(),
            relying_party,
        )
        .await;

        match xsts {
            Ok(xsts) => {
                let authorization = get_xsts_auth_header(xsts);
                println!("xsts ok");
                println!(
                    "    collections -> {}",
                    create_key(&client, COLLECTIONS_URL, &authorization, &collections_ticket).await
                );
                println!(
                    "    purchase    -> {}",
                    create_key(&client, PURCHASE_URL, &authorization, &purchase_ticket).await
                );
            }
            // A relying party Xbox Live does not know is refused here rather than by the
            // store, which is itself the answer for that candidate.
            Err(err) => println!("xsts refused: {}", one_line(&err.to_string())),
        }
    }

    Ok(())
}

/// One key-create attempt, as a printable status + body.
///
/// The interesting failures are distinguishable from each other: `InvalidXToken` means the
/// XSTS half was rejected, while a complaint about `serviceTicket` means the XSTS half was
/// accepted and only the AAD half is wrong (or expired).
async fn create_key(
    client: &reqwest::Client,
    url: &str,
    authorization: &str,
    service_ticket: &str,
) -> String {
    let response = client
        .post(url)
        .header("Authorization", authorization)
        .json(&serde_json::json!({
            "serviceTicket": service_ticket,
            "sandbox": "RETAIL",
        }))
        .send()
        .await;

    match response {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            // A success body contains the key itself, which is a bearer credential.
            if status.is_success() {
                format!("{status} <key: {} bytes>", text.len())
            } else {
                format!("{} {}", status.as_u16(), summarize_error(&text))
            }
        }
        Err(err) => format!("request failed: {err}"),
    }
}

/// Reduce a marketplace error body to its `innererror` code plus the first line of detail.
///
/// These come back with a full .NET stack trace in `data`, which buries the one thing that
/// distinguishes the cases: `InvalidXToken` / `Unable to decrypt` means the XSTS half was
/// refused, anything naming `serviceTicket` means it was accepted.
fn summarize_error(text: &str) -> String {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return one_line(text);
    };
    let inner = &json["innererror"];
    let code = inner["code"].as_str().unwrap_or("?");
    let detail = inner["data"][0]
        .as_str()
        .or_else(|| inner["message"].as_str())
        .unwrap_or_default();
    format!("{code}: {}", one_line(detail.lines().next().unwrap_or_default()))
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
