//! Diagnostic probe for Minecraft Realms answering `401` to every request.
//!
//! The title asks for a token for `https://pocket.realms.minecraft.net/` and then calls
//! `bedrock.frontendlegacy.realms.minecraft-services.net` with it. Xbox Live's
//! title-management endpoint table has no entry for either host, so `relying_party_for`
//! falls back to `http://xboxlive.com` and Realms rejects the audience.
//!
//! Which relying party it *does* want is not published anywhere we can read, so this
//! sweeps the plausible ones against a real Realms endpoint and reports the status of
//! each. `http://xboxlive.com` is included as the control: it should reproduce the 401.
//!
//! Run with: cargo run -p xodus --example realms_probe

use xodus::{
    api::xbox::{auth::get_xsts_auth_header, request_xsts_token_for_title},
    auth, tokens::TokenManager,
};

/// Minecraft's own MSA client id and title id - the pair `do_sisu` needs to authenticate
/// as the title. Realms is a title-scoped service, so a claimless token is unlikely to be
/// what it wants even if the audience were right.
const MINECRAFT_CLIENT_ID: &str = "0000000040159362";
const MINECRAFT_TITLE_ID: i64 = 0x35760C07;

/// A cheap, side-effect-free Realms endpoint the title itself calls on startup.
const REALMS_URL: &str =
    "https://bedrock.frontendlegacy.realms.minecraft-services.net/mco/client/compatible";

/// Relying parties worth trying, most likely first. The `pocket.realms` pair is what the
/// title names when it asks us for a token; the `minecraftservices` one is what Java
/// Realms is documented to use; `http://xboxlive.com` is what we send today.
const CANDIDATES: &[&str] = &[
    "https://pocket.realms.minecraft.net/",
    "http://pocket.realms.minecraft.net/",
    "rp://api.minecraftservices.com/",
    "https://bedrock.frontendlegacy.realms.minecraft-services.net/",
    "http://xboxlive.com",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    xodus::secrets::init_secrets()?;
    let tokens = TokenManager::with_keychain_and_memory();
    xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;

    let (_auth, sisu, device) =
        auth::do_sisu(&client, &tokens, MINECRAFT_CLIENT_ID, MINECRAFT_TITLE_ID).await?;
    println!("sisu: title+user+device tokens ok\n");

    for relying_party in CANDIDATES {
        print!("{relying_party:<62} ");
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
                println!("xsts ok -> realms {}", realms_get(&client, &authorization).await);
            }
            // A relying party Xbox Live does not know is refused here rather than by
            // Realms, which is itself the answer for that candidate.
            Err(err) => println!("xsts refused: {}", one_line(&err.to_string())),
        }
    }

    Ok(())
}

/// One Realms request with the given `Authorization`, as a printable status + body.
///
/// Realms is picky about `Client-Version` and rejects an unrecognised one with 403, so
/// a 403 here means the *auth* got far enough to stop being the complaint.
async fn realms_get(client: &reqwest::Client, authorization: &str) -> String {
    let response = client
        .get(REALMS_URL)
        .header("Authorization", authorization)
        .header("Client-Version", "1.21.44")
        .header("User-Agent", "MCPE/UWP")
        .send()
        .await;

    match response {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            format!("{status} {}", one_line(&text))
        }
        Err(err) => format!("request failed: {err}"),
    }
}

fn one_line(text: &str) -> String {
    text.chars()
        .take(160)
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}
