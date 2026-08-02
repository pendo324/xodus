//! Lists the signed-in account's entitled titles (owned outright or via Game Pass), via
//! the same `beige.xboxservices.com` "My games" library `XStoreQueryEntitledProductsAsync`
//! uses inside a running game - exposed standalone here since answering "what Game Pass
//! titles does this account have?" shouldn't require actually launching a game.

use std::process::ExitCode;

use xodus::{
    api::xbox::{
        auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token},
        services::get_library,
    },
    licensing::content::{exchange_msa_user_token, get_ms_compact_tokens},
    models::secrets::Token,
    tokens::TokenManager,
};

/// Xbox Live's own MSA app registration id - shared infrastructure, not a per-title
/// identity. Matches `xodus-service`'s `XBOX_LIVE_CLIENT_ID`.
const XBOX_LIVE_CLIENT_ID: &str = "000000004424da1f";

/// Same relying party `xodus-service`'s `EntitledProductsRequest` handler uses for the
/// "My games" library's `x-ms-authorization-social` header.
const MP_RELYING_PARTY: &str = "http://mp.microsoft.com/";

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    market: Option<String>,
) -> ExitCode {
    let market = market.unwrap_or_else(|| "US".to_string());

    let Token::Legacy(device_token) = tokens.get_device_sts_token().unwrap() else {
        eprintln!("Invalid device STS token");
        return ExitCode::FAILURE;
    };

    let rps_ticket = match exchange_msa_user_token(
        client,
        tokens,
        device_token,
        XBOX_LIVE_CLIENT_ID,
        "xboxlive.signin",
    )
    .await
    {
        Ok(result) => result.token,
        Err(err) => {
            eprintln!("Failed to exchange MSA user token: {err}");
            return ExitCode::FAILURE;
        }
    };

    let ms_user_token = match authenticate_xbox_user(client, rps_ticket).await {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Failed to authenticate against Xbox Live: {err}");
            return ExitCode::FAILURE;
        }
    };

    let xsts = match request_xsts_token(client, ms_user_token.token, MP_RELYING_PARTY).await {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Failed to get an XSTS token for {MP_RELYING_PARTY}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let xsts_header = get_xsts_auth_header(xsts);

    let ms_tokens = match get_ms_compact_tokens(client, tokens).await {
        Ok(tokens) => tokens,
        Err(err) => {
            eprintln!("Failed to get a compact user token: {err}");
            return ExitCode::FAILURE;
        }
    };

    let library = match get_library(client, ms_tokens.user, xsts_header, market).await {
        Ok(library) => library,
        Err(err) => {
            eprintln!("Failed to fetch the library: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut products: Vec<_> = library
        .result
        .product_ids
        .iter()
        .filter_map(|id| {
            library
                .product_summaries
                .get(id)
                .map(|summary| (id, summary))
        })
        .collect();
    products.sort_by(|(_, a), (_, b)| a.title.cmp(&b.title));

    for (store_id, summary) in &products {
        let game_pass = summary.included_in_ultimate || summary.included_in_pcgp;
        println!(
            "{}{}  [{}]  {store_id}",
            summary.title,
            if game_pass { "  (Game Pass)" } else { "" },
            summary.product_kind,
        );
    }
    println!("{} title(s)", products.len());

    ExitCode::SUCCESS
}
