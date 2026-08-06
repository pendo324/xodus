use std::process::ExitCode;

use xodus::tokens::TokenManager;

use crate::commands::streaming;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    path: String,
    destination: String,
    market: String,
    decrypt_all: bool,
) -> ExitCode {
    streaming::run(
        client,
        tokens,
        "file://".to_owned() + &path,
        destination,
        false,
        None,
        Some(market),
        decrypt_all,
    )
    .await
}
