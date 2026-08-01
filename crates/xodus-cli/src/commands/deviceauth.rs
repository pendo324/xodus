use std::process::ExitCode;

use xodus::{
    auth::{self, TitleIdentity},
    tokens::TokenManager,
};

/// Endpoint covered by a signing policy, so a bad signature is rejected rather than
/// ignored. Requesting a token for it is the cheapest way to find out whether the
/// stored proof key is the one Xbox Live bound our tokens to.
const PROBE_RELYING_PARTY: &str = "http://xboxlive.com";

/// Prove possession of the persisted proof key against Xbox Live.
///
/// Run it twice across a process restart: the reported device id and proof key must be
/// identical both times, otherwise tokens issued by the first run cannot be signed for
/// by the second.
pub async fn run(tokens: &TokenManager) -> ExitCode {
    let identity = TitleIdentity::xodus();

    let device = match tokens.get_or_create_xbl_device_identity() {
        Ok(device) => device,
        Err(err) => {
            eprintln!("Failed to load Xbox Live device identity: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("device id:  {}", device.device_id);
    match serde_json::to_string(&device.signer.get_proof_key()) {
        Ok(json) => println!("proof key:  {json}"),
        Err(err) => eprintln!("Failed to render proof key: {err}"),
    }

    let device_token = match auth::get_device_token(tokens, &identity).await {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Device authentication failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("device token valid until {}", device_token.not_after);

    // Device-only XSTS. This is the request the proof key actually gates: it is signed,
    // and the service checks the signature against the key the device token is bound to.
    let xsts = match auth::get_xsts_token(
        tokens,
        &identity,
        Some(&device_token),
        None,
        None,
        PROBE_RELYING_PARTY,
    )
    .await
    {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Signed XSTS request for {PROBE_RELYING_PARTY} failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "signed XSTS for {PROBE_RELYING_PARTY} valid until {}",
        xsts.not_after
    );
    ExitCode::SUCCESS
}
