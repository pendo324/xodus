use std::process::ExitCode;
use xodus::tokens::TokenManager;

use crate::webview;

pub async fn run(tokens: &TokenManager, device: bool) -> ExitCode {
    let mut failed = false;

    if device && let Err(err) = tokens.remove_device_license() {
        eprintln!("Failed to remove the device license: {err}");
        failed = true;
    }

    // Both halves run even if the first one fails, and both report on stderr rather than
    // through `log`, which is off by default: a logout that half worked and said nothing
    // looks exactly like one that worked.
    if let Err(err) = tokens.remove_persistent() {
        eprintln!("Failed to remove stored tokens: {err}");
        failed = true;
    }

    if let Err(err) = webview::clear_shared_profile() {
        eprintln!("Failed to clear the sign-in window's saved session: {err}");
        failed = true;
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
