use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    xodus::licensing::content::get_full_license(client, tokens, content_id, market).await
}
