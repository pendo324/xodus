use serde::Deserialize;
use xal::{cvlib::CorrelationVector, extensions::CorrelationVectorReqwestBuilder};

/// `GET https://beige.xboxservices.com/pcgafd/mygames` - the PC "My games" library: every
/// title this account owns outright or through a subscription (PC Game Pass / Game Pass
/// Ultimate / EA Play), keyed by product id. See `docs/xbox/xboxservices.md`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyGames {
    pub result: MyGamesResults,
    pub product_summaries: std::collections::HashMap<String, ProductSummaryItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyGamesResults {
    pub product_ids: Vec<String>,
    pub total_item_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductSummaryItem {
    pub product_kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_family_name: Option<String>,
    #[serde(default)]
    pub included_in_ultimate: bool,
    #[serde(default)]
    pub included_in_pcgp: bool,
}

pub async fn get_library(
    client: &reqwest::Client,
    user_token: String,
    xsts_header: String,
    market: String,
) -> reqwest::Result<MyGames> {
    let mut cv = CorrelationVector::new();
    let response = client
        .get("https://beige.xboxservices.com/pcgafd/mygames")
        .query(&[
            ("market", market.as_str()),
            ("language", "en-US"),
            ("appVersion", "2606.1001.27.0"),
        ])
        .header("x-ms-api-version", "1.2")
        .header("x-ms-authorization-social", xsts_header)
        .header("Authorization", user_token)
        .add_cv(&mut cv)
        .unwrap()
        .send()
        .await?
        .error_for_status()?;

    response.json().await
}
