use crate::models::displaycatalog::{AssociatedProduct, DisplayCatalogProductsResponse};

pub async fn find_products_by_id(
    client: &reqwest::Client,
    product: String,
    market: String,
    languages: Vec<String>,
) -> reqwest::Result<DisplayCatalogProductsResponse> {
    let langs = languages.join(",");
    let response = client.get(format!("https://displaycatalog.mp.microsoft.com/v7.0/products/{product}?market={market}&languages={langs}")).send().await?;
    let response = response.error_for_status()?;
    response.json().await
}

/// Resolves a `PackageFamilyName` to its `ProductId`, via the same `alternateid=PackageFamilyName`
/// catalog lookup the real `xgameruntime.dll` uses (recovered from its embedded service-configuration
/// blob, OneCoreStore REST table #9: `GET /v7.0/products/lookup?...&alternateid=PackageFamilyName`).
/// `fieldsTemplate=empty` there means the response shape is not the same as [`find_products_by_id`]'s
/// full-product schema, so this is parsed generically (best-effort field lookup) rather than through
/// [`DisplayCatalogProductsResponse`] - `None` is an honest "not found"/"unrecognized shape", not an error.
pub async fn find_product_id_by_package_family_name(
    client: &reqwest::Client,
    package_family_name: &str,
    market: &str,
    languages: &[String],
) -> reqwest::Result<Option<String>> {
    let langs = languages.join(",");
    let response = client
        .get("https://displaycatalog.mp.microsoft.com/v7.0/products/lookup")
        .query(&[
            ("value", package_family_name),
            ("market", market),
            ("languages", langs.as_str()),
            ("fieldsTemplate", "empty"),
            ("alternateid", "PackageFamilyName"),
        ])
        .send()
        .await?;
    let response = response.error_for_status()?;
    let body: serde_json::Value = response.json().await?;
    Ok(body
        .get("Product")
        .and_then(|product| product.get("ProductId"))
        .and_then(|v| v.as_str())
        .map(str::to_owned))
}

/// Products "sellable by" (associated with) a parent product - `XStoreQueryAssociatedProductsAsync`'s
/// real backing, via the service-configuration blob's OneCoreStore REST table #9-in-Table-2:
/// `GET /v7/products/lookup?...&alternateId=SellableBy&actionFilter=Purchase&fieldsTemplate=StoreSDK`.
/// Like [`find_product_id_by_package_family_name`], the response is walked generically rather than
/// through a fixed struct, since `fieldsTemplate=StoreSDK` is a different (undocumented) field subset
/// than the full catalog schema; any product whose `ProductId` can't be found is skipped rather than
/// guessed at.
pub async fn get_associated_products(
    client: &reqwest::Client,
    parent_product_id: &str,
    market: &str,
    languages: &[String],
    max_items: u32,
) -> reqwest::Result<Vec<AssociatedProduct>> {
    let langs = languages.join(",");
    let response = client
        .get("https://displaycatalog.mp.microsoft.com/v7/products/lookup")
        .query(&[
            ("value", parent_product_id),
            ("market", market),
            ("languages", langs.as_str()),
            ("$top", max_items.to_string().as_str()),
            ("fieldsTemplate", "StoreSDK"),
            ("actionFilter", "Purchase"),
            ("alternateId", "SellableBy"),
        ])
        .send()
        .await?;
    let response = response.error_for_status()?;
    let body: serde_json::Value = response.json().await?;
    Ok(body
        .get("Products")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|product| {
            let product_id = product.get("ProductId")?.as_str()?.to_owned();
            let product_kind = product
                .get("ProductKind")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let title = product
                .get("LocalizedProperties")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|lp| lp.get("ProductTitle"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            Some(AssociatedProduct {
                product_id,
                title,
                product_kind,
            })
        })
        .collect())
}
