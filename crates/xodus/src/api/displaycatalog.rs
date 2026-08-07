use crate::models::displaycatalog::{
    CatalogProduct, CatalogProductPrice, DisplayCatalogProductsResponse,
};

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

/// Resolves a `PackageFamilyName` to its `ProductId`, via the catalog's
/// `GET /v7.0/products/lookup?...&alternateid=PackageFamilyName` route.
/// `fieldsTemplate=empty` there means the response shape is not the same as [`find_products_by_id`]'s
/// full-product schema, so this is parsed generically (best-effort field lookup) rather than through
/// [`DisplayCatalogProductsResponse`] - `None` is an honest "not found"/"unrecognized shape", not an error.
///
/// The lookup answers `{"BigIds": [...], "Products": [...], "HasMorePages", "TotalResultCount"}`.
/// At `fieldsTemplate=empty` only `BigIds` is populated (`Products` comes back empty), which is the
/// whole point of asking for `empty` - the id is all we want. `Products[0].ProductId` is checked as
/// a fallback so a richer `fieldsTemplate` would still resolve if this ever asks for one.
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
    Ok(product_id_from_lookup(&body))
}

/// The `ProductId` out of a `products/lookup` response body - see
/// [`find_product_id_by_package_family_name`] for the shape.
fn product_id_from_lookup(body: &serde_json::Value) -> Option<String> {
    let big_id = body
        .get("BigIds")
        .and_then(|v| v.as_array())
        .and_then(|ids| ids.first())
        .and_then(|v| v.as_str());
    let from_products = || {
        body.get("Products")
            .and_then(|v| v.as_array())
            .and_then(|products| products.first())
            .and_then(|product| product.get("ProductId"))
            .and_then(|v| v.as_str())
    };
    big_id.or_else(from_products).map(str::to_owned)
}

/// Products "sellable by" (associated with) a parent product - `XStoreQueryAssociatedProductsAsync`'s
/// real backing:
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
) -> reqwest::Result<Vec<CatalogProduct>> {
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
        .filter_map(read_product)
        .collect())
}

/// Prices an explicit list of `StoreId`s - `XStoreQueryProductsAsync`'s real backing, via
/// displaycatalog's batch endpoint (`GET /v7.0/products?bigIds=...`). Unlike
/// [`get_associated_products`] this discovers nothing: the title already knows which products it
/// wants to show and is asking what they cost, so ids that don't resolve are simply absent from
/// the answer rather than an error.
pub async fn get_products_by_id(
    client: &reqwest::Client,
    store_ids: &[String],
    market: &str,
    languages: &[String],
) -> reqwest::Result<Vec<CatalogProduct>> {
    if store_ids.is_empty() {
        return Ok(vec![]);
    }
    let langs = languages.join(",");
    let ids = store_ids.join(",");
    let response = client
        .get("https://displaycatalog.mp.microsoft.com/v7.0/products")
        .query(&[
            ("bigIds", ids.as_str()),
            ("market", market),
            ("languages", langs.as_str()),
            ("fieldsTemplate", "StoreSDK"),
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
        .filter_map(read_product)
        .collect())
}

/// One `fieldsTemplate=StoreSDK` product. `None` for an entry with no `ProductId`, which is the
/// one field nothing downstream can do without - skipped rather than guessed at.
fn read_product(product: &serde_json::Value) -> Option<CatalogProduct> {
    Some(CatalogProduct {
        product_id: product.get("ProductId")?.as_str()?.to_owned(),
        title: product
            .get("LocalizedProperties")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|lp| lp.get("ProductTitle"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        product_kind: product
            .get("ProductKind")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        price: first_purchasable_price(product),
    })
}

/// Digs a product's asking price out of a `fieldsTemplate=StoreSDK` entry.
///
/// A product carries one price per *availability*, and availabilities are nested two levels down
/// (`DisplaySkuAvailabilities[].Availabilities[]`) because the same product is sold several ways
/// at once. Picking the right one matters: a subscription lists `Purchase`, `Gift` and `Renew`
/// availabilities at its real price and two `License` ones at 0.00, so taking whichever comes
/// first (or last) would show the player a free Realms subscription. The availability that lists
/// the `Purchase` action wins, with the first priced one at all as a fallback for a product
/// offered some way this doesn't anticipate. Anything unrecognized yields the default all-zero
/// price, i.e. "no price to show", not "free".
fn first_purchasable_price(product: &serde_json::Value) -> CatalogProductPrice {
    let availabilities = product
        .get("DisplaySkuAvailabilities")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|sku| sku.get("Availabilities")?.as_array())
        .flatten()
        .filter(|availability| availability.pointer("/OrderManagementData/Price").is_some());

    let mut fallback = None;
    for availability in availabilities {
        let purchasable = availability
            .get("Actions")
            .and_then(|v| v.as_array())
            .is_some_and(|actions| actions.iter().any(|a| a.as_str() == Some("Purchase")));
        if purchasable {
            return read_price(availability);
        }
        fallback.get_or_insert(availability);
    }
    fallback.map(read_price).unwrap_or_default()
}

/// One availability's `OrderManagementData.Price` block, plus the sale end date that lives beside
/// it under `Conditions`.
fn read_price(availability: &serde_json::Value) -> CatalogProductPrice {
    let amount = |field: &str| {
        availability
            .pointer("/OrderManagementData/Price")
            .and_then(|price| price.get(field))
            .and_then(|v| v.as_f64())
            .unwrap_or_default() as f32
    };
    CatalogProductPrice {
        currency_code: availability
            .pointer("/OrderManagementData/Price/CurrencyCode")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        list_price: amount("ListPrice"),
        msrp: amount("MSRP"),
        recurrence_price: amount("RecurrencePrice"),
        sale_end_date: availability
            .pointer("/Conditions/EndDate")
            .and_then(|v| v.as_str())
            .and_then(|date| date.parse::<chrono::DateTime<chrono::Utc>>().ok())
            .map(|date| date.timestamp())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The response `fieldsTemplate=empty` actually returns: the id lives in `BigIds`, and
    /// `Products` is empty. Reading a top-level `Product` object here (there is none, at any
    /// `fieldsTemplate`) is what left every associated-products query answering nothing.
    #[test]
    fn product_id_comes_from_big_ids() {
        let body = json!({
            "BigIds": ["9NBLGGH2JHXJ"],
            "HasMorePages": false,
            "Products": [],
            "TotalResultCount": 1,
        });
        assert_eq!(
            product_id_from_lookup(&body).as_deref(),
            Some("9NBLGGH2JHXJ")
        );
    }

    #[test]
    fn product_id_falls_back_to_the_products_array() {
        let body = json!({ "BigIds": [], "Products": [{ "ProductId": "9MT4NXQP1KG3" }] });
        assert_eq!(
            product_id_from_lookup(&body).as_deref(),
            Some("9MT4NXQP1KG3")
        );
    }

    #[test]
    fn no_match_is_none_not_a_guess() {
        let body = json!({ "BigIds": [], "Products": [], "TotalResultCount": 0 });
        assert_eq!(product_id_from_lookup(&body), None);
    }

    #[test]
    fn price_comes_from_the_purchasable_availability() {
        let product = json!({
            "DisplaySkuAvailabilities": [{
                "Availabilities": [
                    {
                        "Actions": ["Redeem"],
                        "OrderManagementData": { "Price": { "CurrencyCode": "USD", "ListPrice": 0.0, "MSRP": 0.0 } },
                    },
                    {
                        "Actions": ["Purchase"],
                        "Conditions": { "EndDate": "2026-09-01T00:00:00.0000000Z" },
                        "OrderManagementData": { "Price": {
                            "CurrencyCode": "EUR", "ListPrice": 5.99, "MSRP": 7.99, "RecurrencePrice": 5.99,
                        } },
                    },
                ],
            }],
        });
        let price = first_purchasable_price(&product);
        assert_eq!(price.currency_code, "EUR");
        assert_eq!(price.list_price, 5.99);
        assert_eq!(price.msrp, 7.99);
        assert_eq!(price.recurrence_price, 5.99);
        // 2026-09-01T00:00:00Z
        assert_eq!(price.sale_end_date, 1788220800);
    }

    /// No `Purchase` action anywhere still beats reporting nothing - the first priced
    /// availability is a better answer for a store page than a blank.
    #[test]
    fn price_falls_back_to_the_first_priced_availability() {
        let product = json!({
            "DisplaySkuAvailabilities": [{
                "Availabilities": [{
                    "Actions": ["Redeem"],
                    "OrderManagementData": { "Price": { "CurrencyCode": "USD", "ListPrice": 7.99, "MSRP": 7.99 } },
                }],
            }],
        });
        let price = first_purchasable_price(&product);
        assert_eq!(price.currency_code, "USD");
        assert_eq!(price.list_price, 7.99);
    }

    /// Nothing purchasable must read as "no price", never as free.
    #[test]
    fn a_product_with_no_availabilities_has_no_price() {
        let price = first_purchasable_price(&json!({ "ProductId": "9ABC" }));
        assert!(price.currency_code.is_empty());
        assert_eq!(price.list_price, 0.0);
    }
}
