use serde::{Deserialize, Serialize};

/// `XStoreQueryGameLicenseAsync` - `content_id` is the package's `ContentId` (from its XVD
/// header), published to the game process by `xodus-cli run` via `xodus::ipc::ENV_CONTENT_ID`.
/// No user field: like `UserInfoRequest`, this always answers for whichever account's
/// credentials are on this connection.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseRequest {
    pub content_id: String,
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseResponse {
    pub is_active: bool,
    /// Zero for a license with no expiration (the common case for an outright purchase).
    #[serde(default)]
    pub expiration_date: i64,
}

/// `XStoreQueryEntitledProductsAsync` - like `LicenseRequest`, answers for whichever
/// account's credentials are on this connection; no user field.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EntitledProductsRequest {
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EntitledProductsResponse {
    #[serde(default, rename = "Product")]
    pub products: Vec<EntitledProduct>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EntitledProduct {
    pub store_id: String,
    pub title: String,
    pub product_kind: String,
    #[serde(default)]
    pub included_in_game_pass: bool,
}

/// `XStoreGetUserCollectionsIdAsync` - `service_ticket`/`publisher_user_id` are the
/// caller's own opaque values, forwarded verbatim to `collections.mp.microsoft.com`; like
/// `LicenseRequest`, answers for whichever account's credentials are on this connection.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionsIdRequest {
    pub service_ticket: String,
    pub publisher_user_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CollectionsIdResponse {
    /// Raw response body from `collections.mp.microsoft.com` - an opaque signed blob the
    /// title's own backend is meant to verify, not something xodus parses further.
    #[serde(default)]
    pub key: String,
}

/// `XStoreGetUserPurchaseIdAsync` - the purchase-side twin of [`CollectionsIdRequest`],
/// identical shape and identical caller-supplied opaque values.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PurchaseIdRequest {
    pub service_ticket: String,
    pub publisher_user_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PurchaseIdResponse {
    /// Raw response body from `purchase.mp.microsoft.com` - opaque, see
    /// [`CollectionsIdResponse::key`].
    #[serde(default)]
    pub key: String,
}

/// `XStoreQueryLicenseTokenAsync` - `product_ids[0]` is treated as the parent product and
/// the rest as related products, matching the real GDK signature's single flat array (no
/// separate parent/related split at the API boundary).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseTokenRequest {
    #[serde(default, rename = "ProductId")]
    pub product_ids: Vec<String>,
    #[serde(default)]
    pub custom_developer_string: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseTokenResponse {
    /// Raw response body from `licensing.mp.microsoft.com` - opaque, see
    /// `CollectionsIdResponse::key`.
    #[serde(default)]
    pub token: String,
}

/// `XStoreQueryAssociatedProductsAsync` - `package_family_name` is computed by `xodus-cli run`
/// from the running package's `AppxManifest.xml` and published via
/// `xodus::ipc::ENV_PACKAGE_FAMILY_NAME`, since xodus-service has no other way to know which
/// package is running (mirrors `LicenseRequest::content_id`'s rationale, one level upstream:
/// the DLL can't compute the ProductId itself, only forward the PFN it was handed). Empty when
/// `xodus-cli run` couldn't find/parse a manifest - an honest "nothing to resolve", not an error.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssociatedProductsRequest {
    #[serde(default)]
    pub package_family_name: String,
    #[serde(default)]
    pub market: String,
    /// Cap on products returned, not a page size - the catalog lookup behind this paginates on
    /// its own terms and the answer is always a complete set. Zero means "no cap", which is what
    /// the DLL sends: it reports no further pages to the title, so anything held back here is
    /// held back for good.
    #[serde(default)]
    pub max_items: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssociatedProductsResponse {
    #[serde(default, rename = "Product")]
    pub products: Vec<CatalogProductEntry>,
}

/// One catalog entry, shared by [`AssociatedProductsResponse`] and [`ProductsResponse`] - the
/// two queries differ in how the products are chosen, not in what a product is.
///
/// Price fields are flat rather than a nested struct because they cross the wire as XML, where a
/// nested element buys nothing and costs a level of quick-xml quirks. They mirror the GDK's
/// `XStorePrice` field-for-field so the DLL can fill it in without deciding anything: `base_price`
/// is the undiscounted price (`MSRP`), `price` is what the customer pays today (`ListPrice`), and
/// `is_on_sale` is left for the DLL to derive from the two. All zero with an empty `currency_code`
/// when the catalog listed no purchasable availability - a store page should show no price at all
/// then, not a free one.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CatalogProductEntry {
    pub store_id: String,
    pub title: String,
    pub product_kind: String,
    /// ISO 4217, decided by the `market` the request asked for.
    #[serde(default)]
    pub currency_code: String,
    #[serde(default)]
    pub base_price: f32,
    #[serde(default)]
    pub price: f32,
    /// Per-period price of a subscription; zero for a one-off purchase.
    #[serde(default)]
    pub recurrence_price: f32,
    /// Unix timestamp, zero if the catalog gave none. Only meaningful while `price < base_price`.
    #[serde(default)]
    pub sale_end_date: i64,
}

/// `XStoreQueryProductsAsync` - prices an explicit list of `StoreId`s the title already knows,
/// rather than discovering products the way `AssociatedProductsRequest` does. This is what an
/// in-game storefront page runs on: Minecraft's "Choose your plan" screen names the Realms Core
/// and Realms Plus subscriptions and asks what they cost.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductsRequest {
    #[serde(default, rename = "StoreId")]
    pub store_ids: Vec<String>,
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductsResponse {
    #[serde(default, rename = "Product")]
    pub products: Vec<CatalogProductEntry>,
}

/// `XPersistentLocalStorageMountForPackage` - resolves the `PackageFamilyName` the DLL passes
/// as `packageIdentifier` to a `StoreId`, so it can be checked against `RelatedProducts`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResolveProductIdRequest {
    #[serde(default)]
    pub package_family_name: String,
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResolveProductIdResponse {
    #[serde(default)]
    pub product_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitled_products_response_round_trips_over_quick_xml() {
        let response = EntitledProductsResponse {
            products: vec![
                EntitledProduct {
                    store_id: "9ABC123".to_string(),
                    title: "Some Game".to_string(),
                    product_kind: "Game".to_string(),
                    included_in_game_pass: true,
                },
                EntitledProduct {
                    store_id: "9DEF456".to_string(),
                    title: "Another Game".to_string(),
                    product_kind: "Game".to_string(),
                    included_in_game_pass: false,
                },
            ],
        };

        let xml = quick_xml::se::to_string(&response).unwrap();
        let round_tripped: EntitledProductsResponse = quick_xml::de::from_str(&xml).unwrap();

        assert_eq!(round_tripped.products.len(), 2);
        assert_eq!(round_tripped.products[0].store_id, "9ABC123");
        assert!(round_tripped.products[0].included_in_game_pass);
        assert_eq!(round_tripped.products[1].store_id, "9DEF456");
        assert!(!round_tripped.products[1].included_in_game_pass);
    }

    #[test]
    fn empty_entitled_products_response_round_trips() {
        let response = EntitledProductsResponse { products: vec![] };
        let xml = quick_xml::se::to_string(&response).unwrap();
        let round_tripped: EntitledProductsResponse = quick_xml::de::from_str(&xml).unwrap();
        assert!(round_tripped.products.is_empty());
    }
}
