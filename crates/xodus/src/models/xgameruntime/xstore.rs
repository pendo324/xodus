use serde::{Deserialize, Serialize};

/// `XStoreQueryGameLicenseAsync` - `content_id` is the package's `ContentId` (from its XVD
/// header), published to the game process by `xodus-cli run` via `xodus::ipc::ENV_CONTENT_ID`.
/// No user field: like `UserInfoRequest`, this always answers for whichever account's
/// credentials are on this connection.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseRequest {
    pub content_id: String,
    #[serde(default)]
    pub market: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseResponse {
    pub is_active: bool,
    /// Zero for a license with no expiration (the common case for an outright purchase).
    #[serde(default)]
    pub expiration_date: i64,
}

/// `XStoreQueryEntitledProductsAsync` - like `LicenseRequest`, answers for whichever
/// account's credentials are on this connection; no user field.
#[derive(Deserialize)]
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
#[derive(Deserialize)]
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

/// `XStoreQueryLicenseTokenAsync` - `product_ids[0]` is treated as the parent product and
/// the rest as related products, matching the real GDK signature's single flat array (no
/// separate parent/related split at the API boundary).
#[derive(Deserialize)]
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
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssociatedProductsRequest {
    #[serde(default)]
    pub package_family_name: String,
    #[serde(default)]
    pub market: String,
    #[serde(default)]
    pub max_items: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssociatedProductsResponse {
    #[serde(default, rename = "Product")]
    pub products: Vec<AssociatedProductEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AssociatedProductEntry {
    pub store_id: String,
    pub title: String,
    pub product_kind: String,
}

/// `XPersistentLocalStorageMountForPackage` - resolves the `PackageFamilyName` the DLL passes
/// as `packageIdentifier` to a `StoreId`, so it can be checked against `RelatedProducts`.
#[derive(Deserialize)]
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
