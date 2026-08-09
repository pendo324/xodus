use std::process::ExitCode;

use xodus::api::displaycatalog::get_products_by_id;
use xodus::models::xgameruntime::xstore::StoreUiKind;
use xodus::tokens::TokenManager;

use crate::webview;

/// Minecraft's own Minecoin checkout. Real GDK answers `XStoreShowPurchaseUIAsync` for a
/// consumable by opening the Store's native overlay, which has no web equivalent and no
/// product page to link to instead - see [`store_url`]. This is the one surface that sells
/// the same thing over the web, and it lives on `minecraft.net`, whose session
/// [`StoreUiHandler::mirrored_cookie_domains`] already keeps signed in.
const BUY_MINECOINS_URL: &str = "https://www.minecraft.net/marketplace/buy-minecoins";

/// The catalog `ProductKind` of a Minecoin bundle, and of consumables generally.
const CONSUMABLE_PRODUCT_KIND: &str = "UnmanagedConsumable";

/// The whole `XStoreShow*UIAsync` family fronts one real Microsoft storefront page each.
/// Nothing here parses what the page does - the window closing is the only signal this
/// command reports, same as [`super::login::run`] reports only whether sign-in
/// completed.
///
/// `https://www.microsoft.com/{market}/p/-/{storeId}` only exists for top-level Store
/// apps/games (verified live: Minecraft's own `9nblggh2jhxj` redirects there to a real
/// `xbox.com` page). A live test against a real title (Minecraft) calling
/// `XStoreShowPurchaseUIAsync` for a Marketplace add-on's `storeId` showed that path
/// redirecting to `apps.microsoft.com`, which then rendered its own "page you requested
/// cannot be found" - that `storeId` is not a top-level catalog entry and has no page under
/// `/p/-/` at all. In-game add-ons like this are sold through the title's own marketplace
/// instead; for Minecraft specifically, `https://www.minecraft.net/marketplace/pdp/
/// {storeId}` is used for `Purchase`/`Gifting`/`RateAndReview`, which is where a live call
/// actually supplied an add-on `storeId` rather than a top-level one. Note that this path
/// cannot be verified by status code: it is an SPA shell that returns 200 with
/// byte-identical HTML for a real and a bogus `storeId` alike, so only rendering the page
/// shows whether the id resolves. It does not resolve for every add-on kind - a
/// `storeId` whose catalog product type is `UnmanagedConsumable` (Minecoin bundles, for
/// instance) has no product page on any web surface, and renders the site's "couldn't find
/// that page" view; real GDK opens the Store's native overlay for those, which has no web
/// equivalent. `Purchase` therefore asks the catalog what the id is first
/// ([`is_consumable`]) and sends consumables to [`BUY_MINECOINS_URL`] instead, which is the
/// one web surface that sells them. `Gifting`/`RateAndReview` keep the product page
/// unconditionally - neither has a meaningful consumable form, and the Minecoin checkout is
/// not a gifting or review page. This is a Minecraft-specific fix, not a
/// general one: there is no known way to go from an arbitrary title's Microsoft Store
/// `storeId` to that title's own marketplace domain, so another title calling these same
/// three kinds for its own add-ons would hit the same "no real page" gap this replaced.
/// `ProductPage`/`AssociatedProducts` keep the `microsoft.com` URL, which is verified for
/// top-level titles; `RedeemToken` keeps `https://redeem.microsoft.com/?code=`, which
/// 301-redirects to a real `account.microsoft.com/billing/redeem` page.
async fn store_url(
    kind: StoreUiKind,
    store_id: &str,
    token: &str,
    market: &str,
    client: &reqwest::Client,
) -> String {
    let market = if market.is_empty() { "en-us" } else { market };
    if kind == StoreUiKind::Purchase && is_consumable(store_id, market, client).await {
        return BUY_MINECOINS_URL.to_string();
    }
    match kind {
        StoreUiKind::Purchase | StoreUiKind::Gifting | StoreUiKind::RateAndReview => {
            // No locale segment: `market` is an ISO 3166 country code (the storefront call
            // supplies e.g. `US`), but minecraft.net's first path segment is a full
            // language-region locale, and anything it doesn't recognize is treated as part of
            // the path rather than a locale - `/US/marketplace/pdp/{id}` 404s where
            // `/en-us/marketplace/pdp/{id}` resolves, which is what a live purchase call hit.
            // Mapping country to locale isn't a lowercase-and-prefix either: `en-gb` 404s even
            // though `GB` is a real market. Leaving the segment off entirely resolves (200) and
            // redirects to whichever locale the site negotiates from `Accept-Language`, so the
            // page still comes up localized without this having to track the supported set.
            format!("https://www.minecraft.net/marketplace/pdp/{store_id}")
        }
        StoreUiKind::ProductPage => {
            format!("https://www.microsoft.com/{market}/p/-/{store_id}")
        }
        StoreUiKind::RedeemToken => {
            format!("https://redeem.microsoft.com/?code={token}")
        }
        StoreUiKind::AssociatedProducts => {
            format!("https://www.microsoft.com/{market}/p/-/{store_id}#activetab=pivot:overviewtab")
        }
    }
}

/// Whether `store_id` names a consumable, which decides between the two purchase surfaces in
/// [`store_url`]. Answers from the same catalog the in-game storefront prices against
/// (`fieldsTemplate=StoreSDK`), so the two agree on what a given id is by construction.
///
/// A lookup that fails or comes back empty answers `false`: the product page is the right
/// default for everything that isn't a consumable, and it is also the honest answer for an id
/// we could not classify - it at least names the product the title asked about, where the
/// Minecoin page would silently sell something else entirely.
async fn is_consumable(store_id: &str, market: &str, client: &reqwest::Client) -> bool {
    let ids = [store_id.to_string()];
    let languages = ["en".to_string(), "neutral".to_string()];
    match get_products_by_id(client, &ids, market, &languages).await {
        Ok(products) => products
            .iter()
            .any(|product| product.product_kind == CONSUMABLE_PRODUCT_KIND),
        Err(err) => {
            eprintln!("Product kind lookup for {store_id} failed, assuming not a consumable: {err}");
            false
        }
    }
}

/// Parses the `--kind` value `xodus-service`'s `run_store_ui` sends (see its own
/// `StoreUiKind` -> `&str` mapping, which this must stay the inverse of).
pub fn parse_kind(s: &str) -> Option<StoreUiKind> {
    Some(match s {
        "purchase" => StoreUiKind::Purchase,
        "rate-and-review" => StoreUiKind::RateAndReview,
        "redeem-token" => StoreUiKind::RedeemToken,
        "gifting" => StoreUiKind::Gifting,
        "associated-products" => StoreUiKind::AssociatedProducts,
        "product-page" => StoreUiKind::ProductPage,
        _ => return None,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    kind: StoreUiKind,
    store_id: String,
    _name: String,
    _extended_json_data: String,
    token: String,
    _allowed_store_ids: Vec<String>,
    market: String,
    tokens: TokenManager,
) -> ExitCode {
    let client = reqwest::Client::new();
    let url = store_url(kind, &store_id, &token, &market, &client).await;
    let handler = StoreUiHandler {
        title: window_title(kind),
        url,
    };

    match webview::run_sessions(handler, tokens) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Failed to show store UI: {err}");
            ExitCode::FAILURE
        }
    }
}

fn window_title(kind: StoreUiKind) -> &'static str {
    match kind {
        StoreUiKind::Purchase => "Xodus store - purchase",
        StoreUiKind::RateAndReview => "Xodus store - rate and review",
        StoreUiKind::RedeemToken => "Xodus store - redeem code",
        StoreUiKind::Gifting => "Xodus store - gifting",
        StoreUiKind::AssociatedProducts => "Xodus store - related products",
        StoreUiKind::ProductPage => "Xodus store - product page",
    }
}

struct StoreUiHandler {
    title: &'static str,
    url: String,
}

impl webview::SessionHandler for StoreUiHandler {
    type Output = ();

    fn bootstrap(
        &mut self,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        runtime.open_session(webview::simple_request(self.title, self.url.clone()));
        Ok(())
    }

    fn on_token(
        &mut self,
        _session_id: webview::SessionId,
        _data: xodus::models::live::DAProperty,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        // Nothing here emits the login page's host-bridge script, so this is never called.
        Ok(webview::HandlerControl::Continue)
    }

    fn on_closed(
        &mut self,
        _session_id: webview::SessionId,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(webview::HandlerControl::Complete(()))
    }

    fn mirrored_cookie_domains(&self) -> &[&str] {
        // Minecraft's own site-level session (bearer_token/access_token/session_username/
        // hasMcJavaEntitlement) is set session-only (confirmed live via a diagnostic cookie
        // dump), layered on top of the Microsoft sign-in that `shared_profile_dir` already
        // keeps persistent - without this, every fresh purchase window would show as
        // Microsoft-signed-in but still ask the user to "sign in to Minecraft" again.
        &["minecraft.net"]
    }
}
