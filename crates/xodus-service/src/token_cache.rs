//! Process-wide caches for the Xbox Live token chain.
//!
//! Every `XstsTokenRequest` from a game used to walk the full chain from scratch: MSA
//! exchange -> `user.auth.xboxlive.com/user/authenticate` -> `title.mgt.xboxlive.com`
//! endpoint table -> `xsts.auth.xboxlive.com/xsts/authorize`. That is three or four live
//! HTTPS round trips per token, and titles ask for a lot of tokens - a single Bedrock
//! session was measured issuing 70 requests across ten relying parties in 90 seconds,
//! ~900 ms each, which is what made pages like the player's own profile feel slow.
//!
//! Real Xbox clients cache these: an XSTS token carries a `NotAfter` and is reused for
//! every call to its relying party until then. This module does the same. The caches are
//! process-wide rather than per-connection because the Wine-side client opens a fresh TCP
//! connection per request, so a connection-scoped cache would never hit.
//!
//! Each cache slot is an async mutex held across the fetch, which also collapses a burst
//! of concurrent identical requests (the client dispatches token fetches from a four-wide
//! thread pool) into a single upstream call.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Duration, Utc};
use xodus::models::xbox::{TitleMgtResponse, XstsResponse};

/// Treat a token as expired this long before its stated expiry, so a token never expires
/// in flight between being handed to the game and the game using it.
const EXPIRY_SKEW: Duration = Duration::minutes(5);

/// How long the `title.mgt.xboxlive.com` endpoint table is reused. It carries no expiry of
/// its own and changes on Microsoft's release cadence, not on a session timescale.
const ENDPOINTS_TTL: Duration = Duration::hours(1);

struct Cached<T> {
    value: T,
    expires_at: DateTime<Utc>,
}

type Slot<T> = Arc<tokio::sync::Mutex<Option<Cached<T>>>>;

#[derive(Default)]
struct Caches {
    /// Keyed by client id: the `user.auth.xboxlive.com` user token that feeds XSTS.
    user_tokens: Mutex<HashMap<String, Slot<XstsResponse>>>,
    /// Keyed by (client id, relying party): the XSTS token the game actually gets.
    xsts: Mutex<HashMap<(String, String), Slot<XstsResponse>>>,
    /// Keyed by (client id, title id): the SISU-issued device and title tokens that put
    /// a title claim on an XSTS token. Keyed because a title token, unlike a device
    /// token, is scoped to the one title it was issued for.
    title_tokens: Mutex<HashMap<(String, String), Slot<TitleClaim>>>,
    endpoints: Slot<Arc<TitleMgtResponse>>,
}

fn caches() -> &'static Caches {
    static CACHES: OnceLock<Caches> = OnceLock::new();
    CACHES.get_or_init(Caches::default)
}

fn slot<K: std::hash::Hash + Eq, T>(map: &Mutex<HashMap<K, Slot<T>>>, key: K) -> Slot<T> {
    map.lock()
        .expect("token cache poisoned")
        .entry(key)
        .or_default()
        .clone()
}

/// Returns the cached value if it is still fresh, otherwise runs `fetch` and caches what
/// it returns. The slot lock is held across `fetch`, so concurrent callers for the same
/// key wait for the first one's result instead of each making their own upstream call.
async fn get_or_fetch<T, E, F, Fut>(slot: &Slot<T>, force_refresh: bool, fetch: F) -> Result<T, E>
where
    T: Clone,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(T, DateTime<Utc>), E>>,
{
    let mut guard = slot.lock().await;
    if !force_refresh {
        if let Some(cached) = guard.as_ref() {
            if cached.expires_at > Utc::now() {
                return Ok(cached.value.clone());
            }
        }
    }

    let (value, expires_at) = fetch().await?;
    *guard = Some(Cached {
        value: value.clone(),
        expires_at,
    });
    Ok(value)
}

/// The `user.auth.xboxlive.com` user token for `client_id`, fetched at most once per
/// lifetime. `fetch` runs the MSA exchange and the authenticate call.
pub async fn user_token<E, F, Fut>(client_id: &str, fetch: F) -> Result<XstsResponse, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<XstsResponse, E>>,
{
    let slot = slot(&caches().user_tokens, client_id.to_owned());
    get_or_fetch(&slot, false, || async {
        let token = fetch().await?;
        let expires_at = token.not_after - EXPIRY_SKEW;
        Ok((token, expires_at))
    })
    .await
}

/// The XSTS token for `relying_party`, reused until its `NotAfter`. `force_refresh` comes
/// straight from the game's request - a title that asks for a fresh token gets one.
pub async fn xsts_token<E, F, Fut>(
    client_id: &str,
    relying_party: &str,
    force_refresh: bool,
    fetch: F,
) -> Result<XstsResponse, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<XstsResponse, E>>,
{
    let slot = slot(
        &caches().xsts,
        (client_id.to_owned(), relying_party.to_owned()),
    );
    get_or_fetch(&slot, force_refresh, || async {
        let token = fetch().await?;
        let expires_at = token.not_after - EXPIRY_SKEW;
        Ok((token, expires_at))
    })
    .await
}

/// The device and title tokens that carry a title claim onto an XSTS token.
#[derive(Clone)]
pub struct TitleClaim {
    pub device_token: String,
    pub title_token: String,
}

/// The SISU-issued title claim for `(client_id, title_id)`, reused until it expires.
///
/// Cleared by [`invalidate_user_tokens`]: SISU authenticates the signed-in user as well
/// as the title, so a title token outlives neither a user switch nor a sign-out.
pub async fn title_claim<E, F, Fut>(
    client_id: &str,
    title_id: &str,
    fetch: F,
) -> Result<TitleClaim, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(TitleClaim, DateTime<Utc>), E>>,
{
    let slot = slot(
        &caches().title_tokens,
        (client_id.to_owned(), title_id.to_owned()),
    );
    get_or_fetch(&slot, false, || async {
        let (claim, not_after) = fetch().await?;
        Ok((claim, not_after - EXPIRY_SKEW))
    })
    .await
}

/// The title-management endpoint table, refreshed hourly.
pub async fn title_endpoints<E, F, Fut>(fetch: F) -> Result<Arc<TitleMgtResponse>, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<TitleMgtResponse, E>>,
{
    let slot = caches().endpoints.clone();
    get_or_fetch(&slot, false, || async {
        let endpoints = fetch().await?;
        Ok((Arc::new(endpoints), Utc::now() + ENDPOINTS_TTL))
    })
    .await
}

/// Drops every cached token. Called when the signed-in identity changes, since every
/// cached token belongs to the user who was signed in when it was minted.
pub fn invalidate_user_tokens() {
    caches()
        .user_tokens
        .lock()
        .expect("token cache poisoned")
        .clear();
    caches().xsts.lock().expect("token cache poisoned").clear();
    caches()
        .title_tokens
        .lock()
        .expect("token cache poisoned")
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_fresh_entry_is_reused_and_a_stale_one_is_refetched() {
        let slot: Slot<u32> = Slot::default();
        let calls = AtomicUsize::new(0);
        let fetch = |expiry: DateTime<Utc>| {
            let calls = &calls;
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>((7u32, expiry))
            }
        };

        let far = Utc::now() + Duration::hours(1);
        assert_eq!(get_or_fetch(&slot, false, fetch(far)).await, Ok(7));
        assert_eq!(get_or_fetch(&slot, false, fetch(far)).await, Ok(7));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call should hit the cache"
        );

        // A forced refresh bypasses a still-fresh entry, and leaves an already-expired
        // one behind so the next caller has to fetch again.
        let past = Utc::now() - Duration::hours(1);
        assert_eq!(get_or_fetch(&slot, true, fetch(past)).await, Ok(7));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(get_or_fetch(&slot, false, fetch(far)).await, Ok(7));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "expired entry should refetch"
        );
    }

    #[test]
    fn distinct_keys_get_distinct_slots() {
        let map: Mutex<HashMap<String, Slot<u32>>> = Mutex::default();
        let a = slot(&map, "a".to_owned());
        let b = slot(&map, "b".to_owned());
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&a, &slot(&map, "a".to_owned())));
    }
}
