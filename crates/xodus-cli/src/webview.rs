use std::collections::HashMap;
use std::path::PathBuf;

use tao::dpi::{LogicalSize, Size};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopWindowTarget};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::{Window, WindowBuilder};
use wry::http::{HeaderMap, HeaderValue};
use wry::{PageLoadEvent, WebContext, WebView, WebViewBuilder};
use xodus::models::live::{DAProperty, HostBridgeMessage};
use xodus::tokens::{StoredCookie, StoredStorageItem, TokenManager};

/// Every `xodus-cli` invocation (`login`, `store-ui`, ...) is a separate OS process, and
/// `WebViewBuilder::new()` with no [`WebContext`] gives each one an independent, non-persistent
/// profile - a user who signs in during `login` shows up signed out in a later `store-ui`
/// window (confirmed live: the store UI opened at a Microsoft page with no session). Pointing
/// every session at the same on-disk directory shares cookies/local storage across processes the
/// same way a single long-lived browser profile would.
fn shared_profile_dir() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".local/share")
        });
    base.join("xodus/webview-profile")
}

type HandlerResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(u64);

pub enum HandlerControl<T> {
    Continue,
    Complete(T),
}

pub trait SessionHandler {
    type Output: std::fmt::Debug;

    fn bootstrap(&mut self, runtime: &mut RuntimeCommands) -> HandlerResult<()>;

    fn on_token(
        &mut self,
        session_id: SessionId,
        data: DAProperty,
        runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>>;

    fn on_closed(
        &mut self,
        _session_id: SessionId,
        _runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>> {
        Ok(HandlerControl::Continue)
    }

    /// Domains (suffix-matched against a cookie's own `domain`, so `.minecraft.net` and
    /// `www.minecraft.net` both match `"minecraft.net"`) whose session-only cookies AND
    /// `sessionStorage` should be mirrored across separate `xodus-cli` process launches -
    /// see [`StoredCookie`] and [`StoredStorageItem`] for why each needs its own mechanism.
    /// Empty by default: [`shared_profile_dir`] already gives every launch the same on-disk
    /// WebKit profile, which is enough for anything the site itself marks persistent
    /// (confirmed live: a real Microsoft sign-in survives across launches this way, and so
    /// does `localStorage`) - mirroring is only for a site's own session-only cookies and
    /// its `sessionStorage`, neither of which the profile's on-disk store ever writes out.
    fn mirrored_cookie_domains(&self) -> &[&str] {
        &[]
    }
}

pub struct WebviewRequest {
    title: String,
    url: String,
    headers: HeaderMap,
}

pub struct RuntimeCommands {
    next_session_id: u64,
    actions: Vec<RuntimeAction>,
}

enum RuntimeAction {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    CloseSession(SessionId),
}

enum CustomEvent {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    HostGetContext(SessionId, String),
    Finish(SessionId),
    IpcCallback(SessionId, DAProperty),
}

struct RuntimeState<T: SessionHandler> {
    handler: T,
    next_session_id: u64,
    window: Option<Window>,
    web_context: WebContext,
    tokens: TokenManager,
    active_session: Option<SessionId>,
    active_webview: Option<WebView>,
    result: Option<T::Output>,
    error: Option<String>,
}

impl RuntimeCommands {
    fn new(next_session_id: u64) -> Self {
        Self {
            next_session_id,
            actions: Vec::new(),
        }
    }

    pub fn open_session(&mut self, request: WebviewRequest) -> SessionId {
        let session_id = SessionId(self.next_session_id);
        self.next_session_id += 1;
        self.actions.push(RuntimeAction::OpenSession {
            session_id,
            request,
        });
        session_id
    }

    pub fn close_session(&mut self, session_id: SessionId) {
        self.actions.push(RuntimeAction::CloseSession(session_id));
    }
}

impl WebviewRequest {
    fn new(title: impl Into<String>, url: String, headers: HeaderMap) -> Self {
        Self {
            title: title.into(),
            url,
            headers,
        }
    }
}

pub fn login_request(client_id: String, market: String) -> WebviewRequest {
    let uid = uuid::Uuid::new_v4();
    let url = format!(
        "https://login.live.com/ppsecure/InlineLogin.srf?id=80604&scid=3&mkt={market}&Platform=Windows10&clientid={client_id}&hosted=1"
    );

    let mut headers = HeaderMap::new();
    headers.insert("cxh-capabilities", HeaderValue::from_static(r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":1,"ChromelessUI":0}"#));
    headers.insert(
        "cxh-correlationId",
        HeaderValue::from_str(&format!("{uid}")).unwrap(),
    );
    headers.insert("cxh-msaBinaryVersion", HeaderValue::from_static(r#"55"#));
    headers.insert(
        "cxh-identityClientBinaryVersion",
        HeaderValue::from_static(r#"3"#),
    );
    headers.insert(
        "cxh-osVersionInfo",
        HeaderValue::from_static(
            r#"{"platformId":2,"majorVersion":10,"minorVersion":0,"buildNumber":26100}"#,
        ),
    );
    headers.insert(
        "cxh-platform",
        HeaderValue::from_static(r#"CloudExperienceHost.Platform.DESKTOP"#),
    );
    headers.insert("cxh-protocol", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert("cxh-source", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert(
        "hostApp",
        HeaderValue::from_static(r#"CloudExperienceHost"#),
    );

    WebviewRequest::new("Xodus login", url, headers)
}

pub fn finalize_request(url: String) -> WebviewRequest {
    WebviewRequest::new("Xodus login", url, HeaderMap::new())
}

/// A window with no special headers and no host-bridge script to intercept - the
/// storefront pages `xodus-cli store-ui` opens complete entirely on their own, unlike
/// `login_request`'s MSA page.
pub fn simple_request(title: impl Into<String>, url: String) -> WebviewRequest {
    WebviewRequest::new(title, url, HeaderMap::new())
}

pub fn run_sessions<T>(handler: T, tokens: TokenManager) -> HandlerResult<Option<T::Output>>
where
    T: SessionHandler,
{
    let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let mut state = RuntimeState {
        handler,
        next_session_id: 1,
        window: None,
        web_context: WebContext::new(Some(shared_profile_dir())),
        tokens,
        active_session: None,
        active_webview: None,
        result: None,
        error: None,
    };

    let mut commands = RuntimeCommands::new(state.next_session_id);
    state.handler.bootstrap(&mut commands)?;
    state.next_session_id = commands.next_session_id;
    dispatch_actions(&proxy, commands.actions)?;
    event_loop.run_return(|event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(CustomEvent::OpenSession {
                session_id,
                request,
            }) => {
                if let Err(err) = create_session(
                    target,
                    proxy.clone(),
                    &mut state,
                    session_id,
                    request,
                ) {
                    state.error = Some(err.to_string());
                }
            }
            Event::UserEvent(CustomEvent::Finish(session_id)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script("window.ipc.postMessage(JSON.stringify(ServerData))");
                }
            }
            Event::UserEvent(CustomEvent::HostGetContext(session_id, ctx)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script(&format!(r#"window["CloudExperienceHost.Bridge.dispatchMessage"](JSON.stringify({{"type": "callback", "value": {{ "name": "CloudExperienceHost.getContext", "args": ["CloudExperienceHost", "TokenBroker", "TokenBroker", "{{\"PrivatePropertyBag\":1,\"PasswordlessConnect\":1,\"PreferAssociate\":1,\"ChromelessUI\":0}}"], "context": "{ctx}"}}}}))"#));
                }
            }
            Event::UserEvent(CustomEvent::IpcCallback(session_id, data)) => {
                apply_handler_result(
                    &proxy,
                    target,
                    &mut state,
                    move |handler, runtime| handler.on_token(session_id, data, runtime),
                );
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(session_id) = state.active_session {
                    log_cookie_state(&state);
                    mirror_session_cookies_out(&state);
                    mirror_session_storage_out(&state);
                    remove_session(&mut state, session_id);
                    apply_handler_result(&proxy, target, &mut state, move |handler, runtime| {
                        handler.on_closed(session_id, runtime)
                    });
                }
            }
            _ => {}
        }

        if state.error.is_some() || state.result.is_some() {
            *control_flow = ControlFlow::Exit;
        }
    });

    if let Some(error) = state.error {
        return Err(std::io::Error::other(error).into());
    }

    Ok(state.result)
}

fn dispatch_actions(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    actions: Vec<RuntimeAction>,
) -> HandlerResult<()> {
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => proxy
                .send_event(CustomEvent::OpenSession {
                    session_id,
                    request,
                })
                .map_err(|_| std::io::Error::other("failed to open session"))?,
            RuntimeAction::CloseSession(session_id) => {
                let _ = session_id;
            }
        }
    }

    Ok(())
}

fn apply_handler_result<T, F>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    callback: F,
) where
    T: SessionHandler,
    F: FnOnce(&mut T, &mut RuntimeCommands) -> HandlerResult<HandlerControl<T::Output>>,
{
    let mut commands = RuntimeCommands::new(state.next_session_id);
    match callback(&mut state.handler, &mut commands) {
        Ok(HandlerControl::Continue) => {}
        Ok(HandlerControl::Complete(result)) => state.result = Some(result),
        Err(err) => state.error = Some(err.to_string()),
    }

    state.next_session_id = commands.next_session_id;
    apply_actions(proxy, target, state, commands.actions);
}

fn apply_actions<T>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    actions: Vec<RuntimeAction>,
) where
    T: SessionHandler,
{
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => {
                if let Err(err) = create_session(target, proxy.clone(), state, session_id, request)
                {
                    state.error = Some(err.to_string());
                    break;
                }
            }
            RuntimeAction::CloseSession(session_id) => {
                remove_session(state, session_id);
                let _ = proxy;
            }
        }
    }
}

fn create_session<T: SessionHandler>(
    target: &EventLoopWindowTarget<CustomEvent>,
    proxy: tao::event_loop::EventLoopProxy<CustomEvent>,
    state: &mut RuntimeState<T>,
    session_id: SessionId,
    request: WebviewRequest,
) -> HandlerResult<()> {
    if state.window.is_none() {
        let window = WindowBuilder::new()
            .with_resizable(false)
            .with_title(&request.title)
            .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
            .build(target)?;
        state.window = Some(window);
    }

    let window = state
        .window
        .as_ref()
        .ok_or_else(|| std::io::Error::other("window was not initialized"))?;
    window.set_title(&request.title);

    let proxy_ipc = proxy.clone();
    // `sessionStorage` (unlike a cookie or `localStorage`) only exists for the lifetime of
    // the browsing context that set it, so it has to be restored through an initialization
    // script that runs before the page's own scripts do - unlike cookie restoration, this
    // can't be deferred until after the webview builds (see `restore_mirrored_session_storage`).
    let storage_restore_script = restore_mirrored_session_storage_script(state, &request.url);
    // Navigation is deferred (no `.with_url`/`.with_headers` here) so any mirrored
    // cookies (see `mirrored_cookie_domains`) can be replayed into the webview's cookie
    // jar before the real request goes out - `load_url_with_headers` below does the
    // navigation `.with_url` would otherwise have triggered as soon as the webview builds.
    let mut builder = WebViewBuilder::new_with_web_context(&mut state.web_context)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            .with_initialization_script("window.external = {notify: window.ipc.postMessage }");
    if let Some(script) = storage_restore_script {
        builder = builder.with_initialization_script(script);
    }
    let builder = builder
            .with_ipc_handler(move |request| {
                let body = request.body();
                let payload = serde_json::from_str::<DAProperty>(body);
                if let Ok(data) = payload {
                    if proxy_ipc
                        .send_event(CustomEvent::IpcCallback(session_id, data))
                        .is_err()
                    {
                        eprintln!("Failed to dispatch IPC token callback event");
                    }
                } else {
                    match serde_json::from_str::<HostBridgeMessage>(body) {
                        Ok(message) => {
                            if let Some(ctx) = message.get_context_invoke()
                                && proxy_ipc
                                    .send_event(CustomEvent::HostGetContext(
                                        session_id,
                                        ctx.to_string(),
                                    ))
                                    .is_err()
                            {
                                eprintln!("Failed to dispatch host context event");
                            }
                        }
                        Err(_) => {
                            eprintln!("Ignoring unsupported IPC payload");
                        }
                    }
                }
            })
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished) && url.starts_with("https://login.live.com/ppsecure/post.srf")
                {
                    proxy.send_event(CustomEvent::Finish(session_id)).ok();
                }
            });

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(window.default_vbox().unwrap()).unwrap()
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).unwrap();

    restore_mirrored_cookies(state, &webview, &request.url);
    webview.load_url_with_headers(&request.url, request.headers)?;

    state.active_session = Some(session_id);
    state.active_webview = Some(webview);
    Ok(())
}

/// A cookie's own `domain` (e.g. `.minecraft.net`, `www.minecraft.net`) suffix-matched
/// against a handler's [`SessionHandler::mirrored_cookie_domains`] list (e.g.
/// `"minecraft.net"`), the same way a real browser scopes cookies to a domain and its
/// subdomains.
fn cookie_domain_matches(cookie_domain: &str, allowlist: &[&str]) -> bool {
    let bare = cookie_domain.trim_start_matches('.');
    allowlist
        .iter()
        .any(|domain| bare == *domain || bare.ends_with(&format!(".{domain}")))
}

/// Whether a cookie stored for `cookie_domain` would have been sent to `host`, i.e. `host`
/// is that domain or a subdomain of it (`minecraft.net` covers `www.minecraft.net`).
fn cookie_domain_covers_host(cookie_domain: &str, host: &str) -> bool {
    let bare = cookie_domain.trim_start_matches('.');
    host == bare || host.ends_with(&format!(".{bare}"))
}

/// Replays cookies saved by an earlier session's [`mirror_session_cookies_out`] into a
/// freshly built webview, before it navigates anywhere - see
/// [`SessionHandler::mirrored_cookie_domains`] for why this exists instead of relying on
/// `wry`'s own on-disk cookie persistence.
///
/// Everything restored here lands as a *host-only* cookie scoped to `request_url`'s own host,
/// which is why the target URL has to be known: a domain cookie can't survive this round trip
/// at all. The `cookie` crate's `Cookie::domain()` getter strips a leading `.` (so a site's
/// `Domain=.minecraft.net` reads back as plain `minecraft.net`), and `wry` builds the cookie it
/// hands to the browser engine from that same getter - so the "applies to subdomains too" bit is
/// lost in both directions and cannot be reasserted through this API. Restoring a cookie under
/// the apex domain it was saved from therefore produces one scoped to *only* the apex, which the
/// page at `www.` never sends (confirmed live: a restore that reported success left the site
/// still signed out, and a cookie dump showed the replayed cookies sitting alongside the site's
/// own same-named ones as separate entries). Re-homing each cookie onto the host actually being
/// loaded keeps it on the one origin that matters here.
fn restore_mirrored_cookies<T: SessionHandler>(
    state: &RuntimeState<T>,
    webview: &WebView,
    request_url: &str,
) {
    let domains = state.handler.mirrored_cookie_domains();
    if domains.is_empty() {
        return;
    }
    let Some(host) = url_host(request_url) else {
        return;
    };
    let saved = match state.tokens.get_session_cookies() {
        Ok(saved) => saved,
        Err(err) => {
            eprintln!("[diag] failed to load mirrored cookies from keyring: {err}");
            return;
        }
    };
    eprintln!(
        "[diag] restoring mirrored cookies: {} stored, host={host}, domains={domains:?}",
        saved.len()
    );
    let mut restored = 0;
    for stored in saved.values() {
        if !cookie_domain_matches(&stored.domain, domains) {
            continue;
        }
        if !cookie_domain_covers_host(&stored.domain, host) {
            continue;
        }
        let mut builder = wry::cookie::Cookie::build((stored.name.clone(), stored.value.clone()))
            .domain(host.to_string())
            .secure(stored.secure)
            .http_only(stored.http_only);
        if let Some(path) = &stored.path {
            builder = builder.path(path.clone());
        }
        match webview.set_cookie(&builder.build()) {
            Ok(()) => {
                restored += 1;
                eprintln!("[diag]   restored {} {} as {host}", stored.domain, stored.name);
            }
            Err(err) => eprintln!(
                "[diag]   failed to restore {} {}: {err}",
                stored.domain, stored.name
            ),
        }
    }
    eprintln!("[diag] restored {restored} matching cookie(s)");

    // The authoritative check: what the engine would actually send to this URL. A cookie can
    // be in the jar and still be invisible here if its scope doesn't match, which is exactly
    // the failure this function's scoping works around.
    match webview.cookies_for_url(request_url) {
        Ok(visible) => {
            eprintln!("[diag] {} cookie(s) visible to {request_url}:", visible.len());
            for cookie in &visible {
                eprintln!(
                    "[diag]   {} {}",
                    cookie.domain().unwrap_or("?"),
                    cookie.name()
                );
            }
        }
        Err(err) => eprintln!("[diag] failed to query cookies for url: {err}"),
    }
}

/// Captures the active webview's session-only cookies (no `Expires`/`Max-Age` of their
/// own - `wry`'s on-disk store never writes these out, see [`shared_profile_dir`]) for any
/// domain the handler opted into via [`SessionHandler::mirrored_cookie_domains`], and saves
/// them through the OS keychain so [`restore_mirrored_cookies`] can replay them into the
/// next session opened by a later `xodus-cli` process.
///
/// The jar can legitimately hold several same-named cookies for one domain, because
/// [`restore_mirrored_cookies`]'s replayed copy is scoped to a single host while the site's own
/// is usually scoped to the whole domain - and since `Cookie::domain()` reports both without a
/// leading `.`, they are indistinguishable by domain alone here. Keeping the last one iterated
/// would pick between a possibly-stale replayed value and the site's current one at random, so
/// same-name collisions resolve toward the longer value instead: a re-issued token carries more
/// material than the cleared or truncated placeholder a signed-out page leaves behind, and two
/// copies of an unchanged token tie harmlessly.
fn mirror_session_cookies_out<T: SessionHandler>(state: &RuntimeState<T>) {
    let domains = state.handler.mirrored_cookie_domains();
    if domains.is_empty() {
        return;
    }
    let Some(webview) = state.active_webview.as_ref() else {
        return;
    };
    let Ok(cookies) = webview.cookies() else {
        return;
    };

    let mut current: HashMap<String, StoredCookie> = HashMap::new();
    for cookie in &cookies {
        let Some(domain) = cookie.domain() else {
            continue;
        };
        if !cookie_domain_matches(domain, domains) {
            continue;
        }
        if !matches!(
            cookie.expires(),
            None | Some(wry::cookie::Expiration::Session)
        ) {
            continue;
        }

        let value = cookie.value();
        let entry = current.entry(cookie.name().to_string());
        match entry {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if value.len() <= slot.get().value.len() {
                    continue;
                }
                slot.insert(StoredCookie {
                    domain: domain.to_string(),
                    name: cookie.name().to_string(),
                    value: value.to_string(),
                    path: cookie.path().map(str::to_string),
                    secure: cookie.secure().unwrap_or(false),
                    http_only: cookie.http_only().unwrap_or(false),
                });
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(StoredCookie {
                    domain: domain.to_string(),
                    name: cookie.name().to_string(),
                    value: value.to_string(),
                    path: cookie.path().map(str::to_string),
                    secure: cookie.secure().unwrap_or(false),
                    http_only: cookie.http_only().unwrap_or(false),
                });
            }
        }
    }

    // Rebuilt from the current jar rather than merged into what was there before, so a
    // host-only copy left over from an earlier scoping doesn't linger once it stops appearing.
    let mut saved = state.tokens.get_session_cookies().unwrap_or_default();
    saved.retain(|_, stored| !cookie_domain_matches(&stored.domain, domains));
    for stored in current.into_values() {
        saved.insert(format!("{}|{}", stored.domain, stored.name), stored);
    }
    let _ = state.tokens.save_session_cookies(&saved);
}

/// The host a `https://...` URL targets (matches `window.location.host` once the page
/// loads) - every URL actually used here is `https`, so this only needs to find where the
/// host ends, not full RFC 3986 parsing.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

const SESSION_STORAGE_CAPTURE_SCRIPT: &str = "JSON.stringify(Object.fromEntries(Object.keys(sessionStorage).map(k => [k, sessionStorage.getItem(k)])))";

/// Runs `evaluate_script_with_callback` and blocks until its callback fires, the same way
/// `wry`'s own `cookies()`/`set_cookie()` block internally - safe to call here because,
/// like those, this only ever runs from within a GTK-driven event loop callback.
#[cfg(target_os = "linux")]
fn eval_script_sync(webview: &WebView, js: &str) -> Result<String, wry::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    webview.evaluate_script_with_callback(js, move |result| {
        let _ = tx.send(result);
    })?;
    loop {
        gtk::main_iteration();
        if let Ok(result) = rx.try_recv() {
            return Ok(result);
        }
    }
}

/// Captures the active webview's `sessionStorage` for whichever host it's currently showing,
/// if that host is one of [`SessionHandler::mirrored_cookie_domains`] - see
/// [`StoredStorageItem`] for why this exists alongside cookie mirroring rather than instead
/// of it.
#[cfg(target_os = "linux")]
fn mirror_session_storage_out<T: SessionHandler>(state: &RuntimeState<T>) {
    let domains = state.handler.mirrored_cookie_domains();
    if domains.is_empty() {
        return;
    }
    let Some(webview) = state.active_webview.as_ref() else {
        return;
    };
    let Ok(url) = webview.url() else {
        return;
    };
    let Some(host) = url_host(&url) else {
        return;
    };
    if !cookie_domain_matches(host, domains) {
        return;
    }

    let raw = match eval_script_sync(webview, SESSION_STORAGE_CAPTURE_SCRIPT) {
        Ok(raw) => raw,
        Err(err) => {
            eprintln!("[diag] failed to read sessionStorage: {err}");
            return;
        }
    };
    // `evaluate_script_with_callback` JSON-serializes whatever the script returns, and the
    // script already returns a JSON string (via `JSON.stringify`), so this is
    // double-encoded: decode the callback's own wrapper first, then parse the inner object.
    let inner: String = match serde_json::from_str(&raw) {
        Ok(inner) => inner,
        Err(err) => {
            eprintln!("[diag] failed to decode sessionStorage callback result: {err}");
            return;
        }
    };
    let entries: HashMap<String, String> = match serde_json::from_str(&inner) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("[diag] failed to parse sessionStorage entries: {err}");
            return;
        }
    };

    let mut saved = state.tokens.get_session_storage().unwrap_or_default();
    let count = entries.len();
    for (key, value) in entries {
        saved.insert(
            format!("{host}|{key}"),
            StoredStorageItem {
                host: host.to_string(),
                key,
                value,
            },
        );
    }
    let _ = state.tokens.save_session_storage(&saved);
    eprintln!("[diag] mirrored {count} sessionStorage entrie(s) for {host}");
}

#[cfg(not(target_os = "linux"))]
fn mirror_session_storage_out<T: SessionHandler>(_state: &RuntimeState<T>) {}

/// Builds a `with_initialization_script` body that replays [`StoredStorageItem`]s saved by
/// an earlier session's [`mirror_session_storage_out`] into `sessionStorage`, scoped to
/// whichever host `request_url` will navigate to. Initialization scripts run before the
/// page's own scripts, which is why this has to be wired into the builder chain rather than
/// run after the webview exists, unlike [`restore_mirrored_cookies`] - by the time a page
/// script (e.g. MSAL.js) checks `sessionStorage` on load, it needs to already be there.
/// `None` means there's nothing to restore, so callers can skip
/// `.with_initialization_script` entirely.
fn restore_mirrored_session_storage_script<T: SessionHandler>(
    state: &RuntimeState<T>,
    request_url: &str,
) -> Option<String> {
    let domains = state.handler.mirrored_cookie_domains();
    if domains.is_empty() {
        return None;
    }
    let host = url_host(request_url)?;
    if !cookie_domain_matches(host, domains) {
        return None;
    }
    let saved = state.tokens.get_session_storage().ok()?;
    let matching: Vec<_> = saved.values().filter(|item| item.host == host).collect();
    if matching.is_empty() {
        return None;
    }

    let mut script = String::new();
    for item in &matching {
        // `serde_json::to_string` on a `String` produces a JS-safe double-quoted string
        // literal (quotes/backslashes/control characters all escaped), safe to splice
        // directly into the script instead of hand-rolling escaping.
        let key_literal = serde_json::to_string(&item.key).unwrap();
        let value_literal = serde_json::to_string(&item.value).unwrap();
        script.push_str(&format!(
            "try {{ sessionStorage.setItem({key_literal}, {value_literal}); }} catch (e) {{}}\n"
        ));
    }
    eprintln!(
        "[diag] restoring {} sessionStorage entrie(s) for {host}",
        matching.len()
    );
    Some(script)
}

/// Diagnostic only: prints which cookies exist in the active webview when its window closes,
/// to tell apart "no auth cookie was ever set" from "a session-only cookie was set but can't
/// survive process exit" - `wry`'s on-disk persistence (see [`shared_profile_dir`]) only writes
/// cookies that carry their own expiry, so a session cookie here would still show as signed-out
/// in a later `xodus-cli` process despite the shared profile directory. Domain and name are not
/// secret (an MS auth session's cookie *names* - e.g. `MSPAuth`, `RPSTAuth` - are public
/// knowledge); the value never gets read or printed.
fn log_cookie_state<T: SessionHandler>(state: &RuntimeState<T>) {
    let Some(webview) = state.active_webview.as_ref() else {
        return;
    };
    match webview.cookies() {
        Ok(cookies) => {
            eprintln!("[diag] {} cookie(s) at window close:", cookies.len());
            for cookie in &cookies {
                let persistent = !matches!(cookie.expires(), Some(wry::cookie::Expiration::Session) | None);
                eprintln!(
                    "[diag]   {} {} (persistent={persistent})",
                    cookie.domain().unwrap_or("?"),
                    cookie.name(),
                );
            }
        }
        Err(err) => eprintln!("[diag] failed to read cookies at window close: {err}"),
    }
}

fn remove_session<T: SessionHandler>(state: &mut RuntimeState<T>, session_id: SessionId) {
    if state.active_session == Some(session_id) {
        state.active_session = None;
        state.active_webview = None;
    }
}
