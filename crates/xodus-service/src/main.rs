use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;
use xodus::{models::secrets::LegacyToken, tokens::TokenManager};

use crate::connection::tcp::Endpoint;

mod connection;
mod simple_context;
mod utils;

// Magics are ASCII on the wire: "XSDX"/"PSDX" for v1, "XSDY"/"PSDY" for v2. The first
// byte selects the payload encoding, the last the framing version - see
// `connection::Framing` for what changed and why.
const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;
const XML_MAGIC_V2: u32 = 0x59445358;
const PROTO_MAGIC_V2: u32 = 0x59445350;

/// Where the loopback port and its secret are published, in the runtime dir.
const ENDPOINT_FILE: &str = "xodus-tcp.json";

#[tokio::main]
async fn main() {
    xodus::secrets::init_secrets().expect("Failed to init keychain");
    let tokens = Arc::new(TokenManager::with_keychain_and_memory());
    xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens).await;
    tokens
        .get_or_create_xbl_device_identity()
        .expect("Failed to load/create Xbox Live device identity");
    let xodus::models::secrets::Token::Legacy(device_token) =
        tokens.get_device_sts_token().unwrap()
    else {
        panic!("Device token isnt legacy")
    };

    env_logger::init_from_env("XODUS_LOG");
    let runtime_dir = utils::get_runtime_dir();
    let cancellation = CancellationToken::new();
    let socket_path = format!("{runtime_dir}/xodus.sock");
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failure to handle ctrl_c");
        trigger.cancel();
    });
    let endpoint_path = PathBuf::from(format!("{runtime_dir}/{ENDPOINT_FILE}"));

    let unix = tokio::spawn(serve_unix(
        socket_path.clone(),
        cancellation.clone(),
        device_token.clone(),
        tokens.clone(),
    ));
    let tcp = tokio::spawn(serve_loopback(
        endpoint_path.clone(),
        cancellation.clone(),
        device_token,
        tokens,
    ));

    _ = tokio::join!(unix, tcp);

    _ = tokio::fs::remove_file(socket_path).await;
    // Leaving this behind would advertise a port nothing is listening on, with a secret
    // that is no longer good for anything.
    _ = tokio::fs::remove_file(endpoint_path).await;
}

async fn serve_unix(
    socket_path: String,
    cancellation: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) {
    let listener = UnixListener::bind(&socket_path).expect("Unable to bind to socket");
    let perms = Permissions::from_mode(0o600);
    _ = tokio::fs::set_permissions(&socket_path, perms).await;
    log::info!("Listening on {socket_path}");

    loop {
        let accept = tokio::select! {
            r = listener.accept() => r,
            _ = cancellation.cancelled() => break,
        };
        let Ok((socket, _)) = accept else {
            log::error!("Failed to accept on {socket_path}");
            continue;
        };

        // The socket mode already keeps other users out; this is only for the log.
        let peer = socket.peer_cred().ok().and_then(|cred| cred.pid());
        log::debug!("Connection from pid {peer:?}");

        let token = cancellation.clone();
        let device_token = device_token.clone();
        let tokens = tokens.clone();
        tokio::spawn(async move {
            connection::router::route(socket, token, device_token, tokens).await
        });
    }
}

/// Serve the same protocol over loopback TCP, for clients that cannot use AF_UNIX -
/// which is every client running under Wine. See [`connection::tcp`] for why the
/// handshake is needed and what it is defending against.
async fn serve_loopback(
    endpoint_path: PathBuf,
    cancellation: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) {
    // Port 0: the kernel picks a free port, which is then published rather than fixed,
    // so two runtime dirs on one machine do not collide.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("Unable to bind loopback listener");
    let port = listener.local_addr().expect("no local addr").port();

    let endpoint = Endpoint::generate(port);
    let secret = Arc::new(endpoint.secret_bytes().expect("generated hex is valid"));
    if let Err(err) = endpoint.write_to(&endpoint_path).await {
        log::error!("Failed to publish the loopback endpoint: {err}");
        return;
    }
    log::info!("Listening on 127.0.0.1:{port}, endpoint at {endpoint_path:?}");

    loop {
        let accept = tokio::select! {
            r = listener.accept() => r,
            _ = cancellation.cancelled() => break,
        };
        let Ok((mut socket, peer)) = accept else {
            log::error!("Failed to accept on the loopback listener");
            continue;
        };

        let token = cancellation.clone();
        let device_token = device_token.clone();
        let tokens = tokens.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            if let Err(err) = connection::tcp::accept_handshake(&mut socket, &secret).await {
                log::warn!("Rejected loopback connection from {peer}: {err}");
                return;
            }
            log::debug!("Loopback connection from {peer}");
            connection::router::route(socket, token, device_token, tokens).await
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::connection::{Framing, tcp};

    fn dummy_device_token() -> LegacyToken {
        LegacyToken {
            key_name: None,
            token: "unused-by-ping".into(),
            binary_secret: None,
            tpm_key: None,
            lifetime: xodus::models::soap::Timestamp {
                id: None,
                created: "2026-01-01T00:00:00Z".into(),
                expires: "2036-01-01T00:00:00Z".into(),
            },
        }
    }

    /// Drives the real `serve_loopback` path: publish an endpoint, read it back the way
    /// a client would, handshake, and round-trip a Ping over v2 framing. Ping echoes its
    /// payload without touching credentials, so this exercises the transport alone.
    #[tokio::test]
    async fn published_endpoint_serves_a_ping_over_loopback() {
        let path = std::env::temp_dir().join(format!("xodus-loopback-test-{}", std::process::id()));
        let cancellation = CancellationToken::new();

        let service = tokio::spawn(serve_loopback(
            path.clone(),
            cancellation.clone(),
            dummy_device_token(),
            Arc::new(TokenManager::with_memory()),
        ));

        // The endpoint file appears once the listener is bound.
        let endpoint = loop {
            if let Ok(endpoint) = Endpoint::read_from(&path) {
                break endpoint;
            }
            tokio::task::yield_now().await;
        };

        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", endpoint.port))
            .await
            .expect("connects");
        tcp::perform_handshake(&mut socket, &endpoint.secret_bytes().unwrap())
            .await
            .expect("handshake accepted");

        const PING: u16 = 1;
        let payload = b"round trip".to_vec();
        let request = connection::encode_message(XML_MAGIC_V2, PING, Framing::V2, payload.clone())
            .expect("encodes");
        socket.write_all(&request).await.expect("sends");

        let mut magic = [0u8; 4];
        socket.read_exact(&mut magic).await.expect("reads magic");
        assert_eq!(u32::from_le_bytes(magic), XML_MAGIC_V2);

        let (msg_type, body) = connection::read_message(&mut socket, Framing::V2)
            .await
            .expect("reads reply");
        assert_eq!(msg_type, PING + 1, "Ping should be answered with Pong");
        assert_eq!(body, payload);

        cancellation.cancel();
        let _ = std::fs::remove_file(&path);
        service.abort();
    }

    #[tokio::test]
    async fn loopback_rejects_a_client_without_the_secret() {
        let path =
            std::env::temp_dir().join(format!("xodus-loopback-reject-test-{}", std::process::id()));
        let cancellation = CancellationToken::new();

        let service = tokio::spawn(serve_loopback(
            path.clone(),
            cancellation.clone(),
            dummy_device_token(),
            Arc::new(TokenManager::with_memory()),
        ));

        let endpoint = loop {
            if let Ok(endpoint) = Endpoint::read_from(&path) {
                break endpoint;
            }
            tokio::task::yield_now().await;
        };

        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", endpoint.port))
            .await
            .expect("connects");
        let wrong = vec![0u8; tcp::SECRET_LEN];

        // Reaching the port is not the same as being served: the connection is closed
        // without a reply, so the handshake read hits EOF.
        assert!(
            tcp::perform_handshake(&mut socket, &wrong).await.is_err(),
            "a client that cannot read the endpoint file must not be served"
        );

        cancellation.cancel();
        let _ = std::fs::remove_file(&path);
        service.abort();
    }
}
