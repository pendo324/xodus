//! Loopback TCP transport, for clients that cannot use `xodus.sock`.
//!
//! The Wine-side `xgameruntime.dll` is the reason this exists: Wine's ws2_32 has no
//! working AF_UNIX, so a game process cannot reach the Unix socket at all.
//!
//! A Unix socket authenticates its peer for free - the filesystem mode keeps other
//! users out and `SO_PEERCRED` says who connected. A loopback TCP port has neither: any
//! local process, under any user, can connect to `127.0.0.1`. So the port is paired
//! with a random secret written to a `0600` file that only this user can read, and a
//! connection proves it read that file before the router will talk to it.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The port/secret type and where it is published live in `xodus::ipc` - `xodus-cli`
/// needs to read the same file without linking against this crate.
pub use xodus::ipc::TcpEndpoint as Endpoint;

/// Introduces the handshake. Distinct from the message magics so a client that skips
/// the handshake and opens with a message is rejected outright rather than read as a
/// malformed secret. ASCII "XDAU" on the wire.
pub const HANDSHAKE_MAGIC: u32 = 0x55414458;

/// Length of the shared secret, in bytes.
pub const SECRET_LEN: usize = 32;

/// Sent back once the secret checks out. A rejected client gets the connection closed
/// with no reply, so a probe learns nothing from the response.
pub const HANDSHAKE_ACCEPTED: u8 = 1;

/// Read and check a client's handshake.
///
/// Returns `Ok(())` only for a client that presented the right secret. Everything else
/// - wrong magic, wrong secret, a truncated read - is a rejection.
pub async fn accept_handshake<S>(socket: &mut S, secret: &[u8]) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let magic = socket.read_u32_le().await?;
    if magic != HANDSHAKE_MAGIC {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "connection did not open with a handshake",
        ));
    }

    let mut presented = [0u8; SECRET_LEN];
    socket.read_exact(&mut presented).await?;

    // Constant time: a byte-at-a-time comparison leaks how much of the secret a guess
    // got right, which turns a 2^256 search into 32 separate 2^8 ones.
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&presented[..], secret)) {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::PermissionDenied,
            "handshake presented the wrong secret",
        ));
    }

    socket.write_all(&[HANDSHAKE_ACCEPTED]).await
}

/// Client half of [`accept_handshake`], for tests and for in-tree clients.
pub async fn perform_handshake<S>(socket: &mut S, secret: &[u8]) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socket.write_all(&HANDSHAKE_MAGIC.to_le_bytes()).await?;
    socket.write_all(secret).await?;

    let accepted = socket.read_u8().await?;
    if accepted != HANDSHAKE_ACCEPTED {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::PermissionDenied,
            "service rejected the handshake",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn handshake_with(presented: &[u8], expected: &[u8]) -> tokio::io::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(256);

        let presented = presented.to_vec();
        tokio::spawn(async move {
            let _ = client.write_all(&HANDSHAKE_MAGIC.to_le_bytes()).await;
            let _ = client.write_all(&presented).await;
            // Hold the client end open; dropping it early would fail the reply write
            // and mask the result we are actually asserting on.
            let _ = client.read_u8().await;
        });

        accept_handshake(&mut server, expected).await
    }

    #[tokio::test]
    async fn correct_secret_is_accepted() {
        let endpoint = Endpoint::generate(1234);
        let secret = endpoint.secret_bytes().expect("valid hex");

        handshake_with(&secret, &secret).await.expect("accepted");
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let secret = Endpoint::generate(1234).secret_bytes().expect("valid hex");
        let mut guess = secret.clone();
        guess[SECRET_LEN - 1] ^= 0xff;

        let err = handshake_with(&guess, &secret).await.expect_err("rejected");
        assert_eq!(err.kind(), tokio::io::ErrorKind::PermissionDenied);
    }

    /// A client that skips the handshake and opens with a message must not have that
    /// message read as a secret.
    #[tokio::test]
    async fn message_magic_is_not_a_handshake() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let _ = client.write_all(&crate::XML_MAGIC.to_le_bytes()).await;
            let _ = client.write_all(&[0u8; SECRET_LEN]).await;
        });

        let err = accept_handshake(&mut server, &[0u8; SECRET_LEN])
            .await
            .expect_err("rejected");
        assert_eq!(err.kind(), tokio::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn endpoint_file_is_private_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("xodus-endpoint-test-{}", std::process::id()));
        let endpoint = Endpoint::generate(4321);
        endpoint.write_to(&path).await.expect("written");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "endpoint file must not be readable by others"
        );

        let read = Endpoint::read_from(&path).expect("read back");
        assert_eq!(read.port, endpoint.port);
        assert_eq!(
            read.secret_bytes().unwrap(),
            endpoint.secret_bytes().unwrap()
        );

        let _ = std::fs::remove_file(&path);
    }
}
