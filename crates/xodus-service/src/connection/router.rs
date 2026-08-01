use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

use crate::simple_context::SimpleContext;

/// Serve one connection until it closes or the service shuts down.
///
/// Generic over the stream so the same message loop can serve transports other than
/// `xodus.sock`. The Wine-side `xgameruntime.dll` needs one: Wine's ws2_32 has no
/// working AF_UNIX, so it cannot reach the Unix socket at all.
///
/// Authenticating the peer is the caller's job, since only the caller knows what its
/// transport can prove - `SO_PEERCRED` on a Unix socket proves something TCP cannot.
pub async fn route<S>(
    mut socket: S,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut context = SimpleContext::new(device_token, tokens);
    loop {
        let mut read_magic = [0; 4];
        if token.is_cancelled() {
            return;
        }
        let read = socket.read_exact(&mut read_magic).await;
        if let Err(err) = read {
            log::error!("Failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => super::xml::handle(&mut socket, &mut context).await,
            crate::PROTO_MAGIC => super::proto::handle(&mut socket, &mut context).await,
            _ => {
                log::error!("Unknown magic");
                return;
            }
        };

        if let Err(err) = res {
            log::error!("There was an error handling the message: {err}");
        }
    }
}
