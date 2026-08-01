use tokio::io::{AsyncRead, AsyncWrite};

use crate::{connection::Framing, simple_context::SimpleContext};

pub async fn handle<S>(
    _socket: &mut S,
    _context: &mut SimpleContext,
    _framing: Framing,
) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    unimplemented!("Protobuf path isnt implemented yet");
}
