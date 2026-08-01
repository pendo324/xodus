use tokio::io::{AsyncRead, AsyncWrite};

use crate::simple_context::SimpleContext;

pub async fn handle<S>(_socket: &mut S, _context: &mut SimpleContext) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    unimplemented!("Protobuf path isnt implemented yet");
}
