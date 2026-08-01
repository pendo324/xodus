pub mod proto;
pub mod router;
pub mod xml;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest payload the service will allocate for an inbound message.
///
/// v2 sizes are `u32`, so without this a peer could ask for a 4 GB allocation with a
/// 10-byte header. Well above anything the protocol legitimately carries.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// How a message header spells its payload length.
///
/// v1 uses a `u16`, capping a message at 64 KB. That is fine for tokens but not for
/// everything the DLL will need - a gamer picture alone exceeds it - so v2 widens the
/// field to `u32`. The two are told apart by magic rather than negotiated, so existing
/// v1 clients keep working with no changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// `magic: u32 | type: u16 | size: u16`
    V1,
    /// `magic: u32 | type: u16 | size: u32`
    V2,
}

impl Framing {
    /// The magic that introduces an XML message in this framing.
    pub fn xml_magic(self) -> u32 {
        match self {
            Framing::V1 => crate::XML_MAGIC,
            Framing::V2 => crate::XML_MAGIC_V2,
        }
    }

    async fn read_size<S: AsyncRead + Unpin>(self, socket: &mut S) -> tokio::io::Result<usize> {
        Ok(match self {
            Framing::V1 => socket.read_u16_le().await? as usize,
            Framing::V2 => socket.read_u32_le().await? as usize,
        })
    }
}

/// Read one message's type and payload. The magic has already been consumed by the
/// router, which needed it to pick `framing` in the first place.
pub async fn read_message<S>(socket: &mut S, framing: Framing) -> tokio::io::Result<(u16, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let message_type = socket.read_u16_le().await?;
    let message_size = framing.read_size(socket).await?;
    if message_size > MAX_MESSAGE_SIZE {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            format!("message of {message_size} bytes exceeds the {MAX_MESSAGE_SIZE} byte limit"),
        ));
    }

    let mut buffer = vec![0; message_size];
    log::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    log::debug!("Read buffer");

    Ok((message_type, buffer))
}

pub fn encode_message(
    magic: u32,
    msg_type: u16,
    framing: Framing,
    message_buffer: Vec<u8>,
) -> tokio::io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(message_buffer.len() + 10);
    buffer.extend(magic.to_le_bytes());
    buffer.extend(msg_type.to_le_bytes());
    match framing {
        // Truncating instead would keep the payload but understate its length, leaving
        // the peer to parse the tail of it as the next message's header.
        Framing::V1 => {
            let size = u16::try_from(message_buffer.len()).map_err(|_| {
                tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidInput,
                    format!(
                        "response of {} bytes does not fit v1 framing; the client must use v2",
                        message_buffer.len()
                    ),
                )
            })?;
            buffer.extend(size.to_le_bytes());
        }
        Framing::V2 => buffer.extend((message_buffer.len() as u32).to_le_bytes()),
    }
    buffer.extend(message_buffer);

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v1 response that does not fit has to fail loudly. Truncating the length field
    /// desynchronizes the stream: the peer reads `len % 65536` bytes and then parses the
    /// remainder of the payload as the next header.
    #[test]
    fn oversized_v1_response_is_rejected() {
        let payload = vec![0u8; u16::MAX as usize + 1];

        assert!(encode_message(crate::XML_MAGIC, 1, Framing::V1, payload.clone()).is_err());
        assert!(encode_message(crate::XML_MAGIC_V2, 1, Framing::V2, payload).is_ok());
    }

    #[tokio::test]
    async fn v2_framing_round_trips_past_the_v1_ceiling() {
        let payload = vec![7u8; u16::MAX as usize + 64];
        let encoded =
            encode_message(crate::XML_MAGIC_V2, 3, Framing::V2, payload.clone()).expect("encodes");

        // The router consumes the magic before handing off, so skip it here too.
        let mut cursor = &encoded[4..];
        let (msg_type, body) = read_message(&mut cursor, Framing::V2).await.expect("reads");

        assert_eq!(msg_type, 3);
        assert_eq!(body, payload);
    }

    #[tokio::test]
    async fn oversized_declared_size_is_refused_before_allocating() {
        let mut header = Vec::new();
        header.extend(3u16.to_le_bytes());
        header.extend((MAX_MESSAGE_SIZE as u32 + 1).to_le_bytes());

        let mut cursor = &header[..];
        let err = read_message(&mut cursor, Framing::V2)
            .await
            .expect_err("should refuse");

        assert_eq!(err.kind(), tokio::io::ErrorKind::InvalidData);
    }
}
