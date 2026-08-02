//! Where to find a running `xodus-service`, shared by every client that needs to locate
//! it without linking against the service binary itself. `xodus-cli` reads this to wire
//! up the game process it launches; `xgameruntime-rs` (a separate, Windows-only crate
//! that cannot depend on this one) mirrors these constants on its side.

use std::path::Path;

/// Filename the loopback endpoint is published under, in the runtime dir.
pub const ENDPOINT_FILE: &str = "xodus-tcp.json";

/// Env vars `xodus-cli run` sets on the game process so a Wine-hosted `xgameruntime.dll`
/// can reach `xodus-service` without reading [`ENDPOINT_FILE`] itself. Wine's CRT sees
/// `C:`/`Z:` drives, not `XDG_RUNTIME_DIR` - passing the port and secret directly
/// sidesteps that translation instead of teaching the DLL to do it.
pub const ENV_TCP_PORT: &str = "XODUS_TCP_PORT";
pub const ENV_TCP_SECRET: &str = "XODUS_TCP_SECRET";

/// The `ContentId` of the package `xodus-cli run` just launched, so `XStoreQueryGameLicenseAsync`
/// can ask `xodus-service` for a live license check against the same content the game process
/// actually is - `xodus-service` has no other way to know which package is running.
pub const ENV_CONTENT_ID: &str = "XODUS_CONTENT_ID";

#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> String {
    std::env::var("XDG_RUNTIME_DIR").expect("Runtime dir not set")
}

#[cfg(target_os = "macos")]
pub fn get_runtime_dir() -> String {
    "/tmp/".to_string()
}

/// The port and secret a loopback client needs to connect, as published to
/// [`ENDPOINT_FILE`]. See `xodus-service::connection::tcp` for the handshake this
/// secret guards and why a Unix socket does not need one.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TcpEndpoint {
    pub port: u16,
    /// Hex-encoded, so the file stays greppable and easy to pass through an env var.
    pub secret: String,
}

impl TcpEndpoint {
    pub fn generate(port: u16) -> Self {
        // ThreadRng is a CSPRNG; this secret is the only thing standing between another
        // local process and the user's Xbox Live tokens.
        let secret: [u8; 32] = rand::random();

        Self {
            port,
            secret: hex::encode(secret),
        }
    }

    pub fn secret_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.secret)
    }

    /// Load an endpoint published by a running service.
    pub fn read_from(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(std::io::Error::from)
    }

    /// Publish the endpoint for clients to find, readable only by this user.
    ///
    /// The file is created `0600` *before* the secret is written to it, so it is never
    /// briefly world-readable. An endpoint from a previous run is replaced rather than
    /// appended to.
    #[cfg(unix)]
    pub async fn write_to(&self, path: &Path) -> std::io::Result<()> {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);

        let mut file = options.open(path).await?;
        let json = serde_json::to_vec(self)?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &json).await?;
        file.sync_all().await
    }
}
