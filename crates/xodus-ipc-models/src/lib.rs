//! Wire-format models for the loopback IPC between `xgameruntime.dll` (a separate,
//! Windows-only crate) and `xodus-service`.
//!
//! The two sides are separate Cargo workspaces in separate repositories and can never
//! share a `Cargo` dependency (the DLL is cdylib-only, targets `x86_64-pc-windows-msvc`
//! under a Wine cross toolchain). Their only common interface is this XML dialect over
//! the loopback TCP port, so the request/response shapes live here to keep the two
//! hand-mirrored copies from drifting apart (see `xodus-rs`'s `src/ipc.rs`, which used
//! to redefine them).
//!
//! Every struct derives both `Serialize` and `Deserialize`, because the two sides use
//! opposite directions: `xodus-service` deserializes requests and serializes responses,
//! while `xgameruntime-rs` serializes requests and deserializes responses.

pub mod xstore;
pub mod xuser;
