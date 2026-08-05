//! Wire-format models shared over the loopback IPC with `xgameruntime-rs`'s DLL.
//!
//! The authoritative definitions live in the standalone `xodus-ipc-models` crate (a
//! workspace sibling that the Windows-only DLL can depend on without pulling in all of
//! `xodus`), re-exported here so this crate's consumers keep the historical paths.

pub use xodus_ipc_models::{xstore, xuser};
