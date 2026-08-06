//! Installing the `xgameruntime.dll` / `xgameruntime.so` pair where Wine will load them.
//!
//! The DLL prefers to reach `xodus-service` over `xodus.sock` rather than loopback TCP,
//! because a Unix socket authenticates its peer (mode bits, `SO_PEERCRED`) where a TCP port
//! can only check a shared secret that any same-uid process can read out of the game's
//! environment. Wine's Winsock cannot open a Unix socket at all, so the DLL calls into a
//! native library through `__wine_unix_call` to do it - and getting Wine to load that library
//! is what this module is for.
//!
//! Wine pairs a `.so` with a PE only for modules resolved as *builtins*, and
//! `find_builtin_dll` (`dlls/ntdll/unix/loader.c`) derives the `.so` name by swapping the PE's
//! extension. Crucially it searches exactly two things: the build tree, and `dll_paths[]` -
//! and `set_dll_path` fills that with `dll_dir` (the runtime's own `lib/wine`) *before* any
//! `WINEDLLPATH` entry, unconditionally. It never looks in the prefix, and never in `system32`.
//!
//! That leaves one directory that can win, so that is the one we install into. The Proton fork
//! these titles launch under ships its own C `xgameruntime.dll` there; anything staged
//! elsewhere and pointed at with `WINEDLLPATH` loses to it silently, and the build we were
//! asked to run never loads. See [`install_into_runtime`] for how the original is preserved.
//!
//! If any of this is missing the DLL falls back to TCP on its own, so every failure here is a
//! warning, never fatal.

use std::path::{Path, PathBuf};

/// Where a Wine runtime keeps the builtins `find_builtin_dll` searches first, under its root.
const LIB_WINE: &str = "files/lib/wine";

/// The per-architecture subdirectories `find_builtin_dll` appends for the PE and the `.so`.
const PE_DIR: &str = "x86_64-windows";
const SO_DIR: &str = "x86_64-unix";

/// Points a Proton runtime's builtin `xgameruntime` at the pair we were asked to run.
///
/// Returns whether the game can be launched with a builtin loadorder. `false` means something
/// was missing and the caller should leave the runtime's own DLL in place.
///
/// This writes into the runtime rather than the prefix because the builtin search reaches
/// nowhere else (see the module docs). That is a shared install, so the originals are moved
/// aside to `*.xodus-orig` on first run rather than overwritten - restoring is a matter of
/// moving them back, and re-running is idempotent because we only ever displace a real file,
/// never a symlink we previously made.
///
/// Symlinks rather than copies so a rebuild of the DLL takes effect without reinstalling.
pub fn install_into_runtime(dll_path: &Path, proton: &Path) -> bool {
    let source_so = dll_path.with_file_name(xodus::ipc::UNIXLIB_FILE);
    if !source_so.is_file() {
        log::debug!(
            "No {} beside {dll_path:?} - the game will use the loopback TCP transport.",
            xodus::ipc::UNIXLIB_FILE
        );
        return false;
    }
    if !is_wine_builtin(dll_path) {
        log::warn!(
            "{dll_path:?} is not marked as a Wine builtin, so Wine will not pair {} with it. \
             Rebuild with scripts/build-release.sh. The game will use the loopback TCP \
             transport instead.",
            xodus::ipc::UNIXLIB_FILE
        );
        return false;
    }

    let lib_wine = proton.join(LIB_WINE);
    let pe_dir = lib_wine.join(PE_DIR);
    let so_dir = lib_wine.join(SO_DIR);
    if !pe_dir.is_dir() {
        log::warn!(
            "{pe_dir:?} is not a directory, so this does not look like a Proton runtime. \
             The game will use the loopback TCP transport."
        );
        return false;
    }

    let dll_dest = pe_dir.join("xgameruntime.dll");
    let so_dest = so_dir.join(xodus::ipc::UNIXLIB_FILE);
    match link_over(dll_path, &dll_dest).and_then(|()| link_over(&source_so, &so_dest)) {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "Could not install the xgameruntime pair into {lib_wine:?}: {err}. \
                 The game will use the loopback TCP transport instead."
            );
            false
        }
    }
}

/// Symlinks `dest` at `target`, preserving anything real that was already there.
///
/// The distinction between a symlink and a regular file at `dest` is the whole safety story:
/// a regular file is the runtime's own shipped builtin and gets moved to `*.xodus-orig` so the
/// install stays reversible, while a symlink is one of ours from a previous run and is simply
/// replaced. Without that check a second run would "back up" our own symlink over the real
/// backup and the original would be gone for good.
fn link_over(target: &Path, dest: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            std::fs::remove_file(dest)?;
        } else {
            let backup = dest.with_extension(match dest.extension() {
                Some(ext) => format!("{}.xodus-orig", ext.to_string_lossy()),
                None => "xodus-orig".into(),
            });
            if backup.exists() {
                std::fs::remove_file(dest)?;
            } else {
                log::info!("Preserving the runtime's own {dest:?} as {backup:?}");
                std::fs::rename(dest, &backup)?;
            }
        }
    } else if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(target, dest)
}

/// Copies `from` over `dest`, replacing whatever is there rather than writing through it.
///
/// The unlink is the entire point. Wine seeds a prefix's `system32` with *symlinks* into the
/// runtime's own `lib/wine` for every builtin it ships - `xgameruntime.dll` is one - and
/// `std::fs::copy` follows symlinks. Copying straight onto that path would write through to
/// the shared Proton install from a command whose entire scope is one prefix. Today that fails
/// with `EACCES` only because the artifact ships its files read-only; that is luck, not a
/// safeguard.
pub fn install_file(from: &Path, dest: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    std::fs::copy(from, dest)?;
    Ok(())
}

/// Whether a PE carries the signature that makes Wine treat it as a builtin.
///
/// Mirrors `get_image_params` in Wine's `server/mapping.c`: the 32-byte field directly after
/// the 64-byte DOS header. It is worth checking rather than assuming, because the signature
/// does not merely *prefer* the builtin path - it forecloses the other one. `load_builtin`
/// (`dlls/ntdll/unix/loader.c`) opens with
///
/// ```c
/// if (image_info->wine_builtin)
///     if (loadorder == LO_NATIVE) return STATUS_DLL_NOT_FOUND;
/// ```
///
/// so a signed DLL under `xgameruntime=n` fails its `LoadLibrary` and takes the title down
/// during startup, with nothing in the game's own log to say why.
pub fn is_wine_builtin(pe: &Path) -> bool {
    const SIGNATURE: &[u8] = b"Wine builtin DLL\0";
    let Ok(bytes) = std::fs::read(pe) else {
        return false;
    };
    bytes
        .get(0x40..0x40 + SIGNATURE.len())
        .is_some_and(|found| found == SIGNATURE)
}

/// Adds `path` to the set of host paths pressure-vessel bind-mounts into the container.
///
/// Without this the game gets `ENOENT` on a socket that plainly exists: umu runs titles inside
/// a pressure-vessel container with its own mount namespace, and `$XDG_RUNTIME_DIR` is not
/// among the paths it shares by default. The failure is easy to misread, because every check
/// you would run to diagnose it - `ls`, a test `connect()` - runs on the *host*, where the
/// socket is present and accepting.
pub fn filesystems_rw_with(path: &Path) -> String {
    match std::env::var("PRESSURE_VESSEL_FILESYSTEMS_RW") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", path.display()),
        _ => path.display().to_string(),
    }
}

/// The Unix path the DLL should dial, if `xodus-service` looks to be reachable there.
pub fn socket_path() -> Option<PathBuf> {
    let path = Path::new(&xodus::ipc::get_runtime_dir()).join("xodus.sock");
    if path.exists() {
        return Some(path);
    }
    log::debug!("No {path:?} - the game will use the loopback TCP transport.");
    None
}
