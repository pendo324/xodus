//! Building and installing the patched `XCurl.dll` a GDK title needs on Linux.
//!
//! The title reaches the network through `XCurl.dll`, the GDK's cut-down libcurl. The one
//! Microsoft ships works only against the real GDK runtime, so titles get a stock libcurl
//! instead - which needs three adaptations that cannot be expressed as options the game
//! would set for itself: a CA bundle (libHttpClient never sets `CURLOPT_CAINFO` and a
//! Windows libcurl has no app-directory default, so *every* HTTPS call fails verification),
//! a shared connection cache (libHttpClient calls `curl_multi_init` once per request, so
//! the pool is thrown away every call and each request rebuilds TCP+TLS), and a rewrite of
//! Minecraft's malformed People Hub URLs.
//!
//! All of that lives in the `xodus-xcurl` submodule, which owns the pinned libcurl closure
//! and the shim source. This module only decides *when* to invoke it.
//!
//! Best-effort throughout, like [`super::gameinput`]: building needs `mingw-w64` and
//! network access, and a user who has neither should still get as far as the title's own
//! error rather than a failed launch from us.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the `xodus-xcurl` checkout lives, if we can find one.
///
/// `XODUS_XCURL_DIR` wins so a working copy can be pointed at without reinstalling.
/// Otherwise the submodule beside this crate, resolved from the source tree this binary
/// was built from - `run-umu` is a developer verification command that already assumes it
/// is running out of the workspace.
fn checkout() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XODUS_XCURL_DIR") {
        let dir = PathBuf::from(dir);
        return dir.join("scripts/build.sh").is_file().then_some(dir);
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/xodus-xcurl");
    dir.join("scripts/build.sh").is_file().then_some(dir)
}

/// Ensures the title directory has the patched XCurl beside it.
///
/// Builds the set on first use and reuses it afterwards - the build re-verifies its pinned
/// downloads from cache, so the repeat cost is a compile of one small C file, but it still
/// wants `mingw-w64` and a network path to the msys2 mirror on a cold cache.
///
/// `XODUS_SKIP_XCURL=1` leaves whatever is already in the title directory alone, which is
/// how a hand-built or reverted DLL gets tested without this putting its own back.
pub fn install_xcurl(game_dir: &Path) {
    if std::env::var_os("XODUS_SKIP_XCURL").is_some_and(|v| v == "1") {
        eprintln!("XODUS_SKIP_XCURL=1 - leaving the title's XCurl.dll as it is");
        return;
    }
    let Some(dir) = checkout() else {
        eprintln!(
            "no xodus-xcurl checkout found - the title will use whatever XCurl.dll is \
             already beside it. Run `git submodule update --init` in the xodus checkout, \
             or set XODUS_XCURL_DIR."
        );
        return;
    };

    let set = dir.join("build/set");
    if !set.join("XCurl.dll").is_file() {
        eprintln!("building the patched XCurl (first run; needs mingw-w64 and network)...");
        if !run(&dir, dir.join("scripts/build.sh"), &[]) {
            eprintln!(
                "could not build the patched XCurl - the title will use whatever XCurl.dll \
                 is already beside it. Without it, expect either TLS verification failures \
                 on every request or a connection rebuilt per request."
            );
            return;
        }
    }

    // install.sh is idempotent and preserves the title's own files as *.xodus-orig, so
    // running it on every launch is safe and keeps a rebuilt shim from going unnoticed.
    if !run(
        &dir,
        dir.join("scripts/install.sh"),
        &[game_dir.as_os_str()],
    ) {
        eprintln!("could not install the patched XCurl into {game_dir:?}");
    }
}

fn run(cwd: &Path, script: PathBuf, args: &[&std::ffi::OsStr]) -> bool {
    match Command::new(&script).args(args).current_dir(cwd).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!("{}: exited with {status}", script.display());
            false
        }
        Err(err) => {
            eprintln!("{}: {err}", script.display());
            false
        }
    }
}
