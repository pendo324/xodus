//! Launches a GDK title through `umu-run` with a locally built `xgameruntime.dll`
//! substituted in, for verification against real Xbox Live/MSA endpoints without going
//! through `run`'s encrypted-msixvc mount pipeline (which relies on `WINE_DLL_FILE_MAP`,
//! a patch specific to the `xodus/wine` fork - `umu-run` normally drives a stock
//! GE-Proton/UMU-Proton build that doesn't have it). Because of that, this command needs
//! the title as plain files on disk with nothing left encrypted - including the main
//! `.exe`, which `xodus-cli extract`/`streaming` normally leave encrypted for `run`'s
//! mount trick to decrypt in memory. If `game` isn't already an extracted directory, this
//! downloads and extracts it with `decrypt_all` set, so the `.exe` on disk is fully
//! playable without that trick.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::process::Command;
use xodus::tokens::TokenManager;

/// Depth bound for the `AppxManifest.xml`/`MicrosoftGame.config`/`.exe` searches below -
/// real packages keep these within a couple of levels of the install root, and an
/// unbounded walk would make a misidentified `game` directory (e.g. a whole Wine prefix)
/// hang.
const MAX_SEARCH_DEPTH: usize = 6;

fn find_file_by_name(root: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    find_files_by(root, depth, &|path| {
        path.file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.eq_ignore_ascii_case(name))
    })
    .into_iter()
    .next()
}

/// All files under `root` (depth-bounded) whose filename satisfies `pred` - used to
/// auto-detect the title's `.exe` when the caller doesn't name one explicitly.
fn find_files_by(root: &Path, depth: usize, pred: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    if depth > MAX_SEARCH_DEPTH {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if pred(&path) {
            found.push(path);
        }
    }
    for subdir in subdirs {
        found.extend(find_files_by(&subdir, depth + 1, pred));
    }
    found
}

fn xdg_data_home() -> PathBuf {
    std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".local/share")
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    game: String,
    exe: Option<String>,
    xgameruntime_dll: String,
    prefix: Option<String>,
    proton: Option<String>,
    gameid: Option<String>,
    market: Option<String>,
) -> ExitCode {
    let dll_path = Path::new(&xgameruntime_dll);
    if !dll_path.is_file() {
        eprintln!("{xgameruntime_dll}: not a file");
        return ExitCode::FAILURE;
    }

    let game_dir = if Path::new(&game).is_dir() {
        PathBuf::from(&game)
    } else {
        let destination = xdg_data_home().join("xodus/titles").join(&game);
        println!(
            "{game:?} is not a local directory - treating it as a product/content id and \
             downloading+extracting (fully decrypted) into {destination:?}"
        );
        let status = crate::commands::streaming::run(
            client,
            tokens,
            game.clone(),
            destination.to_string_lossy().into_owned(),
            false,
            None,
            market,
            true,
        )
        .await;
        if status != ExitCode::SUCCESS {
            eprintln!("failed to download/extract {game}");
            return status;
        }
        destination
    };
    let game_dir = game_dir.as_path();

    let exe_path = match exe {
        Some(exe) => game_dir.join(&exe),
        None => {
            let candidates = find_files_by(game_dir, 0, &|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            });
            match candidates.as_slice() {
                [single] => single.clone(),
                [] => {
                    eprintln!("no .exe found under {game_dir:?}; pass --exe explicitly");
                    return ExitCode::FAILURE;
                }
                multiple => {
                    eprintln!(
                        "multiple .exe files found under {game_dir:?}, pass --exe explicitly: {}",
                        multiple
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    if !exe_path.is_file() {
        eprintln!("{}: not a file", exe_path.display());
        return ExitCode::FAILURE;
    }

    let prefix = prefix
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg_data_home().join("xodus/umu-verify-prefix"));

    // Bootstrap the prefix (wineboot creates `drive_c/windows/system32`, among everything
    // else) before we try to drop a file into it. Idempotent - safe to run every time.
    let mut bootstrap = Command::new("umu-run");
    bootstrap.arg("").env("WINEPREFIX", &prefix);
    if let Some(proton) = &proton {
        bootstrap.env("PROTONPATH", proton);
    }
    if let Some(gameid) = &gameid {
        bootstrap.env("GAMEID", gameid);
    }
    match bootstrap.status().await {
        Ok(status) if status.success() => {}
        // umu-run treats a blank command as "just make sure the prefix exists" per its
        // own docs, but some Proton/umu-launcher versions still surface a non-zero exit
        // from the inner (no-op) ShellExecuteEx attempt even though the prefix itself
        // was created fine beforehand - not fatal, so just note it and keep going.
        Ok(status) => {
            log::warn!(
                "umu-run prefix bootstrap exited with {status} (usually harmless - \
                 the prefix is typically still created); continuing"
            );
        }
        Err(err) => {
            eprintln!("failed to run umu-run (is it installed and on PATH?): {err}");
            return ExitCode::FAILURE;
        }
    }

    let system32 = prefix.join("drive_c/windows/system32");
    if let Err(err) = std::fs::create_dir_all(&system32) {
        eprintln!("{}: {err}", system32.display());
        return ExitCode::FAILURE;
    }
    if let Err(err) = crate::unixlib::install_file(dll_path, &system32.join("xgameruntime.dll")) {
        eprintln!("failed to install xgameruntime.dll into the prefix: {err}");
        return ExitCode::FAILURE;
    }

    crate::commands::gameinput::install_gameinput(client, &prefix, game_dir).await;
    crate::commands::xcurl::install_xcurl(game_dir);

    // Prefer the Unix socket over loopback TCP when the service is up and the runtime will
    // actually load the companion library; the DLL falls back on its own when it will not.
    let socket_path = crate::unixlib::socket_path();
    let as_builtin = socket_path.is_some()
        && proton
            .as_ref()
            .is_some_and(|p| crate::unixlib::install_into_runtime(dll_path, Path::new(p)));

    let mut umu_cmd = Command::new("umu-run");
    umu_cmd
        .arg(&exe_path)
        .current_dir(exe_path.parent().unwrap_or(game_dir))
        .env("WINEPREFIX", &prefix);

    // `amd_ags_x64` disabled: on AMD, Wine's builtin stub loops on
    // "err:amd_ags:get_ags_version_from_resource File version info not found, err 1812" and the
    // title hangs on its loader-section wait instead of reaching the game. Rediscovered the
    // hard way more than once - see xgameruntime-rs/scripts/known-good-launch.sh.
    //
    // The `xgameruntime` loadorder is the interesting half, and it is not a free choice - it
    // follows from whether the DLL carries the Wine builtin signature, not from whether we
    // managed to install it. A signed DLL under `=n` makes `load_builtin` return
    // STATUS_DLL_NOT_FOUND and the title dies on its LoadLibrary before it draws anything, so
    // `=n` is only ever safe for an unsigned build.
    let loadorder = if crate::unixlib::is_wine_builtin(dll_path) {
        "amd_ags_x64=;xgameruntime=b,n"
    } else {
        "amd_ags_x64=;xgameruntime=n"
    };
    umu_cmd.env("WINEDLLOVERRIDES", loadorder);
    if as_builtin {
        let socket_path = socket_path.as_deref().unwrap();
        umu_cmd.env(xodus::ipc::ENV_SOCKET_PATH, socket_path).env(
            "PRESSURE_VESSEL_FILESYSTEMS_RW",
            crate::unixlib::filesystems_rw_with(socket_path),
        );
    }
    if let Some(proton) = &proton {
        umu_cmd.env("PROTONPATH", proton);
    }
    if let Some(gameid) = &gameid {
        umu_cmd.env("GAMEID", gameid);
    }

    // Best-effort, same rationale/precedent as `run`: absence here just means the
    // corresponding call answers honestly empty/placeholder later, not a launch failure.
    let mut package_family_name: Option<String> = None;
    match find_file_by_name(game_dir, "AppxManifest.xml", 0) {
        Some(manifest_path) => match std::fs::read_to_string(&manifest_path) {
            Ok(xml) => match crate::appx::parse_identity(&xml) {
                Some(identity) => {
                    let pfn = crate::appx::compute_package_family_name(&identity);
                    umu_cmd.env(xodus::ipc::ENV_PACKAGE_FAMILY_NAME, &pfn);
                    package_family_name = Some(pfn);
                }
                None => log::warn!(
                    "Could not parse Identity out of {manifest_path:?}; \
                     XStoreQueryAssociatedProductsAsync will report an empty result."
                ),
            },
            Err(err) => log::warn!("Could not read {manifest_path:?}: {err}"),
        },
        None => log::warn!(
            "No AppxManifest.xml found under {game_dir:?}; \
             XStoreQueryAssociatedProductsAsync will report an empty result."
        ),
    }

    match find_file_by_name(game_dir, "MicrosoftGame.config", 0) {
        Some(config_path) => match std::fs::read_to_string(&config_path) {
            Ok(xml) => {
                let config = crate::appx::parse_game_config(&xml);
                if let Some(pls) = config.persistent_local_storage {
                    umu_cmd
                        .env(xodus::ipc::ENV_PLS_SIZE_MB, pls.size_mb.to_string())
                        .env(
                            xodus::ipc::ENV_PLS_GROWABLE_TO_MB,
                            pls.growable_to_mb.to_string(),
                        )
                        .env(xodus::ipc::ENV_PLS_SHAREABLE, pls.shareable.to_string());
                }
                umu_cmd.env(
                    xodus::ipc::ENV_RELATED_PRODUCTS,
                    config.related_products.join(","),
                );
            }
            Err(err) => log::warn!("Could not read {config_path:?}: {err}"),
        },
        None => log::warn!(
            "No MicrosoftGame.config found under {game_dir:?}; \
             XPersistentLocalStorage will use placeholder space info."
        ),
    }

    if let Some(pfn) = &package_family_name {
        let save_root = xdg_data_home().join("xodus/gamesaves").join(pfn);
        match std::fs::create_dir_all(&save_root) {
            Ok(()) => {
                let save_root_absolute = std::fs::canonicalize(&save_root).unwrap_or(save_root);
                let nt_path = format!(
                    "Z:{}",
                    save_root_absolute.to_string_lossy().replace('/', "\\")
                );
                umu_cmd.env(xodus::ipc::ENV_GAME_SAVE_ROOT, nt_path);
            }
            Err(err) => log::warn!(
                "Could not create game save directory at {save_root:?}: {err}; \
                 XGameSave will report honest absence instead of persisting saves."
            ),
        }
    }

    let endpoint_path = Path::new(&xodus::ipc::get_runtime_dir()).join(xodus::ipc::ENDPOINT_FILE);
    match xodus::ipc::TcpEndpoint::read_from(&endpoint_path) {
        Ok(endpoint) => {
            umu_cmd
                .env(xodus::ipc::ENV_TCP_PORT, endpoint.port.to_string())
                .env(xodus::ipc::ENV_TCP_SECRET, &endpoint.secret);
        }
        Err(err) => {
            log::warn!(
                "Could not read xodus-service's loopback endpoint at {endpoint_path:?}: {err}. \
                 Sign-in and licensing calls from the game will fail until xodus-service is running."
            );
        }
    }

    let mut child = match umu_cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("failed to spawn umu-run: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(pid) = child.id() {
        ctrlc::set_handler(move || {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        })
        .expect("failed to install Ctrl+C handler");
    }

    let status = child.wait().await.unwrap();
    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}
