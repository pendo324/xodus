use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;

use msixvc::models::xvd::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::license::get_license;

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn prepare(lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .unwrap();

    let device_s = String::from_utf8(
        Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", disk_size.div_ceil(256)))
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();

    let device = device_s.trim();

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await
        .unwrap();
    assert!(fmt.success());

    let mount_dir_obj = tempdir().unwrap();
    let mount_dir = mount_dir_obj.path().to_str().unwrap();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(mount_dir)
        .status()
        .await
        .unwrap();
    assert!(mnt.success());
    let mount_dir_cl = mount_dir.to_string();
    let device_cl = device.to_string();
    (
        async move || {
            let mnt = Command::new("/sbin/umount")
                .arg("-f")
                .arg(mount_dir_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());

            let mnt = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());
        },
        mount_dir.to_owned(),
    )
}

#[cfg(not(target_os = "macos"))]
async fn prepare(_lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    (async || {}, "".to_owned())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = std::fs::canonicalize(out).unwrap();
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let mut fds = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();
    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;

    for fd in fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if exe == fd.0 {
                nt_entry = Some(nt_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path)
        }

        env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix))
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

    let mut wine_cmd = Command::new(wine);
    wine_cmd
        .arg(nt_entry)
        .env("WINE_DLL_FILE_MAP", env_value)
        .env(xodus::ipc::ENV_CONTENT_ID, xvd.content_id().to_string());

    // Best-effort: `XStoreQueryAssociatedProductsAsync` needs the running package's own
    // ProductId, which xodus-service can only resolve from a PackageFamilyName. Absence here
    // just means that one call answers honestly empty later, not a launch failure.
    let mut package_family_name: Option<String> = None;
    match crate::appx::find_manifest_path(&lfiles) {
        Some(manifest_path) => {
            let manifest_path = manifest_path.to_string();
            let source_path = out.join(manifest_path.replace('\\', "/"));
            match std::fs::read_to_string(&source_path) {
                Ok(xml) => match crate::appx::parse_identity(&xml) {
                    Some(identity) => {
                        let pfn = crate::appx::compute_package_family_name(&identity);
                        wine_cmd.env(xodus::ipc::ENV_PACKAGE_FAMILY_NAME, &pfn);
                        package_family_name = Some(pfn);
                    }
                    None => log::warn!(
                        "Could not parse Identity out of {source_path:?}; \
                         XStoreQueryAssociatedProductsAsync will report an empty result."
                    ),
                },
                Err(err) => log::warn!(
                    "Could not read {source_path:?}: {err}; \
                     XStoreQueryAssociatedProductsAsync will report an empty result."
                ),
            }
        }
        None => log::warn!(
            "No AppxManifest.xml found in this package; \
             XStoreQueryAssociatedProductsAsync will report an empty result."
        ),
    }

    // Best-effort, same rationale as above: XPersistentLocalStorage's real numbers and
    // XPersistentLocalStorageMountForPackage's related-product check both come from
    // MicrosoftGame.config. Absence here means those calls fall back to a placeholder /
    // report nothing shareable, not a launch failure.
    match crate::appx::find_game_config_path(&lfiles) {
        Some(config_path) => {
            let config_path = config_path.to_string();
            let source_path = out.join(config_path.replace('\\', "/"));
            match std::fs::read_to_string(&source_path) {
                Ok(xml) => {
                    let config = crate::appx::parse_game_config(&xml);
                    if let Some(pls) = config.persistent_local_storage {
                        wine_cmd
                            .env(xodus::ipc::ENV_PLS_SIZE_MB, pls.size_mb.to_string())
                            .env(
                                xodus::ipc::ENV_PLS_GROWABLE_TO_MB,
                                pls.growable_to_mb.to_string(),
                            )
                            .env(xodus::ipc::ENV_PLS_SHAREABLE, pls.shareable.to_string());
                    }
                    wine_cmd.env(
                        xodus::ipc::ENV_RELATED_PRODUCTS,
                        config.related_products.join(","),
                    );
                }
                Err(err) => log::warn!(
                    "Could not read {source_path:?}: {err}; \
                     XPersistentLocalStorage will use placeholder space info."
                ),
            }
        }
        None => log::warn!(
            "No MicrosoftGame.config found in this package; \
             XPersistentLocalStorage will use placeholder space info."
        ),
    }

    // Best-effort: XGameSave's local container store needs a per-title directory that
    // survives reboots, unlike get_runtime_dir(). Scoped by PackageFamilyName so different
    // titles (and re-runs of the same title) don't collide; if we never resolved one above,
    // XGameSave just reports honest absence instead of guessing a shared location.
    if let Some(pfn) = &package_family_name {
        let data_home = std::env::var("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(std::env::var("HOME").expect("HOME not set"))
                    .join(".local/share")
            });
        let save_root = data_home.join("xodus/gamesaves").join(pfn);
        match std::fs::create_dir_all(&save_root) {
            Ok(()) => {
                let save_root_absolute = std::fs::canonicalize(&save_root).unwrap_or(save_root);
                let nt_path = format!(
                    "Z:{}",
                    save_root_absolute.to_string_lossy().replace('/', "\\")
                );
                wine_cmd.env(xodus::ipc::ENV_GAME_SAVE_ROOT, nt_path);
            }
            Err(err) => log::warn!(
                "Could not create game save directory at {save_root:?}: {err}; \
                 XGameSave will report honest absence instead of persisting saves."
            ),
        }
    }

    // The Wine-hosted xgameruntime.dll cannot see XDG_RUNTIME_DIR the way we do - it
    // only has a C:/Z: view of the world - so hand it the loopback endpoint directly
    // rather than making it locate and parse xodus-tcp.json itself.
    let endpoint_path =
        std::path::Path::new(&xodus::ipc::get_runtime_dir()).join(xodus::ipc::ENDPOINT_FILE);
    match xodus::ipc::TcpEndpoint::read_from(&endpoint_path) {
        Ok(endpoint) => {
            wine_cmd
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

    let mut wn = wine_cmd.spawn().unwrap();

    let pid = wn.id().unwrap();

    ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");

    let status = wn.wait().await.unwrap();

    cleanup().await;

    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}
