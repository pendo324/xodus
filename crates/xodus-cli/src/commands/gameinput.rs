//! Installs the native Microsoft `GameInput` redistributable into a Wine prefix.
//!
//! GDK titles load `GameInputRedist.dll` directly (it exports `GameInputCreate`) via a
//! `RedistDir` registry value, bypassing both `xgameruntime.dll` and this repo's own
//! Wine-builtin `gameinput.dll` once it's present - and the builtin's mouse/controller
//! readers need HID devices `winebus` never exposes, so without the redist a title's
//! keyboard works but the mouse is dead in-game (or, for some titles, the install/setup
//! flow that waits on `GameInputCreate` hangs outright waiting for a device that never
//! reports ready).
//!
//! This deliberately never invokes `msiexec`: running the bundled `GameInputRedist.msi`
//! the normal way reliably deadlocks forever inside a WiX custom action under Wine
//! (reproduced repeatedly; also documented independently by the BedrockOnLinux project,
//! which calls it the "RtlGenRandom custom-action hang"). Instead this parses the MSI's
//! OLE compound-file container and embedded MSZip CAB itself to pull the redist's files
//! straight out, and writes the prefix's `system.reg` directly rather than going through
//! `reg.exe` (which would start Wine Explorer, and possibly initialise a second GPU
//! session, as an unwanted side effect of a setup step). Ported from BedrockOnLinux's
//! `bol/gameinput.py` (MIT), which solved this exact problem for the same class of title.
//!
//! The MSI's own file/stream names (both the CAB entry names and the extracted binaries'
//! `OriginalFilename` PE metadata) are not reliable - `GameInputBridge.dll` reports itself
//! as `GameInputRedist` internally. The only stable signal is structural: PE dll-vs-exe
//! (via the `IMAGE_FILE_DLL` characteristics bit) plus relative size within each group.

use std::io;
use std::path::{Path, PathBuf};

use flate2::{Decompress, FlushDecompress};

use crate::wine_registry::{RegChange, apply_registry_changes};

const REDIST_DIR: &str = r"C:\Program Files\Microsoft GameInput\x64";
const SERVICE_DISPLAY_NAME: &str = "GameInput Redist Service";

/// True when the native redist is fully installed - the only prerequisite the game's own
/// `RedistDir` lookup needs, and the signal this module uses to skip re-extracting on every
/// launch. Testing for `system32/gameinput.dll` would prove nothing, since wineboot always
/// pre-seeds a fresh prefix with this repo's Wine-builtin `gameinput.dll`.
pub fn redist_ok(prefix: &Path) -> bool {
    let x64 = prefix.join("drive_c/Program Files/Microsoft GameInput/x64");
    x64.join("GameInputRedist.dll").is_file() && x64.join("GameInputRedistService.exe").is_file()
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

fn read_u16(data: &[u8], off: usize) -> io::Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| err("truncated OLE/CAB structure"))
}

fn read_u32(data: &[u8], off: usize) -> io::Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| err("truncated OLE/CAB structure"))
}

fn read_u64(data: &[u8], off: usize) -> io::Result<u64> {
    data.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| err("truncated OLE/CAB structure"))
}

const OLE_FREE: u32 = 0xFFFFFFFF;
const OLE_ENDC: u32 = 0xFFFFFFFE;

/// Follows a FAT-style (regular or mini) chain of sector/minisector indices starting at
/// `start`, stopping at `FREE`/`ENDC` or a repeat (a malformed chain must never hang here).
fn chain(fat: &[u32], start: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut n = start;
    while n != OLE_ENDC && n != OLE_FREE && (n as usize) < fat.len() && seen.insert(n) {
        out.push(n);
        n = fat[n as usize];
    }
    out
}

/// Extracts the embedded MSZip CAB from an MSI's raw bytes by walking its OLE compound-file
/// container (the CAB is stored as a stream scattered across OLE sectors, not contiguously).
fn msi_embedded_cab(msi: &[u8]) -> io::Result<Vec<u8>> {
    if msi.get(..8) != Some(&hex_literal(b"d0cf11e0a1b11ae1")[..]) {
        return Err(err("not an OLE compound file (bad magic)"));
    }
    let ssz = 1usize << read_u16(msi, 0x1e)?;
    let mssz = 1usize << read_u16(msi, 0x20)?;
    let dir0 = read_u32(msi, 0x30)?;
    let minicut = read_u32(msi, 0x38)? as u64;
    let minifat0 = read_u32(msi, 0x3c)?;
    let difat0 = read_u32(msi, 0x44)?;
    let ndifat = read_u32(msi, 0x48)?;

    let sect = |n: u32| -> io::Result<&[u8]> {
        let start = (n as usize + 1) * ssz;
        msi.get(start..start + ssz)
            .ok_or_else(|| err("OLE sector index out of range"))
    };
    let sector_u32s = |n: u32| -> io::Result<Vec<u32>> {
        sect(n)?
            .chunks_exact(4)
            .map(|c| Ok(u32::from_le_bytes(c.try_into().unwrap())))
            .collect()
    };

    let mut difat: Vec<u32> = (0..109)
        .map(|i| read_u32(msi, 0x4c + i * 4))
        .collect::<io::Result<_>>()?;
    let mut next = difat0;
    for _ in 0..ndifat {
        if next == OLE_FREE || next == OLE_ENDC {
            break;
        }
        let mut vals = sector_u32s(next)?;
        let follow = vals.pop().unwrap();
        difat.extend(vals);
        next = follow;
    }

    let mut fat = Vec::new();
    for &fs in difat.iter().filter(|&&d| d != OLE_FREE) {
        fat.extend(sector_u32s(fs)?);
    }

    let rbig = |start: u32, size: u64| -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for n in chain(&fat, start) {
            out.extend_from_slice(sect(n)?);
        }
        out.truncate(size as usize);
        Ok(out)
    };

    let dir_chain = chain(&fat, dir0);
    let dird = rbig(dir0, (dir_chain.len() * ssz) as u64)?;
    struct Entry {
        typ: u8,
        start: u32,
        size: u64,
    }
    let mut ents = Vec::new();
    for e in dird.chunks(128) {
        if e.len() < 128 {
            break;
        }
        if read_u16(e, 64)? != 0 {
            ents.push(Entry {
                typ: e[66],
                start: read_u32(e, 116)?,
                size: read_u64(e, 120)?,
            });
        }
    }
    let root = ents
        .iter()
        .find(|e| e.typ == 5)
        .ok_or_else(|| err("OLE compound file has no root storage entry"))?;
    let ministream = rbig(root.start, root.size)?;

    let mut mfat = Vec::new();
    for ms in chain(&fat, minifat0) {
        mfat.extend(sector_u32s(ms)?);
    }
    let rmini = |start: u32, size: u64| -> Vec<u8> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut n = start;
        while n != OLE_ENDC && n != OLE_FREE && (n as usize) < mfat.len() && seen.insert(n) {
            let lo = n as usize * mssz;
            let hi = (lo + mssz).min(ministream.len());
            if lo < ministream.len() {
                out.extend_from_slice(&ministream[lo..hi]);
            }
            n = mfat[n as usize];
        }
        out.truncate(size as usize);
        out
    };

    for e in &ents {
        if e.typ != 2 || e.size < 4 {
            continue;
        }
        let head = if e.size >= minicut {
            rbig(e.start, e.size)?
        } else {
            rmini(e.start, e.size)
        };
        if head.get(..4) == Some(b"MSCF".as_slice()) {
            return Ok(head);
        }
    }
    Err(err("MSI has no embedded MSZip CAB stream"))
}

fn hex_literal(hex: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        let byte = std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap();
        *o = u8::from_str_radix(byte, 16).unwrap();
    }
    out
}

/// Decompresses one MSZip block. Each block in a folder is an independent raw-DEFLATE
/// stream that uses the previous block's uncompressed output (last 32KiB) as a preset
/// dictionary, so blocks must be decompressed in order and chained.
fn mszip_inflate(compressed: &[u8], dict: &[u8]) -> io::Result<Vec<u8>> {
    let mut d = Decompress::new(false);
    if !dict.is_empty() {
        d.set_dictionary(dict).map_err(err_display)?;
    }
    // `decompress_vec` only ever writes into the vec's existing *spare* capacity - unlike
    // e.g. `Vec::extend`, it never grows the vec itself - so an under-sized buffer surfaces
    // as `Status::BufError` rather than being handled internally. Grow and retry, re-slicing
    // `compressed` from `total_in` each time: the stream is stateful across calls, so a retry
    // must feed only the not-yet-consumed remainder, never the same bytes twice.
    let mut out = Vec::with_capacity((dict.len() + compressed.len()).max(4096) * 4);
    loop {
        let before_in = d.total_in() as usize;
        let status = d
            .decompress_vec(&compressed[before_in..], &mut out, FlushDecompress::Finish)
            .map_err(err_display)?;
        if status == flate2::Status::StreamEnd {
            break;
        }
        if (d.total_in() as usize) == before_in && out.len() == out.capacity() {
            out.reserve(out.capacity().max(4096));
            continue;
        }
        if (d.total_in() as usize) == before_in {
            return Err(err(
                "MSZip block decompression stalled without consuming all input",
            ));
        }
    }
    Ok(out)
}

fn err_display(e: impl std::fmt::Display) -> io::Error {
    err(e.to_string())
}

/// Decompresses an MSZip CAB, returning each contained file's payload in file-table order.
fn cab_payload(cab: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if cab.get(..4) != Some(b"MSCF".as_slice()) {
        return Err(err("not a CAB (bad MSCF signature)"));
    }
    let coff_files = read_u32(cab, 16)? as usize;
    let cfolders = read_u16(cab, 26)?;
    let cfiles = read_u16(cab, 28)?;
    let flags = read_u16(cab, 30)?;

    let mut o = 36usize;
    let (mut cb_folder, mut cb_data) = (0usize, 0usize);
    if flags & 4 != 0 {
        let cb_header = read_u16(cab, o)? as usize;
        cb_folder = *cab.get(o + 2).ok_or_else(|| err("truncated CAB header"))? as usize;
        cb_data = *cab.get(o + 3).ok_or_else(|| err("truncated CAB header"))? as usize;
        o += 4 + cb_header;
    }

    let mut folders = Vec::new();
    for _ in 0..cfolders {
        let coff = read_u32(cab, o)?;
        let ndata = read_u16(cab, o + 4)?;
        o += 8 + cb_folder;
        folders.push((coff, ndata));
    }

    let mut files = Vec::new();
    let mut p = coff_files;
    for _ in 0..cfiles {
        let cb = read_u32(cab, p)?;
        let uoff = read_u32(cab, p + 4)?;
        let ifol = read_u16(cab, p + 8)?;
        p += 16;
        let nul = cab[p..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| err("unterminated CAB file name"))?;
        p += nul + 1;
        files.push((cb as usize, uoff as usize, ifol as usize));
    }

    let mut fdata = Vec::new();
    for &(coff, ndata) in &folders {
        let mut q = coff as usize;
        let mut out: Vec<u8> = Vec::new();
        for _ in 0..ndata {
            let cb_d = read_u16(cab, q + 4)? as usize;
            q += 8 + cb_data;
            let blk = cab
                .get(q..q + cb_d)
                .ok_or_else(|| err("truncated CAB data block"))?;
            q += cb_d;
            if blk.get(..2) != Some(b"CK".as_slice()) {
                return Err(err("CAB data block is not MSZip-compressed"));
            }
            let dict_start = out.len().saturating_sub(32768);
            let dict = out[dict_start..].to_vec();
            let decompressed = mszip_inflate(&blk[2..], &dict)?;
            out.extend_from_slice(&decompressed);
        }
        fdata.push(out);
    }

    files
        .into_iter()
        .map(|(cb, uoff, ifol)| {
            let folder = fdata
                .get(ifol)
                .ok_or_else(|| err("CAB file references nonexistent folder"))?;
            folder
                .get(uoff..uoff + cb)
                .map(|s| s.to_vec())
                .ok_or_else(|| err("CAB file payload out of range"))
        })
        .collect()
}

enum PeKind {
    Dll,
    Exe,
}

/// Classifies a PE image as dll/exe via the `IMAGE_FILE_DLL` characteristics bit, or `None`
/// for non-PE payloads (e.g. the redist MSI also bundles a `.cat` signature catalog).
fn pe_kind(data: &[u8]) -> Option<PeKind> {
    if data.len() < 0x40 || data.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if pe + 24 > data.len() || data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let characteristics = u16::from_le_bytes(data.get(pe + 22..pe + 24)?.try_into().ok()?);
    Some(if characteristics & 0x2000 != 0 {
        PeKind::Dll
    } else {
        PeKind::Exe
    })
}

/// Extracts `GameInputRedist.dll`/`GameInputRedistService.exe` (and, when present,
/// `GameInputBridge.dll`, `GameInputRawInputProxy.exe`, and the 32-bit `x86` redist) from
/// the MSI and places them where the real installer would. Returns `Ok(false)` (not an
/// error) for an MSI whose payload doesn't look like the expected redist shape, matching
/// the reference's "fail closed on an unrecognised payload" behavior.
fn extract_gameinput_redist(msi_path: &Path, prefix: &Path) -> io::Result<bool> {
    let msi = std::fs::read(msi_path)?;
    let cab = msi_embedded_cab(&msi)?;
    let payloads = cab_payload(&cab)?;

    let mut dlls: Vec<&[u8]> = Vec::new();
    let mut exes: Vec<&[u8]> = Vec::new();
    for p in &payloads {
        match pe_kind(p) {
            Some(PeKind::Dll) => dlls.push(p),
            Some(PeKind::Exe) => exes.push(p),
            None => {}
        }
    }
    dlls.sort_by_key(|d| std::cmp::Reverse(d.len()));
    exes.sort_by_key(|d| std::cmp::Reverse(d.len()));
    if dlls.is_empty() || exes.is_empty() {
        return Ok(false);
    }

    let x64 = prefix.join("drive_c/Program Files/Microsoft GameInput/x64");
    let x86 = prefix.join("drive_c/Program Files/Microsoft GameInput/x86");
    let sys32 = prefix.join("drive_c/windows/system32");
    std::fs::create_dir_all(&x64)?;
    std::fs::create_dir_all(&sys32)?;

    std::fs::write(x64.join("GameInputRedist.dll"), dlls[0])?;
    std::fs::write(sys32.join("GameInputRedist.dll"), dlls[0])?;
    std::fs::write(x64.join("GameInputRedistService.exe"), exes[0])?;
    if let Some(bridge) = dlls.get(1) {
        std::fs::write(x64.join("GameInputBridge.dll"), bridge)?;
    }
    if let Some(proxy) = exes.get(1) {
        std::fs::write(x64.join("GameInputRawInputProxy.exe"), proxy)?;
    }
    if let Some(redist32) = dlls.get(2) {
        std::fs::create_dir_all(&x86)?;
        std::fs::write(x86.join("GameInputRedist.dll"), redist32)?;
    }

    Ok(redist_ok(prefix))
}

/// Points the game's `GameInput` loader at the extracted redist (`RedistDir`, both registry
/// views) and registers the demand-start service, matching what the real MSI writes. Written
/// directly into the prefix's `system.reg` while Wine isn't running: starting `reg.exe` here
/// would also start Wine Explorer, and could initialise a second GPU session, before the game
/// itself runs.
fn set_gameinput_registry(prefix: &Path) -> io::Result<()> {
    let service = format!(
        r"System\{}\Services\GameInputRedistService",
        current_control_set(prefix)?
    );
    let redist = REDIST_DIR;
    let image_path = format!(r"{redist}\GameInputRedistService.exe");

    let changes = vec![
        RegChange::sz(r"Software\Microsoft\GameInput", "RedistDir", redist),
        RegChange::sz(
            r"Software\Wow6432Node\Microsoft\GameInput",
            "RedistDir",
            redist,
        ),
        RegChange::sz(&service, "DisplayName", SERVICE_DISPLAY_NAME),
        RegChange::sz(&service, "Description", SERVICE_DISPLAY_NAME),
        RegChange::expand_sz(&service, "ImagePath", &image_path),
        RegChange::sz(&service, "ObjectName", "LocalSystem"),
        RegChange::dword(&service, "ErrorControl", 0),
        RegChange::dword(&service, "Start", 3),
        RegChange::dword(&service, "Type", 0x10),
    ];
    apply_registry_changes(&prefix.join("system.reg"), &changes)
}

/// Resolves `CurrentControlSet` to the real on-disk `ControlSetNNN` key it aliases, per
/// `System\Select\Current` - the alias itself is a runtime-only construct that doesn't exist
/// as a literal key in the offline `system.reg` text file, so writing through the alias
/// literally (as the Python reference does) would silently create a dead, unreachable key.
fn current_control_set(prefix: &Path) -> io::Result<String> {
    let text = std::fs::read_to_string(prefix.join("system.reg")).unwrap_or_default();
    let current = find_dword_value(&text, r"System\\Select", "Current").unwrap_or(1);
    Ok(format!("ControlSet{current:03}"))
}

fn find_dword_value(reg_text: &str, key_escaped: &str, value_name: &str) -> Option<u32> {
    let header = format!("[{key_escaped}]");
    let start = reg_text.find(&header)?;
    let section = &reg_text[start..];
    let section_end = section[1..]
        .find("\n[")
        .map(|i| i + 1)
        .unwrap_or(section.len());
    let section = &section[..section_end];
    let needle = format!("\"{value_name}\"=dword:");
    let value_start = section.find(&needle)? + needle.len();
    let hex = &section[value_start..value_start + 8.min(section.len() - value_start)];
    u32::from_str_radix(hex.trim(), 16).ok()
}

/// Installs the native Microsoft `GameInput` redist into `prefix` if it isn't already
/// present, from the title's own `Installers/GameInputRedist.msi` when it ships one and
/// otherwise from Microsoft's public release (see [`resolve_redist_msi`]). Idempotent: if the
/// redist is already installed, this only re-applies the registry (matching the reference's
/// "heal a prefix whose registry got reset without redoing the extraction" behavior). Never
/// falls back to running `msiexec` - an unrecognised or missing payload fails closed with a
/// message on stderr rather than starting a second Wine/Explorer/GPU session.
pub async fn install_gameinput(client: &reqwest::Client, prefix: &Path, game_dir: &Path) {
    if redist_ok(prefix) {
        if let Err(e) = set_gameinput_registry(prefix) {
            eprintln!("GameInput RedistDir registry update failed: {e}");
        }
        return;
    }

    let Some(msi) = resolve_redist_msi(client, game_dir).await else {
        eprintln!(
            "no GameInputRedist.msi available - native GameInput not installed; in-game \
             mouse/controller input will not work (Wine's builtin GameInput has no HID \
             mouse backend)"
        );
        return;
    };

    match extract_gameinput_redist(&msi, prefix) {
        Ok(true) => match set_gameinput_registry(prefix) {
            Ok(()) => eprintln!("Microsoft GameInput installed (native redist)"),
            Err(e) => eprintln!("GameInput extracted but registry update failed: {e}"),
        },
        Ok(false) => eprintln!(
            "{}: payload didn't match the expected GameInput redist shape - not installed",
            msi.display()
        ),
        Err(e) => eprintln!("GameInput direct extraction failed: {e}"),
    }
}

/// Where a downloaded redist is kept, so it is fetched once per machine rather than per
/// prefix.
fn msi_cache_path() -> PathBuf {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share")
        });
    data_home.join("xodus/redist/GameInputRedist.msi")
}

/// Finds a `GameInputRedist.msi` to extract, downloading it if nothing local has one.
///
/// The title's own `Installers/` directory wins when it has one: that is the exact build
/// Microsoft shipped alongside the game, it needs no network, and it is what the extractor's
/// ground-truth test is written against. Titles distributed without the installer payload
/// fall back to the public redist, which is the same component - GDK titles locate it through
/// a machine-wide `RedistDir` registry value, not a per-title path.
async fn resolve_redist_msi(client: &reqwest::Client, game_dir: &Path) -> Option<PathBuf> {
    let bundled = game_dir.join("Installers").join("GameInputRedist.msi");
    if bundled.is_file() {
        return Some(bundled);
    }

    let cached = msi_cache_path();
    if cached.is_file() {
        return Some(cached);
    }

    // `/releases/latest/download/<name>` redirects to whatever the current release calls that
    // asset, so this tracks upstream without pinning a version and without spending a call on
    // the (rate-limited, unauthenticated) releases API.
    const URL: &str = "https://github.com/microsoftconnect/GameInput/releases/latest/download/GameInputRedist.msi";
    eprintln!("GameInputRedist.msi not found locally, downloading from {URL}");

    match download_to(client, URL, &cached).await {
        Ok(()) => Some(cached),
        Err(e) => {
            eprintln!("GameInput redist download failed: {e}");
            None
        }
    }
}

/// Downloads `url` to `dest`, via a temporary file so an interrupted transfer cannot leave a
/// truncated MSI behind for the next launch to trip over.
async fn download_to(client: &reqwest::Client, url: &str, dest: &Path) -> io::Result<()> {
    let response = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| err(e.to_string()))?;
    let body = response.bytes().await.map_err(|e| err(e.to_string()))?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let partial = dest.with_extension("msi.part");
    std::fs::write(&partial, &body)?;
    std::fs::rename(&partial, dest)?;
    eprintln!(
        "GameInput redist cached at {} ({} bytes)",
        dest.display(),
        body.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_matches_admin_install_ground_truth() {
        let msi_path = Path::new(
            "/home/justin/.local/share/xodus/titles/9NBLGGH2JHXJ/Installers/GameInputRedist.msi",
        );
        if !msi_path.is_file() {
            eprintln!("skipping: reference MSI not present in this environment");
            return;
        }
        let tmp = std::env::temp_dir().join("xodus-gameinput-test-prefix");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let ok = extract_gameinput_redist(msi_path, &tmp).unwrap();
        assert!(ok, "extraction reported unrecognised payload");

        let ground_truth = Path::new(
            "/home/justin/.local/share/xodus/basewine-prefix/drive_c/giextract/Microsoft GameInput",
        );
        let pairs = [
            ("x64/GameInputRedist.dll", "x64/GameInputRedist.dll"),
            (
                "x64/GameInputRedistService.exe",
                "x64/GameInputRedistService.exe",
            ),
            ("x64/GameInputBridge.dll", "x64/GameInputBridge.dll"),
            (
                "x64/GameInputRawInputProxy.exe",
                "x64/GameInputRawInputProxy.exe",
            ),
            ("x86/GameInputRedist.dll", "x86/GameInputRedist.dll"),
        ];
        let x64 = tmp.join("drive_c/Program Files/Microsoft GameInput");
        for (ours, theirs) in pairs {
            let ours_path = x64.join(ours);
            let theirs_path = ground_truth.join(theirs);
            let a = std::fs::read(&ours_path).unwrap_or_else(|e| panic!("{ours_path:?}: {e}"));
            let b = std::fs::read(&theirs_path).unwrap_or_else(|e| panic!("{theirs_path:?}: {e}"));
            assert_eq!(
                a, b,
                "{ours} does not byte-match ground truth {theirs_path:?}"
            );
        }
    }

    #[test]
    fn registry_update_against_real_prefix() {
        let real_reg = Path::new("/home/justin/.local/share/xodus/basewine-prefix/system.reg");
        if !real_reg.is_file() {
            eprintln!("skipping: real prefix system.reg not present in this environment");
            return;
        }
        let tmp = std::env::temp_dir().join("xodus-gameinput-test-registry-prefix");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::copy(real_reg, tmp.join("system.reg")).unwrap();

        let ccs = current_control_set(&tmp).unwrap();
        assert_eq!(
            ccs, "ControlSet001",
            "should resolve via System\\Select\\Current, not hardcode"
        );

        set_gameinput_registry(&tmp).unwrap();
        let text = std::fs::read_to_string(tmp.join("system.reg")).unwrap();

        assert!(text.contains(r#"[Software\\Microsoft\\GameInput]"#));
        assert!(text.contains(r#""RedistDir"="C:\\Program Files\\Microsoft GameInput\\x64""#));
        assert!(text.contains(r#"[Software\\Wow6432Node\\Microsoft\\GameInput]"#));
        assert!(text.contains(r#"[System\\ControlSet001\\Services\\GameInputRedistService]"#));
        assert!(
            !text.contains(r#"[System\\CurrentControlSet\\Services\\GameInputRedistService]"#),
            "must resolve the alias to a real on-disk ControlSetNNN key, not write through \
             CurrentControlSet literally (that path doesn't exist as a real key offline)"
        );
        assert!(text.contains(r#""DisplayName"="GameInput Redist Service""#));
        assert!(text.contains(
            r#""ImagePath"=str(2):"C:\\Program Files\\Microsoft GameInput\\x64\\GameInputRedistService.exe""#
        ));
        assert!(text.contains(r#""ObjectName"="LocalSystem""#));
        assert!(text.contains(r#""ErrorControl"=dword:00000000"#));
        assert!(text.contains(r#""Start"=dword:00000003"#));
        assert!(text.contains(r#""Type"=dword:00000010"#));

        // Idempotent: applying again must not duplicate the section or leave a stray
        // half-written line, and the file must still open as valid UTF-8 text.
        set_gameinput_registry(&tmp).unwrap();
        let text2 = std::fs::read_to_string(tmp.join("system.reg")).unwrap();
        assert_eq!(
            text2
                .matches(r#"[System\\ControlSet001\\Services\\GameInputRedistService]"#)
                .count(),
            1,
            "re-applying must update in place, not append a duplicate section"
        );
        assert_eq!(
            text2.matches(r#""RedistDir""#).count(),
            2,
            "exactly one RedistDir value per registry view (native + Wow6432Node)"
        );
    }
}
