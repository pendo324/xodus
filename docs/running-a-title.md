# Running a GDK title end to end

How the pieces fit together, what currently works, and what to expect when it doesn't.

> [!NOTE]
> This page documents a **fork-only** stack. It describes components spread across four repositories plus a Proton build, most of which are not merged upstream. Nothing here is a statement about what `xodus-gaming/xodus` supports on its own.

## The pieces

| Component | Repo | What it does |
|---|---|---|
| `xodus-cli` / `xodus-service` | `xodus` | Auth, licensing, download/decrypt. `xodus-service` holds the credentials and answers the game's questions over IPC. |
| `xgameruntime.dll` + `.so` | `xgameruntime-rs` | Loaded by the title in place of the GDK runtime. Answers what it can locally, forwards the rest to `xodus-service`. |
| `XCurl.dll` + `cacert.pem` | `xodus-xcurl` | Drop-in for the GDK's cut-down libcurl. Without it every HTTPS call from the title fails. |
| `xal` | `xal-rs` | Lower-level XAL/XASU auth primitives `xodus` builds on. |
| Proton | external | The Wine runtime the title launches under. `run-umu` drives a stock GE-Proton/UMU-Proton; we verify against the `proton-xodus` build. |

The path a launch takes: `xodus-cli run-umu` prepares a prefix and installs the DLLs, `umu-run` starts the title under Proton, the title loads our `xgameruntime.dll`, and that reaches `xodus-service` over a Unix socket (or loopback TCP if the `.so` half didn't load). All network traffic from the title goes through our `XCurl.dll`.

## Build

Only one thing needs building by hand — `run-umu` builds and installs XCurl and the GameInput redist on its own, on first use.

```bash
# 1. the workspace
cd xodus && cargo build --release --workspace

# 2. both halves of the runtime DLL
cd ../xgameruntime-rs && ./scripts/build-release.sh
```

`hack/build.sh` in this repo does both, checks the results are actually loadable, and prints the launch command with the right paths filled in. Use it if you'd rather not remember the above.

Do **not** substitute a plain `cargo build` for step 2. It builds only the PE half, skips the `winebuild --builtin` signature, and never produces the `.so` — the result loads, silently falls back to TCP, or fails outright depending on the loadorder. See `xgameruntime-rs/README.md`.

## Launch

```bash
cargo run --release --bin xodus-cli -- run-umu \
  9NBLGGH2JHXJ \
  ../xgameruntime-rs/target/x86_64-pc-windows-msvc/release/xgameruntime.dll \
  --proton ~/.local/share/Steam/compatibilitytools.d/proton-xodus-bleeding-edge-...-x86_64
```

The first positional argument is either a directory of extracted plain files or a product/content id — an id is downloaded and extracted automatically (fully decrypted, cached under `$XDG_DATA_HOME/xodus/titles/<id>`). `9NBLGGH2JHXJ` is Minecraft Bedrock.

Useful environment variables:

| Variable | Effect |
|---|---|
| `WINEDEBUG=err+all` | Not required, but it is what we debug with — without it a failure inside the DLL leaves nothing in the output to go on. |
| `XODUS_LOG=debug` | `xodus-cli`/`xodus-service` logging. |
| `XODUS_DIAG=1` | Extra diagnostics from the DLL's IPC layer. |
| `XODUS_SKIP_XCURL=1` | Leave the title's own `XCurl.dll` alone. |
| `XCURL_NO_SHARE=1` | Disable XCurl's connection-reuse share handle. |
| `XCURL_LOG=1` | Write `xcurl.log` beside the DLL. Captures response bodies for Xbox Live social/profile endpoints — account data, off by default. |

## Status

Last verified 2026-08-06 against Minecraft Bedrock (`9NBLGGH2JHXJ`).

- **Launch** — works. The title starts under Proton, loads our runtime DLL as a Wine builtin, and reaches a running process with no crash markers in the log.
- **Transport** — the Unix-socket path works when the `.so` half is installed alongside the PE; loopback TCP is the automatic fallback and also works.
- **Auth / identity** — device and user login, XSTS token issuance, and gamertag/XUID/age-group claims are served from `xodus-service`.
- **Store / licensing** — game license, entitled products, associated products, and user-collections queries are served.
- **Networking** — all title HTTPS goes through the patched XCurl; the People Hub URL rewrite makes the in-game Friends list populate.
- **Presence** — the player shows as online in-game while playing: XSTS tokens carry a SISU-issued title claim, without which presence writes are rejected with `ArgumentError`.
- **Joining servers / playing** - works fine for all servers I tested.
- **Parties** - I didn't join any parties, but creating one seems to work.
- **Marketplace** - I didn't buy anything, but navigation seems to work as expected.
- **Creating, saving, loading local worlds** - works as expected, but exporting does not work (crashes the game).
- **Not implemented** — Still a lot of unimplemented stubs.

## Known issues

**`run-umu` writes into the Proton runtime, not the prefix.** Wine's builtin search reaches nowhere else, so the DLL pair is symlinked into `<proton>/files/lib/wine/x86_64-{windows,unix}/` and the runtime's originals are moved aside as `*.xodus-orig`. That directory is shared with every other game launched under that Proton. To undo:

```bash
cd <proton>/files/lib/wine
for f in */*.xodus-orig; do mv "$f" "${f%.xodus-orig}"; done
```

Eventually, this could be baked into a Proton release. Right now, we're piggybacking on the upstream Xodus Proton build.

**XCurl's connection-reuse share handle is experimental.** It is on by default and measurably faster, but the bundled `libHttpClient` may avoid connection reuse for a reason that has not surfaced yet. `XCURL_NO_SHARE=1` isolates it in one launch without rebuilding.

**XCurl and GameInput installs are best-effort.** Both are warnings on failure, never fatal, so a launch can succeed with the title's own `XCurl.dll` still in place — and then fail every HTTPS call for a reason the launch output does not make obvious. Building XCurl needs `mingw-w64` and network access on first use.

**The `third_party/xodus-xcurl` submodule points at `pendo324/xodus-xcurl`.** That is a fork-only URL — upstream would want its own. If the repository is not reachable, `run-umu` skips the XCurl step with a warning rather than failing, and the title then uses whatever `XCurl.dll` it shipped with.

**`run-umu` needs the title fully decrypted on disk.** It cannot use the `WINE_DLL_FILE_MAP` mount trick that `run` relies on, since that is a patch specific to the `xodus/wine` fork and `umu-run` drives stock Proton. Passing a product id handles this automatically; passing a directory extracted without `--decrypt-all` will not work.
