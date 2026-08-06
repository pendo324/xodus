#!/bin/sh
# Builds the two things that have to be built by hand, checks they are actually loadable,
# and prints the launch command.
#
# This is deliberately thin. `xodus-cli run-umu` already builds and installs XCurl and the
# GameInput redist on first use, so there is no point orchestrating those here. What is left
# is the workspace and the runtime DLL - and the DLL is the one with a real trap in it: a
# plain `cargo build` produces a file that looks fine, is missing the Wine builtin signature
# and the `.so`, and fails at load time or silently downgrades to the TCP transport. The
# checks below are here to catch exactly that.
#
# Fork-only; see docs/running-a-title.md.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime=${XGAMERUNTIME_DIR:-$root/../xgameruntime-rs}

if [ ! -x "$runtime/scripts/build-release.sh" ]; then
    echo "no xgameruntime-rs checkout at $runtime" >&2
    echo "set XGAMERUNTIME_DIR to point at one" >&2
    exit 1
fi

echo ">>> xodus workspace"
(cd "$root" && cargo build --release --workspace)

echo ">>> xgameruntime-rs (both halves)"
(cd "$runtime" && ./scripts/build-release.sh)

dll="$runtime/target/x86_64-pc-windows-msvc/release/xgameruntime.dll"
so="$runtime/target/x86_64-pc-windows-msvc/release/xgameruntime.so"

# Both checks describe the same failure from opposite sides: a DLL Wine will not pair a .so
# with, or a pairing with nothing on the other end. Either one means the Unix-socket
# transport is unreachable and the DLL will quietly use loopback TCP instead.
# `-a` is load-bearing: the field is NUL-padded, so grep calls the input binary and reports
# no match even when the signature is present. Without it this check fails on a good build.
if ! head -c 96 "$dll" | tail -c +65 | LC_ALL=C grep -qa "Wine builtin DLL"; then
    echo "!! $dll is not marked as a Wine builtin" >&2
    echo "   (build-release.sh should have stamped it - a plain cargo build does not)" >&2
    exit 1
fi
if [ ! -f "$so" ]; then
    echo "!! no $so beside the DLL - the unix half is missing" >&2
    exit 1
fi

proton=${PROTONPATH:-}
if [ -z "$proton" ]; then
    proton=$(ls -d "$HOME"/.local/share/Steam/compatibilitytools.d/proton-xodus-* 2>/dev/null | tail -1 || true)
fi

echo
echo "built:"
echo "  $root/target/release/xodus-cli"
echo "  $dll"
echo "  $so"
echo
echo "launch with:"
echo
if [ -n "$proton" ]; then
    echo "  $root/target/release/xodus-cli run-umu \\"
    echo "    9NBLGGH2JHXJ \\"
    echo "    $dll \\"
    echo "    --proton $proton"
else
    echo "  $root/target/release/xodus-cli run-umu \\"
    echo "    9NBLGGH2JHXJ \\"
    echo "    $dll \\"
    echo "    --proton <path to a Proton build>"
    echo
    echo "  (no proton-xodus-* build found; set PROTONPATH or pass --proton yourself)"
fi
echo
echo "if something goes wrong, re-run with WINEDEBUG=err+all - without it a failure"
echo "inside the DLL leaves nothing in the output to go on."
