#!/bin/sh
# Bakes xgameruntime and XCurl into a Proton build, the way run-umu does at launch time
# (see docs/running-a-title.md), but as a standalone redistributable set rather than a
# live prefix patch. Used both by .github/workflows/combine-proton.yml and directly for
# local dev builds - nothing here is CI-specific.
#
# Usage: hack/combine-proton.sh [--arch=native|x86_64|arm64] [--no-archive] OUT_DIR
#   Downloads the latest successful xgameruntime, XCurl, and xodus-proton snapshot
#   builds via `gh` and bakes them together. `gh` must be authenticated with access to
#   pendo324/xgameruntime-rs, pendo324/xodus-xcurl, and xodus-gaming/Proton.
#
# Usage: hack/combine-proton.sh [--arch=native|x86_64|arm64] [--no-archive] \
#            XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR
#   Bakes already-built local artifacts instead, with no network access.
#   XGAMERUNTIME_DIR   holds xgameruntime.dll and xgameruntime-{x86_64,aarch64}.so
#   XCURL_DIR          holds XCurl.dll and cacert.pem
#   PROTON_DIR         an already-extracted Proton build, named with Proton's own
#                      -x86_64/-arm64 suffix; left untouched - everything is baked
#                      into a copy. If --arch is also given, it must match this suffix.
#
# --arch selects which arch(es) to bake: native (uname -m), x86_64, arm64, or both
#   (the default in download mode; the only sensible value in local-dir mode is
#   whichever arch PROTON_DIR itself is). Building both arches bakes them concurrently,
#   since the extract and repack steps are I/O- and CPU-bound respectively and don't
#   contend with each other.
# --no-archive leaves each baked tree as a directory in OUT_DIR instead of repacking
#   it into a .tar.xz - faster for local iteration.
#
# OUT_DIR holds one <name>-xgameruntime-rs.tar.xz(+.sha512sum), or directory with
# --no-archive, per arch built, plus xcurl/.
set -eu

xgameruntime_repo=pendo324/xgameruntime-rs
xgameruntime_workflow=test.yml
xcurl_repo=pendo324/xodus-xcurl
xcurl_workflow=build.yml
proton_repo=xodus-gaming/Proton
proton_workflow=snapshot.yml
proton_branch=xodus/bleeding-edge

usage() {
    echo "usage: combine-proton.sh [--arch=native|x86_64|arm64] [--no-archive] OUT_DIR" >&2
    echo "       combine-proton.sh [--arch=native|x86_64|arm64] [--no-archive] XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR" >&2
    exit 1
}

arch=both
archive=1
while [ $# -gt 0 ]; do
    case $1 in
        --arch=*) arch=${1#--arch=}; shift ;;
        --no-archive) archive=0; shift ;;
        *) break ;;
    esac
done
case $arch in
    both|native|x86_64|arm64) ;;
    *) echo "!! --arch must be one of: native, x86_64, arm64, both" >&2; exit 1 ;;
esac
if [ "$arch" = native ]; then
    case $(uname -m) in
        x86_64) arch=x86_64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) echo "!! unsupported host arch: $(uname -m)" >&2; exit 1 ;;
    esac
fi

case $# in
    1) xgameruntime_dir=; xcurl_dir=; proton_dir=; out_dir=$1 ;;
    4) xgameruntime_dir=$1; xcurl_dir=$2; proton_dir=$3; out_dir=$4 ;;
    *) usage ;;
esac

if [ -n "$proton_dir" ]; then
    # Local mode only ever has one Proton tree to bake - its own name says which arch.
    case $(basename "$proton_dir") in
        *-x86_64) inferred=x86_64 ;;
        *-arm64) inferred=arm64 ;;
        *) echo "!! cannot infer arch from PROTON_DIR name: $proton_dir" >&2; exit 1 ;;
    esac
    if [ "$arch" != both ] && [ "$arch" != "$inferred" ]; then
        echo "!! --arch=$arch does not match PROTON_DIR's arch ($inferred)" >&2
        exit 1
    fi
    arches=$inferred
elif [ "$arch" = both ]; then
    arches="x86_64 arm64"
else
    arches=$arch
fi

# Maps a Proton arch suffix to the Rust target suffix xgameruntime-rs's build-release.sh
# names its .so outputs with.
rust_arch() {
    case $1 in
        x86_64) echo x86_64 ;;
        arm64) echo aarch64 ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# $1 repo, $2 workflow, $3 artifact name ('' for all), $4 dest dir, [$5 branch]
download_artifact() {
    repo=$1; workflow=$2; name=$3; dest=$4; branch=${5:-}
    echo ">>> finding latest successful $workflow run on $repo${branch:+ ($branch)}"
    run_id=$(gh run list --repo "$repo" --workflow "$workflow" --status success \
        ${branch:+--branch "$branch"} --limit 1 --json databaseId -q '.[0].databaseId')
    [ -n "$run_id" ] || { echo "!! no successful $workflow run found on $repo" >&2; exit 1; }
    echo ">>> downloading ${name:-artifacts} from $repo run $run_id"
    gh run download "$run_id" --repo "$repo" --dir "$dest" ${name:+--name "$name"}
}

# $1 dir holding one or more *.sha512sum files beside the files they cover - skips
# silently if none are found, so it's safe to call on a dir that might not have any.
verify_checksums() {
    dir=$1
    for f in "$dir"/*.sha512sum; do
        [ -e "$f" ] || continue
        ( cd "$dir" && sha512sum -c "$(basename "$f")" )
    done
}

if [ -z "$xgameruntime_dir" ]; then
    xgameruntime_dir="$tmp/xgameruntime"
    mkdir -p "$xgameruntime_dir"
    # Downloaded as separate per-file artifacts (dll, plus one .so per arch actually
    # needed) rather than one bundle, so a single-arch build doesn't pay to fetch the .so
    # it has no use for.
    echo ">>> finding latest successful $xgameruntime_workflow run on $xgameruntime_repo"
    xgameruntime_run_id=$(gh run list --repo "$xgameruntime_repo" --workflow "$xgameruntime_workflow" \
        --status success --limit 1 --json databaseId -q '.[0].databaseId')
    [ -n "$xgameruntime_run_id" ] || { echo "!! no successful $xgameruntime_workflow run found on $xgameruntime_repo" >&2; exit 1; }
    echo ">>> downloading xgameruntime-dll from $xgameruntime_repo run $xgameruntime_run_id"
    gh run download "$xgameruntime_run_id" --repo "$xgameruntime_repo" --dir "$xgameruntime_dir" --name xgameruntime-dll
    for a in $arches; do
        ra=$(rust_arch "$a")
        echo ">>> downloading xgameruntime-$ra-so from $xgameruntime_repo run $xgameruntime_run_id"
        gh run download "$xgameruntime_run_id" --repo "$xgameruntime_repo" --dir "$xgameruntime_dir" --name "xgameruntime-$ra-so"
    done
    verify_checksums "$xgameruntime_dir"
fi
if [ -z "$xcurl_dir" ]; then
    xcurl_dir="$tmp/xcurl"
    download_artifact "$xcurl_repo" "$xcurl_workflow" xcurl "$xcurl_dir"
    verify_checksums "$xcurl_dir"
fi

[ -f "$xgameruntime_dir/xgameruntime.dll" ] || { echo "!! missing $xgameruntime_dir/xgameruntime.dll" >&2; exit 1; }
for a in $arches; do
    ra=$(rust_arch "$a")
    [ -f "$xgameruntime_dir/xgameruntime-$ra.so" ] || { echo "!! missing $xgameruntime_dir/xgameruntime-$ra.so" >&2; exit 1; }
done
for f in "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem"; do
    [ -f "$f" ] || { echo "!! missing $f" >&2; exit 1; }
done

# Resolved once, up front, so a concurrent x86_64 + arm64 build can't end up pulling two
# different Proton versions if a newer run finishes mid-build.
if [ -z "$proton_dir" ]; then
    echo ">>> finding latest successful $proton_workflow run on $proton_repo ($proton_branch)"
    proton_run_id=$(gh run list --repo "$proton_repo" --workflow "$proton_workflow" --status success \
        --branch "$proton_branch" --limit 1 --json databaseId -q '.[0].databaseId')
    [ -n "$proton_run_id" ] || { echo "!! no successful $proton_workflow run found on $proton_repo" >&2; exit 1; }
fi

# $1 arch (x86_64/arm64), $2 dest dir - downloads just that arch's Proton snapshot
# tarball+checksum (the run builds both; --name lets us fetch only the one we need),
# verifies it, and extracts it. Echoes the extracted Proton dir's path.
download_and_extract_proton() {
    a=$1; dest=$2
    tarball_name=$(gh api "repos/$proton_repo/actions/runs/$proton_run_id/artifacts" --paginate \
        -q ".artifacts[] | select(.name | endswith(\"-$a.tar.xz\")) | .name" | head -n1)
    sha_name=$(gh api "repos/$proton_repo/actions/runs/$proton_run_id/artifacts" --paginate \
        -q ".artifacts[] | select(.name | endswith(\"-$a.sha512sum\")) | .name" | head -n1)
    [ -n "$tarball_name" ] && [ -n "$sha_name" ] || { echo "!! no $a Proton artifact found in run $proton_run_id" >&2; exit 1; }

    echo ">>> [$a] downloading $tarball_name from $proton_repo run $proton_run_id" >&2
    mkdir -p "$dest"
    # One `gh run download` call per --name, not combined: with more than one --name in
    # a single call, gh nests each artifact under its own subdirectory instead of
    # flattening into $dest, which broke the sha512sum check below.
    gh run download "$proton_run_id" --repo "$proton_repo" --dir "$dest" --name "$tarball_name" >&2
    gh run download "$proton_run_id" --repo "$proton_repo" --dir "$dest" --name "$sha_name" >&2
    ( cd "$dest" && sha512sum -c "$sha_name" ) >&2

    pname=${tarball_name%.tar.xz}
    extract="$dest/extracted"
    mkdir -p "$extract"
    echo ">>> [$a] extracting $pname" >&2
    if command -v pv >/dev/null 2>&1; then
        pv -f -N "$a" "$dest/$tarball_name" | tar -xJf - -C "$extract"
    else
        tar -xJf "$dest/$tarball_name" -C "$extract"
    fi
    echo "$extract/$pname"
}

# $1 arch, $2 already-extracted Proton dir (left untouched - baked into a copy)
bake_arch() {
    a=$1; pdir=$2
    ra=$(rust_arch "$a")
    pname=$(basename "$pdir")
    work="$tmp/work-$a"
    mkdir -p "$work"

    # Proton trees run well over a gigabyte, so each of these steps can take minutes on a
    # CI runner with nothing else printed in the meantime - without a heartbeat here that
    # looks indistinguishable from a hang.
    echo ">>> [$a] copying $pdir ($(du -sh "$pdir" | cut -f1))"
    cp -a "$pdir" "$work/$pname"

    echo ">>> [$a] baking in xgameruntime"
    wine_dir="$work/$pname/files/lib/wine"
    # The windows-side dir is x86_64-windows regardless of host arch - the DLL is PE code
    # run through Wine's x86 support either way. The unix-side dir matches the Proton
    # build's own host arch, since that's Wine's native half: x86_64-unix there, but
    # aarch64-unix here - arm64 Proton runs Wine natively on aarch64.
    for pair in "x86_64-windows:dll" "$ra-unix:so"; do
        d=${pair%%:*}; ext=${pair##*:}
        target="$wine_dir/$d/xgameruntime.$ext"
        if [ -e "$target" ] && [ ! -e "$target.xodus-orig" ]; then
            mv "$target" "$target.xodus-orig"
        fi
        if [ "$ext" = so ]; then
            cp "$xgameruntime_dir/xgameruntime-$ra.so" "$target"
        else
            cp "$xgameruntime_dir/xgameruntime.dll" "$target"
        fi
    done

    base="$pname-xgameruntime-rs"
    if [ "$archive" -eq 1 ]; then
        out="$base.tar.xz"
        echo ">>> [$a] repacking as $out (xz compression, this is the slow part)"
        if command -v pv >/dev/null 2>&1; then
            size=$(du -sb "$work/$pname" | cut -f1)
            tar -cf - -C "$work" "$pname" | pv -f -N "$a" -s "$size" | xz > "$tmp/$out"
        else
            tar -cJf "$tmp/$out" -C "$work" "$pname"
        fi
        ( cd "$tmp" && sha512sum "$out" > "$out.sha512sum" )
        mv "$tmp/$out" "$tmp/$out.sha512sum" "$out_dir/"
    else
        echo ">>> [$a] leaving baked tree as $out_dir/$base"
        rm -rf "$out_dir/$base"
        mv "$work/$pname" "$out_dir/$base"
    fi
}

mkdir -p "$out_dir"

fail=0
if [ -n "$proton_dir" ]; then
    bake_arch "$arches" "$proton_dir" || fail=1
elif [ "$arch" = both ]; then
    ( pdir=$(download_and_extract_proton x86_64 "$tmp/proton-x86_64"); bake_arch x86_64 "$pdir" ) &
    pid_x86_64=$!
    ( pdir=$(download_and_extract_proton arm64 "$tmp/proton-arm64"); bake_arch arm64 "$pdir" ) &
    pid_arm64=$!
    wait "$pid_x86_64" || fail=1
    wait "$pid_arm64" || fail=1
else
    pdir=$(download_and_extract_proton "$arch" "$tmp/proton-$arch")
    bake_arch "$arch" "$pdir" || fail=1
fi
[ "$fail" -eq 0 ] || { echo "!! one or more arch builds failed" >&2; exit 1; }

echo ">>> bundling XCurl"
mkdir -p "$out_dir/xcurl"
cp "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem" "$out_dir/xcurl/"

echo "built:"
for f in "$out_dir"/*-xgameruntime-rs*; do
    [ -e "$f" ] || continue
    du -sh "$f" | awk '{print "  " $2 " (" $1 ")"}'
done
echo "  $out_dir/xcurl/"
