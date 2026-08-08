#!/bin/sh
# Bakes xgameruntime and XCurl into a Proton build, the way run-umu does at launch time
# (see docs/running-a-title.md), but as a standalone redistributable set rather than a
# live prefix patch. Used both by .github/workflows/combine-proton.yml and directly for
# local dev builds - nothing here is CI-specific.
#
# Usage: hack/combine-proton.sh OUT_DIR
#   Downloads the latest successful xgameruntime, XCurl, and x86_64 xodus-proton
#   snapshot builds via `gh` and bakes them together. `gh` must be authenticated
#   with access to pendo324/xgameruntime-rs, pendo324/xodus-xcurl, and
#   xodus-gaming/Proton.
#
# Usage: hack/combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR
#   Bakes already-built local artifacts instead, with no network access.
#   XGAMERUNTIME_DIR   holds xgameruntime.dll and xgameruntime.so
#   XCURL_DIR          holds XCurl.dll and cacert.pem
#   PROTON_DIR         an already-extracted Proton build; left untouched - everything
#                      is baked into a copy. Its basename becomes the packaged name.
#
# OUT_DIR is where the result lands: <name>-xgameruntime.tar.xz(+.sha512sum) and xcurl/
set -eu

xgameruntime_repo=pendo324/xgameruntime-rs
xgameruntime_workflow=test.yml
xcurl_repo=pendo324/xodus-xcurl
xcurl_workflow=build.yml
proton_repo=xodus-gaming/Proton
proton_workflow=snapshot.yml
proton_branch=xodus/bleeding-edge

usage() {
    echo "usage: combine-proton.sh OUT_DIR" >&2
    echo "       combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR" >&2
    exit 1
}

case $# in
    1) xgameruntime_dir=; xcurl_dir=; proton_dir=; out_dir=$1 ;;
    4) xgameruntime_dir=$1; xcurl_dir=$2; proton_dir=$3; out_dir=$4 ;;
    *) usage ;;
esac

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

if [ -z "$xgameruntime_dir" ]; then
    xgameruntime_dir="$tmp/xgameruntime"
    download_artifact "$xgameruntime_repo" "$xgameruntime_workflow" xgameruntime "$xgameruntime_dir"
fi
if [ -z "$xcurl_dir" ]; then
    xcurl_dir="$tmp/xcurl"
    download_artifact "$xcurl_repo" "$xcurl_workflow" xcurl "$xcurl_dir"
fi
if [ -z "$proton_dir" ]; then
    proton_artifacts="$tmp/proton-artifacts"
    download_artifact "$proton_repo" "$proton_workflow" "" "$proton_artifacts" "$proton_branch"

    # The Snapshot run builds both x86_64 and arm64; we only bake into x86_64. Each
    # artifact lands in its own dir named after it (no --name filter above), so
    # `-type f` is needed - the dir itself also matches -name.
    tarball=$(find "$proton_artifacts" -maxdepth 2 -type f -name '*-x86_64.tar.xz')
    sha=$(find "$proton_artifacts" -maxdepth 2 -type f -name '*-x86_64.sha512sum')
    [ -n "$tarball" ] && [ -n "$sha" ] || { echo "!! x86_64 Proton artifact not found" >&2; exit 1; }
    # The .sha512sum records a bare filename, so both need to be siblings for
    # `sha512sum -c` to find the file it names - flatten them out of their
    # per-artifact subdirectories first.
    flat="$tmp/proton-flat"
    mkdir -p "$flat"
    cp "$tarball" "$sha" "$flat/"
    ( cd "$flat" && sha512sum -c "$(basename "$sha")" )

    proton_name=$(basename "$tarball" .tar.xz)
    proton_extract="$tmp/proton-build"
    mkdir -p "$proton_extract"
    echo ">>> extracting $proton_name"
    if command -v pv >/dev/null 2>&1; then
        pv "$flat/$(basename "$tarball")" | tar -xJf - -C "$proton_extract"
    else
        tar -xJf "$flat/$(basename "$tarball")" -C "$proton_extract"
    fi
    proton_dir="$proton_extract/$proton_name"
fi

for f in "$xgameruntime_dir/xgameruntime.dll" "$xgameruntime_dir/xgameruntime.so" \
         "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem"; do
    [ -f "$f" ] || { echo "!! missing $f" >&2; exit 1; }
done
[ -d "$proton_dir" ] || { echo "!! no such Proton directory: $proton_dir" >&2; exit 1; }

proton_name=$(basename "$proton_dir")
work="$tmp/work"
mkdir -p "$work"

# Proton trees run well over a gigabyte, so each of these steps can take minutes on a
# CI runner with nothing else printed in the meantime - without a heartbeat here that
# looks indistinguishable from a hang.
echo ">>> copying $proton_dir ($(du -sh "$proton_dir" | cut -f1))"
cp -a "$proton_dir" "$work/$proton_name"

echo ">>> baking in xgameruntime"
wine_dir="$work/$proton_name/files/lib/wine"
for pair in "x86_64-windows:dll" "x86_64-unix:so"; do
    dir=${pair%%:*}; ext=${pair##*:}
    target="$wine_dir/$dir/xgameruntime.$ext"
    if [ -e "$target" ] && [ ! -e "$target.xodus-orig" ]; then
        mv "$target" "$target.xodus-orig"
    fi
    cp "$xgameruntime_dir/xgameruntime.$ext" "$target"
done

mkdir -p "$out_dir"
out="$proton_name-xgameruntime.tar.xz"
echo ">>> repacking as $out (xz compression, this is the slow part)"
if command -v pv >/dev/null 2>&1; then
    size=$(du -sb "$work/$proton_name" | cut -f1)
    tar -cf - -C "$work" "$proton_name" | pv -s "$size" | xz > "$out"
else
    tar -cJf "$out" -C "$work" "$proton_name"
fi
sha512sum "$out" > "$out.sha512sum"
mv "$out" "$out.sha512sum" "$out_dir/"

echo ">>> bundling XCurl"
mkdir -p "$out_dir/xcurl"
cp "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem" "$out_dir/xcurl/"

echo "built: $out_dir/$out ($(du -sh "$out_dir/$out" | cut -f1), + .sha512sum), $out_dir/xcurl/"
