#!/bin/sh
# Bakes xgameruntime and XCurl into a Proton build, the way run-umu does at launch time
# (see docs/running-a-title.md), but as a standalone redistributable set rather than a
# live prefix patch. Used both by .github/workflows/combine-proton.yml, against
# artifacts it downloaded, and directly for local dev builds against whatever you just
# built by hand - nothing here is CI-specific.
#
# Usage: hack/combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR
#   XGAMERUNTIME_DIR   holds xgameruntime.dll and xgameruntime.so
#   XCURL_DIR          holds XCurl.dll and cacert.pem
#   PROTON_DIR         an already-extracted Proton build; left untouched - everything
#                      is baked into a copy. Its basename becomes the packaged name.
#   OUT_DIR            where the result lands: <name>-xgameruntime.tar.xz(+.sha512sum)
#                      and xcurl/
set -eu

xgameruntime_dir=${1:?usage: combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR}
xcurl_dir=${2:?usage: combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR}
proton_dir=${3:?usage: combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR}
out_dir=${4:?usage: combine-proton.sh XGAMERUNTIME_DIR XCURL_DIR PROTON_DIR OUT_DIR}

for f in "$xgameruntime_dir/xgameruntime.dll" "$xgameruntime_dir/xgameruntime.so" \
         "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem"; do
    [ -f "$f" ] || { echo "!! missing $f" >&2; exit 1; }
done
[ -d "$proton_dir" ] || { echo "!! no such Proton directory: $proton_dir" >&2; exit 1; }

proton_name=$(basename "$proton_dir")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp -a "$proton_dir" "$work/$proton_name"

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
tar -cJf "$out" -C "$work" "$proton_name"
sha512sum "$out" > "$out.sha512sum"
mv "$out" "$out.sha512sum" "$out_dir/"

mkdir -p "$out_dir/xcurl"
cp "$xcurl_dir/XCurl.dll" "$xcurl_dir/cacert.pem" "$out_dir/xcurl/"

echo "built: $out_dir/$out (+ .sha512sum), $out_dir/xcurl/"
