#!/usr/bin/env bash
# Run the original UberWolfCli.exe under Wine on a copy of a game.
#
#   scripts/reference-wine.sh GAME_DIR OUT_DIR [extra UberWolfCli args]
#
# GAME_DIR is copied (reflink when the file system allows it) to OUT_DIR,
# then UberWolfCli is given the absolute Z: path of Game.exe / GamePro.exe.
# The Wine prefix is isolated under work/wineprefix.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
game=${1:?usage: reference-wine.sh GAME_DIR OUT_DIR [args]}
out=${2:?usage: reference-wine.sh GAME_DIR OUT_DIR [args]}
shift 2
exe_ref=${UBERWOLF_EXE:-$root/UberWolfCli.exe}
prefix=${WINEPREFIX:-$root/work/wineprefix}

[ -e "$out" ] && { echo "refusing to overwrite $out" >&2; exit 1; }
mkdir -p "$(dirname "$out")"
cp -a --reflink=auto "$game" "$out"

exe=""
for n in Game.exe GamePro.exe; do
  [ -f "$out/$n" ] && exe="$out/$n" && break
done
[ -n "$exe" ] || { echo "no Game.exe/GamePro.exe in $game" >&2; exit 1; }

abs=$(realpath "$exe")
winpath="Z:${abs//\//\\}"
mkdir -p "$prefix"
cd "$out"
WINEPREFIX="$prefix" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" \
  wine "$exe_ref" "$winpath" "$@"
