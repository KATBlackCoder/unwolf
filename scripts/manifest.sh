#!/usr/bin/env bash
# Print a sorted manifest of a folder: "<sha256>  <size>  <relative path>".
# Directories are listed with "dir" in place of the hash.
set -euo pipefail
dir=${1:?usage: manifest.sh DIR}
cd "$dir"
{
  find . -mindepth 1 -type d -printf 'dir  -  %P\n'
  find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
    printf '%s  %s  %s\n' "$(sha256sum < "$f" | cut -d' ' -f1)" "$(stat -c %s "$f")" "${f#./}"
  done
} | LC_ALL=C sort -k3
