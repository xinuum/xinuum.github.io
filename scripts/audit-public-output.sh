#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$#" -gt 1 ]; then
  printf '%s\n' "usage: $0 [repository-root]" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  repo_root=$1
else
  repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fi

exec python3 "$script_dir/public_output_audit.py" audit "$repo_root"
