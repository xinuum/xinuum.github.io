#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
audit="$script_dir/audit-public-output.sh"
hash_tool="$script_dir/public_output_audit.py"
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/public-output-audit.XXXXXX")

cleanup() {
  if [ -n "${temporary_root:-}" ] && [ -d "$temporary_root" ]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "public-output self-test: $*" >&2
  exit 1
}

copy_valid_fixture() {
  target=$1
  mkdir -p "$target"
  cp -R "$temporary_root/valid/." "$target/"
}

expect_failure() {
  name=$1
  expected=$2
  fixture=$3
  log="$temporary_root/$name.log"
  if "$audit" "$fixture" >"$log" 2>&1; then
    fail "$name unexpectedly passed"
  fi
  if ! grep -F "$expected" "$log" >/dev/null; then
    sed -n '1,80p' "$log" >&2
    fail "$name failed for an unexpected reason"
  fi
}

valid="$temporary_root/valid"
mkdir -p "$valid/site/assets"
printf '%s\n' '<!doctype html><html lang="en-GB"><title>Fixture</title><p>Reviewed output.</p></html>' >"$valid/site/index.html"
printf '%s\n' 'body { color: #142d24; }' >"$valid/site/assets/site.css"
python3 - "$valid/site/assets/generated.avif" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])

def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind + payload

ftyp = box(b"ftyp", b"avif\x00\x00\x00\x00mif1miaf")
ispe = box(b"ispe", b"\x00\x00\x00\x00" + struct.pack(">II", 1, 1))
meta = box(b"meta", b"\x00\x00\x00\x00" + ispe)
mdat = box(b"mdat", b"\x00")
path.write_bytes(ftyp + meta + mdat)
PY

first_digest=$(python3 "$hash_tool" tree-hash "$valid/site")
second_digest=$(python3 "$hash_tool" tree-hash "$valid/site")
[ "$first_digest" = "$second_digest" ] || fail "tree hash is not deterministic"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "source_repository": "xinuum/personal-website",' \
  '  "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",' \
  '  "hugo_version": "0.165.0",' \
  "  \"site_tree_sha256\": \"$first_digest\"" \
  '}' >"$valid/PROVENANCE.json"
"$audit" "$valid" >/dev/null

digest_case="$temporary_root/digest-case"
copy_valid_fixture "$digest_case"
printf '%s\n' '<!-- changed after provenance -->' >>"$digest_case/site/index.html"
expect_failure "digest" "site tree digest mismatch" "$digest_case"

draft_case="$temporary_root/draft-case"
copy_valid_fixture "$draft_case"
printf '%s\n' '<meta name="fixture" content="draft: true">' >>"$draft_case/site/index.html"
expect_failure "draft" "forbidden private/template text" "$draft_case"

source_case="$temporary_root/source-case"
copy_valid_fixture "$source_case"
mkdir -p "$source_case/site/content"
printf '%s\n' 'source material' >"$source_case/site/content/article.md"
expect_failure "source" "source-only directory leaked" "$source_case"

symlink_case="$temporary_root/symlink-case"
copy_valid_fixture "$symlink_case"
ln -s index.html "$symlink_case/site/alias.html"
expect_failure "symlink" "symlink is not allowed" "$symlink_case"

manifest_case="$temporary_root/manifest-case"
copy_valid_fixture "$manifest_case"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "source_repository": "xinuum/personal-website",' \
  '  "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",' \
  '  "hugo_version": "0.165.0",' \
  "  \"site_tree_sha256\": \"$first_digest\"," \
  '  "unexpected_secret": "must never be accepted"' \
  '}' >"$manifest_case/PROVENANCE.json"
expect_failure "manifest" "unsupported fields: unexpected_secret" "$manifest_case"

credential_case="$temporary_root/credential-case"
copy_valid_fixture "$credential_case"
printf '%s\n' 'window.value = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";' >"$credential_case/site/assets/value.js"
expect_failure "credential" "credential-shaped value" "$credential_case"

metadata_case="$temporary_root/metadata-case"
copy_valid_fixture "$metadata_case"
python3 - "$metadata_case/site/tracking.png" <<'PY'
import pathlib
import struct
import sys
import zlib

path = pathlib.Path(sys.argv[1])

def chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))

png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
png += chunk(b"tEXt", b"Author\x00Private fixture")
png += chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
png += chunk(b"IEND", b"")
path.write_bytes(png)
PY
expect_failure "metadata" "PNG metadata chunk tEXt is not allowed" "$metadata_case"

avif_metadata_case="$temporary_root/avif-metadata-case"
copy_valid_fixture "$avif_metadata_case"
python3 - "$avif_metadata_case/site/assets/generated.avif" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
path.write_bytes(data[:-9] + struct.pack(">I", 12) + b"mdatExif")
PY
expect_failure "avif-metadata" "AVIF metadata item is not allowed" "$avif_metadata_case"

printf '%s\n' "public-output self-test passed"
