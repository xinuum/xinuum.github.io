#!/usr/bin/env python3
"""Validate reviewed GitHub Pages output and calculate its canonical tree hash."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import unicodedata
from collections.abc import Iterable


SCHEMA_VERSION = 1
REQUIRED_MANIFEST_KEYS = {
    "schema_version",
    "hugo_version",
    "site_tree_sha256",
}

SOURCE_ONLY_DIRECTORY_NAMES = {
    ".git",
    ".github",
    "archetypes",
    "content",
    "data",
    "design-system",
    "docs",
    "layouts",
    "node_modules",
    "resources",
    "scripts",
    "themes",
    "tools",
    "vendor",
}
SOURCE_ONLY_FILE_NAMES = {
    ".env",
    ".env.local",
    ".gitignore",
    ".gitmodules",
    ".hugo_build.lock",
    ".pages.yml",
    "Dockerfile",
    "Gemfile",
    "Gemfile.lock",
    "LICENSE",
    "LICENSE.txt",
    "NOTICE",
    "README",
    "go.mod",
    "go.sum",
    "hugo.toml",
    "hugo.yaml",
    "hugo.yml",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
SOURCE_ONLY_FILE_NAMES_CASEFOLDED = {name.casefold() for name in SOURCE_ONLY_FILE_NAMES}
SOURCE_ONLY_SUFFIXES = {
    ".astro",
    ".go",
    ".gotmpl",
    ".jsx",
    ".less",
    ".lock",
    ".map",
    ".markdown",
    ".md",
    ".py",
    ".rb",
    ".rst",
    ".sass",
    ".scss",
    ".sh",
    ".svelte",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".yaml",
    ".yml",
}
PRIVATE_BINARY_SUFFIXES = {
    ".7z",
    ".ai",
    ".bak",
    ".bin",
    ".bmp",
    ".cr2",
    ".dat",
    ".db",
    ".dmg",
    ".dng",
    ".doc",
    ".docx",
    ".eps",
    ".gz",
    ".heic",
    ".heif",
    ".indd",
    ".key",
    ".numbers",
    ".nef",
    ".orig",
    ".pages",
    ".p12",
    ".pdf",
    ".pem",
    ".pkg",
    ".ppt",
    ".pptx",
    ".psd",
    ".rar",
    ".raw",
    ".sqlite",
    ".sqlite3",
    ".sql",
    ".tar",
    ".tif",
    ".tiff",
    ".tmp",
    ".xls",
    ".xlsx",
    ".zip",
}
PRIVATE_OUTPUT_FILE_NAMES = {
    "profile photo selected copy.png",
}

FORBIDDEN_LITERAL_TEXT = (
    "template: true",
    "template_fixture",
    "draft: true",
    '"draft":true',
    '"draft": true',
    "data-draft=",
    "Article template preview",
    "Project template preview",
    "PREVIEW_ONLY",
    "ACADEMIC DEMO",
    "Lorem ipsum",
    "Hugo Blox",
)
FORBIDDEN_TOKEN_PATTERNS = (
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bsk_live_[A-Za-z0-9]{20,}\b"),
)
FORBIDDEN_LOCAL_PATH_PATTERNS = (
    re.compile(
        rb"(?<![A-Za-z0-9:])/(?:Users|home|private|var|tmp|Volumes|opt|srv)/"
        rb"[A-Za-z0-9._-]+(?:/[^\x00\r\n\t <>\"']*)?"
    ),
    re.compile(rb"\b[A-Za-z]:\\Users\\[A-Za-z0-9._-]+(?:\\[^\x00\r\n\t <>\"']*)?", re.I),
    re.compile(rb"\bfile://(?:localhost)?/[^\x00\r\n\t <>\"']+", re.I),
)
PRIVATE_KEY_BOUNDARIES = tuple(
    b"-----BEGIN " + key_type + b"PRIVATE KEY-----"
    for key_type in (b"", b"OPENSSH ", b"RSA ", b"EC ", b"DSA ")
)
FORBIDDEN_BINARY_MARKERS = (
    b"Exif\x00\x00",
    b"<x:xmpmeta",
    b"http://ns.adobe.com/xap/",
)

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_SITE_BYTES = 1024 * 1024 * 1024
MAX_SITE_FILES = 50_000


class AuditFailure(RuntimeError):
    """Expected rejection raised by the public-output audit."""


def fail(message: str) -> None:
    raise AuditFailure(message)


def relative_name(path: pathlib.Path, site: pathlib.Path) -> str:
    return path.relative_to(site).as_posix()


def ensure_safe_relative_name(relative: str) -> None:
    if not relative or relative.startswith("/"):
        fail(f"invalid output path: {relative!r}")
    if unicodedata.normalize("NFC", relative) != relative:
        fail(f"output path is not NFC-normalised: {relative!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in relative):
        fail(f"control character in output path: {relative!r}")
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        fail(f"invalid output path component: {relative!r}")


def inspect_tree(site: pathlib.Path) -> list[pathlib.Path]:
    try:
        site_status = site.lstat()
    except FileNotFoundError:
        fail("site/ is missing")
    if not stat.S_ISDIR(site_status.st_mode) or site.is_symlink():
        fail("site/ must be a real directory")

    files: list[pathlib.Path] = []
    casefolded_names: dict[str, str] = {}
    total_bytes = 0

    for directory, directory_names, file_names in os.walk(site, followlinks=False):
        directory_path = pathlib.Path(directory)
        for name in sorted(directory_names + file_names):
            path = directory_path / name
            relative = relative_name(path, site)
            ensure_safe_relative_name(relative)
            folded = relative.casefold()
            if folded in casefolded_names:
                fail(
                    "case-insensitive output path collision: "
                    f"{casefolded_names[folded]!r} and {relative!r}"
                )
            casefolded_names[folded] = relative

            status = path.lstat()
            if stat.S_ISLNK(status.st_mode):
                fail(f"symlink is not allowed: {relative}")
            if name.startswith("."):
                fail(f"hidden output path is not allowed: {relative}")

            if stat.S_ISDIR(status.st_mode):
                if name.casefold() in SOURCE_ONLY_DIRECTORY_NAMES:
                    fail(f"source-only directory leaked into site/: {relative}")
                continue
            if not stat.S_ISREG(status.st_mode):
                fail(f"special filesystem entry is not allowed: {relative}")
            if status.st_nlink != 1:
                fail(f"hard-linked output file is not allowed: {relative}")
            if status.st_mode & 0o111:
                fail(f"executable output file is not allowed: {relative}")
            if status.st_size > MAX_FILE_BYTES:
                fail(f"output file exceeds 100 MiB: {relative}")

            total_bytes += status.st_size
            if total_bytes > MAX_SITE_BYTES:
                fail("site/ exceeds the 1 GiB audit limit")

            lowered_name = name.casefold()
            lowered_suffix = path.suffix.casefold()
            if lowered_name in SOURCE_ONLY_FILE_NAMES_CASEFOLDED:
                fail(f"source configuration leaked into site/: {relative}")
            if lowered_name in PRIVATE_OUTPUT_FILE_NAMES:
                fail(f"unprocessed private source file is not allowed: {relative}")
            if lowered_suffix in SOURCE_ONLY_SUFFIXES:
                fail(f"source file leaked into site/: {relative}")
            if lowered_suffix in PRIVATE_BINARY_SUFFIXES:
                fail(f"unreviewable/private binary is not allowed: {relative}")
            files.append(path)

    if len(files) > MAX_SITE_FILES:
        fail(f"site/ contains more than {MAX_SITE_FILES} files")
    if not files:
        fail("site/ is empty")
    return files


def scan_image_metadata(path: pathlib.Path, data: bytes, relative: str) -> None:
    suffix = path.suffix.casefold()
    if suffix in {".jpg", ".jpeg"}:
        scan_jpeg_metadata(data, relative)
    elif suffix == ".png":
        scan_png_metadata(data, relative)
    elif suffix == ".webp":
        scan_webp_metadata(data, relative)
    elif suffix == ".gif":
        if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
            fail(f"invalid GIF file: {relative}")
        if b"\x21\xfe" in data:
            fail(f"GIF comment metadata is not allowed: {relative}")
        if b"xmp dataxmp" in data.lower() or b"<x:xmpmeta" in data.lower():
            fail(f"GIF XMP metadata is not allowed: {relative}")
    elif suffix == ".avif":
        scan_avif_metadata(data, relative)
    elif suffix == ".svg":
        lowered = data.lower()
        if b"<metadata" in lowered or b"<rdf:rdf" in lowered:
            fail(f"SVG editor metadata is not allowed: {relative}")


def scan_jpeg_metadata(data: bytes, relative: str) -> None:
    if not data.startswith(b"\xff\xd8"):
        fail(f"invalid JPEG file: {relative}")
    position = 2
    while position < len(data):
        if data[position] != 0xFF:
            fail(f"malformed JPEG marker stream: {relative}")
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            fail(f"truncated JPEG marker stream: {relative}")
        marker = data[position]
        position += 1
        if marker in {0xD8, 0xD9}:
            if marker == 0xD9:
                return
            continue
        if marker == 0xDA:
            return
        if marker in set(range(0xD0, 0xD8)) | {0x01}:
            continue
        if position + 2 > len(data):
            fail(f"truncated JPEG segment: {relative}")
        segment_length = int.from_bytes(data[position : position + 2], "big")
        if segment_length < 2 or position + segment_length > len(data):
            fail(f"invalid JPEG segment length: {relative}")
        payload = data[position + 2 : position + segment_length]
        if marker == 0xFE:
            fail(f"JPEG comment metadata is not allowed: {relative}")
        if 0xE1 <= marker <= 0xED or marker == 0xEF:
            if marker == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"):
                pass
            else:
                fail(f"JPEG application metadata is not allowed: {relative}")
        position += segment_length


def scan_png_metadata(data: bytes, relative: str) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        fail(f"invalid PNG file: {relative}")
    forbidden_chunks = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
    position = 8
    saw_end = False
    while position + 12 <= len(data):
        chunk_length = int.from_bytes(data[position : position + 4], "big")
        chunk_type = data[position + 4 : position + 8]
        end = position + 12 + chunk_length
        if end > len(data):
            fail(f"truncated PNG chunk: {relative}")
        if chunk_type in forbidden_chunks:
            fail(f"PNG metadata chunk {chunk_type.decode('ascii')} is not allowed: {relative}")
        position = end
        if chunk_type == b"IEND":
            saw_end = True
            break
    if not saw_end or position != len(data):
        fail(f"malformed PNG file: {relative}")


def scan_webp_metadata(data: bytes, relative: str) -> None:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        fail(f"invalid WebP file: {relative}")
    declared_size = int.from_bytes(data[4:8], "little") + 8
    if declared_size != len(data):
        fail(f"invalid WebP container size: {relative}")
    position = 12
    while position + 8 <= len(data):
        chunk_type = data[position : position + 4]
        chunk_length = int.from_bytes(data[position + 4 : position + 8], "little")
        end = position + 8 + chunk_length
        if end > len(data):
            fail(f"truncated WebP chunk: {relative}")
        if chunk_type in {b"EXIF", b"XMP "}:
            fail(f"WebP {chunk_type.decode('ascii').strip()} metadata is not allowed: {relative}")
        position = end + (chunk_length % 2)
    if position != len(data):
        fail(f"malformed WebP file: {relative}")


def scan_avif_metadata(data: bytes, relative: str) -> None:
    if len(data) < 24:
        fail(f"truncated AVIF file: {relative}")

    top_level_types: list[bytes] = []
    position = 0
    while position < len(data):
        if position + 8 > len(data):
            fail(f"truncated AVIF box header: {relative}")
        box_size = int.from_bytes(data[position : position + 4], "big")
        box_type = data[position + 4 : position + 8]
        header_size = 8
        if box_size == 1:
            if position + 16 > len(data):
                fail(f"truncated AVIF extended box header: {relative}")
            box_size = int.from_bytes(data[position + 8 : position + 16], "big")
            header_size = 16
        elif box_size == 0:
            box_size = len(data) - position
        if box_size < header_size or position + box_size > len(data):
            fail(f"invalid AVIF box size: {relative}")
        top_level_types.append(box_type)
        position += box_size

    first_box_size = int.from_bytes(data[:4], "big")
    if first_box_size == 1:
        if len(data) < 24:
            fail(f"truncated AVIF ftyp box: {relative}")
        first_box_size = int.from_bytes(data[8:16], "big")
        brand_offset = 16
    else:
        brand_offset = 8
    if top_level_types[0] != b"ftyp" or first_box_size < brand_offset + 8:
        fail(f"AVIF must begin with a valid ftyp box: {relative}")
    ftyp_payload = data[brand_offset:first_box_size]
    major_brand = ftyp_payload[:4]
    compatible_brands = {
        ftyp_payload[index : index + 4]
        for index in range(8, len(ftyp_payload), 4)
        if index + 4 <= len(ftyp_payload)
    }
    if major_brand not in {b"avif", b"avis"} and not compatible_brands.intersection(
        {b"avif", b"avis"}
    ):
        fail(f"ISO BMFF file is not branded as AVIF: {relative}")
    if b"meta" not in top_level_types or b"mdat" not in top_level_types:
        fail(f"AVIF must contain meta and mdat boxes: {relative}")

    lowered = data.lower()
    privacy_markers = (
        b"exif",
        b"xmp ",
        b"application/rdf+xml",
        b"<x:xmpmeta",
        b"uuid",
    )
    if any(marker in lowered for marker in privacy_markers):
        fail(f"AVIF metadata item is not allowed: {relative}")

    dimensions: list[tuple[int, int]] = []
    search_position = 0
    while True:
        marker = data.find(b"ispe", search_position)
        if marker < 0:
            break
        if marker >= 4:
            box_start = marker - 4
            box_size = int.from_bytes(data[box_start:marker], "big")
            if box_size >= 20 and box_start + box_size <= len(data):
                width = int.from_bytes(data[marker + 8 : marker + 12], "big")
                height = int.from_bytes(data[marker + 12 : marker + 16], "big")
                dimensions.append((width, height))
        search_position = marker + 4
    if not dimensions:
        fail(f"AVIF has no valid ispe dimensions: {relative}")
    for width, height in dimensions:
        if width < 1 or height < 1 or width > 32_768 or height > 32_768:
            fail(f"AVIF dimensions are outside the accepted range: {relative}")
        if width * height > 100_000_000:
            fail(f"AVIF exceeds the 100 megapixel audit limit: {relative}")


def scan_file(path: pathlib.Path, site: pathlib.Path) -> None:
    relative = relative_name(path, site)
    data = path.read_bytes()
    scan_image_metadata(path, data, relative)

    lowered = data.lower()
    hits = [term for term in FORBIDDEN_LITERAL_TEXT if term.lower().encode() in lowered]
    if hits:
        fail(f"forbidden private/template text in {relative}: {hits}")
    if any(pattern.search(data) for pattern in FORBIDDEN_TOKEN_PATTERNS):
        fail(f"credential-shaped value in output file: {relative}")
    if any(pattern.search(data) for pattern in FORBIDDEN_LOCAL_PATH_PATTERNS):
        fail(f"local filesystem path in output file: {relative}")
    if any(boundary in data for boundary in PRIVATE_KEY_BOUNDARIES):
        fail(f"private-key boundary in output file: {relative}")
    if any(marker.lower() in lowered for marker in FORBIDDEN_BINARY_MARKERS):
        fail(f"embedded image metadata in output file: {relative}")


def canonical_tree_hash(site: pathlib.Path, files: Iterable[pathlib.Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: relative_name(item, site).encode("utf-8")):
        relative = relative_name(path, site).encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate key in PROVENANCE.json: {key}")
        result[key] = value
    return result


def read_manifest(path: pathlib.Path) -> dict[str, object]:
    try:
        status = path.lstat()
    except FileNotFoundError:
        fail("PROVENANCE.json is missing")
    if not stat.S_ISREG(status.st_mode) or path.is_symlink():
        fail("PROVENANCE.json must be a regular file")
    if status.st_mode & 0o111:
        fail("PROVENANCE.json must not be executable")
    if status.st_size > 16 * 1024:
        fail("PROVENANCE.json exceeds 16 KiB")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid PROVENANCE.json: {error}")
    if not isinstance(parsed, dict):
        fail("PROVENANCE.json must contain one JSON object")
    return parsed


def validate_manifest(manifest: dict[str, object]) -> None:
    keys = set(manifest)
    missing = sorted(REQUIRED_MANIFEST_KEYS - keys)
    unexpected = sorted(keys - REQUIRED_MANIFEST_KEYS)
    if missing:
        fail(f"PROVENANCE.json is missing: {', '.join(missing)}")
    if unexpected:
        fail(f"PROVENANCE.json has unsupported fields: {', '.join(unexpected)}")

    schema_version = manifest["schema_version"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        fail(f"schema_version must be the integer {SCHEMA_VERSION}")
    if not isinstance(manifest["hugo_version"], str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
        manifest["hugo_version"],
    ):
        fail("hugo_version must be a three-part version without a leading v")
    if not isinstance(manifest["site_tree_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", manifest["site_tree_sha256"]
    ):
        fail("site_tree_sha256 must be a lowercase SHA-256 digest")


def audit(root: pathlib.Path) -> str:
    root = root.resolve()
    site = root / "site"
    manifest = read_manifest(root / "PROVENANCE.json")
    validate_manifest(manifest)
    files = inspect_tree(site)
    index = site / "index.html"
    if index not in files or index.stat().st_size == 0:
        fail("site/index.html is missing or empty")
    for path in files:
        scan_file(path, site)
    actual = canonical_tree_hash(site, files)
    if actual != manifest["site_tree_sha256"]:
        fail(
            "site tree digest mismatch: "
            f"manifest={manifest['site_tree_sha256']} actual={actual}"
        )
    return actual


def tree_hash(site: pathlib.Path) -> str:
    site = site.resolve()
    files = inspect_tree(site)
    for path in files:
        scan_file(path, site)
    return canonical_tree_hash(site, files)


def main(arguments: list[str]) -> int:
    if len(arguments) != 2 or arguments[0] not in {"audit", "tree-hash"}:
        print(
            "usage: public_output_audit.py {audit REPOSITORY_ROOT|tree-hash SITE_DIR}",
            file=sys.stderr,
        )
        return 2
    try:
        if arguments[0] == "audit":
            digest = audit(pathlib.Path(arguments[1]))
            print(f"public-output audit passed: {digest}")
        else:
            print(tree_hash(pathlib.Path(arguments[1])))
    except (AuditFailure, OSError) as error:
        print(f"public-output audit: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
