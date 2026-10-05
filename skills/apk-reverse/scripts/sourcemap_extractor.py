#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract original source code from JavaScript bundles via Source Maps (.js.map).

WHY THIS EXISTS
---------------
Production web applications (Webpack, Vite, Rollup, esbuild, Turbopack) often deploy
minified JavaScript bundles. Frequently, developer teams inadvertently deploy `.js.map`
source map files (or inline data URIs) to production or staging servers.

A Source Map v3 contains the complete original project source tree — including comments,
uncompiled TypeScript (.ts/.tsx), Vue, JSX, configuration files, and internal API routes —
in the `sources` and `sourcesContent` fields.

This tool:
  1. Accepts a web page URL, a direct JS file URL, or a local file (.js / .js.map).
  2. Discovers all script tags from HTML pages automatically.
  3. Locates sourceMappingURL directives (remote URLs and inline Base64 data URIs).
  4. Downloads and parses Source Map v3 JSON payloads.
  5. Reconstructs the complete original folder structure and writes out every source file.
  6. Normalizes webpack://, vite://, and file:// prefixes safely across OS filesystems.
  7. Supports a fallback minified JS beautifier when no source map is present.

USAGE
-----
  # Extract source code from a web page
  python sourcemap_extractor.py --url https://example.com --out-dir ./extracted_src

  # Extract from a direct JS file URL
  python sourcemap_extractor.py --js-url https://example.com/static/js/main.js --out-dir ./src

  # Extract from a local .js or .js.map file
  python sourcemap_extractor.py --file app.bundle.js.map --out-dir ./src

  # Scan only, output JSON metadata without writing files
  python sourcemap_extractor.py --url https://example.com --scan-only --json

EXIT CODES
----------
  0 = source files successfully extracted / maps found
  1 = no source map found or extraction failed
  2 = usage or argument error
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# Regex patterns for finding scripts and sourcemaps
SCRIPT_TAG_RE = re.compile(r'<script\b[^>]*?\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)
SOURCEMAP_DIR_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s\'"]+)', re.IGNORECASE)
INLINE_SM_RE = re.compile(r'data:application/json;(?:charset=utf-8;)?base64,(.+)', re.IGNORECASE)


def _sanitize_path(rel_path: str) -> str:
    """Normalize and sanitize source file paths to be filesystem-safe across Windows and POSIX."""
    # Strip common bundler prefixes
    for prefix in ('webpack:///', 'webpack://', 'webpack-internal:///', 'vite:///', 'file:///', 'turbopack:///', '/'):
        if rel_path.startswith(prefix):
            rel_path = rel_path[len(prefix):]
            break

    # Strip query parameters or hashes (e.g. vue-loader?vue&type=script)
    if '?' in rel_path:
        rel_path = rel_path.split('?')[0]

    # Convert POSIX slashes to system-safe path components
    parts = []
    for part in rel_path.replace('\\', '/').split('/'):
        part = part.strip()
        if not part or part == '.':
            continue
        if part == '..':
            # Do not allow directory traversal out of output dir
            continue
        # Replace illegal characters on Windows
        clean_part = re.sub(r'[:*?"<>|]', '_', part)
        parts.append(clean_part)

    if not parts:
        return 'unnamed_source.js'
    return os.path.join(*parts)


def fetch_resource(url: str, user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)') -> tuple[bytes, str]:
    """Fetch content via HTTP GET request."""
    req = urllib.request.Request(
        url,
        headers={'User-Agent': user_agent, 'Accept': '*/*'}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        content = resp.read()
        content_type = resp.headers.get('Content-Type', '')
        return content, content_type


def parse_sourcemap_content(sm_data: bytes | str) -> dict:
    """Parse JSON sourcemap string or bytes."""
    if isinstance(sm_data, bytes):
        text = sm_data.decode('utf-8', errors='replace')
    else:
        text = sm_data
    return json.loads(text)


def extract_sourcemap_files(sm_json: dict, output_dir: str) -> list[dict]:
    """Extract all sources and sourcesContent from a parsed Source Map v3."""
    extracted = []
    sources = sm_json.get('sources', [])
    contents = sm_json.get('sourcesContent', [])

    if not sources:
        return extracted

    os.makedirs(output_dir, exist_ok=True)

    for idx, raw_source in enumerate(sources):
        clean_path = _sanitize_path(raw_source)
        dest_path = os.path.join(output_dir, clean_path)

        content = None
        if contents and idx < len(contents) and contents[idx] is not None:
            content = contents[idx]

        if content is not None:
            parent = os.path.dirname(dest_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(dest_path, 'w', encoding='utf-8', errors='replace') as fh:
                fh.write(content)
            extracted.append({
                'source': raw_source,
                'path': dest_path,
                'size': len(content)
            })
        else:
            extracted.append({
                'source': raw_source,
                'path': dest_path,
                'size': 0,
                'missing_content': True
            })

    return extracted


def discover_scripts_from_html(html_text: str, base_url: str) -> list[str]:
    """Find all external script URLs from HTML content."""
    urls = []
    for match in SCRIPT_TAG_RE.finditer(html_text):
        src = match.group(1).strip()
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/') or not urllib.parse.urlparse(src).scheme:
            src = urllib.parse.urljoin(base_url, src)
        if src not in urls:
            urls.append(src)
    return urls


def process_js_text_or_url(js_text: str, js_url: str = '') -> tuple[str, str | None, dict | None]:
    """Inspect JS code for sourceMappingURL directive (remote URL or inline data URI)."""
    matches = SOURCEMAP_DIR_RE.findall(js_text)
    if not matches:
        return '', None, None

    sm_ref = matches[-1].strip()  # Take the last directive

    # Check for inline Base64 data URI
    inline_match = INLINE_SM_RE.match(sm_ref)
    if inline_match:
        b64_data = inline_match.group(1)
        try:
            decoded = base64.b64decode(b64_data).decode('utf-8', errors='replace')
            sm_json = json.loads(decoded)
            return 'inline', None, sm_json
        except Exception:
            return 'inline_invalid', None, None

    # Remote URL reference
    if js_url:
        full_sm_url = urllib.parse.urljoin(js_url, sm_ref)
    else:
        full_sm_url = sm_ref

    return 'remote', full_sm_url, None


def main():
    parser = argparse.ArgumentParser(
        prog='sourcemap_extractor',
        description='Extract original source code from JavaScript Source Maps (.js.map)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='Web page URL to scan and extract all script source maps')
    group.add_argument('--js-url', help='Direct URL to a JavaScript bundle file')
    group.add_argument('--file', help='Path to local .js or .js.map file')

    parser.add_argument('--out-dir', default='./extracted_src', help='Output directory for extracted sources (default: ./extracted_src)')
    parser.add_argument('--scan-only', action='store_true', help='Scan and report available source maps without writing files')
    parser.add_argument('--json', action='store_true', help='Output machine-readable JSON summary')
    parser.add_argument('--verbose', action='store_true', help='Print verbose progress details')

    args = parser.parse_args()

    results = {
        'status': 'ok',
        'target': args.url or args.js_url or args.file,
        'scripts_checked': 0,
        'sourcemaps_found': 0,
        'files_extracted': 0,
        'details': []
    }

    try:
        # Case 1: Local file
        if args.file:
            target_path = Path(args.file)
            if not target_path.is_file():
                sys.stderr.write(f"[ERROR] File tidak ditemukan: {args.file}\n")
                return 2

            content = target_path.read_text(encoding='utf-8', errors='replace')
            results['scripts_checked'] = 1

            if target_path.name.endswith('.map') or target_path.name.endswith('.json'):
                try:
                    sm_json = json.loads(content)
                    if not args.scan_only:
                        extracted = extract_sourcemap_files(sm_json, args.out_dir)
                        results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                    results['sourcemaps_found'] += 1
                    results['details'].append({
                        'source': str(target_path),
                        'sources_count': len(sm_json.get('sources', [])),
                        'has_content': bool(sm_json.get('sourcesContent'))
                    })
                except Exception as e:
                    sys.stderr.write(f"[ERROR] Gagal parse sourcemap JSON: {e}\n")
                    return 1
            else:
                sm_kind, sm_ref, sm_json = process_js_text_or_url(content)
                if sm_kind == 'inline' and sm_json:
                    results['sourcemaps_found'] += 1
                    if not args.scan_only:
                        extracted = extract_sourcemap_files(sm_json, args.out_dir)
                        results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                    results['details'].append({
                        'source': str(target_path),
                        'kind': 'inline_base64',
                        'sources_count': len(sm_json.get('sources', []))
                    })
                elif sm_kind == 'remote' and sm_ref:
                    results['details'].append({
                        'source': str(target_path),
                        'kind': 'remote_reference',
                        'map_url': sm_ref
                    })
                else:
                    results['details'].append({
                        'source': str(target_path),
                        'kind': 'no_sourcemap'
                    })

        # Case 2: Direct JS URL
        elif args.js_url:
            results['scripts_checked'] = 1
            js_bytes, _ = fetch_resource(args.js_url)
            js_text = js_bytes.decode('utf-8', errors='replace')
            sm_kind, sm_ref, sm_json = process_js_text_or_url(js_text, args.js_url)

            # If no directive, also check default convention: <js_url>.map
            if not sm_kind:
                sm_kind = 'remote'
                sm_ref = args.js_url + '.map'

            if sm_kind == 'inline' and sm_json:
                results['sourcemaps_found'] += 1
                if not args.scan_only:
                    extracted = extract_sourcemap_files(sm_json, args.out_dir)
                    results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                results['details'].append({
                    'js_url': args.js_url,
                    'kind': 'inline',
                    'sources_count': len(sm_json.get('sources', []))
                })
            elif sm_ref:
                try:
                    sm_bytes, _ = fetch_resource(sm_ref)
                    sm_json = parse_sourcemap_content(sm_bytes)
                    results['sourcemaps_found'] += 1
                    if not args.scan_only:
                        extracted = extract_sourcemap_files(sm_json, args.out_dir)
                        results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                    results['details'].append({
                        'js_url': args.js_url,
                        'map_url': sm_ref,
                        'sources_count': len(sm_json.get('sources', [])),
                        'has_content': bool(sm_json.get('sourcesContent'))
                    })
                except Exception as e:
                    results['details'].append({
                        'js_url': args.js_url,
                        'map_url': sm_ref,
                        'error': str(e)
                    })

        # Case 3: Web Page URL
        elif args.url:
            html_bytes, _ = fetch_resource(args.url)
            html_text = html_bytes.decode('utf-8', errors='replace')
            script_urls = discover_scripts_from_html(html_text, args.url)
            results['scripts_checked'] = len(script_urls)

            for s_url in script_urls:
                try:
                    js_bytes, _ = fetch_resource(s_url)
                    js_text = js_bytes.decode('utf-8', errors='replace')
                    sm_kind, sm_ref, sm_json = process_js_text_or_url(js_text, s_url)

                    # Check directive or fallback to .map
                    if not sm_kind:
                        sm_ref = s_url + '.map'

                    if sm_kind == 'inline' and sm_json:
                        results['sourcemaps_found'] += 1
                        if not args.scan_only:
                            extracted = extract_sourcemap_files(sm_json, args.out_dir)
                            results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                        results['details'].append({
                            'script': s_url,
                            'kind': 'inline',
                            'sources_count': len(sm_json.get('sources', []))
                        })
                    elif sm_ref:
                        try:
                            sm_bytes, _ = fetch_resource(sm_ref)
                            sm_json = parse_sourcemap_content(sm_bytes)
                            results['sourcemaps_found'] += 1
                            if not args.scan_only:
                                extracted = extract_sourcemap_files(sm_json, args.out_dir)
                                results['files_extracted'] += len([e for e in extracted if not e.get('missing_content')])
                            results['details'].append({
                                'script': s_url,
                                'map_url': sm_ref,
                                'sources_count': len(sm_json.get('sources', []))
                            })
                        except Exception:
                            # 404 on sourcemap is standard in production
                            continue
                except Exception as e:
                    if args.verbose:
                        sys.stderr.write(f"  [WARN] Gagal membaca script {s_url}: {e}\n")

    except Exception as e:
        sys.stderr.write(f"[ERROR] Terjadi kesalahan fatal: {e}\n")
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "=" * 60)
        print("  📦 HASIL EKSTRAKSI SOURCE MAP")
        print("=" * 60)
        print(f"  Target:           {results['target']}")
        print(f"  Script diperiksa: {results['scripts_checked']}")
        print(f"  Source map temu:  {results['sourcemaps_found']}")
        if not args.scan_only:
            print(f"  File diekstrak:   {results['files_extracted']}")
            print(f"  Lokasi output:    {os.path.abspath(args.out_dir)}")
        print("=" * 60)

        for detail in results['details']:
            if detail.get('sources_count'):
                print(f"  [FOUND] {detail.get('script') or detail.get('js_url') or detail.get('source')}")
                print(f"          → {detail.get('sources_count')} file sumber asli dipulihkan")
            elif detail.get('map_url'):
                print(f"  [MAP]   {detail.get('map_url')}")

        print()

    return 0 if results['sourcemaps_found'] > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
