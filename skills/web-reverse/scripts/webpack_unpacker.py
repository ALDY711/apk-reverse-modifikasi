#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Webpack chunk unpacker and module extractor.

WHY THIS EXISTS
---------------
Modern Single-Page Applications (React, Vue, Next.js, Nuxt, Angular) compile hundreds of
source files into minified Webpack bundles (often split into multiple chunk files like
`app.5a8f2d.js`, `chunk-vendors.js`, `2.js`).

Analyzing a 5MB minified bundle as a single file is overwhelming and error-prone.
Webpack chunks follow structured formats:
  - Webpack 5: `(self["webpackChunk..."] = self["webpackChunk..."] || []).push([[chunkIds], { moduleId: function(e, t, n) { ... } }])`
  - Webpack 4: `(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[chunkIds], { moduleId: function(e, t, n) { ... } }])`
  - Webpack 3 / Classic IIFE: `!function(e) { ... }({ 0: function(...) { ... }, 1: function(...) { ... } })`

This tool automatically detects, parses, and unpacks these Webpack modules into individual
separate JavaScript files. If Webpack path comments are present (e.g. `/*! ./src/api/auth.ts */`),
it preserves the exact original directory structure! It also scans each module for sensitive
features (crypto, signatures, API clients, authentication).

USAGE
-----
  # Unpack a local bundle into a clean module directory
  python webpack_unpacker.py --file app.bundle.js --out-dir ./unpacked_modules

  # Fetch remote bundle directly and unpack
  python webpack_unpacker.py --url https://example.com/static/js/app.js --out-dir ./unpacked

  # Filter and unpack only sensitive modules (crypto, auth, api)
  python webpack_unpacker.py --file app.bundle.js --out-dir ./unpacked --only-sensitive

  # Output structured JSON inventory of all detected modules
  python webpack_unpacker.py --file app.bundle.js --json

EXIT CODES
----------
  0 = modules successfully extracted
  1 = no Webpack chunk patterns detected
  2 = argument or file I/O error
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path


SENSITIVE_KEYWORDS = {
    "auth": re.compile(r'\b(auth|login|token|jwt|refresh_token|accessToken|bearer|credential)\b', re.IGNORECASE),
    "crypto": re.compile(r'\b(crypto|aes|rsa|hmac|sha256|sha1|md5|encrypt|decrypt|cipher|pbkdf2)\b', re.IGNORECASE),
    "signature": re.compile(r'\b(sign|signature|x-sign|token-generator|nonce|canonical|secret_key)\b', re.IGNORECASE),
    "api_client": re.compile(r'\b(axios|createClient|apiBase|baseURL|interceptors\.request|XMLHttpRequest)\b', re.IGNORECASE),
    "anti_debug": re.compile(r'\b(debugger|devtools|antiDebug|detectDevtools|console\.clear)\b', re.IGNORECASE),
}


def sanitize_filename(name: str) -> str:
    """Sanitize path or module ID to be a safe filesystem path."""
    name = name.strip().replace('\\', '/')
    name = re.sub(r'^[./\\]+', '', name)
    name = re.sub(r'[?*:|"<>]+', '_', name)
    if not name:
        name = "unnamed_module"
    if not name.endswith('.js') and not name.endswith('.ts') and not name.endswith('.vue'):
        name += '.js'
    return name


def extract_path_comment(code: str) -> str | None:
    """Extract original source file path if Webpack path comment is present.
    Example: /*!*********************!*\\ \n !*** ./src/api/auth.ts ***!
    """
    m = re.search(r'/\*![\s*!]*\n[\s*!]*([a-zA-Z0-9_.\-/@\\]+\.[a-zA-Z0-9]+)\b', code)
    if m:
        return m.group(1).replace('\\', '/')
    m2 = re.search(r'/\*!\s*(\./[a-zA-Z0-9_.\-/@\\]+)\s*\*/', code)
    if m2:
        return m2.group(1).replace('\\', '/')
    return None


def scan_module_metadata(code: str) -> dict:
    """Scan a module for sensitive features, API routes, and dependencies."""
    tags = []
    for tag_name, pattern in SENSITIVE_KEYWORDS.items():
        if pattern.search(code):
            tags.append(tag_name)

    # Detect API endpoint patterns like '/api/v1/user' or 'https://api...'
    endpoints = set(re.findall(r'["\'](/(?:api|v[0-9]+|v1|v2|auth|users?|order|payment)/[a-zA-Z0-9_/\-?&=%.]*)["\']', code))
    
    # Detect require or import calls
    requires = set(re.findall(r'(?:require|import)\s*\(\s*["\']([^"\']+)["\']\s*\)', code))

    return {
        "tags": tags,
        "is_sensitive": len(tags) > 0,
        "endpoints": sorted(list(endpoints))[:10],
        "requires": sorted(list(requires))[:15],
        "size_bytes": len(code.encode('utf-8', errors='replace')),
    }


def find_matching_bracket(text: str, start_index: int, open_char: str = '{', close_char: str = '}') -> int:
    """Find the closing bracket index matching open_char at start_index, taking strings and comments into account."""
    depth = 0
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    escape = False

    i = start_index
    length = len(text)

    while i < length:
        ch = text[i]

        if escape:
            escape = False
            i += 1
            continue

        if ch == '\\':
            escape = True
            i += 1
            continue

        # Handle comments
        if not in_single_quote and not in_double_quote and not in_backtick:
            if not in_line_comment and not in_block_comment:
                if ch == '/' and i + 1 < length:
                    next_ch = text[i + 1]
                    if next_ch == '/':
                        in_line_comment = True
                        i += 2
                        continue
                    elif next_ch == '*':
                        in_block_comment = True
                        i += 2
                        continue
            elif in_line_comment:
                if ch == '\n':
                    in_line_comment = False
                i += 1
                continue
            elif in_block_comment:
                if ch == '*' and i + 1 < length and text[i + 1] == '/':
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

        # Handle strings
        if not in_line_comment and not in_block_comment:
            if ch == "'" and not in_double_quote and not in_backtick:
                in_single_quote = not in_single_quote
                i += 1
                continue
            if ch == '"' and not in_single_quote and not in_backtick:
                in_double_quote = not in_double_quote
                i += 1
                continue
            if ch == '`' and not in_single_quote and not in_double_quote:
                in_backtick = not in_backtick
                i += 1
                continue

        if not in_single_quote and not in_double_quote and not in_backtick:
            if ch == open_char:
                depth += 1
            elif ch == close_char:
                depth -= 1
                if depth == 0:
                    return i

        i += 1

    return -1


def extract_webpack_modules_object(code: str, dict_start_idx: int) -> dict[str, str]:
    """Extract individual modules from a Webpack dictionary: { [moduleId]: function(...) {...}, ... }."""
    modules = {}
    dict_end_idx = find_matching_bracket(code, dict_start_idx, '{', '}')
    if dict_end_idx == -1:
        return modules

    content = code[dict_start_idx + 1:dict_end_idx]
    
    # Regex to find module keys: "key": function(...) or 123: function(...) or 'key': (function(...) or [key]: ...
    # Module boundaries usually look like: (?:^|,)\s*(["']?[a-zA-Z0-9_.\-/@\\]+["']?|\d+)\s*:\s*(?:function|\([^)]*\)\s*=>)
    key_pattern = re.compile(r'(?:^|,)\s*(["\']?[a-zA-Z0-9_.\-/@\\]+["\']?|\d+)\s*:\s*(?:function|\([^)]*\)\s*=>|\([a-zA-Z0-9_,\s]*\)\s*=>)')
    
    matches = list(key_pattern.finditer(content))
    for i, match in enumerate(matches):
        mod_key = match.group(1).strip('"\'')
        func_start = match.end() - len(match.group(0).split(':', 1)[1].lstrip())
        
        # Function body ends before next module key, or at the end of content
        if i + 1 < len(matches):
            next_start = matches[i + 1].start()
            mod_code = content[func_start:next_start].rstrip(', \r\n\t')
        else:
            mod_code = content[func_start:].rstrip(', \r\n\t')

        if mod_code:
            modules[mod_key] = mod_code

    return modules


def extract_webpack_modules_array(code: str, arr_start_idx: int) -> dict[str, str]:
    """Extract modules from a Webpack array: [ function(e,t,n){...}, function(e,t,n){...} ]."""
    modules = {}
    arr_end_idx = find_matching_bracket(code, arr_start_idx, '[', ']')
    if arr_end_idx == -1:
        return modules

    content = code[arr_start_idx + 1:arr_end_idx]
    
    # Modules in array are separated by commas at depth 0
    func_pattern = re.compile(r'(?:^|,)\s*(?:function|\([^)]*\)\s*=>|\([a-zA-Z0-9_,\s]*\)\s*=>)')
    matches = list(func_pattern.finditer(content))
    for i, match in enumerate(matches):
        mod_key = str(i)
        func_start = match.start()
        if content[func_start] == ',':
            func_start += 1
        
        if i + 1 < len(matches):
            next_start = matches[i + 1].start()
            mod_code = content[func_start:next_start].rstrip(', \r\n\t')
        else:
            mod_code = content[func_start:].rstrip(', \r\n\t')

        if mod_code.strip():
            modules[mod_key] = mod_code.strip()

    return modules


def parse_bundle(code: str) -> tuple[str, dict[str, str]]:
    """Detect bundle type and extract all modules."""
    # Pattern 1: Webpack 5 / Modern Webpack Chunk push
    # (self["webpackChunk..."] = self["webpackChunk..."] || []).push([ [chunkIds], { ...modules... } ])
    wp5_match = re.search(r'\.push\s*\(\s*\[\s*\[[^\]]*\]\s*,\s*(\{)', code)
    if wp5_match:
        dict_start = wp5_match.start(1)
        mods = extract_webpack_modules_object(code, dict_start)
        if mods:
            return "webpack5_chunk", mods

    # Pattern 2: Webpack 4 / webpackJsonp push with object
    # (window["webpackJsonp"] = window["webpackJsonp"] || []).push([ [chunkIds], { ...modules... } ])
    wp4_match = re.search(r'webpackJsonp(?:Callback)?\s*\(\s*\[\s*\[[^\]]*\]\s*,\s*(\{)', code)
    if wp4_match:
        dict_start = wp4_match.start(1)
        mods = extract_webpack_modules_object(code, dict_start)
        if mods:
            return "webpack4_chunk", mods

    # Pattern 3: Webpack chunk push with array of modules
    wp_arr_match = re.search(r'\.push\s*\(\s*\[\s*\[[^\]]*\]\s*,\s*(\[)', code)
    if wp_arr_match:
        arr_start = wp_arr_match.start(1)
        mods = extract_webpack_modules_array(code, arr_start)
        if mods:
            return "webpack_chunk_array", mods

    # Pattern 4: Classic Webpack Bootstrap IIFE with object parameter
    # !function(e) { ... }({ 0: function(...) { ... }, ... })
    classic_obj = re.search(r'\}\s*\(\s*(\{[\s\S]*?\b(?:function|\=\>)\b)', code)
    if classic_obj:
        dict_start = classic_obj.start(1)
        mods = extract_webpack_modules_object(code, dict_start)
        if mods:
            return "webpack_classic_object", mods

    # Pattern 5: Classic Webpack Bootstrap IIFE with array parameter
    classic_arr = re.search(r'\}\s*\(\s*(\[\s*(?:function|\=\>)\b)', code)
    if classic_arr:
        arr_start = classic_arr.start(1)
        mods = extract_webpack_modules_array(code, arr_start)
        if mods:
            return "webpack_classic_array", mods

    return "unknown", {}


def main():
    parser = argparse.ArgumentParser(
        description="Webpack Chunk Unpacker & Module Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Local JavaScript bundle file path")
    group.add_argument("--url", "-u", help="Remote JavaScript bundle URL to fetch and unpack")

    parser.add_argument("--out-dir", "-o", default="./unpacked_modules", help="Output directory for unpacked module files")
    parser.add_argument("--only-sensitive", action="store_true", help="Only extract modules flagged with sensitive features")
    parser.add_argument("--json", action="store_true", help="Output structured module catalog as JSON to stdout")

    args = parser.parse_args()

    # Load code
    if args.url:
        try:
            req = urllib.request.Request(args.url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                code = resp.read().decode('utf-8', errors='replace')
        except Exception as e:
            print(f"[!] Error fetching URL: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] Error: File '{args.file}' does not exist.", file=sys.stderr)
            sys.exit(2)
        try:
            code = file_path.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            print(f"[!] Error reading file: {e}", file=sys.stderr)
            sys.exit(2)

    bundle_type, modules = parse_bundle(code)

    if not modules:
        print("[!] No Webpack chunk modules found in the provided file/URL.", file=sys.stderr)
        sys.exit(1)

    # Process all modules
    catalog = []
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted_count = 0
    sensitive_count = 0

    for mod_id, mod_code in modules.items():
        meta = scan_module_metadata(mod_code)
        path_comment = extract_path_comment(mod_code)
        
        if path_comment:
            clean_rel_path = sanitize_filename(path_comment)
            filename = clean_rel_path
        else:
            filename = sanitize_filename(f"module_{mod_id}")

        meta["module_id"] = str(mod_id)
        meta["path_comment"] = path_comment
        meta["target_file"] = filename
        catalog.append(meta)

        if meta["is_sensitive"]:
            sensitive_count += 1

        if args.only_sensitive and not meta["is_sensitive"]:
            continue

        target_file_path = out_dir / filename
        target_file_path.parent.mkdir(parents=True, exist_ok=True)

        header = f"// Module ID: {mod_id}\n"
        if path_comment:
            header += f"// Original Path: {path_comment}\n"
        if meta["tags"]:
            header += f"// Detected Tags: {', '.join(meta['tags'])}\n"
        header += "// --------------------------------------------------\n\n"

        target_file_path.write_text(header + mod_code, encoding='utf-8', errors='replace')
        extracted_count += 1

    if args.json:
        result = {
            "bundle_type": bundle_type,
            "total_modules": len(modules),
            "extracted_modules": extracted_count,
            "sensitive_modules": sensitive_count,
            "output_directory": str(out_dir.resolve()),
            "modules": catalog,
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    print("=================================================================")
    print("           WEBPACK CHUNK UNPACKER & MODULE EXTRACTOR             ")
    print("=================================================================")
    print(f"[*] Bundle Type Detected : {bundle_type}")
    print(f"[*] Total Modules Found  : {len(modules)}")
    print(f"[*] Sensitive Modules    : {sensitive_count}")
    print(f"[*] Modules Extracted    : {extracted_count}")
    print(f"[*] Output Directory     : {out_dir.resolve()}")
    print("-----------------------------------------------------------------")
    print("TOP SENSITIVE MODULES FOUND:")
    shown = 0
    for item in catalog:
        if item["is_sensitive"]:
            shown += 1
            tags_str = ", ".join(f"[{t}]" for t in item["tags"])
            label = item["path_comment"] or f"module_{item['module_id']}"
            print(f"  • {tags_str:<25} -> {label} ({item['size_bytes']} bytes)")
            if item["endpoints"]:
                print(f"      Endpoints: {', '.join(item['endpoints'])}")
            if shown >= 15:
                remaining = sensitive_count - shown
                if remaining > 0:
                    print(f"      ... and {remaining} more sensitive modules.")
                break
    print("=================================================================")
    sys.exit(0)


if __name__ == "__main__":
    main()
