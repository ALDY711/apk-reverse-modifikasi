#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Deobfuscate, unpack, and beautify minified and protected JavaScript files.

WHY THIS EXISTS
---------------
Web applications frequently obfuscate or pack their client-side code using:
  1. Dean Edwards Packer: `eval(function(p,a,c,k,e,d)...)`
  2. String encoding: Hex escapes (`\x68\x65\x6c\x6c\x6f`), Octal, or Unicode escapes (`\u0041`)
  3. String array indirection: `var _0x12ab = ['hello', 'world'];`
  4. Anti-debugging traps: `setInterval(function() { debugger; }, 50)` or inline `debugger;` loops
  5. Minification: single-line multi-megabyte bundles with zero whitespace

To reverse engineer and modify the code, an analyst needs clean, readable, formatted JavaScript
with anti-debugging traps neutralized and string literals decoded to human-readable form.

This tool:
  - Detects and unpacks Dean Edwards `eval(function(p,a,c,k,e,r)...)` payloads recursively.
  - Decodes `\xHH` and `\uHHHH` escape sequences into standard UTF-8 characters.
  - Automatically neutralizes `debugger;` statements and anti-devtools intervals.
  - Formats and beautifies raw or minified JavaScript with proper indentation and line breaks.

USAGE
-----
  # Beautify and deobfuscate a minified JS file
  python js_deobfuscator.py --file app.min.js --out app.clean.js

  # Remove anti-debugging / debugger loops
  python js_deobfuscator.py --file app.min.js --out app.clean.js --kill-debugger

  # Unpack eval-packed code and print directly to stdout
  python js_deobfuscator.py --file packed.js

EXIT CODES
----------
  0 = successfully processed and beautified
  1 = error during reading or processing
  2 = usage or argument error
"""

import argparse
import os
import re
import sys
from pathlib import Path


# Regex for Dean Edwards packer: eval(function(p,a,c,k,e,r)...) or eval(function(p,a,c,k,e,d)...)
PACKER_RE = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)\s*\{"
    r".*?return\s+p;?\s*\}\s*\(\s*'(?P<p>.*?)'\s*,\s*(?P<a>\d+)\s*,\s*(?P<c>\d+)\s*,\s*'(?P<k>.*?)'\.split\('\|'\)",
    re.DOTALL
)

# Regex for hex string escapes: \x41, \x20
HEX_ESCAPE_RE = re.compile(r'\\x([0-9a-fA-F]{2})')

# Regex for unicode escapes: \u0041
UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')

# Regex for debugger loops and statements
DEBUGGER_LOOP_RE = re.compile(
    r'setInterval\s*\(\s*(?:function\s*\(\s*\)|(?:\(\s*\)\s*=>))\s*\{?\s*debugger;?\s*\}?\s*,\s*\d+\s*\);?',
    re.IGNORECASE
)
DEBUGGER_STMT_RE = re.compile(r'(?<![a-zA-Z0-9_$])debugger;?', re.IGNORECASE)
FUNCTION_DEBUGGER_RE = re.compile(
    r'(?:Function|eval)\s*\(\s*["\']\s*debugger;?\s*["\']\s*\)\s*(?:\(\s*\))?;?',
    re.IGNORECASE
)


def _base_n_decode(num_str: str, base: int) -> int:
    """Decode base-N encoded number (supports base 2 up to 62)."""
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    val = 0
    for char in num_str:
        if char in charset:
            digit = charset.index(char)
            if digit < base:
                val = val * base + digit
            else:
                return 0
        else:
            return 0
    return val


def unpack_dean_edwards(text: str) -> tuple[str, bool]:
    """Unpack Dean Edwards packed JavaScript payload."""
    match = PACKER_RE.search(text)
    if not match:
        return text, False

    p = match.group('p')
    a = int(match.group('a'))
    c = int(match.group('c'))
    k = match.group('k').split('|')

    # Replace words according to base-n lookup
    def _lookup(word_match):
        w = word_match.group(0)
        idx = _base_n_decode(w, a)
        if idx < len(k) and k[idx]:
            return k[idx]
        return w

    # Replace encoded tokens
    unpacked_payload = re.sub(r'\b\w+\b', _lookup, p)

    # Unescape escaped characters in the payload
    unpacked_payload = unpacked_payload.replace(r"\'", "'").replace(r'\"', '"').replace(r'\\', '\\')

    # Substitute the unpacked payload back into the source
    full_text = text[:match.start()] + unpacked_payload + text[match.end():]
    return full_text, True


def decode_string_escapes(text: str) -> str:
    """Decode \\xHH and \\uHHHH escapes inside quotes to readable characters."""
    def _replace_hex(m):
        code = int(m.group(1), 16)
        # Printable ASCII range 32-126, except dangerous characters like \ and quotes
        if 32 <= code <= 126 and chr(code) not in ('\\', '"', "'", '`'):
            return chr(code)
        return m.group(0)

    def _replace_unicode(m):
        code = int(m.group(1), 16)
        if 32 <= code <= 126 and chr(code) not in ('\\', '"', "'", '`'):
            return chr(code)
        return m.group(0)

    text = HEX_ESCAPE_RE.sub(_replace_hex, text)
    text = UNICODE_ESCAPE_RE.sub(_replace_unicode, text)
    return text


def neutralize_anti_debugging(text: str) -> tuple[str, int]:
    """Neutralize debugger statements and anti-debugging intervals."""
    count = 0

    # 1. Remove interval debugger loops
    new_text, n_loops = DEBUGGER_LOOP_RE.subn('/* [removed anti-debug loop] */', text)
    count += n_loops

    # 2. Remove Function/eval debugger constructor tricks
    new_text, n_fn = FUNCTION_DEBUGGER_RE.subn('/* [removed anti-debug ctor] */', new_text)
    count += n_fn

    # 3. Remove standalone debugger statements
    new_text, n_stmts = DEBUGGER_STMT_RE.subn('/* [dbg-halt removed] */', new_text)
    count += n_stmts

    return new_text, count


def beautify_javascript(code: str, indent_size: int = 2) -> str:
    """Fast, dependency-free JavaScript beautifier and formatter."""
    indent_level = 0
    indent_str = ' ' * indent_size
    lines = []
    current_line = []
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    in_single_line_comment = False
    in_multi_line_comment = False
    escaped = False

    i = 0
    length = len(code)

    while i < length:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < length else ''

        # Handle comments
        if in_single_line_comment:
            current_line.append(ch)
            if ch == '\n':
                in_single_line_comment = False
                lines.append(indent_str * indent_level + "".join(current_line).strip())
                current_line = []
            i += 1
            continue

        if in_multi_line_comment:
            current_line.append(ch)
            if ch == '*' and nxt == '/':
                current_line.append(nxt)
                in_multi_line_comment = False
                i += 2
                continue
            i += 1
            continue

        if escaped:
            current_line.append(ch)
            escaped = False
            i += 1
            continue

        if ch == '\\':
            current_line.append(ch)
            escaped = True
            i += 1
            continue

        # Handle strings
        if ch == "'" and not in_double_quote and not in_backtick:
            in_single_quote = not in_single_quote
            current_line.append(ch)
            i += 1
            continue
        elif ch == '"' and not in_single_quote and not in_backtick:
            in_double_quote = not in_double_quote
            current_line.append(ch)
            i += 1
            continue
        elif ch == '`' and not in_single_quote and not in_double_quote:
            in_backtick = not in_backtick
            current_line.append(ch)
            i += 1
            continue

        if in_single_quote or in_double_quote or in_backtick:
            current_line.append(ch)
            i += 1
            continue

        # Check comment starts
        if ch == '/' and nxt == '/':
            in_single_line_comment = True
            current_line.append(ch)
            current_line.append(nxt)
            i += 2
            continue
        elif ch == '/' and nxt == '*':
            in_multi_line_comment = True
            current_line.append(ch)
            current_line.append(nxt)
            i += 2
            continue

        # Structural characters
        if ch == '{':
            current_line.append(' {')
            line_str = "".join(current_line).strip()
            if line_str:
                lines.append(indent_str * indent_level + line_str)
            current_line = []
            indent_level += 1
        elif ch == '}':
            line_str = "".join(current_line).strip()
            if line_str:
                lines.append(indent_str * indent_level + line_str)
            current_line = []
            indent_level = max(0, indent_level - 1)
            # check if next is semicolon or comma
            if nxt in (';', ','):
                lines.append(indent_str * indent_level + '}' + nxt)
                i += 2
                continue
            else:
                lines.append(indent_str * indent_level + '}')
        elif ch == ';':
            current_line.append(';')
            line_str = "".join(current_line).strip()
            if line_str:
                lines.append(indent_str * indent_level + line_str)
            current_line = []
        elif ch == '\n' or ch == '\r':
            line_str = "".join(current_line).strip()
            if line_str:
                lines.append(indent_str * indent_level + line_str)
            current_line = []
        else:
            current_line.append(ch)

        i += 1

    remaining = "".join(current_line).strip()
    if remaining:
        lines.append(indent_str * indent_level + remaining)

    # Filter out empty consecutive lines
    clean_lines = []
    prev_empty = False
    for line in lines:
        if not line:
            if not prev_empty:
                clean_lines.append("")
                prev_empty = True
        else:
            clean_lines.append(line)
            prev_empty = False

    return "\n".join(clean_lines)


def process_code(code: str, kill_debugger: bool = True, beautify: bool = True) -> tuple[str, dict]:
    """Execute complete deobfuscation and beautification pipeline."""
    stats = {
        'unpacked': False,
        'debugger_killed': 0,
        'original_bytes': len(code),
        'output_bytes': 0,
    }

    # Step 1: Unpack Dean Edwards if present (up to 3 recursive passes)
    current_code = code
    for _ in range(3):
        unpacked_code, was_unpacked = unpack_dean_edwards(current_code)
        if was_unpacked:
            stats['unpacked'] = True
            current_code = unpacked_code
        else:
            break

    # Step 2: Decode hex and unicode escapes
    current_code = decode_string_escapes(current_code)

    # Step 3: Remove debugger statements if requested
    if kill_debugger:
        current_code, dbg_count = neutralize_anti_debugging(current_code)
        stats['debugger_killed'] = dbg_count

    # Step 4: Beautify & format
    if beautify:
        current_code = beautify_javascript(current_code)

    stats['output_bytes'] = len(current_code)
    return current_code, stats


def main():
    parser = argparse.ArgumentParser(
        prog='js_deobfuscator',
        description='Deobfuscate, unpack, and beautify minified JavaScript files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--file', '-f', required=True, help='Path ke file JavaScript yang akan diproses')
    parser.add_argument('--out', '-o', help='Path output file hasil deobfuskasi (jika tidak diisi, cetak ke stdout)')
    parser.add_argument('--no-kill-debugger', action='store_true', help='Jangan netralkan debugger statements')
    parser.add_argument('--no-beautify', action='store_true', help='Jangan format ulang baris/indentasi')

    args = parser.parse_args()

    input_path = Path(args.file)
    if not input_path.is_file():
        sys.stderr.write(f"[ERROR] File tidak ditemukan: {args.file}\n")
        return 2

    try:
        raw_code = input_path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        sys.stderr.write(f"[ERROR] Gagal membaca file: {e}\n")
        return 1

    processed, stats = process_code(
        raw_code,
        kill_debugger=not args.no_kill_debugger,
        beautify=not args.no_beautify
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(processed, encoding='utf-8')
        print(f"\n[OK] Deobfuskasi selesai:")
        print(f"  Input:            {args.file} ({stats['original_bytes']} bytes)")
        print(f"  Output:           {args.out} ({stats['output_bytes']} bytes)")
        print(f"  Unpacked:         {'Ya' if stats['unpacked'] else 'Tidak'}")
        print(f"  Debugger dibuang: {stats['debugger_killed']} buah")
    else:
        print(processed)

    return 0


if __name__ == '__main__':
    sys.exit(main())
