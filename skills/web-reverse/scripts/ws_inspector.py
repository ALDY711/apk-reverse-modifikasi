#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebSocket Frame Inspector & Binary Protocol Decoder (Protobuf, Socket.IO, JSON-RPC).

WHY THIS EXISTS
---------------
Modern web applications, real-time trading dashboards, chat services, and game interfaces
rely heavily on WebSockets instead of REST/HTTP APIs.

Analyzing WebSocket traffic captured from Chrome DevTools (or exported HAR logs) presents
unique challenges:
  1. Engine.IO / Socket.IO prepend numeric packet type prefixes (e.g. `42["chat", {...}]`).
  2. Protocol Buffers (Protobuf) serialize messages into raw binary frames without schemas.
  3. JSON-RPC 2.0 frames wrap RPC calls with IDs and method names.

This tool decodes text and binary WebSocket frames without requiring `.proto` definition files,
decodes Socket.IO and JSON-RPC packets, and can scaffold Python `websockets` client replay scripts.

USAGE
-----
  # Decode a single Socket.IO frame text
  python ws_inspector.py --text '42["update_ticker",{"pair":"BTC/USDT","price":94500}]'

  # Decode raw Protobuf hex string
  python ws_inspector.py --hex "089601120774657374696e67"

  # Decode base64 payload from HAR log or DevTools
  python ws_inspector.py --b64 "CJYBEngtdGVzdGluZw=="

  # Inspect a file containing captured WebSocket message frames
  python ws_inspector.py --file ws_capture.log

  # Generate a Python websockets replay client template
  python ws_inspector.py --scaffold-client --url "wss://api.example.com/ws/v1" --out client_replay.py

EXIT CODES
----------
  0 = payload decoded successfully
  1 = unrecognized format or decode error
  2 = argument error
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path


# =========================================================================
# Protobuf Schema-Less Decoder (Wire-format parser)
# =========================================================================
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_START_GROUP = 3
WIRE_END_GROUP = 4
WIRE_32BIT = 5

WIRE_TYPE_NAMES = {
    WIRE_VARINT: "varint",
    WIRE_64BIT: "64-bit",
    WIRE_LENGTH_DELIMITED: "length-delimited",
    WIRE_32BIT: "32-bit",
}


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decodes a protobuf varint starting at offset. Returns (value, new_offset)."""
    val = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 64:
            raise ValueError("Varint too long")
    return val, offset


def decode_protobuf_raw(data: bytes, depth: int = 0) -> list[dict]:
    """Recursively parse raw protobuf wire bytes into structured representation."""
    fields = []
    offset = 0
    length = len(data)

    while offset < length:
        try:
            tag_and_wire, offset = decode_varint(data, offset)
        except Exception:
            break

        wire_type = tag_and_wire & 0x07
        field_num = tag_and_wire >> 3

        if field_num == 0:
            break

        if wire_type == WIRE_VARINT:
            try:
                val, offset = decode_varint(data, offset)
                fields.append({
                    "field": field_num,
                    "wire": WIRE_TYPE_NAMES.get(wire_type, str(wire_type)),
                    "value": val
                })
            except Exception:
                break

        elif wire_type == WIRE_64BIT:
            if offset + 8 > length:
                break
            val_bytes = data[offset:offset+8]
            offset += 8
            fields.append({
                "field": field_num,
                "wire": WIRE_TYPE_NAMES.get(wire_type, str(wire_type)),
                "value_hex": val_bytes.hex(),
                "int64": int.from_bytes(val_bytes, 'little')
            })

        elif wire_type == WIRE_LENGTH_DELIMITED:
            try:
                sub_len, offset = decode_varint(data, offset)
            except Exception:
                break
            if offset + sub_len > length:
                break
            sub_data = data[offset:offset+sub_len]
            offset += sub_len

            # Check if sub_data is printable UTF-8 string
            try:
                text_val = sub_data.decode('utf-8')
                if text_val.isprintable() and len(text_val) > 0:
                    fields.append({
                        "field": field_num,
                        "wire": "string",
                        "value": text_val
                    })
                    continue
            except UnicodeDecodeError:
                pass

            # Try to recursively parse as embedded sub-message
            sub_fields = decode_protobuf_raw(sub_data, depth + 1)
            if sub_fields and len(sub_fields) > 0:
                fields.append({
                    "field": field_num,
                    "wire": "embedded_message",
                    "sub_fields": sub_fields
                })
            else:
                fields.append({
                    "field": field_num,
                    "wire": "bytes",
                    "length": len(sub_data),
                    "hex": sub_data.hex(),
                    "base64": base64.b64encode(sub_data).decode('ascii')
                })

        elif wire_type == WIRE_32BIT:
            if offset + 4 > length:
                break
            val_bytes = data[offset:offset+4]
            offset += 4
            fields.append({
                "field": field_num,
                "wire": WIRE_TYPE_NAMES.get(wire_type, str(wire_type)),
                "value_hex": val_bytes.hex(),
                "int32": int.from_bytes(val_bytes, 'little')
            })
        else:
            # Unknown wire type, cannot proceed safely
            break

    return fields


# =========================================================================
# Socket.IO & Engine.IO Decoder
# =========================================================================
ENGINE_IO_TYPES = {
    "0": "OPEN (Handshake)",
    "1": "CLOSE",
    "2": "PING",
    "3": "PONG",
    "4": "MESSAGE",
    "5": "UPGRADE",
    "6": "NOOP"
}

SOCKET_IO_TYPES = {
    "0": "CONNECT",
    "1": "DISCONNECT",
    "2": "EVENT",
    "3": "ACK",
    "4": "ERROR",
    "5": "BINARY_EVENT",
    "6": "BINARY_ACK"
}


def parse_engine_socket_io(text: str) -> dict | None:
    """Parse Socket.IO packet string (e.g. 42["event", {...}])."""
    text = text.strip()
    if not text or not text[0].isdigit():
        return None

    engine_type_char = text[0]
    engine_name = ENGINE_IO_TYPES.get(engine_type_char)
    if not engine_name:
        return None

    res = {
        "engine_io_type": engine_name,
        "raw": text
    }

    remaining = text[1:]
    if engine_type_char == "4" and remaining:
        # Socket.IO packet
        sio_type_char = remaining[0]
        sio_name = SOCKET_IO_TYPES.get(sio_type_char, f"UNKNOWN({sio_type_char})")
        res["socket_io_type"] = sio_name
        payload_str = remaining[1:]
        
        # Check namespace if present (e.g. /admin,)
        if payload_str.startswith('/'):
            ns_match = re.match(r'^(/[^,]+),(.*)$', payload_str)
            if ns_match:
                res["namespace"] = ns_match.group(1)
                payload_str = ns_match.group(2)

        try:
            parsed_json = json.loads(payload_str)
            res["payload"] = parsed_json
            if isinstance(parsed_json, list) and len(parsed_json) > 0:
                res["event_name"] = parsed_json[0]
                res["event_data"] = parsed_json[1:] if len(parsed_json) > 1 else []
        except Exception:
            res["payload_raw"] = payload_str
    elif remaining:
        try:
            res["payload"] = json.loads(remaining)
        except Exception:
            res["payload_raw"] = remaining

    return res


# =========================================================================
# Replay Script Scaffold Generator
# =========================================================================
def generate_client_scaffold(ws_url: str) -> str:
    return f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"WebSocket Replay & Interactive Client Template.
Target: {ws_url}
\"\"\"

import asyncio
import json
import ssl
import websockets


WS_URL = "{ws_url}"
HEADERS = {{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Origin": "{ws_url.split('/')[0]}//{ws_url.split('/')[2]}",
}}


async def run_client():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print(f"[*] Connecting to {{WS_URL}}...")
    async with websockets.connect(WS_URL, extra_headers=HEADERS, ssl=ssl_context) as ws:
        print("[+] Connected! Listening for incoming messages...")

        # Example: send handshake or subscription message
        # await ws.send(json.dumps({{"action": "subscribe", "topic": "updates"}}))

        async for message in ws:
            if isinstance(message, str):
                print(f"[RECV TEXT] {{message}}")
            else:
                print(f"[RECV BINARY] ({{len(message)}} bytes) Hex: {{message.hex()[:60]}}...")


if __name__ == "__main__":
    try:
        asyncio.run(run_client())
    except KeyboardInterrupt:
        print("\\n[*] Disconnected by user.")
"""


def main():
    parser = argparse.ArgumentParser(
        description="WebSocket Frame Inspector & Protobuf/Socket.IO Decoder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--text", "-t", help="Raw text frame string to decode")
    group.add_argument("--hex", "-x", help="Hex string of binary frame to decode")
    group.add_argument("--b64", "-b", help="Base64 encoded binary frame")
    group.add_argument("--file", "-f", help="File containing WebSocket dump frames (one per line)")
    group.add_argument("--scaffold-client", action="store_true", help="Generate Python websockets client script")

    parser.add_argument("--url", "-u", default="wss://example.com/ws", help="WebSocket URL for client scaffold")
    parser.add_argument("--out", "-o", help="Output file for client scaffold")

    args = parser.parse_args()

    if args.scaffold_client:
        code = generate_client_scaffold(args.url)
        if args.out:
            Path(args.out).write_text(code, encoding='utf-8')
            print(f"[+] Saved WebSocket client replay script -> {args.out}")
        else:
            print(code)
        sys.exit(0)

    # Process text
    if args.text:
        sio = parse_engine_socket_io(args.text)
        if sio:
            print("[+] Detected Engine.IO / Socket.IO Packet:")
            print(json.dumps(sio, indent=2, ensure_ascii=False))
            sys.exit(0)

        try:
            parsed = json.loads(args.text)
            print("[+] Detected Valid JSON / JSON-RPC Frame:")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
            sys.exit(0)
        except Exception:
            print(f"[*] Raw text string: {args.text}")
            sys.exit(0)

    # Process binary
    binary_data = None
    if args.hex:
        try:
            binary_data = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', args.hex))
        except ValueError as e:
            print(f"[!] Invalid hex input: {e}", file=sys.stderr)
            sys.exit(2)
    elif args.b64:
        try:
            binary_data = base64.b64decode(args.b64)
        except Exception as e:
            print(f"[!] Invalid base64 input: {e}", file=sys.stderr)
            sys.exit(2)

    if binary_data is not None:
        print(f"[*] Inspecting Binary Frame ({len(binary_data)} bytes)...")
        pb_fields = decode_protobuf_raw(binary_data)
        if pb_fields:
            print("[+] Successfully Decoded Raw Protobuf Wire Fields:")
            print(json.dumps(pb_fields, indent=2, ensure_ascii=False))
        else:
            print("[!] Could not parse as Protobuf. Raw Hex:")
            print(binary_data.hex())
        sys.exit(0)

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        lines = file_path.read_text(encoding='utf-8', errors='replace').splitlines()
        print(f"[*] Processing {len(lines)} frames from {args.file}...")
        for idx, line in enumerate(lines[:30], 1):
            line = line.strip()
            if not line:
                continue
            sio = parse_engine_socket_io(line)
            if sio:
                ev = sio.get("event_name", sio.get("socket_io_type", sio["engine_io_type"]))
                print(f"  [{idx:03d}] Socket.IO: {ev}")
            else:
                print(f"  [{idx:03d}] Frame: {line[:80]}")
        sys.exit(0)

    parser.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
