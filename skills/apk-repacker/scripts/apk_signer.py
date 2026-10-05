#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stand-alone Android APK signer and signature scheme verifier.

WHY THIS EXISTS
---------------
Android 11+ (API 30+) strictly requires Signature Scheme V2 or V3. An APK signed using legacy
`jarsigner` (V1 only) cannot be installed on modern devices.
This script wraps apksigner to sign with V1+V2+V3 and verify all active signature blocks.

USAGE
-----
  # Sign an aligned APK with debug credentials
  python skills/apk-repacker/scripts/apk_signer.py --apk unaligned.apk --out signed.apk

  # Verify signature schemes present in an APK
  python skills/apk-repacker/scripts/apk_signer.py --verify signed.apk

EXIT CODES
----------
  0 = signature valid
  1 = signature verification failure
  2 = usage or argument error
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def find_apksigner() -> str | None:
    aks = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if aks:
        return aks
    sdk_base = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools"
    if sdk_base.is_dir():
        for d in sorted(sdk_base.iterdir(), reverse=True):
            cand = d / ("apksigner.bat" if sys.platform == "win32" else "apksigner")
            if cand.is_file():
                return str(cand)
    return None


def main():
    parser = argparse.ArgumentParser(
        prog="apk_signer.py",
        description="Sign and verify Android APK signatures (V1, V2, V3)",
    )
    parser.add_argument("--apk", help="File APK yang akan ditandatangani")
    parser.add_argument("--out", "-o", help="File APK output hasil penandatanganan")
    parser.add_argument("--verify", help="Verifikasi signature pada APK")
    parser.add_argument("--keystore", help="Path keystore khusus")

    args = parser.parse_args()
    apksigner = find_apksigner()

    if not apksigner:
        print("[ERROR] apksigner tidak ditemukan di PATH atau Android SDK build-tools.")
        sys.exit(2)

    if args.verify:
        print(f"[*] Memverifikasi signature untuk: {args.verify}")
        res = subprocess.run([apksigner, "verify", "-v", args.verify], capture_output=True, text=True, errors="replace")
        print(res.stdout)
        if res.returncode == 0:
            print("[+] Verifikasi Berhasil: APK valid untuk instalasi Android.")
            sys.exit(0)
        else:
            print(f"[!] Verifikasi Gagal:\n{res.stderr}")
            sys.exit(1)

    if not args.apk or not args.out:
        parser.print_help()
        sys.exit(2)

    ks = args.keystore or os.path.join(tempfile.gettempdir(), "debug.keystore")
    if not os.path.isfile(ks):
        kt = shutil.which("keytool") or shutil.which("keytool.exe") or "keytool"
        subprocess.run([
            kt, "-genkeypair", "-keystore", ks, "-storepass", "android",
            "-alias", "androiddebugkey", "-keypass", "android", "-keyalg", "RSA",
            "-keysize", "2048", "-validity", "10000", "-dname", "CN=Debug,O=Android,C=US"
        ], capture_output=True)

    cmd = [
        apksigner, "sign",
        "--ks", ks,
        "--ks-pass", "pass:android",
        "--ks-key-alias", "androiddebugkey",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", args.out,
        args.apk
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if res.returncode == 0:
        print(f"[+] APK berhasil ditandatangani: {args.out}")
        sys.exit(0)
    else:
        print(f"[ERROR] Gagal menandatangani APK:\n{res.stderr}")
        sys.exit(1)


if __name__ == "__main__":
    main()
