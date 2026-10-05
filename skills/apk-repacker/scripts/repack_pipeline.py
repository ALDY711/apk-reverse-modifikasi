#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Automated pipeline to unpack, modify, zipalign, and sign APKs for Android installation.

WHY THIS EXISTS
---------------
Repacking an Android APK into an artifact that cleanly installs and runs requires:
  1. Preserving uncompressed storage for resources.arsc.
  2. Performing 4-byte alignment (zipalign) for memory mapping.
  3. Generating APK Signature Scheme V1, V2, and V3 signatures.
  4. Stripping previous vendor signature files from META-INF.

This script executes this complete pipeline from a single command line interface.

USAGE
-----
  # Rebuild and sign an unpacked directory
  python skills/apk-repacker/scripts/repack_pipeline.py --dir ./unpacked_dir --out ./ready.apk

  # Check alignment of an existing APK
  python skills/apk-repacker/scripts/repack_pipeline.py --check-align target.apk

EXIT CODES
----------
  0 = operation successful
  1 = repacking or alignment error
  2 = usage or argument error
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

STORED_ENTRIES = ("resources.arsc",)


def find_zipalign() -> str | None:
    za = shutil.which("zipalign") or shutil.which("zipalign.exe")
    if za:
        return za
    # SDK search
    sdk_base = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools"
    if sdk_base.is_dir():
        for d in sorted(sdk_base.iterdir(), reverse=True):
            cand = d / ("zipalign.exe" if sys.platform == "win32" else "zipalign")
            if cand.is_file():
                return str(cand)
    return None


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
        prog="repack_pipeline.py",
        description="Repack, align, and sign Android APKs",
    )
    parser.add_argument("--dir", "-d", help="Direktori hasil decompile / modifikasi")
    parser.add_argument("--out", "-o", help="File APK output siap pakai")
    parser.add_argument("--check-align", help="Periksa apakah APK sudah 4-byte aligned")
    parser.add_argument("--keystore", help="Path keystore khusus")

    args = parser.parse_args()

    zipalign = find_zipalign()
    apksigner = find_apksigner()

    if args.check_align:
        if not zipalign:
            print("[-] zipalign tidak ditemukan untuk memeriksa alignment.")
            sys.exit(2)
        res = subprocess.run([zipalign, "-c", "-v", "4", args.check_align], capture_output=True, text=True, errors="replace")
        if res.returncode == 0:
            print("[+] APK sudah 4-byte aligned dengan benar.")
            sys.exit(0)
        else:
            print("[-] APK BELUM aligned dengan benar (akan ditolak oleh Android OS).")
            sys.exit(1)

    if not args.dir or not args.out:
        parser.print_help()
        sys.exit(2)

    temp_zip = args.out + ".tmp.zip"
    print(f"[*] Mengemas {args.dir}...")
    with zipfile.ZipFile(temp_zip, "w") as z_out:
        for root, _, files in os.walk(args.dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, args.dir).replace("\\", "/")
                if rel_path.startswith("META-INF/") and any(rel_path.endswith(ext) for ext in (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                    continue
                is_stored = any(rel_path == s or rel_path.endswith("/" + s) for s in STORED_ENTRIES)
                comp = zipfile.ZIP_STORED if is_stored else zipfile.ZIP_DEFLATED
                z_out.write(abs_path, rel_path, compress_type=comp)

    temp_aligned = args.out + ".aligned.zip"
    if zipalign:
        print("[*] Melakukan zipalign 4-byte...")
        subprocess.run([zipalign, "-f", "-p", "4", temp_zip, temp_aligned], check=True)
        os.remove(temp_zip)
    else:
        temp_aligned = temp_zip

    # Signing
    if apksigner:
        print("[*] Menandatangani APK dengan apksigner (V1, V2, V3)...")
        ks = args.keystore or os.path.join(tempfile.gettempdir(), "debug.keystore")
        if not os.path.isfile(ks):
            kt = shutil.which("keytool") or shutil.which("keytool.exe") or "keytool"
            subprocess.run([
                kt, "-genkeypair", "-keystore", ks, "-storepass", "android",
                "-alias", "androiddebugkey", "-keypass", "android", "-keyalg", "RSA",
                "-keysize", "2048", "-validity", "10000", "-dname", "CN=Debug,O=Android,C=US"
            ], capture_output=True)

        cmd = [
            apksigner, "sign", "--ks", ks, "--ks-pass", "pass:android",
            "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true", "--out", args.out, temp_aligned
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if os.path.isfile(temp_aligned):
            os.remove(temp_aligned)

        if res.returncode == 0:
            print(f"[+] Berhasil mengemas dan menandatangani APK: {args.out}")
            sys.exit(0)
        else:
            print(f"[ERROR] Signing gagal:\n{res.stderr}")
            sys.exit(1)
    else:
        shutil.move(temp_aligned, args.out)
        print(f"[!] Selesai dikemas (tanpa apksigner): {args.out}")
        sys.exit(0)


if __name__ == "__main__":
    main()
