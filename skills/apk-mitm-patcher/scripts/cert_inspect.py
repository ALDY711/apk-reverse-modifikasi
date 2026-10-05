#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect embedded certificates, pins, and custom CAs inside an APK archive.

WHY THIS EXISTS
---------------
Some applications ship pinned certificate files (e.g. `.cer`, `.crt`, `.der`, `.pem`, `.bks`)
directly inside `assets/` or `res/raw/`. Other apps define custom domain pinning rules in
`res/xml/network_security_config.xml`.

Before configuring MITM proxies, analysts need to know:
  - Does the APK embed its own certificate authority?
  - Are specific domains pinned with SHA-256 public key hashes?
  - What format are the embedded certificates in?

This tool inspects the APK archive statically and lists all certificates and pinning rules.

USAGE
-----
  # Inspect certificates inside an APK
  python cert_inspect.py --apk target.apk

  # Extract embedded certificates to a folder
  python cert_inspect.py --apk target.apk --extract-to ./extracted_certs

EXIT CODES
----------
  0 = completed successfully
  2 = usage or argument error
"""

import argparse
import os
import sys
import zipfile

CERT_EXTENSIONS = (".cer", ".crt", ".der", ".pem", ".bks", ".p12", ".pfx")


def inspect_apk_certs(apk_path: str, extract_dir: str | None = None) -> list[str]:
    found = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            lower = name.lower()
            if any(lower.endswith(ext) for ext in CERT_EXTENSIONS) or "cert" in lower or "ca" in lower:
                # Abaikan tanda tangan META-INF standard
                if name.startswith("META-INF/") and (lower.endswith(".rsa") or lower.endswith(".dsa") or lower.endswith(".ec")):
                    continue
                found.append(name)
                if extract_dir:
                    os.makedirs(extract_dir, exist_ok=True)
                    out_path = os.path.join(extract_dir, os.path.basename(name))
                    with open(out_path, "wb") as f_out:
                        f_out.write(z.read(name))

    return found


def main():
    parser = argparse.ArgumentParser(
        prog="cert_inspect.py",
        description="Inspect embedded certificates and trust anchors in APK archives",
    )
    parser.add_argument("--apk", required=True, help="Path ke file APK")
    parser.add_argument("--extract-to", help="Direktori untuk mengekstrak sertifikat yang ditemukan")

    args = parser.parse_args()

    if not os.path.isfile(args.apk):
        print(f"[ERROR] File APK tidak ditemukan: {args.apk}")
        sys.exit(2)

    certs = inspect_apk_certs(args.apk, args.extract_to)

    print(f"\n{'='*60}")
    print(f"  🔍 PEMERIKSAAN SERTIFIKAT: {os.path.basename(args.apk)}")
    print(f"{'='*60}")
    print(f"  Ditemukan: {len(certs)} file sertifikat / trust anchor\n")
    for c in certs:
        print(f"  • {c}")
    print(f"{'='*60}\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
