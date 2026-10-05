#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inject permissive Network Security Config and cleartext permissions into Android APK projects.

WHY THIS EXISTS
---------------
Since Android 7.0 (Nougat, API 24), Android apps by default trust only system CA certificates.
User-installed CA certificates (used by Burp Suite, Charles, mitmproxy, Fiddler) are untrusted,
causing SSL handshake failures (`javax.net.ssl.SSLHandshakeException`).
In addition, Android 9.0 (Pie, API 28) disables cleartext HTTP by default.

This script patches an unpacked APK project by:
  1. Creating `res/xml/network_security_config.xml` trusting both `system` and `user` certificates.
  2. Injecting `android:networkSecurityConfig="@xml/network_security_config"` and
     `android:usesCleartextTraffic="true"` into `AndroidManifest.xml`.

USAGE
-----
  # Patch an unpacked APK project directory
  python mitm_patch.py --dir ./unpacked_apk

  # Generate network_security_config.xml standalone file
  python mitm_patch.py --generate-xml --out network_security_config.xml

EXIT CODES
----------
  0 = completed successfully
  1 = patching error or manifest not found
  2 = usage or argument error
"""

import argparse
import os
import re
import sys

PERMISSIVE_XML = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""


def patch_project(project_dir: str) -> bool:
    manifest_file = os.path.join(project_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_file):
        print(f"[ERROR] AndroidManifest.xml tidak ditemukan di: {project_dir}")
        return False

    res_xml_dir = os.path.join(project_dir, "res", "xml")
    os.makedirs(res_xml_dir, exist_ok=True)
    target_xml = os.path.join(res_xml_dir, "network_security_config.xml")

    with open(target_xml, "w", encoding="utf-8") as f:
        f.write(PERMISSIVE_XML)
    print(f"[+] Ditulis config permisif ke: {target_xml}")

    with open(manifest_file, "r", encoding="utf-8", errors="replace") as f:
        manifest_text = f.read()

    modified = False
    if "android:networkSecurityConfig" not in manifest_text:
        match = re.search(r"<application\b", manifest_text)
        if match:
            pos = match.end()
            injection = '\n        android:networkSecurityConfig="@xml/network_security_config"\n        android:usesCleartextTraffic="true"'
            manifest_text = manifest_text[:pos] + injection + manifest_text[pos:]
            modified = True
            print("[+] Atribut networkSecurityConfig ditambahkan ke tag <application>")

    if 'android:usesCleartextTraffic="false"' in manifest_text:
        manifest_text = manifest_text.replace('android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"')
        modified = True
        print("[+] Mengubah usesCleartextTraffic menjadi true")

    if modified:
        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write(manifest_text)
        print(f"[+] AndroidManifest.xml berhasil diperbarui.")
    else:
        print("[*] AndroidManifest.xml sudah memiliki konfigurasi NSC.")

    return True


def main():
    parser = argparse.ArgumentParser(
        prog="mitm_patch.py",
        description="Inject permissive Network Security Config to enable HTTPS interception",
    )
    parser.add_argument("--dir", "-d", help="Direktori hasil decompile APK (apktool)")
    parser.add_argument("--generate-xml", action="store_true", help="Generate template XML saja")
    parser.add_argument("--out", "-o", help="File output XML")

    args = parser.parse_args()

    if args.generate_xml:
        out = args.out or "network_security_config.xml"
        with open(out, "w", encoding="utf-8") as f:
            f.write(PERMISSIVE_XML)
        print(f"[+] File XML disimpan ke: {out}")
        sys.exit(0)

    if not args.dir:
        parser.print_help()
        sys.exit(2)

    ok = patch_project(args.dir)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
