#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze and neuter ad SDK declarations and telemetry components in AndroidManifest.xml.

WHY THIS EXISTS
---------------
Commercial applications frequently embed advertising networks (AdMob, Unity, AppLovin, ironSource)
and aggressive tracking services (Adjust, AppsFlyer, Facebook Analytics).

Simply stripping the bytecode often results in crashes (`ClassNotFoundException` or unresolved
binder transactions) when the application attempts to initialize the SDKs.
The safest and most reliable way to disable these networks without modifying DEX logic is
**Manifest Neutering**: setting `android:enabled="false"` and `android:exported="false"` on all
declared activities, services, broadcast receivers, and content providers belonging to the ad SDK.

USAGE
-----
  # Scan manifest for ad and tracking components
  python debloat_manifest.py --manifest AndroidManifest.xml --scan

  # Neuter discovered ad components in-place
  python debloat_manifest.py --manifest AndroidManifest.xml --neuter --out AndroidManifest_clean.xml

EXIT CODES
----------
  0 = completed successfully
  1 = ad components discovered (scan mode) or error during patching
  2 = usage or argument error
"""

import argparse
import os
import re
import sys

TRACKER_PATTERNS = [
    "com.google.android.gms.ads",
    "com.unity3d.ads",
    "com.unity3d.services",
    "com.applovin",
    "com.ironsource",
    "com.facebook.ads",
    "com.vungle",
    "com.mbridge.msdk",
    "com.bytedance.sdk.openadsdk",
    "com.adjust.sdk",
    "com.appsflyer",
    "com.kochava",
    "io.branch.referral",
]


def scan_manifest(text: str) -> list[dict]:
    findings = []
    pattern = re.compile(r'<(activity|service|receiver|provider)\b([^>]*?)android:name=["\']([^"\']+)["\']([^>]*?)>', re.DOTALL)
    for m in pattern.finditer(text):
        tag = m.group(1)
        name = m.group(3)
        for tp in TRACKER_PATTERNS:
            if tp in name:
                findings.append({
                    "tag": tag,
                    "name": name,
                    "matched_pattern": tp,
                })
                break
    return findings


def neuter_manifest(text: str) -> tuple[str, int]:
    count = 0

    def replace_fn(match):
        nonlocal count
        name = match.group(3)
        full = match.group(0)
        is_tracker = any(tp in name for tp in TRACKER_PATTERNS)
        if is_tracker:
            count += 1
            cleaned = full.replace('android:enabled="true"', '')
            if 'android:enabled="false"' not in cleaned:
                if cleaned.endswith("/>"):
                    return cleaned[:-2] + ' android:enabled="false" android:exported="false" />'
                elif cleaned.endswith(">"):
                    return cleaned[:-1] + ' android:enabled="false" android:exported="false">'
            return cleaned
        return full

    pattern = re.compile(r'<(activity|service|receiver|provider)\b([^>]*?)android:name=["\']([^"\']+)["\']([^>]*?)>', re.DOTALL)
    new_text = pattern.sub(replace_fn, text)
    return new_text, count


def main():
    parser = argparse.ArgumentParser(
        prog="debloat_manifest.py",
        description="Scan and neuter ad SDKs and analytics in AndroidManifest.xml",
    )
    parser.add_argument("--manifest", "-m", required=True, help="Path ke file AndroidManifest.xml")
    parser.add_argument("--scan", action="store_true", help="Pindai komponen iklan")
    parser.add_argument("--neuter", action="store_true", help="Nonaktifkan komponen iklan")
    parser.add_argument("--out", "-o", help="File output manifest")

    args = parser.parse_args()

    if not os.path.isfile(args.manifest):
        print(f"[ERROR] File manifest tidak ditemukan: {args.manifest}")
        sys.exit(2)

    with open(args.manifest, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    findings = scan_manifest(content)

    if args.neuter:
        neutered_content, modified = neuter_manifest(content)
        out_path = args.out or args.manifest
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(neutered_content)
        print(f"[+] Berhasil menonaktifkan {modified} komponen di {out_path}")
        sys.exit(0)

    print(f"\n[*] Hasil pemindaian manifest: Ditemukan {len(findings)} komponen ad/tracker.")
    for f in findings:
        print(f"  [{f['tag'].upper()}] {f['name']} (pattern: {f['matched_pattern']})")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
