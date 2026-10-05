#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect, debloat, and neuter ad SDKs, analytics, and tracking components from Android APKs.

WHY THIS EXISTS
---------------
Commercial APKs frequently ship heavy advertising networks (AdMob, Unity Ads, AppLovin, IronSource)
and intrusive tracking SDKs (Adjust, AppsFlyer, Facebook Audience Network, Firebase Analytics).
These components consume system resources, display modal/banner paywalls, and leak user telemetry.

Simply deleting classes often causes `ClassNotFoundException` or `NoClassDefFoundError` when the app
initializes them at startup. The surgical approach to debloating requires:
  1. Component Neutering: Disabling ad and tracking components in `AndroidManifest.xml`
     by setting `android:enabled="false"` so the Android OS refuses to instantiate them.
  2. No-op Stubbing: Neutralizing ad verification and rewarded callback handlers without
     crashing the calling UI loop.

This script scans for known advertising and telemetry SDK signatures, disables their manifest
declarations, and can generate drop-in no-op smali replacement templates.

USAGE
-----
  # Scan an APK or decompile directory for ad/tracker SDKs
  python apk_debloater.py --target ./unpacked_apk --scan

  # Neuter all discovered ad components in AndroidManifest.xml
  python apk_debloater.py --target ./unpacked_apk --neuter --out ./unpacked_apk/AndroidManifest.xml

  # Generate smali no-op stubs for common ad callbacks
  python apk_debloater.py --generate-stubs --out ./ad_stubs

  # Output scan results in JSON format
  python apk_debloater.py --target ./unpacked_apk --scan --json

EXIT CODES
----------
  0 = completed successfully (or no ads found)
  1 = ad/tracker components detected (in scan mode) or modification error
  2 = usage or argument error
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Optional
import xml.etree.ElementTree as ET
import zipfile

# Pastikan output konsol Windows mendukung UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

KNOWN_TRACKERS = {
    "Google AdMob": [
        "com.google.android.gms.ads",
        "com.google.ads",
    ],
    "Unity Ads": [
        "com.unity3d.ads",
        "com.unity3d.services.ads",
    ],
    "AppLovin / MAX": [
        "com.applovin",
    ],
    "ironSource": [
        "com.ironsource",
        "com.supersonicads",
    ],
    "Facebook Audience Network": [
        "com.facebook.ads",
    ],
    "Vungle / Liftoff": [
        "com.vungle",
    ],
    "Mintegral": [
        "com.mbridge.msdk",
        "com.mintegral",
    ],
    "Pangle / ByteDance": [
        "com.bytedance.sdk.openadsdk",
    ],
    "Adjust Tracker": [
        "com.adjust.sdk",
    ],
    "AppsFlyer Tracker": [
        "com.appsflyer",
    ],
    "Kochava Tracker": [
        "com.kochava",
    ],
    "Branch.io": [
        "io.branch.referral",
    ],
}

STUB_SMALI_REWARDED = """.class public Lcom/google/android/gms/ads/rewarded/RewardedAd;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public isLoaded()Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method

.method public show(Landroid/app/Activity;Lcom/google/android/gms/ads/rewarded/RewardedAdCallback;)V
    .registers 3
    if-eqz p2, :cond_0
    new-instance v0, Lcom/google/android/gms/ads/rewarded/RewardItemStub;
    invoke-direct {v0}, Lcom/google/android/gms/ads/rewarded/RewardItemStub;-><init>()V
    invoke-virtual {p2, v0}, Lcom/google/android/gms/ads/rewarded/RewardedAdCallback;->onUserEarnedReward(Lcom/google/android/gms/ads/rewarded/RewardItem;)V
    :cond_0
    return-void
.end method
"""


def scan_manifest_text(manifest_text: str) -> dict[str, Any]:
    """Analyze AndroidManifest.xml string for tracker components."""
    detected_networks: dict[str, list[str]] = {}
    flagged_components: list[dict[str, Any]] = []

    # Cari komponen di manifest
    component_pattern = re.compile(
        r'<(activity|service|receiver|provider)\b([^>]*?)android:name=["\']([^"\']+)["\']([^>]*?)>',
        re.DOTALL | re.IGNORECASE
    )

    for match in component_pattern.finditer(manifest_text):
        tag_type = match.group(1).lower()
        comp_name = match.group(3)
        full_tag = match.group(0)

        for network, patterns in KNOWN_TRACKERS.items():
            if any(p in comp_name for p in patterns):
                if network not in detected_networks:
                    detected_networks[network] = []
                detected_networks[network].append(comp_name)
                flagged_components.append({
                    "type": tag_type,
                    "name": comp_name,
                    "network": network,
                    "is_enabled": 'android:enabled="false"' not in full_tag,
                })
                break

    return {
        "detected_networks": detected_networks,
        "flagged_components": flagged_components,
        "total_flagged": len(flagged_components),
    }


def neuter_manifest_components(manifest_text: str) -> tuple[str, int]:
    """Disable matched ad components by injecting android:enabled="false"."""
    count = 0

    def replace_comp(match):
        nonlocal count
        tag_type = match.group(1)
        pre_attr = match.group(2)
        comp_name = match.group(3)
        post_attr = match.group(4)
        full_tag = match.group(0)

        is_ad = False
        for network, patterns in KNOWN_TRACKERS.items():
            if any(p in comp_name for p in patterns):
                is_ad = True
                break

        if is_ad:
            count += 1
            # Bersihkan jika sudah ada enabled=true
            cleaned = full_tag.replace('android:enabled="true"', '')
            if 'android:enabled="false"' not in cleaned:
                # Sisipkan sebelum penutup '>'
                if cleaned.endswith("/>"):
                    return cleaned[:-2] + ' android:enabled="false" />'
                elif cleaned.endswith(">"):
                    return cleaned[:-1] + ' android:enabled="false">'
            return cleaned
        return full_tag

    pattern = re.compile(
        r'<(activity|service|receiver|provider)\b([^>]*?)android:name=["\']([^"\']+)["\']([^>]*?)>',
        re.DOTALL | re.IGNORECASE
    )
    new_text = pattern.sub(replace_comp, manifest_text)
    return new_text, count


def main():
    parser = argparse.ArgumentParser(
        prog="apk_debloater.py",
        description="Scan, debloat, and neuter Ad SDKs and telemetry in Android APKs",
    )
    parser.add_argument("--target", help="Path direktori hasil decompile atau file AndroidManifest.xml")
    parser.add_argument("--scan", action="store_true", help="Pindai keberadaan ad/telemetry SDK")
    parser.add_argument("--neuter", action="store_true", help="Nonaktifkan komponen iklan di AndroidManifest.xml")
    parser.add_argument("--out", help="File output untuk manifest yang sudah di-neuter")
    parser.add_argument("--generate-stubs", action="store_true", help="Generate template smali no-op ad stubs")
    parser.add_argument("--json", action="store_true", help="Output dalam format JSON")

    args = parser.parse_args()

    if args.generate_stubs:
        out_dir = args.out or "./ad_stubs"
        os.makedirs(out_dir, exist_ok=True)
        stub_file = os.path.join(out_dir, "RewardedAd.smali")
        with open(stub_file, "w", encoding="utf-8") as f:
            f.write(STUB_SMALI_REWARDED)
        print(f"[+] Template smali no-op stub dibuat di: {stub_file}")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(2)

    manifest_file = args.target
    if os.path.isdir(args.target):
        manifest_file = os.path.join(args.target, "AndroidManifest.xml")

    if not os.path.isfile(manifest_file):
        print(f"[!] AndroidManifest.xml tidak ditemukan di: {manifest_file}")
        sys.exit(2)

    with open(manifest_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    results = scan_manifest_text(content)

    if args.neuter:
        neutered_text, modified_count = neuter_manifest_components(content)
        out_path = args.out or manifest_file
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(neutered_text)
        print(f"[+] Berhasil menonaktifkan {modified_count} komponen iklan/telemetry di: {out_path}")
        sys.exit(0)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*60}")
        print("  [*] HASIL PEMINDAIAN AD & TELEMETRY SDK")
        print(f"{'='*60}")
        print(f"  Total komponen iklan terdeteksi: {results['total_flagged']}")
        for net, comps in results["detected_networks"].items():
            print(f"\n  • [{net}] ({len(comps)} komponen):")
            for c in comps[:5]:
                print(f"    - {c}")
            if len(comps) > 5:
                print(f"    - ... dan {len(comps) - 5} komponen lainnya")
        print(f"\n{'='*60}\n")

    sys.exit(1 if results["total_flagged"] > 0 else 0)


if __name__ == "__main__":
    main()
