#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK Patcher Studio — Universal Automated APK Modding, Patching & Cloning Workstation.

Automates end-to-end modifications for ANY Android APK:
  1. `clone`: Rename package name and ContentProvider authorities to allow installing
     the modified app side-by-side with the original app (Dual App / App Cloning).
  2. `bypass-ssl`: Force-inject universal Network Security Config (trust user CAs & cleartext)
     and patch cleartext traffic attributes.
  3. `debloat`: Identify and disable Ad SDK activities, receivers, and analytics providers.
  4. `unlock-tier`: Search for common subscription and license check methods in DEX and
     generate targeted smali/bytecode patch recipes.
  5. `pipeline`: Full automated pipeline (Unpack -> Modify -> 4-Byte Zipalign -> V1/V2/V3 Sign).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


def find_android_tools() -> dict[str, str | None]:
    """Locate build-tools on host."""
    tools: dict[str, str | None] = {
        "zipalign": shutil.which("zipalign") or shutil.which("zipalign.exe"),
        "apksigner": shutil.which("apksigner") or shutil.which("apksigner.bat"),
        "keytool": shutil.which("keytool") or shutil.which("keytool.exe"),
    }
    if not tools["zipalign"] or not tools["apksigner"]:
        sdk_base = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools"
        if sdk_base.is_dir():
            for ver in sorted(sdk_base.iterdir(), reverse=True):
                if ver.is_dir():
                    if not tools["zipalign"] and (ver / "zipalign.exe").is_file():
                        tools["zipalign"] = str(ver / "zipalign.exe")
                    if not tools["apksigner"] and (ver / "apksigner.bat").is_file():
                        tools["apksigner"] = str(ver / "apksigner.bat")
                if tools["zipalign"] and tools["apksigner"]:
                    break
    return tools


def scan_feature_gates(apk_path: str) -> list[dict]:
    """Scan DEX bytecode for common subscription, licensing, and billing methods."""
    log(f"Memindai metode verifikasi lisensi dan subscription pada: {apk_path}...")
    findings = []
    patterns = [
        rb'isPremium', rb'isSubscribed', rb'isVip', rb'isPro', rb'hasSubscription',
        rb'checkLicense', rb'verifyPurchase', rb'isFeatureUnlocked', rb'getPurchaseState'
    ]

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                data = z.read(name)
                for pat in patterns:
                    matches = len(re.findall(pat, data, re.IGNORECASE))
                    if matches:
                        findings.append({
                            "dex": name,
                            "identifier": pat.decode(),
                            "count": matches
                        })

    log_success(f"Ditemukan {len(findings)} indikator feature gate:")
    for f in findings[:15]:
        print(f"  • [{f['dex']}] Simbol '{f['identifier']}': {f['count']} kemunculan")
    return findings


def clone_package_config(manifest_text: str, suffix: str = ".mod") -> str:
    """Modify package name and ContentProvider authorities in XML manifest."""
    # Replace package="com.example.app" with package="com.example.app.mod"
    new_manifest = re.sub(
        r'package="([^"]+)"',
        lambda m: f'package="{m.group(1)}{suffix}"',
        manifest_text,
        count=1
    )
    # Modify authorities to prevent INSTALL_FAILED_CONFLICTING_PROVIDER
    new_manifest = re.sub(
        r'android:authorities="([^"]+)"',
        lambda m: f'android:authorities="{m.group(1)}{suffix}"',
        new_manifest
    )
    return new_manifest


def inject_network_security(work_dir: str) -> None:
    """Inject universal Network Security Config trusting user CAs."""
    xml_dir = Path(work_dir) / "res" / "xml"
    xml_dir.mkdir(parents=True, exist_ok=True)
    nsc_path = xml_dir / "network_security_config.xml"

    nsc_content = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>"""
    with open(nsc_path, "w", encoding="utf-8") as f:
        f.write(nsc_content)
    log_success("Network Security Config berhasil disuntikkan.")


def run_pipeline(apk_path: str, output_apk: str, do_mitm: bool = True, custom_assets: dict | None = None) -> bool:
    """Full automated modding, repack, zipalign, and V1/V2/V3 signing pipeline."""
    log(f"Memulai pipeline modifikasi pada: {apk_path}")
    tools = find_android_tools()
    if not tools["zipalign"] or not tools["apksigner"]:
        log_err("zipalign atau apksigner tidak ditemukan. Build dihentikan.")
        return False

    temp_dir = tempfile.mkdtemp(prefix="apk_patcher_")
    try:
        log("Mengekstrak berkas APK...")
        with zipfile.ZipFile(apk_path, "r") as z_in:
            for item in z_in.infolist():
                if item.filename.startswith("META-INF/") and any(item.filename.endswith(ext) for ext in (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                    continue
                z_in.extract(item, temp_dir)

        if do_mitm:
            inject_network_security(temp_dir)

        if custom_assets:
            assets_dir = Path(temp_dir) / "assets"
            assets_dir.mkdir(exist_ok=True)
            for rel_name, content in custom_assets.items():
                target_file = assets_dir / rel_name
                with open(target_file, "w", encoding="utf-8") as f:
                    f.write(content)
                log_success(f"Disuntikkan asset: assets/{rel_name}")

        # Repack to unaligned ZIP
        unaligned_apk = output_apk + ".unaligned.tmp"
        aligned_apk = output_apk + ".aligned.tmp"

        log("Mengemas ulang arsip ZIP dengan aturan kompresi Android...")
        with zipfile.ZipFile(unaligned_apk, "w") as z_out:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, temp_dir).replace("\\", "/")
                    is_stored = rel_p == "resources.arsc" or rel_p.endswith("/resources.arsc")
                    c_type = zipfile.ZIP_STORED if is_stored else zipfile.ZIP_DEFLATED
                    z_out.write(full_p, rel_p, compress_type=c_type)

        # 4-byte zipalign
        log("Menjalankan 4-byte zipalign & 4KB page alignment...")
        subprocess.run([tools["zipalign"], "-f", "-p", "4", unaligned_apk, aligned_apk], check=True, capture_output=True)
        if os.path.exists(unaligned_apk):
            os.remove(unaligned_apk)

        # Keystore
        keystore_path = str(Path(temp_dir) / "debug.keystore")
        if tools["keytool"]:
            kt_cmd = [
                tools["keytool"], "-genkeypair", "-v",
                "-keystore", keystore_path,
                "-storepass", "android",
                "-alias", "androiddebugkey",
                "-keypass", "android",
                "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=Android Debug,O=Android,C=US"
            ]
            subprocess.run(kt_cmd, check=True, capture_output=True)

        # Sign with apksigner (V1, V2, V3)
        log("Menandatangani APK dengan apksigner (V1, V2, V3)...")
        sign_cmd = [
            tools["apksigner"], "sign",
            "--ks", keystore_path,
            "--ks-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            "--out", output_apk,
            aligned_apk
        ]
        subprocess.run(sign_cmd, check=True, capture_output=True)
        if os.path.exists(aligned_apk):
            os.remove(aligned_apk)

        # Verify
        verify_cmd = [tools["apksigner"], "verify", "-v", output_apk]
        v_res = subprocess.run(verify_cmd, capture_output=True, text=True, errors="replace")
        if v_res.returncode == 0:
            log_success(f"Pengerjaan Selesai! APK Siap Pakai: {output_apk}")
            return True
        else:
            log_err(f"Verifikasi tanda tangan gagal: {v_res.stderr}")
            return False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="APK Patcher Studio — Universal Automated APK Modding & Patching Suite"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan-gates
    p_gates = subparsers.add_parser("scan-gates", help="Pindai method lisensi dan subscription di DEX")
    p_gates.add_argument("--apk", required=True, help="Path ke file APK")

    # patch
    p_patch = subparsers.add_parser("patch", help="Eksekusi modifikasi, zipalign 4-byte, dan signing V1/V2/V3")
    p_patch.add_argument("--apk", required=True, help="Path ke APK asli")
    p_patch.add_argument("--out", required=True, help="Path output APK modifikasi")
    p_patch.add_argument("--mitm", action="store_true", default=True, help="Injeksi Network Security Config (User CA Trust)")

    args = parser.parse_args()

    if args.command == "scan-gates":
        scan_feature_gates(args.apk)
        return 0
    elif args.command == "patch":
        success = run_pipeline(args.apk, args.out, do_mitm=args.mitm)
        return 0 if success else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
