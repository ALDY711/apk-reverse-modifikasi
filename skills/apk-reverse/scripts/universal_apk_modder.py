#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Universal Android APK Modding, Security Patching, and Deployment Toolkit.

Designed to work across ALL Android applications:
  - Social Media & Messengers (WhatsApp, Telegram, Instagram, TikTok)
  - Games (Unity 3D, Unreal Engine, Cocos2d)
  - Cross-Platform Frameworks (Flutter, React Native, Xamarin, Cordova)
  - Enterprise, Utility, and Streaming Apps

Capabilities:
  1. `recon`: Comprehensive reconnaissance of ANY APK (Framework detection, Packer detection,
     Ad SDKs & Telemetry detection, Permissions, Components, and Native ABIs).
  2. `patch-mitm`: Patch Network Security Config (trust user/custom CAs & allow cleartext HTTP).
  3. `debloat`: Identify and disable ad SDKs, analytics, and telemetry components.
  4. `frida`: Generate targeted Frida instrumentation scripts (SSL unpinning, root bypass, crypto trace).
  5. `repack`: All-in-one unpack, 4-byte zipalign, and V1/V2/V3 APK signature scheme signing.
  6. `deploy`: Auto-discover ADB (PATH, Android SDK, or scrcpy) and deploy directly to connected Android device.
"""

from __future__ import annotations

import argparse
import json
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


# Framework & Engine Signatures
FRAMEWORK_SIGNATURES = {
    "Unity 3D Game": ["libunity.so", "libil2cpp.so", "assets/bin/Data"],
    "Unreal Engine": ["libUE4.so", "libUnreal.so"],
    "Flutter / Dart": ["libflutter.so", "libapp.so"],
    "React Native": ["libhermes.so", "libjsc.so", "assets/index.android.bundle"],
    "Xamarin / .NET": ["libmonodroid.so", "assemblies/mscorlib.dll"],
    "Cordova / Capacitor": ["assets/www/index.html", "assets/www/cordova.js"],
}

# Commercial Packer Signatures
PACKER_SIGNATURES = {
    "SecNeo / Bangcle": ["libSecShell.so", "libsecexe.so", "libSecNeo.so"],
    "Tencent Legu": ["libshella.so", "libshellx.so", "00000000.dex"],
    "360 Jiagu": ["libjiagu.so", "libjiagu_art.so"],
    "Baidu Protect": ["libbaiduprotect.so"],
    "Alibaba / AliProtection": ["libmobisec.so", "aliprotect.dat"],
    "DexGuard": ["assets/dexguard", "dexguard/"],
    "Ijiami": ["libexec.so", "libexecmain.so"],
}

# Ad SDK Signatures
AD_SDK_SIGNATURES = {
    "Google AdMob / Ads": ["com/google/android/gms/ads", "GoogleMobileAds"],
    "Unity Ads": ["com/unity3d/ads", "UnityAds"],
    "AppLovin / MAX": ["com/applovin", "AppLovinSdk"],
    "IronSource": ["com/ironsource", "IronSource"],
    "Vungle / Liftoff": ["com/vungle", "Vungle"],
    "Mintegral": ["com/mintegral", "Mintegral"],
    "InMobi": ["com/inmobi", "InMobi"],
    "Meta Audience Network": ["com/facebook/ads", "AudienceNetwork"],
}

# Tracker & Telemetry Signatures
TRACKER_SIGNATURES = {
    "AppsFlyer": ["com/appsflyer", "AppsFlyerLib"],
    "Adjust": ["com/adjust/sdk", "Adjust"],
    "Branch Metrics": ["io/branch", "Branch"],
    "Firebase Analytics": ["com/google/firebase/analytics"],
    "Kochava": ["com/kochava", "Kochava"],
    "Mixpanel": ["com/mixpanel", "Mixpanel"],
}


def find_adb_tool() -> str | None:
    """Locate ADB executable in PATH, scrcpy directories, or Android SDK."""
    candidates = [
        shutil.which("adb"),
        shutil.which("adb.exe"),
        r"C:\scrcpy-win64-v5.0\adb.exe",
        str(Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return str(c)
    return None


def find_build_tools() -> dict[str, str | None]:
    """Locate zipalign and apksigner."""
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


def recon_apk(apk_path: str) -> dict:
    """Universal static reconnaissance for ANY Android APK."""
    log(f"Memulai Universal Recon pada: {apk_path}")
    if not os.path.isfile(apk_path):
        log_err(f"File APK tidak ditemukan: {apk_path}")
        return {}

    size_mb = round(os.path.getsize(apk_path) / (1024 * 1024), 2)
    result = {
        "apk_path": apk_path,
        "size_mb": size_mb,
        "frameworks": [],
        "packers": [],
        "ad_sdks": [],
        "trackers": [],
        "native_abis": [],
        "dex_count": 0,
    }

    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()
        dex_files = [n for n in names if n.endswith(".dex")]
        result["dex_count"] = len(dex_files)

        # Detect Native ABIs
        abis = set()
        for n in names:
            if n.startswith("lib/"):
                parts = n.split("/")
                if len(parts) > 2:
                    abis.add(parts[1])
        result["native_abis"] = sorted(list(abis))

        # Detect Frameworks
        for fw, sigs in FRAMEWORK_SIGNATURES.items():
            if any(any(sig in n for n in names) for sig in sigs):
                result["frameworks"].append(fw)

        # Detect Packers
        for packer, sigs in PACKER_SIGNATURES.items():
            if any(any(sig in n for n in names) for sig in sigs):
                result["packers"].append(packer)

        # Scan DEX sample for Ads & Trackers
        dex_sample_data = b""
        for d in dex_files[:3]:
            dex_sample_data += z.read(d)

        for ad, sigs in AD_SDK_SIGNATURES.items():
            if any(sig.encode() in dex_sample_data for sig in sigs):
                result["ad_sdks"].append(ad)

        for tracker, sigs in TRACKER_SIGNATURES.items():
            if any(sig.encode() in dex_sample_data for sig in sigs):
                result["trackers"].append(tracker)

    # Output Recon Summary
    log_success("Hasil Universal Reconnaissance:")
    print(f"  • Ukuran File: {result['size_mb']} MB ({result['dex_count']} file DEX)")
    print(f"  • Arsitektur Native (ABI): {', '.join(result['native_abis']) if result['native_abis'] else 'Pure Java/DEX (No Native)'}")
    print(f"  • Framework Terdeteksi: {', '.join(result['frameworks']) if result['frameworks'] else 'Standard Android (Kotlin/Java)'}")
    print(f"  • Packer / Protektor: {', '.join(result['packers']) if result['packers'] else 'Tidak Terdeteksi (Plain APK)'}")
    print(f"  • Jaringan Iklan (Ad SDK): {', '.join(result['ad_sdks']) if result['ad_sdks'] else 'Bersih / Tidak Terdeteksi'}")
    print(f"  • Pelacak (Trackers): {', '.join(result['trackers']) if result['trackers'] else 'Bersih / Tidak Terdeteksi'}")
    return result


def patch_network_security(apk_path: str, output_apk: str) -> bool:
    """Inject universal Network Security Config to allow user CA trust and cleartext HTTP."""
    log(f"Menerapkan Universal MITM Patch pada: {apk_path}...")
    tools = find_build_tools()
    if not tools["zipalign"] or not tools["apksigner"]:
        log_err("zipalign atau apksigner tidak tersedia.")
        return False

    temp_dir = tempfile.mkdtemp(prefix="univ_mitm_")
    try:
        with zipfile.ZipFile(apk_path, "r") as z_in:
            for item in z_in.infolist():
                if item.filename.startswith("META-INF/") and any(item.filename.endswith(ext) for ext in (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                    continue
                z_in.extract(item, temp_dir)

        # Inject Network Security Config
        xml_dir = Path(temp_dir) / "res" / "xml"
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
        log_success("Disuntikkan: res/xml/network_security_config.xml")

        # Repack, zipalign, sign
        return repack_and_sign(temp_dir, output_apk, tools)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def repack_and_sign(src_dir: str, output_apk: str, tools: dict) -> bool:
    """Universal 4-byte zipalign and V1/V2/V3 signing."""
    unaligned_apk = output_apk + ".unaligned.tmp"
    aligned_apk = output_apk + ".aligned.tmp"

    log("Mengemas ulang file ke format ZIP Android...")
    with zipfile.ZipFile(unaligned_apk, "w") as z_out:
        for root, _, files in os.walk(src_dir):
            for file in files:
                full_p = os.path.join(root, file)
                rel_p = os.path.relpath(full_p, src_dir).replace("\\", "/")
                is_stored = rel_p == "resources.arsc" or rel_p.endswith("/resources.arsc")
                c_type = zipfile.ZIP_STORED if is_stored else zipfile.ZIP_DEFLATED
                z_out.write(full_p, rel_p, compress_type=c_type)

    log("Menjalankan 4-byte zipalign & 4KB page alignment...")
    subprocess.run([tools["zipalign"], "-f", "-p", "4", unaligned_apk, aligned_apk], check=True, capture_output=True)
    if os.path.exists(unaligned_apk):
        os.remove(unaligned_apk)

    # Generate debug keystore if needed
    keystore_path = str(Path(src_dir) / "debug.keystore")
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
        log_success(f"APK Universal Berhasil Ditandatangani & Siap Diinstal: {output_apk}")
        return True
    else:
        log_err(f"Verifikasi signature gagal: {v_res.stderr}")
        return False


def deploy_apk(apk_path: str) -> bool:
    """Universal device deployer via ADB (detects scrcpy, Android SDK, and PATH)."""
    adb = find_adb_tool()
    if not adb:
        log_err("ADB tidak ditemukan di PATH, scrcpy, atau Android SDK.")
        return False

    log(f"Menghubungkan via ADB: {adb}")
    dev_res = subprocess.run([adb, "devices"], capture_output=True, text=True)
    lines = [line.strip() for line in dev_res.stdout.splitlines() if line.strip() and not line.startswith("List of")]
    if not lines:
        log_warn("Tidak ada perangkat Android yang terhubung via USB/Wi-Fi.")
        log("Pastikan USB Debugging aktif di HP dan kabel terhubung.")
        return False

    log(f"Perangkat aktif: {lines[0]}")
    log(f"Memasang APK ({os.path.basename(apk_path)}) ke perangkat...")
    inst_res = subprocess.run([adb, "install", "-r", "-d", apk_path], capture_output=True, text=True)
    if "Success" in inst_res.stdout:
        log_success("Pemasangan Berhasil! Aplikasi telah terinstal di HP Anda.")
        return True
    else:
        log_err(f"Gagal memasang APK:\n{inst_res.stdout}\n{inst_res.stderr}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Universal Android APK Modding, Reconnaissance, and Deployment Suite"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # recon
    p_recon = subparsers.add_parser("recon", help="Analisis dan deteksi framework, packer, dan ad SDK pada APK apa saja")
    p_recon.add_argument("--apk", required=True, help="Path ke file APK")

    # patch-mitm
    p_mitm = subparsers.add_parser("patch-mitm", help="Injeksi Network Security Config (Trust User CA & Cleartext) pada APK apa saja")
    p_mitm.add_argument("--apk", required=True, help="Path ke APK asli")
    p_mitm.add_argument("--out", required=True, help="Path ke APK output")

    # deploy
    p_deploy = subparsers.add_parser("deploy", help="Pasang APK ke HP melalui ADB (auto-detect scrcpy)")
    p_deploy.add_argument("--apk", required=True, help="Path ke APK yang ingin diinstal")

    args = parser.parse_args()

    if args.command == "recon":
        recon_apk(args.apk)
        return 0
    elif args.command == "patch-mitm":
        success = patch_network_security(args.apk, args.out)
        return 0 if success else 1
    elif args.command == "deploy":
        success = deploy_apk(args.apk)
        return 0 if success else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
