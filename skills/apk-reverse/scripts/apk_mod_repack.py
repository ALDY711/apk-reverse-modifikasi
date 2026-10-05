#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""All-in-one APK Modding, Repackaging, 4-Byte Zipalign, and V1/V2/V3 Signing Pipeline.

WHY THIS EXISTS
---------------
After modifying DEX bytecode, native `.so` binaries, resources, or `AndroidManifest.xml`, the
application must be repacked into a valid Android APK package.

Modern Android devices (Android 7.0 through Android 15, API 24-35) strictly enforce:
  1. ZIP Archive Integrity: `resources.arsc` and uncompressed native libraries must be stored
     uncompressed (STORED mode, not DEFLATED).
  2. 4-Byte Alignment (zipalign): 32-bit and 64-bit memory mappings require 4-byte boundaries,
     and uncompressed `.so` files require 4KB (4096-byte) page alignment. Failing this causes
     `INSTALL_FAILED_INVALID_APK`.
  3. Signature Scheme V2/V3 (apksigner): Android 11+ (API 30+) refuses APKs signed only with V1
     (`jarsigner`), throwing `INSTALL_PARSE_FAILED_NO_CERTIFICATES`. V2 and V3 whole-file binary
     hashes are mandatory.
  4. Signature Stripping: Pre-existing signature files in `META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.EC`
     must be removed, while legitimate runtime descriptors (`META-INF/services/`) must be kept.

This script provides an automated, end-to-end pipeline that:
  - Discovers Android SDK build-tools (`zipalign`, `apksigner`, `keytool`) automatically.
  - Generates a reusable debug keystore if no keystore is provided.
  - Offers granular modification flags (`--debuggable`, `--cleartext`, `--trust-user-ca`, `--replace-dex`).
  - Produces an installable, verified APK ready for deployment on any Android device.

USAGE
-----
  # 1. All-in-one: Patch APK with debuggable + cleartext + user CA trust, then repack & sign
  python apk_mod_repack.py auto --apk original.apk --debuggable --cleartext --trust-user-ca --out modified.apk

  # 2. Swap a DEX file and repack into ready-to-use signed APK
  python apk_mod_repack.py auto --apk original.apk --replace-dex classes.dex=patched_classes.dex --out signed.apk

  # 3. Unpack an APK to a directory for manual editing
  python apk_mod_repack.py unpack --apk original.apk --out ./unpacked_dir

  # 4. Repack, zipalign, and sign an unpacked directory
  python apk_mod_repack.py repack --dir ./unpacked_dir --out final_ready.apk

EXIT CODES
----------
  0 = operation completed successfully and signature verified
  1 = repacking, alignment, or signing failure
  2 = usage or argument error
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Entries that MUST NOT be compressed in Android APKs
STORED_ENTRIES = ("resources.arsc",)


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[ERROR] {msg}", flush=True)


def find_android_tools() -> dict:
    """Discover zipalign, apksigner, keytool, and java on host."""
    tools = {
        "zipalign": shutil.which("zipalign") or shutil.which("zipalign.exe"),
        "apksigner": shutil.which("apksigner") or shutil.which("apksigner.bat"),
        "keytool": shutil.which("keytool") or shutil.which("keytool.exe"),
        "java": shutil.which("java") or shutil.which("java.exe"),
    }

    # Search standard Android SDK build-tools directories if not on PATH
    if not tools["zipalign"] or not tools["apksigner"]:
        sdk_candidates = []
        user_home = Path.home()
        sdk_candidates.append(user_home / "AppData" / "Local" / "Android" / "Sdk" / "build-tools")
        sdk_candidates.append(Path("C:/Android/sdk/build-tools"))
        sdk_candidates.append(Path("/opt/android-sdk/build-tools"))

        env_sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if env_sdk:
            sdk_candidates.insert(0, Path(env_sdk) / "build-tools")

        for base in sdk_candidates:
            if base.is_dir():
                # Check version subdirectories descending
                subdirs = sorted([d for d in base.iterdir() if d.is_dir()], reverse=True)
                for sd in subdirs:
                    if not tools["zipalign"]:
                        za = sd / ("zipalign.exe" if sys.platform == "win32" else "zipalign")
                        if za.is_file():
                            tools["zipalign"] = str(za)
                    if not tools["apksigner"]:
                        aks = sd / ("apksigner.bat" if sys.platform == "win32" else "apksigner")
                        if aks.is_file():
                            tools["apksigner"] = str(aks)
                    if tools["zipalign"] and tools["apksigner"]:
                        break

    return tools


def ensure_keystore(keystore_path: str, keytool_exe: str | None = None) -> tuple[str, str, str]:
    """Ensure a valid signing keystore exists, generating a debug one if necessary."""
    if os.path.isfile(keystore_path):
        # Default debug credentials or custom
        return keystore_path, "android", "androiddebugkey"

    log(f"Keystore tidak ditemukan, membuat debug keystore baru di: {keystore_path}")
    os.makedirs(os.path.dirname(os.path.abspath(keystore_path)), exist_ok=True)

    cmd = [
        keytool_exe or "keytool",
        "-genkeypair",
        "-v",
        "-keystore", keystore_path,
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if res.returncode != 0:
        log_err(f"Gagal membuat debug keystore via keytool:\n{res.stderr}")
        raise RuntimeError("Gagal membuat keystore")

    log_success("Debug keystore berhasil dibuat (pass: android, alias: androiddebugkey).")
    return keystore_path, "android", "androiddebugkey"


def unpack_apk(apk_path: str, out_dir: str) -> None:
    """Extract APK contents, preserving directory structure and stripping old signature."""
    log(f"Mengekstrak {apk_path} ke {out_dir}...")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(apk_path, "r") as z:
        for info in z.infolist():
            # Strip signature files
            name = info.filename
            if name.startswith("META-INF/") and any(name.endswith(ext) for ext in (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                continue
            z.extract(info, out_dir)
    log_success(f"Ekstraksi selesai: {out_dir}")


def build_unsigned_aligned_apk(src_dir: str, output_apk: str, zipalign_exe: str | None = None) -> str:
    """Pack directory into intermediate ZIP and run 4-byte zipalign."""
    temp_unaligned = output_apk + ".unaligned.tmp"
    log("Mengemas file ke arsip ZIP dengan aturan kompresi Android...")

    with zipfile.ZipFile(temp_unaligned, "w") as z_out:
        for root, _, files in os.walk(src_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, src_dir).replace("\\", "/")

                # Skip signature files
                if rel_path.startswith("META-INF/") and any(rel_path.endswith(ext) for ext in (".SF", ".RSA", ".DSA", ".EC", ".MF")):
                    continue

                # Determine compression
                is_stored = any(rel_path == s or rel_path.endswith("/" + s) for s in STORED_ENTRIES)
                # Uncompressed native libs if required
                if rel_path.startswith("lib/") and rel_path.endswith(".so"):
                    # keep default deflated unless specified
                    pass

                compress_type = zipfile.ZIP_STORED if is_stored else zipfile.ZIP_DEFLATED
                z_out.write(abs_path, rel_path, compress_type=compress_type)

    # Run zipalign
    temp_aligned = output_apk + ".aligned.tmp"
    if zipalign_exe and os.path.isfile(zipalign_exe):
        log("Menjalankan 4-byte zipalign & 4KB page alignment...")
        cmd = [zipalign_exe, "-f", "-p", "4", temp_unaligned, temp_aligned]
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if res.returncode != 0:
            log_warn(f"zipalign gagal ({res.stderr.strip()}), beralih ke arsip unaligned.")
            shutil.copy2(temp_unaligned, temp_aligned)
        else:
            log_success("Zipalign 4-byte berhasil diterapkan.")
    else:
        log_warn("zipalign tidak ditemukan; menggunakan alignment standar ZIP.")
        shutil.copy2(temp_unaligned, temp_aligned)

    if os.path.exists(temp_unaligned):
        os.remove(temp_unaligned)

    return temp_aligned


def sign_and_verify_apk(aligned_apk: str, final_apk: str, ks_path: str, ks_pass: str, ks_alias: str, apksigner_exe: str | None = None, do_verify: bool = True) -> bool:
    """Sign APK with V1, V2, and V3 schemes, then verify signature."""
    if not apksigner_exe or not os.path.isfile(apksigner_exe):
        log_err("apksigner tidak ditemukan. APK modern memerlukan V2/V3 signature agar bisa diinstal di Android.")
        return False

    log("Menandatangani APK dengan apksigner (V1, V2, V3 enabled)...")
    cmd = [
        apksigner_exe,
        "sign",
        "--ks", ks_path,
        "--ks-pass", f"pass:{ks_pass}",
        "--ks-key-alias", ks_alias,
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", final_apk,
        aligned_apk
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if res.returncode != 0:
        log_err(f"Gagal menandatangani APK:\n{res.stderr}")
        return False

    log_success(f"Penandatanganan selesai -> {final_apk}")

    if not do_verify:
        log("Verifikasi signature dilewati (--no-verify).")
        return True

    # Verify signature
    log("Memverifikasi integritas signature dengan apksigner verify...")
    verify_cmd = [apksigner_exe, "verify", "-v", final_apk]
    v_res = subprocess.run(verify_cmd, capture_output=True, text=True, errors="replace")
    if v_res.returncode == 0:
        log_success("Verifikasi Berhasil: APK valid dan siap diinstal di Android!")
        for line in v_res.stdout.splitlines():
            if "Verified using" in line or "Number of signers" in line:
                print(f"  • {line.strip()}")
        return True
    else:
        log_warn(f"Peringatan saat verifikasi:\n{v_res.stderr}")
        return False


def modify_project_manifest(project_dir: str, debuggable: bool = False, cleartext: bool = False, trust_user_ca: bool = False) -> None:
    """Apply common modifications directly to AndroidManifest.xml and res/xml."""
    manifest_path = os.path.join(project_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        return

    # Check if text XML or binary
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        # Binary AXML, skip raw string injection or notify
        log_warn("AndroidManifest.xml berformat binary AXML; gunakan modifikasi DEX/assets atau decompile apktool.")
        return

    modified = False
    if debuggable and 'android:debuggable="true"' not in content:
        content = re.sub(r'<application\b', '<application android:debuggable="true"', content, count=1)
        modified = True
        log_success("Ditambahkan android:debuggable=\"true\" ke manifest.")

    if cleartext:
        content = content.replace('android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"')
        if 'android:usesCleartextTraffic="true"' not in content:
            content = re.sub(r'<application\b', '<application android:usesCleartextTraffic="true"', content, count=1)
            modified = True
            log_success("Ditambahkan android:usesCleartextTraffic=\"true\" ke manifest.")

    if trust_user_ca:
        nsc_dir = os.path.join(project_dir, "res", "xml")
        os.makedirs(nsc_dir, exist_ok=True)
        nsc_file = os.path.join(nsc_dir, "network_security_config.xml")
        nsc_xml = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>"""
        with open(nsc_file, "w", encoding="utf-8") as f:
            f.write(nsc_xml)
        if 'android:networkSecurityConfig' not in content:
            content = re.sub(r'<application\b', '<application android:networkSecurityConfig="@xml/network_security_config"', content, count=1)
            modified = True
        log_success("Dikonfigurasi Network Security Config untuk mempercayai User CA.")

    if modified:
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(content)


def main():
    parser = argparse.ArgumentParser(
        prog="apk_mod_repack.py",
        description="All-in-one APK Modding, Repackaging, 4-byte Zipalign, and V1/V2/V3 Signing",
    )
    sub = parser.add_subparsers(dest="action", help="Aksi yang tersedia (auto, unpack, repack)")

    # ── auto ───────────────────────────────────────────────────────────
    p_auto = sub.add_parser("auto", help="Alur lengkap: unpack -> modifikasi -> repack -> zipalign -> sign")
    p_auto.add_argument("--apk", required=True, help="File APK asli")
    p_auto.add_argument("--out", "-o", required=True, help="File APK hasil modifikasi yang siap diinstal")
    p_auto.add_argument("--debuggable", action="store_true", help="Set android:debuggable=\"true\"")
    p_auto.add_argument("--cleartext", action="store_true", help="Set android:usesCleartextTraffic=\"true\"")
    p_auto.add_argument("--trust-user-ca", action="store_true", help="Injeksi Network Security Config untuk percaya User CA")
    p_auto.add_argument("--replace-dex", "--swap-dex", dest="replace_dex", action="append", help="Ganti DEX: nama_dex=path_file (misal: classes.dex=new.dex)")
    p_auto.add_argument("--replace-file", action="append", help="Ganti file apa saja: target_rel=path_file")
    p_auto.add_argument("--keystore", help="Path keystore khusus (default: auto generate debug.keystore)")
    p_auto.add_argument("--ks-pass", default="android", help="Password keystore (default: android)")
    p_auto.add_argument("--ks-alias", default="androiddebugkey", help="Alias key (default: androiddebugkey)")
    p_auto.add_argument("--no-verify", action="store_true", help="Lewati verifikasi apksigner")

    # ── unpack ─────────────────────────────────────────────────────────
    p_unpack = sub.add_parser("unpack", help="Ekstrak file APK ke direktori kerja")
    p_unpack.add_argument("--apk", required=True, help="File APK target")
    p_unpack.add_argument("--out", "--out-dir", "-o", dest="out", required=True, help="Direktori tujuan ekstraksi")

    # ── repack ─────────────────────────────────────────────────────────
    p_repack = sub.add_parser("repack", help="Kemas direktori kerja menjadi APK, lakukan zipalign, dan tanda tangani")
    p_repack.add_argument("--dir", "-d", required=True, help="Direktori hasil ekstraksi/modifikasi")
    p_repack.add_argument("--out", "-o", required=True, help="File APK output siap pakai")
    p_repack.add_argument("--keystore", help="Path keystore khusus (default: auto generate debug.keystore)")
    p_repack.add_argument("--ks-pass", default="android", help="Password keystore (default: android)")
    p_repack.add_argument("--ks-alias", default="androiddebugkey", help="Alias key (default: androiddebugkey)")
    p_repack.add_argument("--no-verify", action="store_true", help="Lewati verifikasi apksigner")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        sys.exit(2)

    tools = find_android_tools()
    log(f"Tools ditemukan: zipalign={bool(tools['zipalign'])}, apksigner={bool(tools['apksigner'])}, keytool={bool(tools['keytool'])}")

    if args.action == "unpack":
        unpack_apk(args.apk, args.out)
        sys.exit(0)

    elif args.action == "repack":
        ks_path = args.keystore or os.path.join(tempfile.gettempdir(), "debug.keystore")
        ks_path, ks_pass, ks_alias = ensure_keystore(ks_path, tools["keytool"])
        ks_pass = args.ks_pass or ks_pass
        ks_alias = args.ks_alias or ks_alias

        aligned = build_unsigned_aligned_apk(args.dir, args.out, tools["zipalign"])
        ok = sign_and_verify_apk(aligned, args.out, ks_path, ks_pass, ks_alias, tools["apksigner"], do_verify=not args.no_verify)
        if os.path.isfile(aligned):
            os.remove(aligned)
        sys.exit(0 if ok else 1)

    elif args.action == "auto":
        with tempfile.TemporaryDirectory(prefix="apk_mod_") as tmp_dir:
            unpack_apk(args.apk, tmp_dir)

            # Apply manifest modifications
            modify_project_manifest(
                tmp_dir,
                debuggable=args.debuggable,
                cleartext=args.cleartext,
                trust_user_ca=args.trust_user_ca
            )

            # Apply DEX replacements
            if args.replace_dex:
                for item in args.replace_dex:
                    if "=" in item:
                        target_name, src_file = item.split("=", 1)
                        dest = os.path.join(tmp_dir, target_name.strip())
                        shutil.copy2(src_file.strip(), dest)
                        log_success(f"Mengganti DEX: {target_name} -> {src_file}")

            # Apply arbitrary file replacements
            if args.replace_file:
                for item in args.replace_file:
                    if "=" in item:
                        target_rel, src_file = item.split("=", 1)
                        dest = os.path.join(tmp_dir, target_rel.strip())
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.copy2(src_file.strip(), dest)
                        log_success(f"Mengganti File: {target_rel} -> {src_file}")

            ks_path = args.keystore or os.path.join(tempfile.gettempdir(), "debug.keystore")
            ks_path, ks_pass, ks_alias = ensure_keystore(ks_path, tools["keytool"])
            ks_pass = args.ks_pass or ks_pass
            ks_alias = args.ks_alias or ks_alias

            aligned = build_unsigned_aligned_apk(tmp_dir, args.out, tools["zipalign"])
            ok = sign_and_verify_apk(aligned, args.out, ks_path, ks_pass, ks_alias, tools["apksigner"], do_verify=not args.no_verify)
            if os.path.isfile(aligned):
                os.remove(aligned)

            if ok:
                log_success(f"SELESAI! APK siap pakai untuk Android tersimpan di: {args.out}")
            sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
