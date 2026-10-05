#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Setup & install helper — persiapkan lingkungan kerja apk-reverse.
Dimodifikasi oleh ALDY.

Skrip ini:
  1. Memeriksa versi Python (3.9+)
  2. Menginstall dependensi dari requirements.txt
  3. Memeriksa tool-tool penting (adb, java, jadx, dll)
  4. Membuat direktori kerja standar
  5. Menyalin config.example.yaml → config.yaml (jika belum ada)
  6. Menjalankan doctor.py untuk verifikasi akhir

Usage:
    python setup.py              # Setup lengkap
    python setup.py --check      # Hanya periksa, jangan install
    python setup.py --minimal    # Install minimal (tanpa optional deps)
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "skills", "apk-reverse", "scripts")


def banner():
    print(r"""
╔══════════════════════════════════════════════════════════╗
║         🔧  APK Reverse — Setup & Install  🔧           ║
║        Persiapan lingkungan kerja analisis APK           ║
║             Dimodifikasi oleh ALDY                       ║
╚══════════════════════════════════════════════════════════╝
    """)


def check_python():
    """Periksa versi Python."""
    print("[1/6] Memeriksa versi Python...", end=" ")
    v = sys.version_info
    if v.major >= 3 and v.minor >= 9:
        print(f"✅ Python {v.major}.{v.minor}.{v.micro}")
        return True
    else:
        print(f"❌ Python {v.major}.{v.minor}.{v.micro} — diperlukan 3.9+")
        return False


def install_deps(minimal=False):
    """Install dependensi Python."""
    print("[2/6] Menginstall dependensi Python...")
    req_file = os.path.join(HERE, "requirements.txt")
    if not os.path.isfile(req_file):
        print("  ⚠️  requirements.txt tidak ditemukan, melewati...")
        return True

    if minimal:
        # Hanya install core deps
        minimal_deps = ["lief", "rich", "pyyaml", "requests"]
        for dep in minimal_deps:
            print(f"  → Installing {dep}...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", dep, "-q"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"  ⚠️  Gagal install {dep}: {result.stderr.strip()}")
    else:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", req_file, "-q"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  ⚠️  Beberapa dependensi gagal diinstall:")
            print(f"      {result.stderr.strip()[:200]}")
            print("  💡 Coba: pip install -r requirements.txt --ignore-installed")
            return False

    print("  ✅ Dependensi terinstall")
    return True


def check_tools():
    """Periksa tool-tool penting."""
    print("[3/6] Memeriksa tool-tool yang tersedia...")

    tools = {
        "python": {"cmd": [sys.executable, "--version"], "required": True},
        "java": {"cmd": ["java", "-version"], "required": False},
        "adb": {"cmd": ["adb", "version"], "required": False},
        "jadx": {"cmd": ["jadx", "--version"], "required": False},
        "apktool": {"cmd": ["apktool", "--version"], "required": False},
        "zipalign": {"cmd": ["zipalign"], "required": False},
        "apksigner": {"cmd": ["apksigner", "--version"], "required": False},
        "frida": {"cmd": ["frida", "--version"], "required": False},
        "git": {"cmd": ["git", "--version"], "required": False},
    }

    results = {}
    for name, info in tools.items():
        try:
            result = subprocess.run(
                info["cmd"], capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            version = (result.stdout + result.stderr).strip().split("\n")[0][:60]
            results[name] = {"found": True, "version": version}
            status = "✅"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            results[name] = {"found": False}
            status = "❌" if info["required"] else "⚠️ (opsional)"

        req_label = "WAJIB" if info["required"] else "opsional"
        print(f"  {status} {name:<12s} [{req_label}]", end="")
        if results[name]["found"]:
            print(f"  — {results[name].get('version', '')}")
        else:
            print()

    return results


def create_directories():
    """Buat direktori kerja standar."""
    print("[4/6] Membuat direktori kerja...")
    dirs = ["work", "reports", "logs", "out"]
    for d in dirs:
        path = os.path.join(HERE, d)
        os.makedirs(path, exist_ok=True)
        print(f"  📁 {d}/")
    print("  ✅ Direktori siap")


def copy_config():
    """Salin config template."""
    print("[5/6] Menyiapkan konfigurasi...")
    src = os.path.join(HERE, "config.example.yaml")
    dst = os.path.join(HERE, "config.yaml")
    if os.path.isfile(dst):
        print("  ℹ️  config.yaml sudah ada, tidak ditimpa")
    elif os.path.isfile(src):
        shutil.copy2(src, dst)
        print("  ✅ config.yaml dibuat dari template")
    else:
        print("  ⚠️  config.example.yaml tidak ditemukan")


def run_doctor():
    """Jalankan doctor.py untuk verifikasi akhir."""
    print("[6/6] Menjalankan pemeriksaan akhir (doctor.py)...")
    doctor = os.path.join(SCRIPTS, "doctor.py")
    if os.path.isfile(doctor):
        result = subprocess.run(
            [sys.executable, doctor],
            capture_output=True, text=True
        )
        # Tampilkan ringkasan
        for line in result.stdout.split("\n"):
            if any(kw in line.upper() for kw in ["OK", "BLOCKED", "MISSING", "RESULT", "WARN"]):
                print(f"  {line.strip()}")
        print(f"\n  Exit code: {result.returncode}")
    else:
        print(f"  ⚠️  doctor.py tidak ditemukan di {doctor}")


def main():
    parser = argparse.ArgumentParser(description="APK Reverse — Setup & Install")
    parser.add_argument("--check", action="store_true", help="Hanya periksa, jangan install")
    parser.add_argument("--minimal", action="store_true", help="Install minimal")
    args = parser.parse_args()

    banner()

    # Step 1: Python version
    if not check_python():
        print("\n❌ Python 3.9+ diperlukan. Silakan upgrade Python.")
        sys.exit(1)

    if args.check:
        print()
        check_tools()
        print("\n✅ Pemeriksaan selesai (mode check-only).")
        return

    # Step 2: Install deps
    install_deps(minimal=args.minimal)

    # Step 3: Check tools
    print()
    check_tools()

    # Step 4: Create dirs
    print()
    create_directories()

    # Step 5: Copy config
    print()
    copy_config()

    # Step 6: Doctor
    print()
    run_doctor()

    print(f"""
{'='*60}
  ✅ Setup selesai!

  Langkah selanjutnya:
  1. Edit config.yaml sesuai lingkungan Anda
  2. Jalankan:  python apk_cli.py doctor
  3. Mulai:     python apk_cli.py recon --apk target.apk

  Dokumentasi:  python apk_cli.py list
  Bantuan:      python apk_cli.py --help
{'='*60}
""")


if __name__ == "__main__":
    main()
