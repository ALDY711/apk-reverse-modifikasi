#!/usr/bin/env python3
"""
scripts/secret_scanner.py - High-Entropy & Regex-Based Secret Leak Scanner

Pemindai statis canggih untuk mendeteksi kebocoran kredensial, kunci API,
token autentikasi, private key, dan string entropi tinggi pada kode sumber
aplikasi web (Laravel, Node.js, Python, frontend bundles, .env, konfigurasi).

Fitur:
- Deteksi pola tanda tangan kunci API populer (AWS, Stripe, GitHub, Google, Slack, dll.)
- Deteksi Private Key RSA, SSH, PGP, dan sertifikat sensitif
- Analisis Entropi Shannon (Shannon Entropy) untuk mendeteksi random high-entropy secrets
- Pelaporan file sensitif yang tidak sengaja ter-commit (.env, .git, id_rsa, db.sqlite)
- Output laporan rapi (Tabel CLI, JSON export) dengan penilaian tingkat risiko (CRITICAL/HIGH/MEDIUM)

Penggunaan:
  python secret_scanner.py --path /path/to/project
  python secret_scanner.py --path . --json audit_secrets.json --max-size 2097152
"""

import os
import sys
import math
import re
import json
import argparse
from typing import List, Dict, Any, Optional

# Kumpulan Pola Tanda Tangan Secret (Signatures)
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL"
    },
    {
        "name": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "regex": r"(?i)aws_(?:secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "CRITICAL"
    },
    {
        "name": "Google / Firebase API Key",
        "category": "API Keys",
        "regex": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "HIGH"
    },
    {
        "name": "Stripe Secret Key",
        "category": "Payment Gateways",
        "regex": r"sk_live_[0-9a-zA-Z]{24,99}",
        "severity": "CRITICAL"
    },
    {
        "name": "Stripe Restricted Key",
        "category": "Payment Gateways",
        "regex": r"rk_live_[0-9a-zA-Z]{24,99}",
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Personal Access Token (Classic)",
        "category": "Developer Tokens",
        "regex": r"ghp_[0-9a-zA-Z]{36}",
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Fine-Grained Token",
        "category": "Developer Tokens",
        "regex": r"github_pat_[0-9a-zA-Z_]{82}",
        "severity": "CRITICAL"
    },
    {
        "name": "Slack Webhook URL",
        "category": "Webhooks",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": "HIGH"
    },
    {
        "name": "Discord Webhook URL",
        "category": "Webhooks",
        "regex": r"https://(?:ptb\.|canary\.)?discord\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80}",
        "severity": "HIGH"
    },
    {
        "name": "Private Key Header (RSA/OpenSSH/PGP)",
        "category": "Cryptography",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "severity": "CRITICAL"
    },
    {
        "name": "Generic Database Connection URI with Password",
        "category": "Database Credentials",
        "regex": r"(?:mysql|postgres|postgresql|mongodb|redis)://[^:]+:([^@]+)@[a-zA-Z0-9.\-_]+:\d+",
        "severity": "CRITICAL"
    },
    {
        "name": "Hardcoded JWT Token",
        "category": "Authentication",
        "regex": r"eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}",
        "severity": "HIGH"
    },
    {
        "name": "Telegram Bot Token",
        "category": "Bot Credentials",
        "regex": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
        "severity": "HIGH"
    },
    {
        "name": "Midtrans Server Key (Indonesian Gateway)",
        "category": "Payment Gateways",
        "regex": r"(?:SB-Mid-server-|Mid-server-)[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL"
    }
]

# Nama file sensitif yang tidak boleh ter-commit
SENSITIVE_FILENAMES = {
    ".env": "File konfigurasi environment lokal dengan kredensial aktif.",
    ".env.backup": "File backup konfigurasi rahasia.",
    ".env.local": "File environment lokal.",
    ".env.production": "File konfigurasi produksi.",
    "id_rsa": "Private key SSH.",
    "id_ecdsa": "Private key SSH ECDSA.",
    "id_ed25519": "Private key SSH ED25519.",
    "database.sqlite": "Database SQLite mentah yang dapat diunduh publik.",
    "credentials.json": "File kredensial Google Service Account.",
    "service-account.json": "File kredensial service account.",
}

# Direktori yang diabaikan saat scanning
IGNORED_DIRECTORIES = {
    "node_modules", "vendor", ".git", "storage", ".idea", ".vscode",
    "dist", "build", "__pycache__", ".next", ".nuxt", ".svelte-kit"
}

# Ekstensi biner yang diabaikan
IGNORED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".svg",
    ".mp4", ".mp3", ".wav", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".eot"
}


def calculate_shannon_entropy(data: str) -> float:
    """Menghitung nilai Shannon Entropy dari sebuah string untuk mengukur keacakan (randomness)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def is_false_positive(snippet: str) -> bool:
    """Menyaring pola contoh umum/placeholder yang sering memicu false positive."""
    false_positive_indicators = [
        "example", "your_api_key", "change_me", "dummy", "sample",
        "placeholder", "your-secret-key", "test_key", "insert_here",
        "1234567890", "abcdefghij", "xxxx", "00000000"
    ]
    lower = snippet.lower()
    return any(indicator in lower for indicator in false_positive_indicators)


def scan_file(file_path: str, root_dir: str) -> List[Dict[str, Any]]:
    """Memindai satu file teks untuk menemukan tanda tangan secret dan high entropy."""
    findings = []
    rel_path = os.path.relpath(file_path, root_dir)
    filename = os.path.basename(file_path)

    # 1. Cek apakah nama file itu sendiri adalah file sensitif
    if filename.lower() in SENSITIVE_FILENAMES:
        findings.append({
            "type": "SENSITIVE_FILE_EXPOSED",
            "name": f"File Sensitif Terdeteksi: {filename}",
            "file": rel_path,
            "line": 0,
            "snippet": SENSITIVE_FILENAMES[filename.lower()],
            "severity": "CRITICAL",
            "category": "Configuration Exposure"
        })

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or len(line_clean) > 5000:
            continue

        # 2. Cek Pattern Regex
        for pat in SECRET_PATTERNS:
            matches = re.finditer(pat["regex"], line_clean)
            for m in matches:
                matched_str = m.group(0)
                if not is_false_positive(matched_str):
                    # Sensor sebagian string untuk keamanan tampilan
                    masked = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:] if len(matched_str) > 10 else "***"
                    findings.append({
                        "type": "SECRET_SIGNATURE",
                        "name": pat["name"],
                        "file": rel_path,
                        "line": line_idx,
                        "snippet": line_clean[:120],
                        "matched_masked": masked,
                        "severity": pat["severity"],
                        "category": pat["category"]
                    })

        # 3. Cek Assign Variabel dengan High Entropy (misal: APP_KEY=base64:..., SECRET=...)
        entropy_assignment_match = re.search(r"(?i)(?:key|secret|token|password|auth|salt)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\+/=]{24,})['\"]?", line_clean)
        if entropy_assignment_match:
            candidate = entropy_assignment_match.group(1)
            entropy = calculate_shannon_entropy(candidate)
            # Entropi > 4.2 biasanya menunjukkan random cryptographic string
            if entropy >= 4.2 and not is_false_positive(candidate):
                # Hindari duplikasi jika sudah terdeteksi oleh regex spesifik di atas
                if not any(f["line"] == line_idx and f["file"] == rel_path for f in findings):
                    masked = candidate[:4] + "*" * (len(candidate) - 8) + candidate[-4:] if len(candidate) > 10 else "***"
                    findings.append({
                        "type": "HIGH_ENTROPY_SECRET",
                        "name": f"High-Entropy Secret String (Entropy: {entropy:.2f})",
                        "file": rel_path,
                        "line": line_idx,
                        "snippet": line_clean[:120],
                        "matched_masked": masked,
                        "severity": "HIGH",
                        "category": "Potential Hardcoded Credential"
                    })

    return findings


def scan_directory(target_dir: str, max_file_size: int = 1048576) -> List[Dict[str, Any]]:
    """Menelusuri seluruh file dalam direktori dan mengumpulkan seluruh temuan."""
    all_findings = []

    for root, dirs, files in os.walk(target_dir):
        # Abaikan direktori yang masuk filter
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORED_EXTENSIONS:
                continue

            full_path = os.path.join(root, file)
            try:
                if os.path.getsize(full_path) > max_file_size:
                    continue
            except OSError:
                continue

            findings = scan_file(full_path, target_dir)
            all_findings.extend(findings)

    return all_findings


def render_cli_report(findings: List[Dict[str, Any]], target_dir: str) -> None:
    """Merender laporan audit yang bersih, profesional, dan informatif ke terminal."""
    print("=" * 80)
    print(" WEB APPLICATION SECRET LEAK & CREDENTIAL EXPOSURE AUDIT")
    print("=" * 80)
    print(f" Direktori Target : {os.path.abspath(target_dir)}")
    print(f" Total Temuan     : {len(findings)}")
    print("-" * 80)

    if not findings:
        print(" [√] EXCELLENT: Tidak ditemukan kebocoran secret, kunci API, atau file sensitif!")
        print("=" * 80)
        return

    # Kelompokkan berdasarkan keparahan
    criticals = [f for f in findings if f["severity"] == "CRITICAL"]
    highs = [f for f in findings if f["severity"] == "HIGH"]
    mediums = [f for f in findings if f["severity"] == "MEDIUM"]

    print(f" STATUS TEMUAN: [CRITICAL: {len(criticals)}] | [HIGH: {len(highs)}] | [MEDIUM: {len(mediums)}]")
    print("-" * 80)

    for idx, f in enumerate(findings, start=1):
        color_tag = f"[{f['severity']}]"
        print(f"\n#{idx} {color_tag} {f['name']}")
        print(f"   Kategori : {f['category']}")
        print(f"   Lokasi   : {f['file']}:{f['line']}")
        if "matched_masked" in f:
            print(f"   Kunci    : {f['matched_masked']}")
        print(f"   Snippet  : {f['snippet']}")

    print("\n" + "=" * 80)
    print(" REKOMENDASI PERBAIKAN DEFENSIVE:")
    print(" 1. Cabut (Revoke/Rotate) segera semua kunci API yang terdeteksi di atas!")
    print(" 2. Pindahkan semua kredensial ke file .env dan pastikan .env terdaftar di .gitignore.")
    print(" 3. Bersihkan riwayat Git dari kunci bocor menggunakan git-filter-repo atau BFG Repo-Cleaner.")
    print(" 4. Gunakan Secrets Manager (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets).")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Web Application Secret Leak Scanner")
    parser.add_argument("--path", required=True, help="Direktori codebase yang ingin dipindai")
    parser.add_argument("--json", dest="json_output", help="Path untuk mengekspor laporan ke file JSON")
    parser.add_argument("--max-size", type=int, default=1048576, help="Batas ukuran file maksimal (byte) [default: 1MB]")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"[!] Error: Direktori target '{args.path}' tidak ditemukan.")
        sys.exit(1)

    findings = scan_directory(args.path, max_file_size=args.max_size)
    render_cli_report(findings, args.path)

    if args.json_output:
        try:
            with open(args.json_output, "w", encoding="utf-8") as jf:
                json.dump({"target_path": os.path.abspath(args.path), "total": len(findings), "findings": findings}, jf, indent=2)
            print(f"\n[+] Laporan JSON berhasil disimpan ke: {args.json_output}")
        except Exception as e:
            print(f"[!] Gagal menyimpan file JSON: {e}")


if __name__ == "__main__":
    main()
