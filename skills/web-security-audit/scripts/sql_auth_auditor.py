#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL & Authentication Backend Auditor (Login & Register Security).

Audits backend codebases (PHP, Node.js, Python) for:
  1. SQL Injection on Auth Endpoints:
     - Direct string concatenation in login/register/reset queries
     - Format strings, f-strings, template literals in SQL execution
     - Unsafe ORM raw queries (whereRaw, sequelize.literal, raw())
     - Second-Order SQL Injection patterns (unsafe registration data flow)
  2. Password Storage & Hashing Architecture:
     - Detection of deprecated hash functions (MD5, SHA1, plain SHA256)
     - Validation of adaptive key derivation (Argon2id, Bcrypt, PBKDF2)
     - Timing attack vulnerabilities in password comparison
  3. Defensive Remediation:
     - Instant generation of parameterized prepared statements
     - Production-grade password hashing templates
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


# Vulnerable SQL concatenation patterns in Auth context
SQL_INJECTION_PATTERNS = [
    # PHP: String concatenation or variable interpolation in SQL
    {
        "name": "PHP Concatenation / Variable Interpolation in SQL",
        "lang": "php",
        "regex": r"""(?:mysqli_query|\$db->query|\$pdo->query|\$conn->query)\s*\(\s*['"].*?\$(?:_POST|_GET|_REQUEST|username|password|email|user|pass).*?['"]""",
        "severity": "CRITICAL",
        "desc": "Variabel user langsung diinterpolasi atau digabungkan ke query SQL tanpa prepared statement.",
    },
    {
        "name": "PHP Unescaped String Concatenation in SQL",
        "lang": "php",
        "regex": r"""(?:SELECT|INSERT|UPDATE|DELETE).*?(?:FROM|INTO)\s+[`'"]?\w+[`'"]?.*?\.\s*\$(?:username|password|email|user|pass|_POST|_GET)""",
        "severity": "CRITICAL",
        "desc": "Penggabungan string '.' langsung dengan variabel input pada query SQL.",
    },
    {
        "name": "Laravel Unsafe Raw Query (whereRaw / DB::raw)",
        "lang": "php",
        "regex": r"""(?:whereRaw|havingRaw|orderByRaw|DB::raw)\s*\(\s*['"].*?\$(?:request|email|username|input|data)""",
        "severity": "HIGH",
        "desc": "Penggunaan whereRaw/DB::raw dengan konkatenasi variabel tanpa binding parameter array.",
    },
    # Node.js: Template literals or concatenation in SQL queries
    {
        "name": "Node.js Template Literal / String Concatenation in SQL",
        "lang": "js",
        "regex": r"""(?:\.query|\.execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{req\.(?:body|query|params)[^`]*\}""",
        "severity": "CRITICAL",
        "desc": "Template literal JavaScript (${req.body...}) dimasukkan langsung ke kueri SQL.",
    },
    {
        "name": "Node.js Sequelize / TypeORM Unsafe Raw Literal",
        "lang": "js",
        "regex": r"""(?:Sequelize\.literal|sequelize\.literal)\s*\(\s*[`'"].*?\$\{.*?\}[`'"]""",
        "severity": "HIGH",
        "desc": "Sequelize.literal dieksekusi dengan interpolasi string langsung.",
    },
    # Python: f-strings or % formatting in SQL queries
    {
        "name": "Python f-string or % formatting in SQL Query",
        "lang": "py",
        "regex": r"""(?:cursor\.execute|db\.session\.execute)\s*\(\s*(?:f['"].*?(?:SELECT|INSERT|UPDATE).*?\{.*?\}|['"].*?(?:SELECT|INSERT|UPDATE).*?['"]\s*%\s*\()""",
        "severity": "CRITICAL",
        "desc": "Python f-string atau format % dipakai untuk membangun query SQL alih-alih tuple parameterized.",
    },
    {
        "name": "Django / SQLAlchemy Unsafe Raw SQL Execution",
        "lang": "py",
        "regex": r"""(?:\.raw|\.extra)\s*\(\s*f['"].*?(?:SELECT|FROM|WHERE).*?\{.*?\}""",
        "severity": "HIGH",
        "desc": "ORM raw query dieksekusi dengan f-string Python yang rentan injeksi.",
    },
]

# Weak vs Strong Password Hashing patterns
PASSWORD_HASH_PATTERNS = [
    {
        "name": "MD5 Hash Function (Sangat Rentan)",
        "regex": r"""\b(?:md5|hash\(['"]md5['"]|crypto\.createHash\(['"]md5['"]|hashlib\.md5)\b""",
        "type": "WEAK",
        "desc": "MD5 tidak memiliki salt komputasi lambat dan rentan rainbow table collision.",
    },
    {
        "name": "SHA-1 Hash Function (Rentan)",
        "regex": r"""\b(?:sha1|hash\(['"]sha1['"]|crypto\.createHash\(['"]sha1['"]|hashlib\.sha1)\b""",
        "type": "WEAK",
        "desc": "SHA-1 telah didepresiasi karena kelemahan collision dan kecepatan hash tinggi.",
    },
    {
        "name": "Plain / Fast SHA-256 (Tidak Dianjurkan untuk Password)",
        "regex": r"""\b(?:hash\(['"]sha256['"]|crypto\.createHash\(['"]sha256['"]|hashlib\.sha256)\b(?!\s*,\s*iterations)""",
        "type": "WEAK",
        "desc": "SHA-256 standar tanpa key derivation (PBKDF2/Argon2) terlalu cepat sehingga rentan brute-force GPU.",
    },
    {
        "name": "Plaintext / Insecure Password Comparison (== atau ===)",
        "regex": r"""\$(?:row|user)\['(?:password|passwd)'\]\s*===?\s*\$(?:password|pass|input)""",
        "type": "CRITICAL",
        "desc": "Verifikasi password dilakukan dengan pembanding string biasa (plaintext) tanpa fungsi verifikasi hash.",
    },
    {
        "name": "Bcrypt / Argon2 Secure Hashing (Standar Industri)",
        "regex": r"""\b(?:password_hash|password_verify|bcrypt\.hash|bcrypt\.compare|argon2\.hash|argon2\.verify|generate_password_hash|check_password_hash)\b""",
        "type": "SECURE",
        "desc": "Menggunakan adaptive password hashing (Bcrypt / Argon2) dengan cost factor otomatis.",
    },
]

# Second-Order SQLi Indicators: registration storing unsanitized profile/display name
SECOND_ORDER_PATTERNS = [
    r"""INSERT\s+INTO\s+.*?(?:username|name|nickname|bio).*?VALUES""",
    r"""UPDATE\s+.*?SET\s+.*?(?:username|name|email).*?WHERE""",
]


def audit_file_content(file_path: Path, content: str) -> dict:
    """Analyze file content for SQL injection, auth flaws, and weak hashing."""
    findings = {
        "sqli": [],
        "hashing": [],
        "second_order": [],
    }

    lines = content.splitlines()

    # 1. SQL Injection audit
    for rule in SQL_INJECTION_PATTERNS:
        matches = re.finditer(rule["regex"], content, re.IGNORECASE | re.DOTALL)
        for m in matches:
            # Hitung nomor baris
            start_pos = m.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = content[start_pos : min(start_pos + 120, len(content))].strip().replace("\n", " ")
            findings["sqli"].append({
                "rule": rule["name"],
                "severity": rule["severity"],
                "line": line_no,
                "desc": rule["desc"],
                "snippet": snippet,
            })

    # 2. Password Hashing audit
    for rule in PASSWORD_HASH_PATTERNS:
        matches = re.finditer(rule["regex"], content, re.IGNORECASE)
        for m in matches:
            start_pos = m.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = content[start_pos : min(start_pos + 80, len(content))].strip().replace("\n", " ")
            findings["hashing"].append({
                "rule": rule["name"],
                "type": rule["type"],
                "line": line_no,
                "desc": rule["desc"],
                "snippet": snippet,
            })

    # 3. Second-Order checks on registration/update files
    is_auth_file = bool(re.search(r"(?:register|signup|profile|user|account)", str(file_path), re.IGNORECASE))
    if is_auth_file:
        for p in SECOND_ORDER_PATTERNS:
            if re.search(p, content, re.IGNORECASE):
                findings["second_order"].append({
                    "pattern": p,
                    "desc": "Endpoint registrasi/profil menyimpan data pengguna. Pastikan data tidak pernah dievaluasi ulang via raw query dinamis pada alur login atau dashboard berikutnya.",
                })
                break

    return findings


def scan_directory(target_path: str, extensions: list[str] | None = None) -> None:
    """Recursively scan directory for SQL and Authentication vulnerabilities."""
    p = Path(target_path)
    if not p.exists():
        log_err(f"Target path tidak ditemukan: {target_path}")
        return

    exts = extensions or [".php", ".js", ".ts", ".py"]
    files_to_scan = []

    if p.is_file():
        files_to_scan.append(p)
    else:
        for ext in exts:
            files_to_scan.extend(p.rglob(f"*{ext}"))

    log(f"Memulai audit backend SQL & Auth pada {len(files_to_scan)} file...")

    total_sqli = 0
    total_weak_hash = 0
    total_secure_hash = 0

    for f in files_to_scan:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            continue

        res = audit_file_content(f, content)

        has_findings = bool(res["sqli"] or any(h["type"] in ("WEAK", "CRITICAL") for h in res["hashing"]))
        if has_findings:
            print("\n" + "=" * 75)
            log_warn(f"FILE: {f.resolve()}")
            print("=" * 75)

            if res["sqli"]:
                for item in res["sqli"]:
                    total_sqli += 1
                    color_tag = "[CRITICAL]" if item["severity"] == "CRITICAL" else "[HIGH]"
                    print(f"  {color_tag} Baris {item['line']}: {item['rule']}")
                    print(f"      Deskripsi : {item['desc']}")
                    print(f"      Kode      : {item['snippet']}")

            if res["hashing"]:
                for item in res["hashing"]:
                    if item["type"] in ("WEAK", "CRITICAL"):
                        total_weak_hash += 1
                        print(f"  [KELEMAHAN HASH] Baris {item['line']}: {item['rule']}")
                        print(f"      Deskripsi : {item['desc']}")
                        print(f"      Kode      : {item['snippet']}")
                    else:
                        total_secure_hash += 1

            if res["second_order"]:
                for so in res["second_order"]:
                    print(f"  [INFO SECOND-ORDER] {so['desc']}")

    print("\n" + "#" * 50)
    print("           RINGKASAN AUDIT SQL & AUTH")
    print("#" * 50)
    print(f"  Total Potensi SQL Injection : {total_sqli}")
    print(f"  Total Kelemahan Hash/Pass   : {total_weak_hash}")
    print(f"  Fungsi Hash Aman Terdeteksi : {total_secure_hash}")
    print("#" * 50)

    if total_sqli > 0 or total_weak_hash > 0:
        log_warn("Ditemukan kelemahan kritis pada modul otentikasi/database.")
        print("Gunakan subcommand 'remediate' untuk melihat template perbaikan aman.")
    else:
        log_success("Tidak ditemukan pola konkatenasi query SQL atau hash usang yang mencolok.")


def print_remediation_recipes() -> None:
    """Print hardened, secure implementation templates for Login & Register."""
    recipe = """
================================================================================
          PANDUAN REMEDIASI RESEP AMAN (PREPARED STATEMENTS & HASHING)
================================================================================

1. PHP (PDO) - Login & Register Aman:
--------------------------------------------------------------------------------
// [A] REGISTRASI USER (Password Hashing via Argon2id / Bcrypt)
$hashedPassword = password_hash($rawPassword, PASSWORD_ARGON2ID);
$stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password)");
$stmt->execute([
    ':username' => $username,
    ':email'    => $email,
    ':password' => $hashedPassword,
]);

// [B] LOGIN USER (Prepared Statement + Timing-Safe Verification)
$stmt = $pdo->prepare("SELECT id, username, password_hash, role FROM users WHERE email = :email LIMIT 1");
$stmt->execute([':email' => $email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user && password_verify($rawPassword, $user['password_hash'])) {
    // Login berhasil - regenerasi session ID untuk cegah Session Fixation
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
} else {
    // Berikan pesan kesalahan generik untuk cegah User Enumeration
    $error = "Email atau password tidak valid.";
}


2. Node.js (mysql2 / pg) - Login & Register Aman:
--------------------------------------------------------------------------------
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// [A] REGISTRASI
const hash = await bcrypt.hash(password, SALT_ROUNDS);
await db.query(
  'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
  [username, email, hash]
);

// [B] LOGIN
const result = await db.query(
  'SELECT id, username, password_hash FROM users WHERE email = $1 LIMIT 1',
  [email]
);
if (result.rows.length > 0) {
  const match = await bcrypt.compare(password, result.rows[0].password_hash);
  if (match) {
    // Generate secure JWT / Session
  }
}


3. Python (SQLite3 / psycopg2) - Login & Register Aman:
--------------------------------------------------------------------------------
import bcrypt

# [A] REGISTRASI
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
cursor.execute(
    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
    (username, email, hashed)
)
conn.commit()

# [B] LOGIN
cursor.execute(
    "SELECT id, password_hash FROM users WHERE email = %s LIMIT 1",
    (email,)
)
row = cursor.fetchone()
if row and bcrypt.checkpw(password.encode('utf-8'), row[1].encode('utf-8')):
    # Login berhasil
    pass
================================================================================
"""
    print(recipe)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQL & Authentication Backend Auditor (Login, Register & Password Security)"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Command: audit
    p_audit = subparsers.add_parser("audit", help="Audit direktori atau file terhadap SQL Injection & Hash security")
    p_audit.add_argument("path", help="Path direktori atau file target backend")
    p_audit.add_argument(
        "--ext",
        nargs="+",
        default=[".php", ".js", ".ts", ".py"],
        help="Ekstensi file yang diaudit (default: .php .js .ts .py)",
    )

    # Command: remediate
    p_remedy = subparsers.add_parser("remediate", help="Tampilkan template kode aman (Prepared Statements & Argon2/Bcrypt)")

    args = parser.parse_args()

    if args.command == "audit":
        scan_directory(args.path, args.ext)
    elif args.command == "remediate":
        print_remediation_recipes()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
