#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mobile Cryptography Static Pattern Scanner.

WHY THIS EXISTS
---------------
Android applications frequently suffer from cryptographic vulnerabilities such
as insecure cipher modes (AES/ECB), hardcoded encryption keys, static or zero
Initialization Vectors (IVs), and deprecated hashing algorithms (MD5, SHA-1).

This scanner analyzes smali, Java, or Kotlin source files for insecure
cryptographic constructs, flagging violations of OWASP Mobile Application
Security Verification Standard (MASVS-CRYPTO).

USAGE
-----
  # Scan a folder of decompiled smali or source files
  python crypto_smali_scanner.py --dir ./smali_classes

  # Scan a single source file
  python crypto_smali_scanner.py --file MainActivity.smali

  # Output machine-readable JSON
  python crypto_smali_scanner.py --dir ./smali_classes --json

EXIT CODES
----------
  0 = Clean; no insecure cryptographic patterns detected
  1 = High or critical cryptographic weaknesses detected
  2 = Usage error or invalid input arguments
"""

import argparse
import json
import os
import re
import sys

WEAK_CIPHER_PATTERNS = [
    {
        "id": "CRYPTO-01-ECB-MODE",
        "severity": "CRITICAL",
        "regex": re.compile(r'["\'](?:AES|DES|DESede)/ECB/(?:PKCS5Padding|NoPadding|PKCS7Padding)["\']|Cipher\.getInstance\(["\']AES["\']\)', re.IGNORECASE),
        "title": "Insecure AES/ECB Cipher Mode Detected",
        "description": "ECB mode does not provide semantic security; identical plaintext blocks encrypt to identical ciphertext blocks.",
        "remediation": "Replace with AES/GCM/NoPadding using an authenticated 128-bit authentication tag."
    },
    {
        "id": "CRYPTO-02-DES-ALGORITHM",
        "severity": "CRITICAL",
        "regex": re.compile(r'["\'](?:DES|DESede|TripleDES|RC2|RC4|Blowfish)["\']', re.IGNORECASE),
        "title": "Deprecated / Weak Encryption Algorithm",
        "description": "Legacy symmetric ciphers like DES, 3DES, or RC4 are vulnerable to brute-force and known cryptanalytic attacks.",
        "remediation": "Migrate to AES-256 or ChaCha20-Poly1305."
    },
    {
        "id": "CRYPTO-03-WEAK-HASH",
        "severity": "HIGH",
        "regex": re.compile(r'MessageDigest\.getInstance\(["\'](?:MD5|MD4|MD2|SHA-?1)["\']\)', re.IGNORECASE),
        "title": "Broken / Weak Hash Algorithm (MD5 / SHA-1)",
        "description": "MD5 and SHA-1 suffer from practical collision attacks and should never be used for security-critical integrity or signatures.",
        "remediation": "Use SHA-256, SHA-384, or SHA-512 for hashing."
    },
    {
        "id": "CRYPTO-04-HARDCODED-KEY",
        "severity": "CRITICAL",
        "regex": re.compile(r'new\s+SecretKeySpec\(\s*["\'][A-Za-z0-9+/=]{8,}["\']\.getBytes\(|const-string\s+[vp]\d+,\s*["\'][0-9a-fA-F]{16,32}["\'][\s\S]{1,100}SecretKeySpec', re.MULTILINE),
        "title": "Hardcoded Cryptographic Secret Key",
        "description": "Hardcoded symmetric keys embedded in APK binaries can be easily extracted by reverse engineering.",
        "remediation": "Store encryption keys inside the hardware-backed Android KeyStore provider."
    },
    {
        "id": "CRYPTO-05-STATIC-IV",
        "regex": re.compile(r'new\s+IvParameterSpec\(\s*new\s+byte\[\s*\]\s*\{[^}]{0,80}\}\s*\)|new\s+IvParameterSpec\(\s*["\'][^"\']{8,16}["\']\.getBytes\(', re.IGNORECASE),
        "severity": "HIGH",
        "title": "Static / Hardcoded Initialization Vector (IV)",
        "description": "Reusing fixed IVs breaks confidentiality in modes like CBC and enables plaintext recovery in GCM/CTR modes.",
        "remediation": "Generate unique cryptographic IVs dynamically using SecureRandom for every encryption call."
    },
    {
        "id": "CRYPTO-06-INSECURE-PRNG",
        "regex": re.compile(r'java\.util\.Random|new\s+SecureRandom\(\s*byte\[\]\s*|\.setSeed\(\s*\d+\s*\)', re.IGNORECASE),
        "severity": "MEDIUM",
        "title": "Insecure / Predictable Random Number Generation",
        "description": "Using java.util.Random or seeding SecureRandom with static values produces predictable cryptographic material.",
        "remediation": "Use java.security.SecureRandom with default OS entropy seeding."
    }
]


def scan_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return findings

    for rule in WEAK_CIPHER_PATTERNS:
        matches = rule["regex"].finditer(content)
        for m in matches:
            line_num = content[:m.start()].count("\n") + 1
            snippet = m.group(0).strip()
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "file": file_path,
                "line": line_num,
                "snippet": snippet,
                "remediation": rule["remediation"]
            })
    return findings


def scan_directory(dir_path):
    all_findings = []
    valid_exts = {".smali", ".java", ".kt", ".txt", ".json"}
    for root, _, files in os.walk(dir_path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in valid_exts:
                full_path = os.path.join(root, f)
                findings = scan_file(full_path)
                all_findings.extend(findings)
    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Mobile Cryptography Static Pattern Scanner for Android Smali and Source Files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir", help="Path to directory containing smali or source files to scan.")
    group.add_argument("--file", help="Path to a single file to scan.")
    parser.add_argument("--json", action="store_true", help="Output results in structured JSON format.")

    args = parser.parse_args()

    target_path = args.dir if args.dir else args.file
    if not os.path.exists(target_path):
        sys.stderr.write(f"Error: Target path '{target_path}' does not exist.\n")
        return 2

    if args.dir:
        findings = scan_directory(args.dir)
    else:
        findings = scan_file(args.file)

    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

    if args.json:
        report = {
            "target": target_path,
            "total_findings": len(findings),
            "summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count
            },
            "findings": findings
        }
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🔍 MOBILE CRYPTOGRAPHY AUDIT REPORT")
        print("=" * 72)
        print(f" Target: {target_path}")
        print(f" Findings: Total={len(findings)} (Critical={critical_count}, High={high_count}, Medium={medium_count})\n")

        if not findings:
            print(" [OK] No insecure cryptographic patterns detected.")
        else:
            for idx, item in enumerate(findings, 1):
                print(f" [{idx}] [{item['severity']}] {item['title']} ({item['rule_id']})")
                print(f"     File   : {item['file']}:{item['line']}")
                print(f"     Snippet: {item['snippet']}")
                print(f"     Fix    : {item['remediation']}")
                print("-" * 72)

    return 1 if (critical_count > 0 or high_count > 0) else 0


if __name__ == "__main__":
    sys.exit(main())
