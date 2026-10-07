#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mobile Encrypted Storage & Local Database Auditor.

WHY THIS EXISTS
---------------
Mobile applications frequently cache sensitive user credentials, auth tokens,
and PII locally. Leaving SQLite databases unencrypted or storing sensitive
data in standard SharedPreferences XML files exposes user data if a device is
rooted or backed up.

This tool audits local data directories, SQLite files, and XML preferences for:
  1. Plaintext SQLite database headers vs SQLCipher encryption.
  2. Unencrypted SharedPreferences holding auth tokens or passwords.
  3. Proper androidx.security.crypto encryption markers.

USAGE
-----
  # Audit an extracted /data/data/<pkg> directory
  python encrypted_storage_audit.py --path ./data_dir

  # Check a specific database file
  python encrypted_storage_audit.py --file app_data.db

  # Output JSON report
  python encrypted_storage_audit.py --path ./data_dir --json

EXIT CODES
----------
  0 = All local storage artifacts are properly encrypted
  1 = Unencrypted databases or plaintext secrets detected
  2 = Usage error or path does not exist
"""

import argparse
import json
import os
import re
import sys

SQLITE_HEADER = b"SQLite format 3\x00"

SENSITIVE_KEY_PATTERNS = re.compile(
    r'(password|passwd|token|auth_key|access_token|refresh_token|secret|private_key|pin|session_id)',
    re.IGNORECASE
)


def inspect_db_file(db_path):
    result = {
        "file": db_path,
        "is_database": False,
        "is_encrypted": True,
        "type": "UNKNOWN"
    }

    try:
        with open(db_path, "rb") as f:
            header = f.read(16)
            if header == SQLITE_HEADER:
                result["is_database"] = True
                result["is_encrypted"] = False
                result["type"] = "PLAINTEXT_SQLITE"
            elif len(header) >= 16:
                result["is_database"] = True
                result["is_encrypted"] = True
                result["type"] = "ENCRYPTED_SQLCIPHER_OR_BLOB"
    except Exception:
        pass
    return result


def inspect_xml_shared_prefs(xml_path):
    findings = []
    try:
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        is_jetpack_encrypted = "__androidx_security_crypto" in content

        for line_num, line in enumerate(content.splitlines(), 1):
            match = SENSITIVE_KEY_PATTERNS.search(line)
            if match and not is_jetpack_encrypted:
                findings.append({
                    "file": xml_path,
                    "line": line_num,
                    "keyword": match.group(0),
                    "is_encrypted": False,
                    "snippet": line.strip()[:80]
                })
    except Exception:
        pass
    return findings


def audit_storage_directory(dir_path):
    db_results = []
    pref_findings = []

    for root, _, files in os.walk(dir_path):
        for f in files:
            full_path = os.path.join(root, f)
            lower = f.lower()

            if lower.endswith((".db", ".sqlite", ".sqlite3")) or "database" in root.lower():
                db_info = inspect_db_file(full_path)
                if db_info["is_database"]:
                    db_results.append(db_info)

            elif lower.endswith(".xml") and ("shared_prefs" in root.lower() or "pref" in lower):
                pref_hits = inspect_xml_shared_prefs(full_path)
                pref_findings.extend(pref_hits)

    return db_results, pref_findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit mobile SQLite databases and SharedPreferences for encryption and secret leaks."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", help="Directory containing app storage files (/data/data/<pkg>).")
    group.add_argument("--file", help="Path to a single SQLite database file.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    target = args.path if args.path else args.file
    if not os.path.exists(target):
        sys.stderr.write(f"Error: Target '{target}' not found.\n")
        return 2

    if args.file:
        db_res = inspect_db_file(args.file)
        db_results = [db_res]
        pref_findings = []
    else:
        db_results, pref_findings = audit_storage_directory(args.path)

    unencrypted_dbs = [db for db in db_results if not db["is_encrypted"]]
    has_issues = len(unencrypted_dbs) > 0 or len(pref_findings) > 0

    report = {
        "target": target,
        "unencrypted_database_count": len(unencrypted_dbs),
        "plaintext_preference_findings": len(pref_findings),
        "database_audit": db_results,
        "preference_audit": pref_findings
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🗄️  MOBILE ENCRYPTED STORAGE AUDIT")
        print("=" * 72)
        print(f" Target: {target}")
        print(f" Databases Audited  : {len(db_results)} ({len(unencrypted_dbs)} unencrypted)")
        print(f" Sensitive XML Hits : {len(pref_findings)}")
        print("-" * 72)

        if unencrypted_dbs:
            print(" [ALERT] Unencrypted SQLite Databases Detected:")
            for db in unencrypted_dbs:
                print(f"   ❌ {db['file']} -> Standard plaintext SQLite format!")
        else:
            print(" [OK] No plaintext SQLite database headers found.")

        if pref_findings:
            print("\n [ALERT] Sensitive Plaintext Values in SharedPreferences:")
            for pf in pref_findings[:10]:
                print(f"   ⚠️ {pf['file']}:{pf['line']} (Key: {pf['keyword']})")
                print(f"      Snippet: {pf['snippet']}")
        else:
            print(" [OK] No plaintext secrets detected in SharedPreferences.")
        print("=" * 72)

    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
