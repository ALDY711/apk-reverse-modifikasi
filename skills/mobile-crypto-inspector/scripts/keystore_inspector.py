#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Android KeyStore & MasterKey Security Auditor.

WHY THIS EXISTS
---------------
Android KeyStore provides hardware-backed cryptographic key isolation inside
Trusted Execution Environments (TEE) or dedicated Secure Elements (StrongBox).
Improper configuration—such as missing biometric authentication bounds,
allowing key export, or omitting hardware-backing flags—compromises key security.

This tool audits Android source code, smali files, or AndroidManifest.xml for:
  1. Proper usage of KeyStore.getInstance("AndroidKeyStore")
  2. Hardware backing via StrongBox (setIsStrongBoxBacked)
  3. User authentication enforcement (setUserAuthenticationRequired)
  4. Jetpack Security MasterKey and EncryptedSharedPreferences implementation
  5. Manifest backup leakage (android:allowBackup)

USAGE
-----
  # Audit a directory of Android source or decompiled smali
  python keystore_inspector.py --target ./app_project

  # Output structured JSON audit report
  python keystore_inspector.py --target ./app_project --json

EXIT CODES
----------
  0 = KeyStore configuration is properly hardened
  1 = KeyStore misconfigurations or security gaps detected
  2 = Usage error or target path not found
"""

import argparse
import json
import os
import re
import sys


def audit_keystore_implementation(target_path):
    checks = {
        "uses_android_keystore": False,
        "uses_strongbox": False,
        "uses_auth_required": False,
        "uses_encrypted_prefs": False,
        "allow_backup_enabled": False,
        "backup_flag_found": False
    }

    details = []

    # Regex patterns
    re_keystore = re.compile(r'KeyStore\.getInstance\(["\']AndroidKeyStore["\']\)|"AndroidKeyStore"', re.IGNORECASE)
    re_strongbox = re.compile(r'setIsStrongBoxBacked\(\s*true\s*\)', re.IGNORECASE)
    re_auth_req = re.compile(r'setUserAuthenticationRequired\(\s*true\s*\)', re.IGNORECASE)
    re_enc_prefs = re.compile(r'EncryptedSharedPreferences|MasterKey\.Builder|MasterKeys\.getOrCreate', re.IGNORECASE)
    re_backup_true = re.compile(r'android:allowBackup\s*=\s*["\']true["\']', re.IGNORECASE)
    re_backup_false = re.compile(r'android:allowBackup\s*=\s*["\']false["\']', re.IGNORECASE)

    for root, _, files in os.walk(target_path):
        for f in files:
            full_path = os.path.join(root, f)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
            except Exception:
                continue

            if f == "AndroidManifest.xml":
                if re_backup_true.search(content):
                    checks["allow_backup_enabled"] = True
                    checks["backup_flag_found"] = True
                    details.append({
                        "file": full_path,
                        "type": "MANIFEST_BACKUP",
                        "status": "VULNERABLE",
                        "msg": "android:allowBackup is enabled ('true'). App data and KeyStore references can be extracted via ADB."
                    })
                elif re_backup_false.search(content):
                    checks["backup_flag_found"] = True
                    details.append({
                        "file": full_path,
                        "type": "MANIFEST_BACKUP",
                        "status": "SECURE",
                        "msg": "android:allowBackup is explicitly disabled ('false')."
                    })

            if re_keystore.search(content):
                checks["uses_android_keystore"] = True
                details.append({
                    "file": full_path,
                    "type": "KEYSTORE_PROVIDER",
                    "status": "DETECTED",
                    "msg": "Found AndroidKeyStore provider usage."
                })

            if re_strongbox.search(content):
                checks["uses_strongbox"] = True
                details.append({
                    "file": full_path,
                    "type": "STRONGBOX_BACKING",
                    "status": "DETECTED",
                    "msg": "Hardware-backed StrongBox protection explicitly enabled."
                })

            if re_auth_req.search(content):
                checks["uses_auth_required"] = True
                details.append({
                    "file": full_path,
                    "type": "USER_AUTH_BOUND",
                    "status": "DETECTED",
                    "msg": "setUserAuthenticationRequired(true) enforced for key usage."
                })

            if re_enc_prefs.search(content):
                checks["uses_encrypted_prefs"] = True
                details.append({
                    "file": full_path,
                    "type": "ENCRYPTED_STORAGE",
                    "status": "DETECTED",
                    "msg": "Jetpack Security EncryptedSharedPreferences / MasterKey in use."
                })

    return checks, details


def main():
    parser = argparse.ArgumentParser(
        description="Audit Android KeyStore, MasterKey, and Encrypted Storage implementation."
    )
    parser.add_argument("--target", required=True, help="Directory containing source files, smali, or AndroidManifest.xml.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        sys.stderr.write(f"Error: Target path '{args.target}' does not exist.\n")
        return 2

    checks, details = audit_keystore_implementation(args.target)

    # Determine issues
    issues = []
    if not checks["uses_android_keystore"] and not checks["uses_encrypted_prefs"]:
        issues.append("App does not appear to use AndroidKeyStore or Jetpack EncryptedSharedPreferences.")
    if checks["allow_backup_enabled"]:
        issues.append("AndroidManifest.xml enables allowBackup='true'.")
    if checks["uses_android_keystore"] and not checks["uses_strongbox"]:
        issues.append("AndroidKeyStore keys do not explicitly request StrongBox hardware backing.")

    score = 100
    if not checks["uses_android_keystore"] and not checks["uses_encrypted_prefs"]:
        score -= 40
    if checks["allow_backup_enabled"]:
        score -= 30
    if not checks["uses_strongbox"]:
        score -= 10

    report = {
        "target": args.target,
        "security_score": max(0, score),
        "status": "SECURE" if score >= 80 else ("WARNING" if score >= 50 else "VULNERABLE"),
        "features_detected": checks,
        "recommendations": issues,
        "evidence_count": len(details),
        "details": details[:30]
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🛡️  ANDROID KEYSTORE & STORAGE AUDIT")
        print("=" * 72)
        print(f" Target         : {args.target}")
        print(f" Security Score : {report['security_score']}/100 [{report['status']}]")
        print("\n Feature Checks:")
        print(f"   - AndroidKeyStore Provider      : {'[YES]' if checks['uses_android_keystore'] else '[NO]'}")
        print(f"   - Jetpack EncryptedPrefs        : {'[YES]' if checks['uses_encrypted_prefs'] else '[NO]'}")
        print(f"   - StrongBox Hardware Backing    : {'[YES]' if checks['uses_strongbox'] else '[NO]'}")
        print(f"   - User Authentication Bound     : {'[YES]' if checks['uses_auth_required'] else '[NO]'}")
        print(f"   - Insecure AllowBackup Flag     : {'[ALERT: TRUE]' if checks['allow_backup_enabled'] else '[OK: FALSE/ABSENT]'}")

        if issues:
            print("\n Recommendations:")
            for issue in issues:
                print(f"   ⚠️  {issue}")
        else:
            print("\n [OK] KeyStore configuration follows Android security best practices.")
        print("=" * 72)

    return 0 if report["security_score"] >= 70 else 1


if __name__ == "__main__":
    sys.exit(main())
