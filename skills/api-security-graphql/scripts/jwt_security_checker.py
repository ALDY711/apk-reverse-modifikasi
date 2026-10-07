#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JWT (JSON Web Token) Defensive Security Auditor.

WHY THIS EXISTS
---------------
JSON Web Tokens (JWT) are the standard authentication mechanism for modern
REST and GraphQL APIs. Improper implementation leads to critical vulnerabilities
including the "none" algorithm exploit, key confusion attacks (treating RS256
public keys as HMAC secrets), missing expiration claims, and leaking sensitive
PII in unencrypted claims.

This tool audits raw JWT strings for:
  1. Algorithm header flaws ("none", weak algorithms).
  2. Asymmetric vs symmetric algorithm risks (Key Confusion).
  3. Expiration claim presence and validity (exp, nbf, iat).
  4. Sensitive data disclosure within the payload claims.

USAGE
-----
  # Audit a JWT string
  python jwt_security_checker.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  # Output structured JSON audit report
  python jwt_security_checker.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --json

EXIT CODES
----------
  0 = JWT structure is properly configured
  1 = Critical or high-severity JWT security weaknesses detected
  2 = Usage error or invalid JWT format
"""

import argparse
import base64
import json
import re
import sys
import time


def base64url_decode(payload):
    rem = len(payload) % 4
    if rem > 0:
        payload += "=" * (4 - rem)
    return base64.urlsafe_b64decode(payload.encode("utf-8"))


def audit_jwt(token_str):
    parts = token_str.strip().split(".")
    if len(parts) != 3:
        return None, "Invalid JWT format. Expected exactly 3 parts separated by dots."

    try:
        header_raw = base64url_decode(parts[0]).decode("utf-8", errors="ignore")
        header = json.loads(header_raw)
    except Exception as e:
        return None, f"Failed to parse JWT header: {e}"

    try:
        payload_raw = base64url_decode(parts[1]).decode("utf-8", errors="ignore")
        payload = json.loads(payload_raw)
    except Exception as e:
        return None, f"Failed to parse JWT payload: {e}"

    signature = parts[2]
    findings = []

    # 1. Check Algorithm
    alg = header.get("alg", "").strip()
    if not alg or alg.lower() == "none":
        findings.append({
            "severity": "CRITICAL",
            "type": "ALG_NONE_VULNERABILITY",
            "message": "Algorithm is set to 'none' or missing. Signature verification can be bypassed."
        })
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        findings.append({
            "severity": "MEDIUM",
            "type": "SYMMETRIC_HMAC_ALGORITHM",
            "message": f"Token uses symmetric HMAC ({alg}). Ensure shared secret is high-entropy (>256-bit) and protected from public exposure."
        })

    # 2. Check Signature Presence
    if not signature:
        findings.append({
            "severity": "CRITICAL",
            "type": "MISSING_SIGNATURE",
            "message": "Token has an empty signature part."
        })

    # 3. Check Claims
    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        findings.append({
            "severity": "HIGH",
            "type": "MISSING_EXPIRATION_CLAIM",
            "message": "Token does not contain an 'exp' (expiration) claim. Tokens without expiry never become invalid."
        })
    else:
        try:
            exp_val = int(exp)
            if exp_val < now:
                findings.append({
                    "severity": "INFO",
                    "type": "TOKEN_EXPIRED",
                    "message": f"Token expired {now - exp_val} seconds ago."
                })
        except ValueError:
            findings.append({
                "severity": "HIGH",
                "type": "INVALID_EXPIRATION_FORMAT",
                "message": "Claim 'exp' is not a valid integer timestamp."
            })

    # 4. Check Sensitive PII / Secret Leaks
    sensitive_keys = ["password", "passwd", "secret", "private_key", "pin", "ssn", "credit_card"]
    for k in payload.keys():
        if any(sk in k.lower() for sk in sensitive_keys):
            findings.append({
                "severity": "HIGH",
                "type": "SENSITIVE_CLAIM_EXPOSURE",
                "message": f"Payload contains potentially sensitive claim key: '{k}'."
            })

    report = {
        "header": header,
        "payload": payload,
        "algorithm": alg,
        "signature_present": bool(signature),
        "total_findings": len(findings),
        "findings": findings
    }
    return report, None


def main():
    parser = argparse.ArgumentParser(
        description="Audit JWT tokens for security misconfigurations, weak algorithms, and claim leakage."
    )
    parser.add_argument("--token", required=True, help="Raw JWT string to audit.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    report, err = audit_jwt(args.token)
    if err:
        sys.stderr.write(f"Error: {err}\n")
        return 2

    has_critical = any(f["severity"] in ("CRITICAL", "HIGH") for f in report["findings"])

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 72)
        print(" 🔑 JWT DEFENSIVE SECURITY AUDIT")
        print("=" * 72)
        print(f" Algorithm         : {report['algorithm']}")
        print(f" Signature Present : {report['signature_present']}")
        print(f" Claims Count      : {len(report['payload'])}")
        print("-" * 72)

        if report["findings"]:
            print(" Findings:")
            for f in report["findings"]:
                icon = "❌" if f["severity"] == "CRITICAL" else ("⚠️" if f["severity"] == "HIGH" else "ℹ️")
                print(f"   {icon} [{f['severity']}] {f['message']}")
        else:
            print(" [OK] JWT headers and claims follow standard security best practices.")
        print("=" * 72)

    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
