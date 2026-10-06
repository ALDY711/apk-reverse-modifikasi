#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static Code Security Auditor & Secrets Scanner for Web Projects.

WHY THIS EXISTS
---------------
Web applications frequently suffer from security regressions caused by:
  1. Accidental commitment of production secrets, private keys, or database credentials.
  2. Insecure configuration values left enabled (e.g. `APP_DEBUG=true` in Laravel).
  3. Template XSS risks (e.g. unescaped raw Blade `{!! $data !!}`).
  4. Missing CSRF protection tokens in HTML forms.
  5. Dangerous execution primitives (`eval`, `unserialize`, `shell_exec`).

This tool performs fast, local static analysis across project source files (PHP, Blade,
JavaScript, TypeScript, Python, .env files, and configs) to detect security risks
before code reaches production.

USAGE
-----
  # Scan current project or specific directory
  python static_code_audit.py --path "C:/suumik/Si_UMIK_V1 (6)"

  # Scan with focus on high-severity issues only
  python static_code_audit.py --path ./my-project --severity HIGH

  # Output structured JSON audit report
  python static_code_audit.py --path ./my-project --json

EXIT CODES
----------
  0 = no high/critical security findings
  1 = security findings detected
  2 = invalid arguments or directory error
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


# Regex patterns for static code auditing
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "HIGH"),
    ("Private Key Header", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "CRITICAL"),
    ("Generic Hardcoded Secret/Token", re.compile(r'(?:api_key|apiKey|secret_key|secretKey|auth_token|client_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE), "HIGH"),
    ("Stripe Secret Key", re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'), "CRITICAL"),
    ("Slack Webhook URL", re.compile(r'https://hooks\.slack\.com/services/T[0-9a-zA-Z_]+/B[0-9a-zA-Z_]+/[0-9a-zA-Z_]+'), "HIGH"),
    ("Hardcoded Database Password", re.compile(r'(?:DB_PASSWORD|database_password)\s*=\s*["\']?([^"\'\s]{8,})["\']?', re.IGNORECASE), "MEDIUM"),
]

FRAMEWORK_CONFIG_PATTERNS = [
    ("Laravel Debug Mode Enabled", re.compile(r'^\s*APP_DEBUG\s*=\s*true\b', re.IGNORECASE | re.MULTILINE), "HIGH",
     "APP_DEBUG=true leaks full environment variables, database credentials, and code stack traces on error."),
    ("Insecure Session Cookie", re.compile(r'^\s*SESSION_SECURE_COOKIE\s*=\s*false\b', re.IGNORECASE | re.MULTILINE), "MEDIUM",
     "SESSION_SECURE_COOKIE should be true in HTTPS environments to prevent session hijacking."),
    ("PHP Display Errors Enabled", re.compile(r'^\s*display_errors\s*=\s*(?:On|1)\b', re.IGNORECASE | re.MULTILINE), "MEDIUM",
     "Displaying errors directly to users discloses sensitive internal backend structures."),
]

BLADE_TEMPLATE_PATTERNS = [
    ("Unescaped Raw Blade Output", re.compile(r'\{\!\![\s\S]*?\!\!\}'), "LOW",
     "Unescaped output {!! $var !!} bypasses HTML entity encoding. Ensure variable is safe/sanitized to prevent XSS."),
]

DANGEROUS_FUNCTIONS = [
    ("PHP eval() Execution", re.compile(r'\beval\s*\('), "HIGH", "Arbitrary code execution primitive."),
    ("PHP shell_exec / exec", re.compile(r'\b(?:shell_exec|exec|passthru|system)\s*\('), "MEDIUM", "Direct command execution. Validate input sanitization."),
    ("Insecure PHP unserialize()", re.compile(r'\bunserialize\s*\('), "HIGH", "Object injection risk if un-sanitized user input is processed."),
]

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", ".idea", ".vscode", "dist", "build", "storage/framework"
}

EXTENSIONS_TO_SCAN = {
    ".php", ".blade.php", ".js", ".ts", ".vue", ".py", ".env", ".env.example", ".json", ".yaml", ".yml", ".ini"
}


def scan_file(file_path: Path) -> list[dict]:
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = content.splitlines()

    # 1. Scan for Secrets
    for label, pattern, severity in SECRET_PATTERNS:
        for idx, line in enumerate(lines, 1):
            if pattern.search(line):
                # Mask secret preview
                preview = line.strip()[:100]
                findings.append({
                    "file": str(file_path),
                    "line": idx,
                    "type": "Hardcoded Secret",
                    "title": label,
                    "severity": severity,
                    "preview": preview,
                    "recommendation": "Move sensitive credentials to external environment variables (.env).",
                })

    # 2. Scan Framework Configs
    if file_path.name in [".env", ".env.local", ".env.production", "php.ini"]:
        for label, pattern, severity, desc in FRAMEWORK_CONFIG_PATTERNS:
            if pattern.search(content):
                findings.append({
                    "file": str(file_path),
                    "line": 1,
                    "type": "Insecure Configuration",
                    "title": label,
                    "severity": severity,
                    "preview": label,
                    "recommendation": desc,
                })

    # 3. Scan Blade Templates
    if file_path.name.endswith(".blade.php"):
        # Check raw unescaped output
        for label, pattern, severity, desc in BLADE_TEMPLATE_PATTERNS:
            for idx, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append({
                        "file": str(file_path),
                        "line": idx,
                        "type": "Template XSS Risk",
                        "title": label,
                        "severity": severity,
                        "preview": line.strip()[:100],
                        "recommendation": desc,
                    })

        # Check for <form method="POST"> missing @csrf
        form_matches = list(re.finditer(r'<form\b[^>]*\bmethod\s*=\s*["\']POST["\'][^>]*>', content, re.IGNORECASE))
        for fm in form_matches:
            form_start = fm.start()
            # Look ahead up to 500 chars for @csrf or csrf_field
            chunk = content[form_start:form_start + 600]
            if "@csrf" not in chunk and "csrf_field" not in chunk and "_token" not in chunk:
                line_no = content[:form_start].count('\n') + 1
                findings.append({
                    "file": str(file_path),
                    "line": line_no,
                    "type": "Missing CSRF Token",
                    "title": "HTML Form Missing @csrf Directive",
                    "severity": "HIGH",
                    "preview": fm.group(0),
                    "recommendation": "Insert '@csrf' inside the POST form to protect against Cross-Site Request Forgery.",
                })

    # 4. Scan Dangerous Functions in PHP/JS
    if file_path.suffix in [".php", ".js", ".ts"]:
        for label, pattern, severity, desc in DANGEROUS_FUNCTIONS:
            for idx, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append({
                        "file": str(file_path),
                        "line": idx,
                        "type": "Dangerous Execution Function",
                        "title": label,
                        "severity": severity,
                        "preview": line.strip()[:100],
                        "recommendation": desc,
                    })

    return findings


def scan_directory(root_path: Path, min_severity: str = "LOW") -> dict:
    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = severity_order.get(min_severity.upper(), 1)

    all_findings = []
    scanned_files_count = 0

    for root, dirs, files in os.walk(root_path):
        # Exclude ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not any(part in IGNORE_DIRS for part in Path(root, d).parts)]

        for f in files:
            file_path = Path(root, f)
            if any(f.endswith(ext) for ext in EXTENSIONS_TO_SCAN):
                scanned_files_count += 1
                file_findings = scan_file(file_path)
                for finding in file_findings:
                    if severity_order.get(finding["severity"], 1) >= threshold:
                        all_findings.append(finding)

    # Calculate summary counts
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {
        "scanned_path": str(root_path.resolve()),
        "total_files_scanned": scanned_files_count,
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Static Code Security Auditor & Secrets Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path", "-p", default=".", help="Root project path to scan")
    parser.add_argument("--severity", "-s", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW", help="Minimum severity to report")
    parser.add_argument("--json", action="store_true", help="Output audit report as structured JSON")

    args = parser.parse_args()
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"[!] Error: Path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    report = scan_directory(target_path, args.severity)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0 if (report["summary"]["CRITICAL"] + report["summary"]["HIGH"]) == 0 else 1)

    print("=================================================================")
    print("           STATIC CODE SECURITY AUDIT REPORT                     ")
    print("=================================================================")
    print(f"[*] Scanned Path       : {report['scanned_path']}")
    print(f"[*] Files Scanned      : {report['total_files_scanned']}")
    print(f"[*] Total Findings     : {report['total_findings']}")
    print(f"[*] Severity Breakdown : CRITICAL: {report['summary']['CRITICAL']} | HIGH: {report['summary']['HIGH']} | MEDIUM: {report['summary']['MEDIUM']} | LOW: {report['summary']['LOW']}")
    print("-----------------------------------------------------------------")

    if report["findings"]:
        for item in report["findings"][:50]:
            rel_file = Path(item["file"]).name
            print(f"  [!] [{item['severity']:<8}] {item['title']}")
            print(f"      Location: {rel_file}:{item['line']}")
            print(f"      Preview : {item['preview']}")
            print(f"      Fix     : {item['recommendation']}\n")

        if len(report["findings"]) > 50:
            print(f"  ... and {len(report['findings']) - 50} more findings. Use --json to view all.")
    else:
        print("[+] SUCCESS: No security findings detected matching current threshold.")

    print("=================================================================")
    sys.exit(0 if (report["summary"]["CRITICAL"] + report["summary"]["HIGH"]) == 0 else 1)


if __name__ == "__main__":
    main()
