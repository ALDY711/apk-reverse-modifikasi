#!/usr/bin/env python3
"""
scripts/csrf_audit.py - Cross-Site Request Forgery (CSRF) & State-Change Auditor

Alat audit komprehensif untuk memeriksa kepatuhan proteksi Cross-Site Request
Forgery (CSRF) pada aplikasi web modern, baik melalui URL hidup (Live Dynamic Audit)
maupun analisis statis template (Blade, Jinja, HTML, Vue, React).

Fitur:
- Deteksi form HTML dengan method POST/PUT/DELETE yang tidak memiliki token CSRF.
- Deteksi tindakan perubahan state sensitif (Logout, Delete, Update) yang salah diimplementasikan via GET (<a href="...">).
- Pengecekan meta tag <meta name="csrf-token"> untuk request AJAX / SPA.
- Audit atribut SameSite dan Secure pada cookie sesi dari target hidup.
- Ekspor hasil analisis ke format JSON atau visualisasi konsol terstruktur.

Penggunaan:
  python csrf_audit.py --url http://127.0.0.1:8000
  python csrf_audit.py --path /path/to/project/resources/views
  python csrf_audit.py --url https://example.com --json csrf_report.json
"""

import os
import sys
import re
import json
import argparse
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Optional

STATE_CHANGING_KEYWORDS = [
    "delete", "hapus", "destroy", "remove",
    "logout", "keluar", "signout",
    "update", "ubah", "edit",
    "create", "tambah", "store",
    "approve", "setujui", "reject", "tolak",
    "reset-password", "transfer", "pay", "bayar"
]

IGNORED_DIRECTORIES = {
    "node_modules", "vendor", ".git", "storage", ".idea", ".vscode", "dist", "build"
}


def audit_live_url(target_url: str) -> Dict[str, Any]:
    """Mengaudit URL aplikasi yang sedang berjalan untuk proteksi CSRF dan Cookie Flags."""
    result = {
        "target": target_url,
        "mode": "live",
        "has_csrf_meta": False,
        "csrf_meta_content": None,
        "forms_inspected": 0,
        "unprotected_forms": [],
        "risky_get_links": [],
        "session_cookies": [],
        "vulnerabilities": []
    }

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "CSRF-Audit-Scanner/1.0 (+DefensiveSecurityCheck)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode("utf-8", errors="ignore")
            headers = dict(response.info())
            cookie_headers = response.info().get_all("Set-Cookie") or []
    except Exception as e:
        return {"error": f"Gagal menghubungi target '{target_url}': {e}"}

    # 1. Audit Cookie Flags
    for cookie_str in cookie_headers:
        cookie_parts = [p.strip() for p in cookie_str.split(";")]
        name_val = cookie_parts[0]
        cookie_name = name_val.split("=")[0] if "=" in name_val else name_val
        lower_parts = [p.lower() for p in cookie_parts]

        has_httponly = "httponly" in lower_parts
        has_secure = "secure" in lower_parts
        samesite = "None"
        for p in cookie_parts:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1]

        cookie_info = {
            "name": cookie_name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite
        }
        result["session_cookies"].append(cookie_info)

        if samesite == "None" and not has_secure:
            result["vulnerabilities"].append({
                "type": "INSECURE_COOKIE_SAMESITE",
                "severity": "HIGH",
                "detail": f"Cookie '{cookie_name}' memiliki SameSite=None tanpa flag Secure!"
            })
        elif samesite == "None":
            result["vulnerabilities"].append({
                "type": "WEAK_COOKIE_SAMESITE",
                "severity": "MEDIUM",
                "detail": f"Cookie '{cookie_name}' memiliki SameSite=None (Rentan terhadap serangan cross-site jika tanpa proteksi token CSRF)."
            })

    # 2. Audit Meta Tag CSRF
    meta_match = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if not meta_match:
        meta_match = re.search(r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']', html, re.IGNORECASE)

    if meta_match:
        result["has_csrf_meta"] = True
        result["csrf_meta_content"] = meta_match.group(1)[:10] + "..."
    else:
        result["vulnerabilities"].append({
            "type": "MISSING_CSRF_META",
            "severity": "MEDIUM",
            "detail": "Tidak ditemukan meta tag <meta name='csrf-token'> di bagian <head>. Request SPA/AJAX berisiko tidak memiliki proteksi token otomatis."
        })

    # 3. Audit Form HTML
    form_matches = re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
    for form in form_matches:
        attrs = form.group(1)
        body = form.group(2)
        result["forms_inspected"] += 1

        method_match = re.search(r'method=["\']([a-zA-Z]+)["\']', attrs, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "GET"

        if method in ("POST", "PUT", "PATCH", "DELETE"):
            # Cek keberadaan input hidden token
            has_token = bool(re.search(r'<input[^>]+name=["\'](?:_token|csrf_token|csrfToken|authenticity_token)["\']', body, re.IGNORECASE))
            if not has_token:
                action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                action = action_match.group(1) if action_match else "[Current URL]"
                result["unprotected_forms"].append({
                    "method": method,
                    "action": action,
                    "snippet": form.group(0)[:150].replace("\n", " ")
                })
                result["vulnerabilities"].append({
                    "type": "UNPROTECTED_POST_FORM",
                    "severity": "CRITICAL",
                    "detail": f"Form {method} menuju '{action}' tidak memiliki input token CSRF (_token/csrf_token)!"
                })

    # 4. Audit Link State-Changing Menggunakan GET
    link_matches = re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL)
    for link in link_matches:
        href = link.group(1)
        text = link.group(2).strip()

        # Lewati javascript: atau anchor murni
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        lower_href = href.lower()
        lower_text = text.lower()

        is_suspicious = any(kw in lower_href or kw in lower_text for kw in STATE_CHANGING_KEYWORDS)
        if is_suspicious:
            result["risky_get_links"].append({
                "href": href,
                "text": text[:50],
                "reason": "Menggunakan HTTP GET untuk aksi yang berpotensi mengubah data atau sesi pengguna."
            })
            result["vulnerabilities"].append({
                "type": "STATE_CHANGING_GET_LINK",
                "severity": "HIGH",
                "detail": f"Aksi sensitif '{text}' dijalankan via tautan GET (href: {href}). Ini dapat dipicu secara paksa oleh gambar <img src='...'> pada serangan CSRF!"
            })

    return result


def audit_static_templates(target_dir: str) -> Dict[str, Any]:
    """Mengaudit file view/template lokal (Blade, HTML, PHP, Vue) untuk proteksi CSRF."""
    result = {
        "target": target_dir,
        "mode": "static",
        "files_scanned": 0,
        "unprotected_forms": [],
        "risky_get_routes": [],
        "vulnerabilities": []
    }

    allowed_exts = {".blade.php", ".php", ".html", ".htm", ".vue", ".jsx", ".tsx"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

        for file in files:
            ext = next((e for e in allowed_exts if file.endswith(e)), None)
            if not ext:
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_dir)
            result["files_scanned"] += 1

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            # 1. Cari form POST
            form_matches = re.finditer(r'<form\b([^>]*)>(.*?)</form>', content, re.IGNORECASE | re.DOTALL)
            for form in form_matches:
                attrs = form.group(1)
                body = form.group(2)

                method_match = re.search(r'method=["\']([a-zA-Z]+)["\']', attrs, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    # Cek direktif @csrf atau input hidden
                    has_csrf_directive = "@csrf" in body
                    has_token_input = bool(re.search(r'name=["\'](?:_token|csrf_token)["\']', body, re.IGNORECASE))

                    if not has_csrf_directive and not has_token_input:
                        action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                        action = action_match.group(1) if action_match else "unspecified"
                        result["unprotected_forms"].append({
                            "file": rel_path,
                            "method": method,
                            "action": action
                        })
                        result["vulnerabilities"].append({
                            "type": "MISSING_CSRF_TOKEN_IN_TEMPLATE",
                            "severity": "CRITICAL",
                            "file": rel_path,
                            "detail": f"Form {method} pada file {rel_path} tidak menyertakan @csrf atau input token CSRF!"
                        })

            # 2. Cari GET logout/delete route
            link_matches = re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', content, re.IGNORECASE | re.DOTALL)
            for link in link_matches:
                href = link.group(1)
                text = link.group(2).strip()
                lower_href = href.lower()
                lower_text = text.lower()

                if any(kw in lower_href or kw in lower_text for kw in ["logout", "delete", "destroy", "hapus"]):
                    # Cek apakah ini tombol submit form tersembunyi (misal: onclick="event.preventDefault(); document.getElementById('logout-form').submit();")
                    is_js_post = "submit()" in link.group(0) or "preventDefault()" in link.group(0)
                    if not is_js_post:
                        result["risky_get_routes"].append({
                            "file": rel_path,
                            "href": href,
                            "text": text[:40]
                        })
                        result["vulnerabilities"].append({
                            "type": "STATE_CHANGE_VIA_GET_LINK",
                            "severity": "HIGH",
                            "file": rel_path,
                            "detail": f"Tautan aksi sensitif '{text[:30]}' ({href}) pada {rel_path} menggunakan GET langsung tanpa form POST + CSRF."
                        })

    return result


def render_cli_report(data: Dict[str, Any]) -> None:
    """Menampilkan laporan audit CSRF ke konsol terminal."""
    print("=" * 80)
    print(" WEB APPLICATION CSRF & STATE-CHANGE SECURITY AUDIT")
    print("=" * 80)
    print(f" Target Mode  : {data.get('mode', 'unknown').upper()}")
    print(f" Target Path  : {data.get('target')}")

    vulns = data.get("vulnerabilities", [])
    print(f" Total Celah  : {len(vulns)}")
    print("-" * 80)

    if not vulns:
        print(" [√] EXCELLENT: Seluruh form dan token proteksi CSRF terpasang dengan baik!")
        print("=" * 80)
        return

    crits = [v for v in vulns if v.get("severity") == "CRITICAL"]
    highs = [v for v in vulns if v.get("severity") == "HIGH"]
    meds  = [v for v in vulns if v.get("severity") == "MEDIUM"]

    print(f" STATUS TEMUAN: [CRITICAL: {len(crits)}] | [HIGH: {len(highs)}] | [MEDIUM: {len(meds)}]")
    print("-" * 80)

    for idx, v in enumerate(vulns, start=1):
        sev_tag = f"[{v.get('severity')}]"
        print(f"\n#{idx} {sev_tag} {v.get('type')}")
        if "file" in v:
            print(f"   Lokasi   : {v['file']}")
        print(f"   Deskripsi: {v.get('detail')}")

    print("\n" + "=" * 80)
    print(" REKOMENDASI PERBAIKAN DEFENSIVE CSRF:")
    print(" 1. Selalu sertakan direktif `@csrf` di setiap form POST, PUT, DELETE pada Blade.")
    print(" 2. Ganti seluruh endpoint logout/delete yang menggunakan GET menjadi form POST:")
    print("    <form method=\"POST\" action=\"{{ route('logout') }}\"> @csrf <button>Logout</button> </form>")
    print(" 3. Pada SPA / Frontend: Pastikan Axios atau Fetch menyertakan header 'X-XSRF-TOKEN'.")
    print(" 4. Pastikan session cookie memiliki flag: SameSite=Lax, Secure, dan HttpOnly.")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="CSRF & State-Change Vulnerability Auditor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="URL aplikasi live yang ingin diaudit (cth: http://127.0.0.1:8000)")
    group.add_argument("--path", help="Path direktori template lokal yang ingin dipindai")
    parser.add_argument("--json", dest="json_output", help="Path untuk mengekspor laporan ke file JSON")
    args = parser.parse_args()

    if args.url:
        report = audit_live_url(args.url)
    else:
        if not os.path.exists(args.path):
            print(f"[!] Error: Direktori target '{args.path}' tidak ditemukan.")
            sys.exit(1)
        report = audit_static_templates(args.path)

    if "error" in report:
        print(f"[!] {report['error']}")
        sys.exit(1)

    render_cli_report(report)

    if args.json_output:
        try:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Laporan JSON berhasil disimpan ke: {args.json_output}")
        except Exception as e:
            print(f"[!] Gagal menyimpan file JSON: {e}")


if __name__ == "__main__":
    main()
