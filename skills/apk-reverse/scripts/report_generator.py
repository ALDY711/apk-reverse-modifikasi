#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report generator — menghasilkan laporan analisis APK dalam format Markdown atau HTML.

Mengumpulkan semua output dari proses analisis (recon, string extraction, patching,
verification) dan menyusunnya menjadi laporan terstruktur yang siap dibagikan.

Usage:
    python report_generator.py --apk target.apk --work-dir ./work --format markdown
    python report_generator.py --apk target.apk --format html --out report.html
    python report_generator.py --apk target.apk --lang id
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import sys
import zipfile

TEMPLATE_MD = """# 📋 Laporan Analisis APK

> Dihasilkan secara otomatis oleh **apk-reverse report generator**
> Tanggal: {date}

---

## 📱 Informasi Target

| Properti | Nilai |
|---|---|
| **Nama File** | `{filename}` |
| **SHA-256** | `{sha256}` |
| **Ukuran** | {size} |
| **Jumlah Entry** | {entry_count} |
| **Jumlah DEX** | {dex_count} |
| **Jumlah SO** | {so_count} |
| **Min SDK** | {min_sdk} |
| **Target SDK** | {target_sdk} |
| **Package** | `{package}` |
| **Version** | {version} |

---

## 📂 Struktur APK

### File DEX
{dex_files}

### Library Native (.so)
{so_files}

### Aset Penting
{important_assets}

---

## 🔍 Temuan Analisis

### String & Endpoint
{strings_section}

### Indikator Keamanan
{security_section}

### Indikator Packer/Hardening
{hardening_section}

---

## 🛡️ Penilaian Risiko

| Kategori | Status | Detail |
|---|---|---|
| **Packer** | {packer_status} | {packer_detail} |
| **Signature Check** | {sig_status} | {sig_detail} |
| **Root Detection** | {root_status} | {root_detail} |
| **SSL Pinning** | {ssl_status} | {ssl_detail} |
| **Native Protection** | {native_status} | {native_detail} |

---

## 📊 Statistik

- **Total class**: {class_count}
- **Total method**: {method_count}
- **String mengandung URL**: {url_count}
- **String mengandung API key pattern**: {apikey_count}
- **Library pihak ketiga terdeteksi**: {lib_count}

---

## 🔧 Rekomendasi

{recommendations}

---

## ⚙️ Lingkungan Analisis

| Properti | Nilai |
|---|---|
| **OS** | {os_info} |
| **Python** | {python_version} |
| **Platform** | {platform_info} |
| **Skill Version** | 1.0 |

---

> ⚠️ **Disclaimer**: Laporan ini dihasilkan untuk tujuan edukasi dan penelitian keamanan.
> Gunakan secara bertanggung jawab sesuai hukum yang berlaku.

> 🏷️ Label kekuatan klaim: `observed` = perintah dijalankan dan output-nya ada |
> `inferred` = mengikuti dari observasi | `unverified` = asumsi, belum direproduksi.
"""

TEMPLATE_HTML_HEAD = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Laporan Analisis APK — {filename}</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-yellow: #d29922;
    --accent-purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
  }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin: 2rem 0 1rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }}
  h2 {{ color: var(--accent-purple); font-size: 1.3rem; margin: 1.5rem 0 0.8rem; }}
  h3 {{ color: var(--text); font-size: 1.1rem; margin: 1rem 0 0.5rem; }}
  .header {{
    background: linear-gradient(135deg, #1a1e2e, #2d1b3d);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
    text-align: center;
  }}
  .header h1 {{ border: none; margin: 0; font-size: 2rem; }}
  .header .subtitle {{ color: var(--text-muted); margin-top: 0.5rem; }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
  }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
  th, td {{ padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--accent); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
  code {{ background: rgba(110,118,129,0.2); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9em; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-ok {{ background: rgba(63,185,80,0.15); color: var(--accent-green); }}
  .badge-warn {{ background: rgba(210,153,34,0.15); color: var(--accent-yellow); }}
  .badge-danger {{ background: rgba(248,81,73,0.15); color: var(--accent-red); }}
  .badge-info {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .stat-card {{ text-align: center; padding: 1rem; }}
  .stat-card .number {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .stat-card .label {{ font-size: 0.85rem; color: var(--text-muted); }}
  .disclaimer {{ background: rgba(210,153,34,0.1); border: 1px solid rgba(210,153,34,0.3); border-radius: 8px; padding: 1rem; margin-top: 2rem; color: var(--accent-yellow); font-size: 0.85rem; }}
  ul {{ padding-left: 1.5rem; }}
  li {{ margin: 0.3rem 0; }}
</style>
</head>
<body>
"""


def sha256_file(path):
    """Hitung SHA-256 dari file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(size_bytes):
    """Konversi byte ke format manusia."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def analyze_apk(apk_path):
    """Analisis APK dan kumpulkan informasi."""
    info = {
        "filename": os.path.basename(apk_path),
        "sha256": sha256_file(apk_path),
        "size": human_size(os.path.getsize(apk_path)),
        "size_bytes": os.path.getsize(apk_path),
        "dex_files": [],
        "so_files": [],
        "important_assets": [],
        "entry_count": 0,
        "min_sdk": "N/A",
        "target_sdk": "N/A",
        "package": "N/A",
        "version": "N/A",
        "url_strings": [],
        "api_key_patterns": [],
        "security_indicators": [],
        "hardening_indicators": [],
        "packer_detected": False,
        "packer_name": "",
    }

    known_packers = {
        "com.stub.StubApp": "360加固",
        "com.secneo.apkwrapper": "梆梆加固",
        "com.tencent.StubShell": "腾讯乐固",
        "com.baidu.protect": "百度加固",
        "com.qihoo.util": "360加固 (Qihoo)",
        "s.h.e.l.l": "DexProtect/通用",
        "com.wrapper": "Generic Wrapper",
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            info["entry_count"] = len(zf.namelist())

            for entry in zf.namelist():
                if entry.endswith(".dex"):
                    entry_info = zf.getinfo(entry)
                    info["dex_files"].append({
                        "name": entry,
                        "size": human_size(entry_info.file_size),
                        "compressed": human_size(entry_info.compress_size),
                    })
                elif entry.endswith(".so"):
                    entry_info = zf.getinfo(entry)
                    info["so_files"].append({
                        "name": entry,
                        "size": human_size(entry_info.file_size),
                    })
                elif any(entry.endswith(ext) for ext in [".json", ".xml", ".db", ".sqlite"]):
                    if "META-INF" not in entry:
                        info["important_assets"].append(entry)

            # Scan string dari dex
            for dex_entry in info["dex_files"]:
                try:
                    dex_data = zf.read(dex_entry["name"])
                    # Simple string extraction dari DEX
                    text = dex_data.decode("utf-8", errors="ignore")
                    import re
                    urls = re.findall(r'https?://[^\s\x00"\'<>]{5,100}', text)
                    info["url_strings"].extend(urls[:50])  # Cap at 50

                    # API key patterns
                    api_patterns = re.findall(
                        r'(?:api[_-]?key|secret|token|password|auth)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})',
                        text, re.IGNORECASE
                    )
                    info["api_key_patterns"].extend(api_patterns[:20])
                except Exception:
                    pass

            # Check for packer
            try:
                manifest_data = zf.read("AndroidManifest.xml")
                manifest_text = manifest_data.decode("utf-8", errors="ignore")
                for packer_sig, packer_name in known_packers.items():
                    if packer_sig in manifest_text:
                        info["packer_detected"] = True
                        info["packer_name"] = packer_name
                        break
            except Exception:
                pass

            # Security indicators
            for dex_entry in info["dex_files"]:
                try:
                    dex_data = zf.read(dex_entry["name"])
                    text = dex_data.decode("utf-8", errors="ignore")
                    checks = [
                        ("Root Detection", ["su", "Superuser", "magisk", "/system/xbin/su", "com.topjohnwu.magisk"]),
                        ("Emulator Detection", ["goldfish", "sdk_gphone", "generic_x86", "Andy", "nox", "BlueStacks"]),
                        ("Debug Detection", ["isDebuggerConnected", "Debug.isDebuggerConnected", "android.os.Debug"]),
                        ("Frida Detection", ["frida", "gmain", "linjector", "/proc/self/maps"]),
                        ("Xposed Detection", ["de.robv.android.xposed", "XposedBridge", "XposedHelpers"]),
                        ("Signature Check", ["toCharsString", "signatures[0]", "getPackageInfo", "PackageManager.GET_SIGNATURES"]),
                        ("SSL Pinning", ["X509TrustManager", "checkServerTrusted", "OkHostnameVerifier", "CertificatePinner"]),
                    ]
                    for check_name, indicators in checks:
                        found = [ind for ind in indicators if ind.lower() in text.lower()]
                        if found:
                            info["security_indicators"].append({
                                "name": check_name,
                                "indicators": found,
                                "count": len(found),
                            })
                except Exception:
                    pass

    except zipfile.BadZipFile:
        info["error"] = "File bukan ZIP/APK yang valid"

    return info


def render_markdown(info, lang="id"):
    """Render laporan dalam format Markdown."""

    # Format sections
    dex_lines = []
    for d in info["dex_files"]:
        dex_lines.append(f"- `{d['name']}` — {d['size']} (compressed: {d['compressed']})")
    dex_section = "\n".join(dex_lines) if dex_lines else "_Tidak ada file DEX ditemukan_"

    so_lines = []
    for s in info["so_files"]:
        so_lines.append(f"- `{s['name']}` — {s['size']}")
    so_section = "\n".join(so_lines) if so_lines else "_Tidak ada library native_"

    asset_lines = [f"- `{a}`" for a in info["important_assets"][:20]]
    asset_section = "\n".join(asset_lines) if asset_lines else "_Tidak ada aset penting terdeteksi_"

    # Strings
    url_lines = [f"- `{u}`" for u in list(set(info["url_strings"]))[:25]]
    strings_section = "#### URL/Endpoint Ditemukan\n" + ("\n".join(url_lines) if url_lines else "_Tidak ada URL ditemukan_")
    if info["api_key_patterns"]:
        strings_section += "\n\n#### ⚠️ Pola API Key Terdeteksi\n"
        for p in info["api_key_patterns"][:10]:
            masked = p[:4] + "****" + p[-4:] if len(p) > 8 else "****"
            strings_section += f"- `{masked}`\n"

    # Security
    sec_lines = []
    for s in info["security_indicators"]:
        sec_lines.append(f"- **{s['name']}**: {s['count']} indikator ({', '.join(s['indicators'][:3])})")
    security_section = "\n".join(sec_lines) if sec_lines else "_Tidak ada indikator keamanan khusus terdeteksi_"

    # Hardening
    if info["packer_detected"]:
        hardening_section = f"⚠️ **Packer terdeteksi**: {info['packer_name']}\n\nPerlu proses unpacking sebelum analisis lebih lanjut."
    else:
        hardening_section = "✅ Tidak ada packer/hardening yang terdeteksi dari manifest."

    # Risk assessment
    def _status(indicators, name):
        matches = [s for s in info["security_indicators"] if s["name"] == name]
        if matches:
            return "⚠️ Terdeteksi", f"{matches[0]['count']} indikator ditemukan"
        return "✅ Tidak terdeteksi", "Tidak ada indikator ditemukan"

    packer_status = "⚠️ Terdeteksi" if info["packer_detected"] else "✅ Bersih"
    packer_detail = info.get("packer_name", "Tidak terdeteksi") if info["packer_detected"] else "Tidak terdeteksi"

    sig_s, sig_d = _status(info["security_indicators"], "Signature Check")
    root_s, root_d = _status(info["security_indicators"], "Root Detection")
    ssl_s, ssl_d = _status(info["security_indicators"], "SSL Pinning")

    native_s = "📊 Info" if info["so_files"] else "✅ Tidak ada"
    native_d = f"{len(info['so_files'])} library native" if info["so_files"] else "Tidak ada library native"

    # Recommendations
    recs = []
    if info["packer_detected"]:
        recs.append("1. **Unpack terlebih dahulu** — Gunakan `frida` atau `dex_mem_scan.py` untuk dump DEX dari memori.")
    if any(s["name"] == "Root Detection" for s in info["security_indicators"]):
        recs.append(f"{len(recs)+1}. **Bypass root detection** — Gunakan `anti_detect_probe.js` untuk identifikasi mekanisme, lalu patch.")
    if any(s["name"] == "SSL Pinning" for s in info["security_indicators"]):
        recs.append(f"{len(recs)+1}. **Bypass SSL pinning** — Gunakan `tls_check.py` untuk identifikasi implementasi pinning.")
    if any(s["name"] == "Signature Check" for s in info["security_indicators"]):
        recs.append(f"{len(recs)+1}. **Handle signature check** — Baca `references/signature-derived-keys.md` sebelum repack.")
    if info["api_key_patterns"]:
        recs.append(f"{len(recs)+1}. **Periksa API key yang bocor** — Jalankan `scan_leaks.py` untuk analisis mendalam.")
    if not recs:
        recs.append("1. Target terlihat relatif bersih. Lanjutkan dengan workflow standar 4-gate.")

    recommendations = "\n".join(recs)

    return TEMPLATE_MD.format(
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        filename=info["filename"],
        sha256=info["sha256"],
        size=info["size"],
        entry_count=info["entry_count"],
        dex_count=len(info["dex_files"]),
        so_count=len(info["so_files"]),
        min_sdk=info["min_sdk"],
        target_sdk=info["target_sdk"],
        package=info["package"],
        version=info["version"],
        dex_files=dex_section,
        so_files=so_section,
        important_assets=asset_section,
        strings_section=strings_section,
        security_section=security_section,
        hardening_section=hardening_section,
        packer_status=packer_status,
        packer_detail=packer_detail,
        sig_status=sig_s,
        sig_detail=sig_d,
        root_status=root_s,
        root_detail=root_d,
        ssl_status=ssl_s,
        ssl_detail=ssl_d,
        native_status=native_s,
        native_detail=native_d,
        class_count="(jalankan dex_dump_validate.py)",
        method_count="(jalankan dex_dump_validate.py)",
        url_count=len(set(info["url_strings"])),
        apikey_count=len(info["api_key_patterns"]),
        lib_count=len(info["so_files"]),
        recommendations=recommendations,
        os_info=f"{platform.system()} {platform.release()}",
        python_version=platform.python_version(),
        platform_info=platform.platform(),
    )


def render_html(info, lang="id"):
    """Render laporan dalam format HTML dengan dark theme premium."""
    md = render_markdown(info, lang)
    # Untuk HTML kita pakai template yang lebih kaya
    html = TEMPLATE_HTML_HEAD.format(filename=info["filename"])

    html += f"""
<div class="header">
  <h1>📋 Laporan Analisis APK</h1>
  <div class="subtitle">Dihasilkan oleh <strong>apk-reverse</strong> — {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
</div>

<div class="card">
  <h2>📱 Informasi Target</h2>
  <table>
    <tr><th>Nama File</th><td><code>{info['filename']}</code></td></tr>
    <tr><th>SHA-256</th><td><code style="font-size:0.8em">{info['sha256']}</code></td></tr>
    <tr><th>Ukuran</th><td>{info['size']}</td></tr>
    <tr><th>DEX</th><td>{len(info['dex_files'])} file</td></tr>
    <tr><th>Native (.so)</th><td>{len(info['so_files'])} file</td></tr>
    <tr><th>Total Entry</th><td>{info['entry_count']}</td></tr>
  </table>
</div>

<div class="grid">
  <div class="card stat-card">
    <div class="number">{len(info['dex_files'])}</div>
    <div class="label">File DEX</div>
  </div>
  <div class="card stat-card">
    <div class="number">{len(info['so_files'])}</div>
    <div class="label">Library Native</div>
  </div>
  <div class="card stat-card">
    <div class="number">{len(set(info['url_strings']))}</div>
    <div class="label">URL Ditemukan</div>
  </div>
  <div class="card stat-card">
    <div class="number">{len(info['security_indicators'])}</div>
    <div class="label">Indikator Keamanan</div>
  </div>
</div>

<div class="card">
  <h2>🛡️ Penilaian Keamanan</h2>
  <table>
    <tr><th>Kategori</th><th>Status</th></tr>
"""

    packer_badge = "badge-danger" if info["packer_detected"] else "badge-ok"
    packer_text = f"Terdeteksi: {info['packer_name']}" if info["packer_detected"] else "Bersih"
    html += f'    <tr><td>Packer/Hardening</td><td><span class="badge {packer_badge}">{packer_text}</span></td></tr>\n'

    for check_name in ["Root Detection", "Emulator Detection", "Frida Detection",
                        "Xposed Detection", "Signature Check", "SSL Pinning", "Debug Detection"]:
        matches = [s for s in info["security_indicators"] if s["name"] == check_name]
        if matches:
            html += f'    <tr><td>{check_name}</td><td><span class="badge badge-warn">Terdeteksi ({matches[0]["count"]} indikator)</span></td></tr>\n'
        else:
            html += f'    <tr><td>{check_name}</td><td><span class="badge badge-ok">Tidak terdeteksi</span></td></tr>\n'

    html += """  </table>
</div>
"""

    if info["url_strings"]:
        html += '<div class="card">\n  <h2>🔗 URL/Endpoint</h2>\n  <ul>\n'
        for url in list(set(info["url_strings"]))[:25]:
            html += f"    <li><code>{url}</code></li>\n"
        html += "  </ul>\n</div>\n"

    if info["api_key_patterns"]:
        html += '<div class="card">\n  <h2>⚠️ API Key Patterns</h2>\n  <ul>\n'
        for p in info["api_key_patterns"][:10]:
            masked = p[:4] + "****" + p[-4:] if len(p) > 8 else "****"
            html += f"    <li><code>{masked}</code></li>\n"
        html += "  </ul>\n</div>\n"

    html += """
<div class="disclaimer">
  ⚠️ <strong>Disclaimer:</strong> Laporan ini dihasilkan untuk tujuan edukasi dan penelitian keamanan.
  Gunakan secara bertanggung jawab sesuai hukum yang berlaku.
</div>

</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(
        description="APK Reverse — Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apk", required=True, help="Path ke file APK")
    parser.add_argument("--work-dir", help="Direktori kerja (opsional)")
    parser.add_argument("--format", choices=["markdown", "html", "json", "all"],
                        default="markdown", help="Format output")
    parser.add_argument("--out", "-o", help="File output (default: stdout)")
    parser.add_argument("--lang", choices=["en", "id"], default="id", help="Bahasa laporan")

    args = parser.parse_args()

    if not os.path.isfile(args.apk):
        print(f"[ERROR] File tidak ditemukan: {args.apk}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Menganalisis: {args.apk}", file=sys.stderr)
    info = analyze_apk(args.apk)

    if args.format == "json":
        output = json.dumps(info, indent=2, ensure_ascii=False)
    elif args.format == "html":
        output = render_html(info, args.lang)
    elif args.format == "all":
        # Generate both
        md_out = render_markdown(info, args.lang)
        html_out = render_html(info, args.lang)
        if args.out:
            base = os.path.splitext(args.out)[0]
            with open(base + ".md", "w", encoding="utf-8") as f:
                f.write(md_out)
            with open(base + ".html", "w", encoding="utf-8") as f:
                f.write(html_out)
            with open(base + ".json", "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2, ensure_ascii=False)
            print(f"[✓] Laporan disimpan: {base}.md, {base}.html, {base}.json", file=sys.stderr)
            return
        output = md_out  # fallback to markdown for stdout
    else:
        output = render_markdown(info, args.lang)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[✓] Laporan disimpan: {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
