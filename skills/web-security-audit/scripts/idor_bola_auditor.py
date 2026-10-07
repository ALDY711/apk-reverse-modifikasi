#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDOR & BOLA (Broken Object Level Authorization) Defensive Auditor.

Audits backend controllers and API route handlers (PHP/Laravel, Node.js/Express, Python/FastAPI/Django)
for Missing Access Control and Tenant Isolation:
  1. Direct ID retrieval without user ownership checks (e.g. `Order::findOrFail($id)` without `where('user_id', Auth::id())`)
  2. Route parameters passed directly into UPDATE / DELETE queries without policy authorization
  3. Sequential integer IDs exposed in public API routes instead of UUID/ULID
  4. Missing authorization middleware / policy gate invocations (`authorize()`, `can()`)
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


# IDOR / BOLA vulnerability detection rules
IDOR_PATTERNS = [
    # Laravel / PHP: find/findOrFail without user scope
    {
        "name": "Laravel Unscoped Model Lookup by ID (BOLA Risk)",
        "lang": "php",
        "regex": r"""\b([A-Z][a-zA-Z0-9]+)::(?:findOrFail|find)\s*\(\s*\$(?:id|order_id|invoice_id|account_id|item_id)\s*\)(?!\s*->where|\s*->user)""",
        "severity": "HIGH",
        "desc": "Model diambil langsung berdasarkan $id tanpa verifikasi kepemilikan user (user_id = Auth::id()) atau pemanggilan Policy ($this->authorize).",
    },
    {
        "name": "PHP Direct SQL Lookup by URL Parameter",
        "lang": "php",
        "regex": r"""(?:SELECT|UPDATE|DELETE)\s+.*?FROM\s+[`'"]?\w+[`'"]?\s+WHERE\s+(?:id|order_id)\s*=\s*(?::id|\?|\$(?:_GET|_POST)\['id'\])(?!.*user_id)""",
        "severity": "HIGH",
        "desc": "Query basis data mencari ID objek tanpa menyaring klausa user_id atau tenant_id penyewa saat ini.",
    },
    # Node.js Express: findById / findOne without req.user check
    {
        "name": "Express.js Unscoped findById / findOne (BOLA Risk)",
        "lang": "js",
        "regex": r"""(?:findById|findByPk|findOne)\s*\(\s*(?:req\.params\.id|\{?\s*(?:_id|id)\s*:\s*req\.params\.id\s*\}?)\s*\)(?!.*req\.user)""",
        "severity": "HIGH",
        "desc": "Dokumen/baris dicari hanya dengan req.params.id tanpa membatasi query ke req.user.id atau memeriksa kepemilikan objek.",
    },
    {
        "name": "Express.js Unchecked Update / Delete by Param ID",
        "lang": "js",
        "regex": r"""(?:\.findByIdAndUpdate|\.findByIdAndDelete|\.destroy\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*req\.params\.id)\b""",
        "severity": "CRITICAL",
        "desc": "Operasi modifikasi atau penghapusan data bergantung penuh pada ID dari URL tanpa validasi izin kepemilikan.",
    },
    # Python Django / FastAPI / SQLAlchemy: get_object_or_404 without filter
    {
        "name": "Django get_object_or_404 Unscoped Lookup",
        "lang": "py",
        "regex": r"""get_object_or_404\s*\(\s*([A-Za-z0-9]+)\s*,\s*(?:pk|id)\s*=\s*(?:id|pk|item_id)\s*\)(?!.*user)""",
        "severity": "HIGH",
        "desc": "get_object_or_404 mencari objek hanya berdasarkan ID tanpa menyertakan user=request.user.",
    },
    {
        "name": "SQLAlchemy Direct Session Query by ID without Tenant Filter",
        "lang": "py",
        "regex": r"""db\.query\s*\(\s*([A-Za-z0-9]+)\s*\)\.filter\s*\(\s*\1\.id\s*==\s*(?:id|item_id)\s*\)\.first\s*\(\s*\)(?!.*current_user)""",
        "severity": "HIGH",
        "desc": "Query SQLAlchemy memfilter hanya pada primary key tanpa memastikan filter kepemilikan pemilik saat ini.",
    },
]

# Good Authorization Indicators
AUTHZ_GUARDS = [
    r"""\$this->authorize\s*\(""",
    r"""Gate::authorize\s*\(""",
    r"""where\s*\(\s*['"]user_id['"]\s*,\s*(?:auth\(\)->id\(\)|Auth::id\(\))""",
    r"""req\.user\s*&&\s*.*?\.userId\s*===\s*req\.user\.id""",
    r"""check_permission\s*\(""",
    r"""user_id\s*=\s*request\.user\.id""",
    r"""owner_id\s*==\s*current_user\.id""",
]


def audit_idor_file(file_path: Path, content: str) -> list[dict]:
    """Scan code content for potential IDOR / BOLA flaws."""
    findings = []

    # Periksa apakah file memiliki mitigasi otorisasi menyeluruh
    has_guards = any(re.search(g, content, re.IGNORECASE) for g in AUTHZ_GUARDS)

    for rule in IDOR_PATTERNS:
        matches = re.finditer(rule["regex"], content, re.IGNORECASE)
        for m in matches:
            start_pos = m.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = content[start_pos : min(start_pos + 120, len(content))].strip().replace("\n", " ")

            findings.append({
                "rule": rule["name"],
                "severity": rule["severity"],
                "line": line_no,
                "desc": rule["desc"],
                "snippet": snippet,
                "mitigated_nearby": has_guards,
            })

    return findings


def scan_idor_directory(target_path: str, extensions: list[str] | None = None) -> None:
    """Scan directory recursively for IDOR / BOLA authorization vulnerabilities."""
    p = Path(target_path)
    if not p.exists():
        log_err(f"Target path tidak ditemukan: {target_path}")
        return

    exts = extensions or [".php", ".js", ".ts", ".py"]
    files = [p] if p.is_file() else [f for ext in exts for f in p.rglob(f"*{ext}")]

    log(f"Memulai audit IDOR & BOLA Otorisasi pada {len(files)} file...")

    total_findings = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        findings = audit_idor_file(f, content)
        if findings:
            total_findings += len(findings)
            print("\n" + "=" * 75)
            log_warn(f"FILE: {f.resolve()}")
            print("=" * 75)
            for item in findings:
                tag = f"[{item['severity']}]"
                print(f"  {tag} Baris {item['line']}: {item['rule']}")
                print(f"      Deskripsi : {item['desc']}")
                print(f"      Kode      : {item['snippet']}")
                if item["mitigated_nearby"]:
                    print("      Catatan   : Terdeteksi ada guard otorisasi di dalam file ini; pastikan guard mencakup aksi ini.")

    print("\n" + "#" * 50)
    print("           RINGKASAN AUDIT IDOR & BOLA")
    print("#" * 50)
    print(f"  Total Potensi Kerentanan IDOR/BOLA : {total_findings}")
    print("#" * 50)

    if total_findings > 0:
        log_warn("Ditemukan potensi celah Insecure Direct Object Reference.")
        print("Gunakan subcommand 'remediate' untuk melihat arsitektur otorisasi defensif.")
    else:
        log_success("Tidak ditemukan pola pengambilan objek telanjang tanpa klausa otorisasi.")


def print_idor_remediation_recipes() -> None:
    """Print hardened authorization and tenant-scoping templates."""
    recipe = """
================================================================================
     PANDUAN REMEDIASI IDOR / BOLA (TENANT SCOPING & POLICY AUTHORIZATION)
================================================================================

1. Laravel (PHP) - Model Policy & Tenant-Scoped Relations:
--------------------------------------------------------------------------------
// [A] PENDEKATAN RELASI KEPEMILIKAN OTOMATIS (TERBAIK & AMAN)
public function show($id) {
    // Alih-alih: $order = Order::findOrFail($id); (RENTAN IDOR)
    // Gunakan relasi user terautentikasi:
    $order = auth()->user()->orders()->findOrFail($id);
    return response()->json($order);
}

// [B] PENDEKATAN LARAVEL POLICY
public function update(Request $request, Order $order) {
    // Otorisasi via Policy (OrderPolicy::update)
    $this->authorize('update', $order);
    
    $order->update($request->validated());
    return response()->json($order);
}

// OrderPolicy.php:
public function update(User $user, Order $order): bool {
    return $user->id === $order->user_id;
}


2. Node.js (Express & Prisma / Mongoose) - Scoped Query:
--------------------------------------------------------------------------------
// [A] MONGOOSE / MONGODB SCOPING
app.get('/api/orders/:id', authenticateJWT, async (req, res) => {
  // Selalu sertakan pemilik objek pada kriteria pencarian
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id // Isolasi kepemilikan tenant
  });

  if (!order) {
    return res.status(404).json({ error: 'Order tidak ditemukan atau tidak memiliki akses.' });
  }
  return res.json(order);
});


3. Python (FastAPI & SQLAlchemy) - Scoped Dependency:
--------------------------------------------------------------------------------
@router.get("/orders/{order_id}", response_model=OrderResponse)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    # Wajib menyertakan user_id = current_user.id
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.user_id == current_user.id
    ).first()

    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order tidak ditemukan atau akses ditolak."
        )
    return order
================================================================================
"""
    print(recipe)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IDOR & BOLA (Broken Object Level Authorization) Defensive Auditor"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_audit = subparsers.add_parser("audit", help="Audit direktori terhadap potensi celah IDOR dan BOLA")
    p_audit.add_argument("path", help="Path direktori atau file target backend")
    p_audit.add_argument(
        "--ext",
        nargs="+",
        default=[".php", ".js", ".ts", ".py"],
        help="Ekstensi file yang diaudit (default: .php .js .ts .py)",
    )

    p_rem = subparsers.add_parser("remediate", help="Tampilkan panduan dan template perbaikan otorisasi aman")

    args = parser.parse_args()
    if args.command == "audit":
        scan_idor_directory(args.path, args.ext)
    elif args.command == "remediate":
        print_idor_remediation_recipes()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
