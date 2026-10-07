#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apk-reverse — Unified CLI entry point.
Dimodifikasi oleh ALDY.

Wraps all 55+ individual scripts into a single command-line interface with
organized subcommands. Instead of remembering individual script names, use:

    python apk_cli.py <command> [options]

Commands are grouped by workflow phase:
    doctor      Environment health check
    recon       Reconnaissance and target classification
    strings     Extract strings and endpoints from dex
    patch       Apply surgical dex/native patches
    repack      Repack, align, and re-sign APK
    verify      Verify a build on device
    scan        Security and leak scanning
    frida       Dynamic analysis with Frida
    report      Generate analysis reports
    config      Manage configuration

Run 'python apk_cli.py <command> --help' for command-specific help.
"""

import argparse
import importlib.util
import os
import subprocess
import sys
import textwrap

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "skills", "apk-reverse", "scripts")
if not os.path.isdir(SCRIPTS):
    SCRIPTS = os.path.join(HERE, ".agents", "skills", "apk-reverse", "scripts")
REFS = os.path.join(HERE, "skills", "apk-reverse", "references")
if not os.path.isdir(REFS):
    REFS = os.path.join(HERE, ".agents", "skills", "apk-reverse", "references")


def _banner():
    return textwrap.dedent(r"""
    ╔══════════════════════════════════════════════════════╗
    ║          🔧  APK Reverse Engineering CLI  🔧         ║
    ║     Unified interface for 55+ analysis scripts      ║
    ║             Dimodifikasi oleh ALDY                   ║
    ╚══════════════════════════════════════════════════════╝
    """)


def _run_script(name, extra_args=None):
    """Run a script from the scripts/ directory."""
    script_path = os.path.join(SCRIPTS, name)
    if not os.path.isfile(script_path):
        print(f"[ERROR] Script tidak ditemukan: {name}")
        print(f"        Path: {script_path}")
        sys.exit(1)
    cmd = [sys.executable, script_path] + (extra_args or [])
    return subprocess.run(cmd, cwd=os.getcwd())


# ═══════════════════════════════════════════════════════════════════════
# Subcommand handlers
# ═══════════════════════════════════════════════════════════════════════

def cmd_doctor(args):
    """Periksa kesehatan lingkungan kerja."""
    extra = []
    if args.json:
        extra.append("--json")
    if args.scripts:
        extra.append("--scripts")
    if args.capabilities:
        extra.append("--capabilities")
    if args.device:
        extra.extend(["--device", args.device])
    return _run_script("doctor.py", extra)


def cmd_recon(args):
    """Reconnaissance: identifikasi target APK."""
    if not args.apk:
        print("[ERROR] Argumen --apk diperlukan")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  🔍 REKON: {os.path.basename(args.apk)}")
    print(f"{'='*60}\n")

    # Step 1: APK fingerprint
    print("[1/4] Fingerprint APK...")
    _run_script("apk_diff.py", [args.apk])

    # Step 2: Extract strings
    print("\n[2/4] Ekstraksi string dari DEX...")
    extra = [args.apk]
    if args.output:
        extra.extend(["--out", args.output])
    _run_script("dex_strings.py", extra)

    # Step 3: Library mapping
    print("\n[3/4] Mapping library native...")
    _run_script("lib_map.py", [args.apk])

    # Step 4: Validate dex
    print("\n[4/4] Validasi struktur DEX...")
    _run_script("dex_dump_validate.py", [args.apk])

    print(f"\n{'='*60}")
    print("  ✅ Rekon selesai. Lihat output di atas.")
    print(f"{'='*60}\n")


def cmd_strings(args):
    """Ekstrak string dan endpoint dari DEX."""
    extra = [args.apk]
    if args.pattern:
        extra.extend(["--pattern", args.pattern])
    if args.output:
        extra.extend(["--out", args.output])
    return _run_script("dex_strings.py", extra)


def cmd_patch(args):
    """Terapkan patch pada DEX atau native library."""
    subcmd = args.patch_type

    if subcmd == "dex-bytes":
        extra = [args.dex]
        if args.offset:
            extra.extend(["--offset", args.offset])
        if args.old_bytes:
            extra.extend(["--old", args.old_bytes])
        if args.new_bytes:
            extra.extend(["--new", args.new_bytes])
        return _run_script("dex_patch_bytes.py", extra)

    elif subcmd == "dex-string":
        extra = [args.dex]
        if args.old_string:
            extra.extend(["--old", args.old_string])
        if args.new_string:
            extra.extend(["--new", args.new_string])
        return _run_script("dex_strpatch.py", extra)

    elif subcmd == "native":
        extra = [args.so_file]
        return _run_script("so_constpatch.py", extra)

    elif subcmd == "smali":
        extra = [args.smali_dir]
        return _run_script("patch_smali.py", extra)

    elif subcmd == "find-insn":
        extra = [args.dex]
        if args.method:
            extra.extend(["--method", args.method])
        return _run_script("dex_find_insn.py", extra)

    else:
        print(f"[ERROR] Tipe patch tidak dikenal: {subcmd}")
        sys.exit(1)


def cmd_repack(args):
    """Repack, align, dan sign ulang APK."""
    extra = ["--apk", args.apk, "--out", args.output]
    if args.dexdir:
        extra.extend(["--dexdir", args.dexdir])
    if args.dex:
        for d in args.dex:
            extra.extend(["--dex", d])
    if args.keystore:
        extra.extend(["--ks", args.keystore])
    if args.no_sign:
        extra.append("--no-sign")
    return _run_script("repack.py", extra)


def cmd_mod_repack(args):
    """Modifikasi APK dan kemas ulang menjadi APK siap jadi untuk Android."""
    if not hasattr(args, "action") or not args.action:
        print("[ERROR] Subcommand action diperlukan (auto, unpack, repack). Gunakan --help.")
        sys.exit(1)

    extra = [args.action]
    if args.action == "auto":
        extra.extend(["--apk", args.apk, "--out", args.output])
        if getattr(args, "debuggable", False):
            extra.append("--debuggable")
        if getattr(args, "cleartext", False):
            extra.append("--cleartext")
        if getattr(args, "trust_user_ca", False):
            extra.append("--trust-user-ca")
        if getattr(args, "swap_dex", None):
            for s in args.swap_dex:
                extra.extend(["--swap-dex", s])
        if getattr(args, "keystore", None):
            extra.extend(["--keystore", args.keystore])
        if getattr(args, "ks_pass", None):
            extra.extend(["--ks-pass", args.ks_pass])
        if getattr(args, "ks_alias", None):
            extra.extend(["--ks-alias", args.ks_alias])
        if getattr(args, "no_verify", False):
            extra.append("--no-verify")
    elif args.action == "unpack":
        extra.extend(["--apk", args.apk, "--out-dir", args.out_dir])
    elif args.action == "repack":
        extra.extend(["--dir", args.dir, "--out", args.output])
        if getattr(args, "keystore", None):
            extra.extend(["--keystore", args.keystore])
        if getattr(args, "ks_pass", None):
            extra.extend(["--ks-pass", args.ks_pass])
        if getattr(args, "ks_alias", None):
            extra.extend(["--ks-alias", args.ks_alias])
        if getattr(args, "no_verify", False):
            extra.append("--no-verify")
    return _run_script("apk_mod_repack.py", extra)


def cmd_verify(args):
    """Verifikasi build di perangkat."""
    extra = []
    if args.apk:
        extra.extend(["--apk", args.apk])
    if args.serial:
        extra.extend(["--serial", args.serial])

    print(f"\n{'='*60}")
    print(f"  ✅ VERIFIKASI: {os.path.basename(args.apk)}")
    print(f"{'='*60}\n")

    # Preflight
    print("[1/3] Preflight perangkat...")
    preflight_extra = []
    if args.serial:
        preflight_extra.extend(["--serial", args.serial])
    _run_script("preflight.py", preflight_extra)

    # Install
    print("\n[2/3] Install dan tes...")
    _run_script("install_test.py", extra)

    # Screenshot
    if not args.no_screenshot:
        print("\n[3/3] Ambil screenshot...")
        snap_extra = []
        if args.serial:
            snap_extra.extend(["--serial", args.serial])
        _run_script("snap.py", snap_extra)

    print(f"\n{'='*60}")
    print("  ✅ Verifikasi selesai.")
    print(f"{'='*60}\n")


def cmd_scan(args):
    """Security scanning dan leak detection."""
    subcmd = args.scan_type

    if subcmd == "leaks":
        extra = [args.target]
        if args.show_exempt:
            extra.append("--show-exempt")
        return _run_script("scan_leaks.py", extra)

    elif subcmd == "tls":
        extra = [args.target]
        return _run_script("tls_check.py", extra)

    elif subcmd == "api":
        extra = [args.target]
        return _run_script("probe_api.py", extra)

    elif subcmd == "signatures":
        extra = [args.target]
        return _run_script("sig_probe.py", extra)

    elif subcmd == "anti-detect":
        extra = []
        if args.target:
            extra.append(args.target)
        return _run_script("anti_detect_probe.js", extra)

    else:
        print(f"[ERROR] Tipe scan tidak dikenal: {subcmd}")
        sys.exit(1)


def cmd_frida(args):
    """Dynamic analysis dengan Frida."""
    subcmd = args.frida_cmd

    if subcmd == "probe":
        extra = [args.package]
        return _run_script("frida_probe.js", extra)

    elif subcmd == "rpc":
        extra = [args.package]
        if args.script:
            extra.extend(["--script", args.script])
        return _run_script("frida_rpc_serve.py", extra)

    elif subcmd == "spawn":
        extra = [args.package]
        if args.script:
            extra.extend(["--script", args.script])
        return _run_script("spawn_patch_detach.py", extra)

    elif subcmd == "stalker":
        extra = [args.target]
        return _run_script("stalker_trace.js", extra)

    elif subcmd == "coldstart":
        extra = [args.package]
        return _run_script("coldstart.py", extra)

    elif subcmd == "mem-scan":
        extra = [args.package]
        return _run_script("dex_mem_scan.py", extra)

def cmd_web(args):
    """Web reverse engineering: sourcemap & API signature tracer."""
    subcmd = args.web_cmd
    if subcmd == "sourcemap":
        extra = []
        if args.url:
            extra.extend(["--url", args.url])
        elif args.js_url:
            extra.extend(["--js-url", args.js_url])
        elif args.file:
            extra.extend(["--file", args.file])
        if args.out_dir:
            extra.extend(["--out-dir", args.out_dir])
        if args.scan_only:
            extra.append("--scan-only")
        if args.json:
            extra.append("--json")
        return _run_script("sourcemap_extractor.py", extra)
    elif subcmd == "api-tracer":
        extra = []
        if args.file:
            extra.extend(["--file", args.file])
        elif args.url:
            extra.extend(["--url", args.url])
        if args.query:
            extra.extend(["--query", args.query])
        if args.json:
            extra.append("--json")
        return _run_script("web_api_tracer.py", extra)
    elif subcmd == "deobf":
        extra = ["--file", args.file]
        if args.output:
            extra.extend(["--out", args.output])
        if args.no_kill_debugger:
            extra.append("--no-kill-debugger")
        if args.no_beautify:
            extra.append("--no-beautify")
        return _run_script("js_deobfuscator.py", extra)
    elif subcmd == "userscript":
        extra = ["userscript", "--domain", args.domain]
        if args.template:
            extra.extend(["--template", args.template])
        if args.name:
            extra.extend(["--name", args.name])
        if args.func:
            extra.extend(["--func", args.func])
        if args.return_val:
            extra.extend(["--return-val", args.return_val])
        if args.custom_code:
            extra.extend(["--custom-code", args.custom_code])
        if args.output:
            extra.extend(["--out", args.output])
        return _run_script("web_modifier.py", extra)
    elif subcmd == "serve":
        extra = ["serve", "--port", str(args.port)]
        for m in (args.map_local or []):
            extra.extend(["--map-local", m])
        return _run_script("web_modifier.py", extra)
    else:
        print(f"[ERROR] Perintah web tidak dikenal: {subcmd}")
        sys.exit(1)


def cmd_mitm(args):
    """Inspeksi dan patch APK untuk intersepsi HTTPS / user CA trust."""
    extra = []
    if args.apk:
        extra.extend(["--apk", args.apk])
    if args.dir:
        extra.extend(["--dir", args.dir])
    if args.out:
        extra.extend(["--out", args.out])
    if args.inspect_only:
        extra.append("--inspect-only")
    if args.export_frida:
        extra.extend(["--export-frida", args.export_frida])
    return _run_script("apk_mitm_patch.py", extra)


def cmd_debloat(args):
    """Scan, debloat, dan neuter komponen iklan di manifest."""
    extra = []
    if args.target:
        extra.extend(["--target", args.target])
    if args.scan:
        extra.append("--scan")
    if args.neuter:
        extra.append("--neuter")
    if args.out:
        extra.extend(["--out", args.out])
    if args.generate_stubs:
        extra.append("--generate-stubs")
    if args.json:
        extra.append("--json")
    return _run_script("apk_debloater.py", extra)


def cmd_frida_gen(args):
    """Generate skrip Frida hook (SSL unpinning, root bypass, crypto, method trace)."""
    extra = ["--template", args.template]
    if args.class_name:
        extra.extend(["--class-name", args.class_name])
    if args.method_name:
        extra.extend(["--method-name", args.method_name])
    if args.out:
        extra.extend(["--out", args.out])
    if args.print_only:
        extra.append("--print-only")
    return _run_script("frida_hook_gen.py", extra)


def cmd_jni(args):
    """Analisis exported JNI symbols dari file native .so."""
    extra = ["--so", args.so]
    if args.generate_hooks:
        extra.append("--generate-hooks")
    if args.out:
        extra.extend(["--out", args.out])
    if args.json:
        extra.append("--json")
    return _run_script("jni_export_resolve.py", extra)


def cmd_decode(args):
    """Decode opaque payloads, cached config blobs, dan raw protobuf."""
    subcmd = args.decode_type
    if subcmd == "blob":
        extra = []
        if getattr(args, "file", None):
            extra.extend(["--file", args.file])
        if getattr(args, "prefs_xml", None):
            extra.extend(["--prefs-xml", args.prefs_xml])
        if getattr(args, "name", None):
            extra.extend(["--name", args.name])
        if getattr(args, "out", None):
            extra.extend(["--out", args.out])
        if getattr(args, "max_skip", None) is not None:
            extra.extend(["--max-skip", str(args.max_skip)])
        if getattr(args, "encode", False):
            extra.append("--encode")
        if getattr(args, "outer", None):
            extra.extend(["--outer", args.outer])
        if getattr(args, "inner", None):
            extra.extend(["--inner", args.inner])
        if getattr(args, "cut", None) is not None:
            extra.extend(["--cut", str(args.cut)])
        return _run_script("blob_decode.py", extra)
    elif subcmd == "proto":
        extra = []
        if getattr(args, "hex", None):
            extra.extend(["--hex", args.hex])
        if getattr(args, "file", None):
            extra.extend(["--file", args.file])
        if getattr(args, "split", None):
            extra.extend(["--split", args.split])
        if getattr(args, "reencode", False):
            extra.append("--reencode")
        return _run_script("protobuf_decode_raw.py", extra)
    else:
        print(f"[ERROR] Subcommand decode tidak dikenal: {subcmd}")
        sys.exit(1)


def cmd_report(args):
    """Generate laporan analisis."""
    report_path = os.path.join(HERE, "skills", "apk-reverse", "scripts", "report_generator.py")
    extra = []
    if args.apk:
        extra.extend(["--apk", args.apk])
    if args.work_dir:
        extra.extend(["--work-dir", args.work_dir])
    if args.format:
        extra.extend(["--format", args.format])
    if args.output:
        extra.extend(["--out", args.output])
    if args.language:
        extra.extend(["--lang", args.language])
    return subprocess.run([sys.executable, report_path] + extra, cwd=os.getcwd())


def cmd_list(args):
    """Tampilkan daftar semua skrip yang tersedia."""
    print(_banner())
    print("  📂 Skrip yang Tersedia:")
    print(f"  {'='*56}\n")

    categories = {
        "🔍 Rekon & Analisis": [
            ("doctor.py", "Cek kesehatan lingkungan"),
            ("preflight.py", "Preflight perangkat"),
            ("apk_diff.py", "Bandingkan dua APK"),
            ("dex_strings.py", "Ekstrak string dari DEX"),
            ("dex_dump_validate.py", "Validasi struktur DEX"),
            ("dex_classdiff.py", "Bandingkan class-set dua DEX"),
            ("dex_check_verifier.py", "Cek kompatibilitas verifier"),
            ("lib_map.py", "Mapping library native"),
            ("find_refs.py", "Cari referensi method/field"),
            ("dex_find_insn.py", "Cari instruksi dalam DEX"),
            ("elf_plt.py", "Parse PLT/GOT dari ELF"),
            ("java2c_probe.py", "Deteksi Java2C/JNI sinking"),
        ],
        "🔧 Patching": [
            ("dex_patch_bytes.py", "Patch byte-level pada DEX"),
            ("dex_strpatch.py", "Patch string dalam DEX"),
            ("so_constpatch.py", "Patch konstanta di .so native"),
            ("patch_smali.py", "Patch smali"),
            ("apk_debloater.py", "Neuter komponen iklan dan telemetry di manifest"),
            ("dexpatch/", "Method rewriting via dexlib2"),
        ],
        "📦 Repack & Sign": [
            ("repack.py", "Repack, align, dan sign APK"),
            ("apk_mod_repack.py", "All-in-one APK modifier, aligner & V1-V3 signer siap pakai"),
            ("install_test.py", "Install dan tes di device"),
            ("snap.py", "Ambil screenshot dari device"),
        ],
        "🛡️ Security & Scanning": [
            ("scan_leaks.py", "Scan kebocoran data sensitif"),
            ("apk_mitm_patch.py", "Patch Network Security Config untuk HTTPS inspection"),
            ("tls_check.py", "Cek TLS/certificate pinning"),
            ("probe_api.py", "Probe API endpoint"),
            ("sig_probe.py", "Analisis signature verification"),
            ("anti_detect_probe.js", "Cek mekanisme anti-deteksi"),
            ("svc_scan.py", "Scan syscall mentah"),
        ],
        "🔬 Dynamic Analysis (Frida)": [
            ("frida_probe.js", "Universal Frida probe"),
            ("frida_hook_gen.py", "Generator skrip Frida unpinning, root bypass, crypto"),
            ("frida_rpc_serve.py", "Frida RPC server"),
            ("spawn_patch_detach.py", "Spawn, patch, detach"),
            ("stalker_trace.js", "Stalker execution trace"),
            ("stalker_report.py", "Analisis Stalker report"),
            ("coldstart.py", "Cold-start analysis"),
            ("dex_mem_scan.py", "Scan DEX di memori"),
            ("run_probe.py", "Probe runner"),
            ("hook_patch_only.js", "Hook untuk patch-only"),
            ("rpc_template.js", "Template RPC service"),
        ],
        "🔐 Native & Advanced": [
            ("native_crash.py", "Analisis native crash"),
            ("grab_crash.py", "Ambil crash log"),
            ("blob_decode.py", "Decode blob terenkripsi"),
            ("protobuf_decode_raw.py", "Decode protobuf tanpa schema"),
            ("vmp_diff_harness.py", "VMP differential analysis"),
            ("kernelsu_syscall_mask.py", "KernelSU syscall masking"),
            ("lsposed_scaffold.py", "Scaffold modul LSPosed"),
            ("jni_export_resolve.py", "Ekstrak exported JNI symbols dari .so dan generate Frida hooks"),
        ],
        "📱 Device & Dart": [
            ("device_shell.py", "Shell helper untuk device"),
            ("devsh.py", "Quick device shell"),
            ("mt_mcp_probe.py", "MT Manager MCP probe"),
            ("usb_net_proxy.py", "USB network proxy"),
            ("dart_disasm.py", "Disassembly Dart AOT"),
            ("dart_pool_strings.py", "Dart object pool strings"),
            ("dart_pprefs.py", "Dart shared preferences"),
            ("datastore_inject.py", "DataStore injection"),
        ],
        "🌐 Web Reverse Engineering": [
            ("sourcemap_extractor.py", "Ekstrak source code dari Source Map (.js.map)"),
            ("web_api_tracer.py", "Lacak signature, token, dan kripto pada JS web"),
            ("js_deobfuscator.py", "Deobfuskasi, unpack eval/packer, dan format JS"),
            ("web_modifier.py", "Generate Userscript dan Map-Local proxy server"),
        ],
        "📊 Utilitas": [
            ("capabilities.py", "Registry kapabilitas"),
            ("dexutil.py", "Utilitas parsing DEX"),
            ("smtool.py", "Smali tool helper"),
            ("rasc_build.py", "RASC build helper"),
        ],
    }

    for cat_name, scripts in categories.items():
        print(f"  {cat_name}")
        print(f"  {'─'*54}")
        for script, desc in scripts:
            print(f"    {script:<30s} {desc}")
        print()

    total = sum(len(s) for s in categories.values())
    print(f"  Total: {total} skrip terdaftar")
    print(f"  Path:  {SCRIPTS}\n")


# ═══════════════════════════════════════════════════════════════════════
# Argument parser
# ═══════════════════════════════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="apk_cli",
        description="APK Reverse Engineering — Unified CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Contoh penggunaan:
          apk_cli.py doctor                     Cek lingkungan
          apk_cli.py doctor --json              Output JSON
          apk_cli.py recon --apk target.apk     Rekon lengkap
          apk_cli.py strings target.apk         Ekstrak string
          apk_cli.py patch dex-bytes ...        Patch DEX
          apk_cli.py repack --apk ... --out ... Repack APK
          apk_cli.py mod-repack auto --apk app.apk -o out.apk --cleartext
          apk_cli.py scan leaks ./project       Scan kebocoran
          apk_cli.py frida probe com.app        Frida probe
          apk_cli.py list                       Lihat semua skrip
        """),
    )
    sub = parser.add_subparsers(dest="command", help="Perintah yang tersedia")

    # ── doctor ─────────────────────────────────────────────────────────
    p_doc = sub.add_parser("doctor", help="Cek kesehatan lingkungan kerja")
    p_doc.add_argument("--json", action="store_true", help="Output dalam JSON")
    p_doc.add_argument("--scripts", action="store_true", help="Tampilkan per-script")
    p_doc.add_argument("--capabilities", action="store_true", help="Tampilkan kapabilitas")
    p_doc.add_argument("--device", type=str, default=None, help="Serial perangkat")
    p_doc.set_defaults(func=cmd_doctor)

    # ── recon ──────────────────────────────────────────────────────────
    p_recon = sub.add_parser("recon", help="Reconnaissance target APK")
    p_recon.add_argument("--apk", required=True, help="Path ke file APK")
    p_recon.add_argument("--output", "-o", help="Direktori output")
    p_recon.set_defaults(func=cmd_recon)

    # ── strings ────────────────────────────────────────────────────────
    p_str = sub.add_parser("strings", help="Ekstrak string dari DEX")
    p_str.add_argument("apk", help="Path ke file APK atau DEX")
    p_str.add_argument("--pattern", "-p", help="Filter regex")
    p_str.add_argument("--output", "-o", help="File output")
    p_str.set_defaults(func=cmd_strings)

    # ── patch ──────────────────────────────────────────────────────────
    p_patch = sub.add_parser("patch", help="Patch DEX atau native")
    p_patch_sub = p_patch.add_subparsers(dest="patch_type", help="Tipe patch")

    p_dexb = p_patch_sub.add_parser("dex-bytes", help="Patch byte-level DEX")
    p_dexb.add_argument("dex", help="Path ke file DEX")
    p_dexb.add_argument("--offset", help="Offset byte")
    p_dexb.add_argument("--old-bytes", help="Byte lama (hex)")
    p_dexb.add_argument("--new-bytes", help="Byte baru (hex)")

    p_dexs = p_patch_sub.add_parser("dex-string", help="Patch string DEX")
    p_dexs.add_argument("dex", help="Path ke file DEX")
    p_dexs.add_argument("--old-string", help="String lama")
    p_dexs.add_argument("--new-string", help="String baru")

    p_nat = p_patch_sub.add_parser("native", help="Patch native .so")
    p_nat.add_argument("so_file", help="Path ke file .so")

    p_sml = p_patch_sub.add_parser("smali", help="Patch smali")
    p_sml.add_argument("smali_dir", help="Direktori smali")

    p_find = p_patch_sub.add_parser("find-insn", help="Cari instruksi")
    p_find.add_argument("dex", help="Path ke file DEX")
    p_find.add_argument("--method", help="Nama method target")

    p_patch.set_defaults(func=cmd_patch)

    # ── repack ─────────────────────────────────────────────────────────
    p_repack = sub.add_parser("repack", help="Repack dan sign ulang APK")
    p_repack.add_argument("--apk", required=True, help="APK asli")
    p_repack.add_argument("--output", "-o", required=True, help="Path output")
    p_repack.add_argument("--dexdir", help="Direktori DEX pengganti")
    p_repack.add_argument("--dex", action="append", help="DEX individual (nama=path)")
    p_repack.add_argument("--keystore", "--ks", help="Path keystore")
    p_repack.add_argument("--no-sign", action="store_true", help="Jangan sign")
    p_repack.set_defaults(func=cmd_repack)

    # ── mod-repack ─────────────────────────────────────────────────────
    p_mod_repack = sub.add_parser("mod-repack", help="Modifikasi APK dan kemas ulang siap pakai untuk Android")
    p_mod_sub = p_mod_repack.add_subparsers(dest="action", help="Aksi mod-repack (auto, unpack, repack)")

    p_mauto = p_mod_sub.add_parser("auto", help="Otomatis unpack, modifikasi manifest/dex, zipalign 4-byte & V1-V3 sign")
    p_mauto.add_argument("--apk", required=True, help="File APK target")
    p_mauto.add_argument("--output", "-o", required=True, help="File APK output hasil kemas ulang")
    p_mauto.add_argument("--debuggable", action="store_true", help="Injeksi android:debuggable='true'")
    p_mauto.add_argument("--cleartext", action="store_true", help="Injeksi android:usesCleartextTraffic='true'")
    p_mauto.add_argument("--trust-user-ca", action="store_true", help="Izinkan user CA certificates di manifest")
    p_mauto.add_argument("--swap-dex", action="append", help="Ganti DEX (format: target_in_apk=source_file, misal classes.dex=patch.dex)")
    p_mauto.add_argument("--keystore", help="Path keystore khusus (default: auto debug.keystore)")
    p_mauto.add_argument("--ks-pass", default="android", help="Password keystore")
    p_mauto.add_argument("--ks-alias", default="androiddebugkey", help="Alias key")
    p_mauto.add_argument("--no-verify", action="store_true", help="Lewati verifikasi apksigner")

    p_munpack = p_mod_sub.add_parser("unpack", help="Ekstrak file APK ke direktori kerja")
    p_munpack.add_argument("--apk", required=True, help="File APK target")
    p_munpack.add_argument("--out-dir", required=True, help="Direktori tujuan ekstraksi")

    p_mrepack = p_mod_sub.add_parser("repack", help="Kemas direktori kerja menjadi APK ter-align dan ter-sign")
    p_mrepack.add_argument("--dir", required=True, help="Direktori kerja modifikasi")
    p_mrepack.add_argument("--output", "-o", required=True, help="File APK output hasil kemas ulang")
    p_mrepack.add_argument("--keystore", help="Path keystore khusus (default: auto debug.keystore)")
    p_mrepack.add_argument("--ks-pass", default="android", help="Password keystore")
    p_mrepack.add_argument("--ks-alias", default="androiddebugkey", help="Alias key")
    p_mrepack.add_argument("--no-verify", action="store_true", help="Lewati verifikasi apksigner")

    p_mod_repack.set_defaults(func=cmd_mod_repack)

    # ── verify ─────────────────────────────────────────────────────────
    p_verify = sub.add_parser("verify", help="Verifikasi build di device")
    p_verify.add_argument("--apk", required=True, help="Path APK")
    p_verify.add_argument("--serial", "-s", help="Serial perangkat")
    p_verify.add_argument("--no-screenshot", action="store_true", help="Skip screenshot")
    p_verify.set_defaults(func=cmd_verify)

    # ── scan ───────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Security scanning")
    p_scan_sub = p_scan.add_subparsers(dest="scan_type", help="Tipe scan")

    p_leaks = p_scan_sub.add_parser("leaks", help="Scan kebocoran data")
    p_leaks.add_argument("target", help="Direktori atau file target")
    p_leaks.add_argument("--show-exempt", action="store_true", help="Tampilkan exemptions")

    p_tls = p_scan_sub.add_parser("tls", help="Cek TLS/cert pinning")
    p_tls.add_argument("target", help="APK atau package name")

    p_api = p_scan_sub.add_parser("api", help="Probe API endpoint")
    p_api.add_argument("target", help="URL atau konfigurasi")

    p_sig = p_scan_sub.add_parser("signatures", help="Analisis signature")
    p_sig.add_argument("target", help="APK target")

    p_ad = p_scan_sub.add_parser("anti-detect", help="Cek anti-detection")
    p_ad.add_argument("target", nargs="?", help="Package name")

    p_scan.set_defaults(func=cmd_scan)

    # ── frida ──────────────────────────────────────────────────────────
    p_frida = sub.add_parser("frida", help="Analisis dinamis dengan Frida")
    p_frida_sub = p_frida.add_subparsers(dest="frida_cmd", help="Perintah Frida")

    p_probe = p_frida_sub.add_parser("probe", help="Universal probe")
    p_probe.add_argument("package", help="Package name")

    p_rpc = p_frida_sub.add_parser("rpc", help="RPC server")
    p_rpc.add_argument("package", help="Package name")
    p_rpc.add_argument("--script", help="Custom script path")

    p_spawn = p_frida_sub.add_parser("spawn", help="Spawn-patch-detach")
    p_spawn.add_argument("package", help="Package name")
    p_spawn.add_argument("--script", help="Patch script")

    p_stalk = p_frida_sub.add_parser("stalker", help="Stalker trace")
    p_stalk.add_argument("target", help="Target function/module")

    p_cold = p_frida_sub.add_parser("coldstart", help="Cold-start analysis")
    p_cold.add_argument("package", help="Package name")

    p_mem = p_frida_sub.add_parser("mem-scan", help="Memory DEX scan")
    p_mem.add_argument("package", help="Package name")

    p_frida.set_defaults(func=cmd_frida)

    # ── web ────────────────────────────────────────────────────────────
    p_web = sub.add_parser("web", help="Web Reverse Engineering (Source Maps & API tracer)")
    p_web_sub = p_web.add_subparsers(dest="web_cmd", help="Perintah Web RE")

    p_sm = p_web_sub.add_parser("sourcemap", help="Ekstrak source code dari Source Map (.js.map)")
    sm_grp = p_sm.add_mutually_exclusive_group(required=True)
    sm_grp.add_argument("--url", help="URL website")
    sm_grp.add_argument("--js-url", help="URL file JS")
    sm_grp.add_argument("--file", help="File lokal .js atau .js.map")
    p_sm.add_argument("--out-dir", default="./extracted_src", help="Direktori output")
    p_sm.add_argument("--scan-only", action="store_true", help="Pindai saja tanpa ekstrak")
    p_sm.add_argument("--json", action="store_true", help="Format JSON")
    p_sm.add_argument("--verbose", action="store_true", help="Output detail")

    p_tracer = p_web_sub.add_parser("api-tracer", help="Lacak signature, token, dan kripto di JS web")
    tr_grp = p_tracer.add_mutually_exclusive_group(required=True)
    tr_grp.add_argument("--file", help="File JS lokal")
    tr_grp.add_argument("--url", help="URL file JS")
    p_tracer.add_argument("--query", help="Keyword/header spesifik (misal X-Sign)")
    p_tracer.add_argument("--json", action="store_true", help="Format JSON")

    p_deobf = p_web_sub.add_parser("deobf", help="Deobfuskasi, unpack eval/packer, dan format JS")
    p_deobf.add_argument("--file", "-f", required=True, help="File JS target")
    p_deobf.add_argument("--output", "-o", help="File output hasil format/deobfuskasi")
    p_deobf.add_argument("--no-kill-debugger", action="store_true", help="Jangan netralkan debugger statements")
    p_deobf.add_argument("--no-beautify", action="store_true", help="Jangan format ulang baris")

    p_usr = p_web_sub.add_parser("userscript", help="Generate Tampermonkey userscript (.user.js)")
    p_usr.add_argument("--domain", required=True, help="Domain target (misal: example.com)")
    p_usr.add_argument("--template", choices=["bypass-anti-debug", "hook-api", "dom-unlock", "override-func"],
                       default="bypass-anti-debug", help="Template modifikasi")
    p_usr.add_argument("--name", help="Nama userscript")
    p_usr.add_argument("--func", help="Fungsi target untuk override-func (misal: window.checkVip)")
    p_usr.add_argument("--return-val", default="true", help="Return value untuk override-func")
    p_usr.add_argument("--custom-code", help="Snippet JS kustom")
    p_usr.add_argument("--output", "-o", help="File output .user.js")

    p_srv = p_web_sub.add_parser("serve", help="Jalankan Map-Local interceptor server")
    p_srv.add_argument("--port", type=int, default=8080, help="Port server (default: 8080)")
    p_srv.add_argument("--map-local", action="append", default=[], help="Mapping path=file (misal: /app.js=./clean.js)")

    p_web.set_defaults(func=cmd_web)

    # ── mitm ───────────────────────────────────────────────────────────
    p_mitm = sub.add_parser("mitm", help="Patch Network Security Config untuk inspeksi HTTPS/user CA")
    p_mitm.add_argument("--apk", help="Path file APK untuk dianalisis")
    p_mitm.add_argument("--dir", help="Path direktori hasil decompile APK (apktool)")
    p_mitm.add_argument("--out", "-o", help="Path output untuk hasil patching")
    p_mitm.add_argument("--inspect-only", action="store_true", help="Hanya periksa konfigurasi tanpa modifikasi")
    p_mitm.add_argument("--export-frida", help="Simpan skrip bypass SSL pinning Frida ke file")
    p_mitm.set_defaults(func=cmd_mitm)

    # ── debloat ────────────────────────────────────────────────────────
    p_deb = sub.add_parser("debloat", help="Scan, debloat, dan neuter komponen iklan di manifest")
    p_deb.add_argument("--target", "-t", help="Path direktori decompile atau AndroidManifest.xml")
    p_deb.add_argument("--scan", action="store_true", help="Pindai keberadaan ad/telemetry SDK")
    p_deb.add_argument("--neuter", action="store_true", help="Nonaktifkan komponen iklan di manifest")
    p_deb.add_argument("--out", "-o", help="File output untuk manifest hasil neuter")
    p_deb.add_argument("--generate-stubs", action="store_true", help="Generate template smali no-op stubs")
    p_deb.add_argument("--json", action="store_true", help="Output dalam format JSON")
    p_deb.set_defaults(func=cmd_debloat)

    # ── frida-gen ──────────────────────────────────────────────────────
    p_fgen = sub.add_parser("frida-gen", help="Generator skrip Frida hook (SSL unpinning, root bypass, crypto, trace)")
    p_fgen.add_argument("--template", "-t", choices=["ssl-unpin", "root-bypass", "crypto-monitor", "method-trace", "intent-monitor"], default="ssl-unpin", help="Template hook")
    p_fgen.add_argument("--class-name", "-c", help="Nama class lengkap")
    p_fgen.add_argument("--method-name", "-m", help="Nama method target")
    p_fgen.add_argument("--out", "-o", help="File output JavaScript")
    p_fgen.add_argument("--print-only", action="store_true", help="Cetak skrip ke terminal tanpa simpan ke file")
    p_fgen.set_defaults(func=cmd_frida_gen)

    # ── jni ────────────────────────────────────────────────────────────
    p_jni = sub.add_parser("jni", help="Analisis exported JNI symbols dari native .so dan generate Frida hooks")
    p_jni.add_argument("--so", required=True, help="Path ke file library native .so")
    p_jni.add_argument("--generate-hooks", action="store_true", help="Generate kode Frida native interceptor")
    p_jni.add_argument("--out", "-o", help="File output skrip Frida")
    p_jni.add_argument("--json", action="store_true", help="Output dalam format JSON")
    p_jni.set_defaults(func=cmd_jni)

    # ── decode ─────────────────────────────────────────────────────────
    p_dec = sub.add_parser("decode", help="Decode opaque blobs, cached configs, dan protobuf")
    p_dec_sub = p_dec.add_subparsers(dest="decode_type", help="Tipe decoder")

    p_blob = p_dec_sub.add_parser("blob", help="Decode opaque config blobs (rotasi byte + kompresi)")
    p_blob.add_argument("--file", help="File berisi blob target")
    p_blob.add_argument("--prefs-xml", help="Path ke SharedPreferences XML")
    p_blob.add_argument("--name", help="Nama key dalam XML")
    p_blob.add_argument("--out", "-o", help="File output hasil dekode")
    p_blob.add_argument("--max-skip", type=int, help="Maksimum byte header yang di-skip")
    p_blob.add_argument("--encode", action="store_true", help="Re-encode payload yang telah diedit")
    p_blob.add_argument("--outer", choices=["base64", "base64url", "hex"], help="Outer encoding")
    p_blob.add_argument("--inner", choices=["raw", "zlib", "gzip"], help="Inner compression")
    p_blob.add_argument("--cut", type=int, help="Panjang cyclic cut")

    p_proto = p_dec_sub.add_parser("proto", help="Decode binary protobuf tanpa file schema .proto")
    p_proto.add_argument("--hex", help="Hex string dari payload protobuf")
    p_proto.add_argument("--file", help="File binary protobuf")
    p_proto.add_argument("--split", choices=["varint-length"], help="Framing split")
    p_proto.add_argument("--reencode", action="store_true", help="Verifikasi round-trip re-encode")

    p_dec.set_defaults(func=cmd_decode)

    # ── report ─────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate laporan analisis")
    p_report.add_argument("--apk", help="APK yang dianalisis")
    p_report.add_argument("--work-dir", help="Direktori kerja")
    p_report.add_argument("--format", choices=["markdown", "html", "json"], default="markdown")
    p_report.add_argument("--output", "-o", help="File output")
    p_report.add_argument("--language", "--lang", choices=["en", "id"], default="id")
    p_report.set_defaults(func=cmd_report)

    # ── list ───────────────────────────────────────────────────────────
    p_list = sub.add_parser("list", help="Tampilkan semua skrip")
    p_list.set_defaults(func=cmd_list)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print(_banner())
        parser.print_help()
        sys.exit(0)

    result = args.func(args)
    if hasattr(result, "returncode"):
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
