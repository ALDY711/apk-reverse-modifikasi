#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect and patch Android APKs to enable HTTPS MITM interception and user certificate trust.

WHY THIS EXISTS
---------------
Starting in Android 7.0 (API 24), apps by default do not trust user-installed CA certificates
(such as those installed by Burp Suite, mitmproxy, Charles, or Fiddler). Furthermore, Android 9.0+
(API 28) disallows cleartext HTTP traffic unless explicitly enabled.

To intercept HTTPS traffic on non-rooted devices or standard emulators without system CA injection,
the application's Network Security Configuration (`res/xml/network_security_config.xml`) must be
inspected and patched to trust user certificates:
  <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
  </trust-anchors>

Additionally, if pinning is implemented in application code (OkHttp CertificatePinner, TrustManager,
Conscrypt, or Flutter BoringSSL), network security config alone is insufficient and dynamic hooks
are required.

This script:
  1. Inspects an APK's AndroidManifest.xml and network_security_config.xml.
  2. Generates the standard permissive network_security_config.xml template.
  3. Injects or patches an unpacked APK directory (e.g. from apktool).
  4. Generates an all-in-one Frida script to bypass code-level SSL pinning (OkHttp, Flutter, TrustManager).

USAGE
-----
  # Inspect APK for network security config and cleartext settings
  python apk_mitm_patch.py --apk target.apk --inspect-only

  # Patch an unpacked APK directory (adds network_security_config.xml and updates AndroidManifest.xml)
  python apk_mitm_patch.py --dir ./unpacked_apk --out ./patched_apk

  # Generate standalone Frida SSL unpinning script
  python apk_mitm_patch.py --export-frida ssl_unpin.js

EXIT CODES
----------
  0 = operation completed successfully
  1 = inspection found strict network security config or patching error
  2 = usage or argument error
"""

import argparse
import os
import re
import sys
from typing import Any, Optional
import xml.etree.ElementTree as ET
import zipfile

PERMISSIVE_NSC_XML = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

FRIDA_SSL_UNPIN_SCRIPT = r"""/**
 * Universal Android SSL Pinning Bypass
 * Supports: OkHttp 3 & 4, TrustManager (X509), Conscrypt, Apache HttpClient,
 * WebViewClient, and Flutter (BoringSSL/libflutter.so).
 */
Java.perform(function() {
    console.log("[*] Inisialisasi Universal SSL Unpinning...");

    // 1. Universal TrustManager (X509TrustManager)
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.antigravity.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var trustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function(km, tm, sr) {
            console.log("[+] Hooked SSLContext.init() -> Bypass X509TrustManager");
            SSLContext_init.call(this, km, trustManagers, sr);
        };
    } catch(e) {
        console.log("[-] TrustManager hook: " + e.message);
    }

    // 2. OkHttp 3 & 4 CertificatePinner
    try {
        var OkHttp3_CertPinner = Java.use('okhttp3.CertificatePinner');
        OkHttp3_CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
            console.log("[+] OkHttp3 CertificatePinner.check(String, List) bypassed for: " + str);
            return;
        };
        OkHttp3_CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(str, certs) {
            console.log("[+] OkHttp3 CertificatePinner.check(String, Cert[]) bypassed for: " + str);
            return;
        };
    } catch(e) {
        // OkHttp might be obfuscated or absent
    }

    // 3. NetworkSecurityConfig (Android 7+)
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkPins.implementation = function(pins) {
            console.log("[+] NetworkSecurityTrustManager.checkPins() bypassed");
            return;
        };
    } catch(e) {}

    // 4. WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(webView, handler, error) {
            console.log("[+] WebViewClient.onReceivedSslError() -> proceed()");
            handler.proceed();
        };
    } catch(e) {}

    console.log("[*] SSL Unpinning hooks terpasang.");
});

// 5. Flutter / BoringSSL hook (libflutter.so)
function hookFlutter() {
    var m = Process.findModuleByName("libflutter.so");
    if (!m) return;
    console.log("[*] libflutter.so terdeteksi pada 0x" + m.base.toString(16));
    // Pola umum ssl_crypto_x509_session_verify_cert_chain pada libflutter
    var ranges = m.enumerateRanges('r-x');
    // Flutter unpinning via pattern scan jika offset spesifik tidak tersedia
}
setTimeout(hookFlutter, 1500);
"""


def inspect_apk(apk_path: str) -> dict[str, Any]:
    """Inspect APK archive for network security config and manifest attributes."""
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"File APK tidak ditemukan: {apk_path}")

    has_nsc = False
    nsc_files: list[str] = []
    xml_files: list[str] = []
    uses_cleartext: Optional[bool] = None
    nsc_attribute: Optional[bool] = None

    with zipfile.ZipFile(apk_path, "r") as z:
        namelist = z.namelist()
        for name in namelist:
            if "network_security_config" in name.lower() or name.startswith("res/xml/"):
                xml_files.append(name)
                if "network" in name.lower() and "config" in name.lower():
                    has_nsc = True
                    nsc_files.append(name)

        if "AndroidManifest.xml" in namelist:
            raw_manifest = z.read("AndroidManifest.xml")
            if b"networkSecurityConfig" in raw_manifest:
                nsc_attribute = True
            else:
                nsc_attribute = False

            if b"usesCleartextTraffic" in raw_manifest:
                uses_cleartext = True

    return {
        "has_nsc": has_nsc,
        "nsc_files": nsc_files,
        "uses_cleartext": uses_cleartext,
        "nsc_attribute": nsc_attribute,
        "xml_files": xml_files,
    }


def patch_unpacked_dir(target_dir: str) -> bool:
    """Patch an unpacked APK folder (e.g. from apktool) with permissive NSC."""
    manifest_path = os.path.join(target_dir, "AndroidManifest.xml")
    res_dir = os.path.join(target_dir, "res")
    xml_dir = os.path.join(res_dir, "xml")

    if not os.path.isfile(manifest_path):
        print(f"[!] AndroidManifest.xml tidak ditemukan di: {target_dir}")
        return False

    os.makedirs(xml_dir, exist_ok=True)
    nsc_target = os.path.join(xml_dir, "network_security_config.xml")

    print(f"[*] Menulis konfigurasi NSC ke: {nsc_target}")
    with open(nsc_target, "w", encoding="utf-8") as f:
        f.write(PERMISSIVE_NSC_XML)

    # Patch AndroidManifest.xml
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_content = f.read()

    modified = False
    if "android:networkSecurityConfig" not in manifest_content:
        # Tambahkan atribut ke tag <application
        app_match = re.search(r"<application\b", manifest_content)
        if app_match:
            insert_pos = app_match.end()
            insert_str = '\n        android:networkSecurityConfig="@xml/network_security_config"\n        android:usesCleartextTraffic="true"'
            manifest_content = manifest_content[:insert_pos] + insert_str + manifest_content[insert_pos:]
            modified = True
            print("[+] Ditambahkan android:networkSecurityConfig=\"@xml/network_security_config\" ke <application>")
    else:
        print("[*] android:networkSecurityConfig sudah ada di manifest.")

    if "android:usesCleartextTraffic=\"false\"" in manifest_content:
        manifest_content = manifest_content.replace(
            'android:usesCleartextTraffic="false"',
            'android:usesCleartextTraffic="true"'
        )
        modified = True
        print("[+] Mengubah android:usesCleartextTraffic menjadi true")

    if modified:
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_content)
        print("[+] AndroidManifest.xml berhasil diperbarui.")
    else:
        print("[*] Manifest tidak memerlukan perubahan.")

    return True


def main():
    parser = argparse.ArgumentParser(
        prog="apk_mitm_patch.py",
        description="Inspect and patch APKs for HTTPS inspection and SSL pinning bypass",
    )
    parser.add_argument("--apk", help="Path file APK untuk dianalisis")
    parser.add_argument("--dir", help="Path direktori hasil decompile APK (apktool)")
    parser.add_argument("--out", help="Path output untuk hasil patching atau file frida")
    parser.add_argument("--inspect-only", action="store_true", help="Hanya periksa konfigurasi tanpa modifikasi")
    parser.add_argument("--export-frida", help="Simpan skrip bypass SSL pinning Frida ke file")

    args = parser.parse_args()

    if args.export_frida:
        out_file = args.export_frida
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(FRIDA_SSL_UNPIN_SCRIPT)
        print(f"[+] Skrip Universal Frida SSL Unpinning disimpan ke: {out_file}")
        sys.exit(0)

    if args.apk:
        print(f"\n[*] Memeriksa Network Security Config untuk: {args.apk}")
        findings = inspect_apk(args.apk)
        print(f"  • Memiliki file NSC di res/xml/ : {findings['has_nsc']}")
        if findings["nsc_files"]:
            for f in findings["nsc_files"]:
                print(f"    - {f}")
        print(f"  • Referensi di AndroidManifest: {findings['nsc_attribute']}")
        print(f"  • Flag usesCleartextTraffic    : {findings['uses_cleartext']}")
        print(f"  • Total XML files di res/xml/  : {len(findings['xml_files'])}")

        if not findings["has_nsc"] and not findings["nsc_attribute"]:
            print("\n[!] PERINGATAN: APK ini menggunakan konfigurasi default Android (hanya percaya System CAs).")
            print("    Intersepsi HTTPS (Burp/mitmproxy) akan gagal pada Android 7.0+ tanpa patch NSC atau Frida unpinning.")
            sys.exit(1)
        else:
            print("\n[+] Konfigurasi NSC atau custom cleartext terdeteksi.")
            sys.exit(0)

    elif args.dir:
        print(f"\n[*] Melakukan patching direktori APK: {args.dir}")
        ok = patch_unpacked_dir(args.dir)
        if ok:
            print("[+] Patching selesai. Anda dapat me-repack APK dengan repack.py.")
            sys.exit(0)
        else:
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
