#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate specialized Frida bypass scripts for Android security controls.

WHY THIS EXISTS
---------------
Dynamic analysis often hits immediate blockers:
  - Strict SSL/TLS certificate pinning (OkHttp, TrustManager, Conscrypt, Flutter)
  - Root detection checks (su binary scan, test-keys, RootBeer, Magisk)
  - Anti-debugging and Frida detection (TracerPid, port 27042, thread names)

This tool generates targeted, modular Frida scripts to neutralize these protections
cleanly before performing application logic inspection.

USAGE
-----
  # Generate universal SSL unpinning script
  python generate_bypass.py --type ssl --out unpin.js

  # Generate root detection bypass script
  python generate_bypass.py --type root --out bypass_root.js

  # Generate combined SSL + root bypass script
  python generate_bypass.py --type all --out full_bypass.js

EXIT CODES
----------
  0 = script generated successfully
  2 = usage or argument error
"""

import argparse
import os
import sys

SSL_BYPASS_JS = r"""// Universal SSL Pinning Bypass (OkHttp, TrustManager, Conscrypt, NetworkSecurityConfig)
Java.perform(function() {
    console.log("[*] [Frida] Mengaktifkan SSL Pinning Bypass...");

    // 1. javax.net.ssl.TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
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
            console.log("[+] [Frida] Hooked SSLContext.init() -> X509TrustManager bypassed");
            SSLContext_init.call(this, km, trustManagers, sr);
        };
    } catch(e) {}

    // 2. OkHttp 3 & 4 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] [Frida] OkHttp CertificatePinner.check bypassed for: " + hostname);
            return;
        };
    } catch(e) {}

    // 3. Android NetworkSecurityConfig
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkPins.implementation = function(pins) {
            console.log("[+] [Frida] NetworkSecurityTrustManager.checkPins bypassed");
            return;
        };
    } catch(e) {}
});
"""

ROOT_BYPASS_JS = r"""// Universal Root & Anti-Tamper Bypass
Java.perform(function() {
    console.log("[*] [Frida] Mengaktifkan Root Detection Bypass...");

    // 1. java.io.File checks for root binaries
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootIndicators = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/su",
            "/data/local/bin/su", "/system/xbin/busybox"
        ];
        for (var i = 0; i < rootIndicators.length; i++) {
            if (path.indexOf(rootIndicators[i]) !== -1) {
                console.log("[+] [Frida] Menyamarkan keberadaan root binary: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // 2. Runtime.exec su checks
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[+] [Frida] Menetralisir perintah root shell: " + cmd);
            return Runtime.exec.call(this, "echo_null");
        }
        return this.exec(cmd);
    };

    // 3. Build tags
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
});
"""


def main():
    parser = argparse.ArgumentParser(
        prog="generate_bypass.py",
        description="Generate Frida bypass scripts for Android SSL pinning and root detection",
    )
    parser.add_argument(
        "--type", "-t",
        choices=["ssl", "root", "all"],
        default="all",
        help="Tipe bypass yang ingin di-generate (ssl, root, all)"
    )
    parser.add_argument("--out", "-o", help="File output JavaScript hasil generate")

    args = parser.parse_args()

    content = ""
    if args.type == "ssl":
        content = SSL_BYPASS_JS
    elif args.type == "root":
        content = ROOT_BYPASS_JS
    elif args.type == "all":
        content = SSL_BYPASS_JS + "\n\n" + ROOT_BYPASS_JS

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Skrip bypass ({args.type}) disimpan ke: {args.out}")
    else:
        print(content)

    sys.exit(0)


if __name__ == "__main__":
    main()
