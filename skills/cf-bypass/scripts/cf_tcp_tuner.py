#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP Stack & OS Fingerprint Tuner for Anti-Bot & p0f Mismatch Neutralization.

WHY THIS EXISTS
---------------
When an HTTP request claims to originate from:
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
Cloudflare's edge packet filters inspect the initial TCP SYN packet parameters (p0f / JA4T):
  - IP Default TTL (Linux = 64, Windows = 128)
  - TCP Window Size (Linux = 29200, Windows = 64240/65535)
  - TCP Window Scaling Factor (Linux = 7, Windows = 8)
  - TCP Timestamps (Linux = Enabled by default, Windows Chrome = Disabled)

If your scraping bot runs on an Ubuntu/Debian Linux VPS with default kernel parameters,
Cloudflare flags an **Operating System Mismatch (p0f OS anomaly)**, increasing the bot
threat score and triggering immediate Turnstile challenges.

This tool checks local network stack parameters and outputs the exact `sysctl` commands
required to make a Linux server's TCP stack mimic Windows 10/11.

USAGE
-----
  # Check current OS TCP stack parameters
  python cf_tcp_tuner.py --check

  # Generate Linux sysctl configuration for Windows 10/11 emulation
  python cf_tcp_tuner.py --generate-sysctl

  # Apply sysctl settings directly (requires sudo/root privileges on Linux)
  sudo python cf_tcp_tuner.py --apply

EXIT CODES
----------
  0 = check complete or settings generated/applied
  1 = OS mismatch detected (on --check)
  2 = argument or permission error
"""

import argparse
import os
import platform
import subprocess
import sys


WINDOWS_TARGET_PARAMS = {
    "ip_default_ttl": 128,
    "tcp_window_scaling": 1,
    "tcp_timestamps": 0,
    "tcp_sack": 1,
}

LINUX_DEFAULT_PARAMS = {
    "ip_default_ttl": 64,
    "tcp_window_scaling": 1,
    "tcp_timestamps": 1,
    "tcp_sack": 1,
}


def read_linux_sysctl(param_path: str) -> str | None:
    """Read a sysctl parameter value from /proc/sys/."""
    try:
        with open(f"/proc/sys/{param_path}", "r") as f:
            return f.read().strip()
    except Exception:
        return None


def check_current_stack():
    """Inspect and report current TCP/IP stack configuration."""
    current_os = platform.system()
    print("=================================================================")
    print("           TCP / OS FINGERPRINT (p0f / JA4T) INSPECTOR           ")
    print("=================================================================")
    print(f"[*] Detected Host OS : {current_os} ({platform.release()})")

    if current_os == "Windows":
        print("[+] Host is running native Windows.")
        print("[+] TCP SYN packets naturally produce Windows JA4T fingerprints (TTL=128).")
        print("[+] No kernel sysctl tuning required.")
        return 0

    if current_os != "Linux":
        print(f"[*] Host OS '{current_os}' is not Linux. Kernel tuning is only applicable to Linux.")
        return 0

    # Inspect Linux parameters
    ttl = read_linux_sysctl("net/ipv4/ip_default_ttl")
    scaling = read_linux_sysctl("net/ipv4/tcp_window_scaling")
    timestamps = read_linux_sysctl("net/ipv4/tcp_timestamps")
    sack = read_linux_sysctl("net/ipv4/tcp_sack")

    print(f"[*] Current net.ipv4.ip_default_ttl   : {ttl} (Windows Target: 128)")
    print(f"[*] Current net.ipv4.tcp_window_scaling : {scaling} (Windows Target: 1)")
    print(f"[*] Current net.ipv4.tcp_timestamps     : {timestamps} (Windows Target: 0)")
    print(f"[*] Current net.ipv4.tcp_sack           : {sack} (Windows Target: 1)")
    print("-----------------------------------------------------------------")

    is_mismatch = (ttl != "128" or timestamps != "0")
    if is_mismatch:
        print("[!] WARNING: OS MISMATCH DETECTED!")
        print("    Your User-Agent header claims to be Windows, but your Linux TCP SYN")
        print("    packet sends TTL=64 and Timestamps enabled. Cloudflare p0f will flag this.")
        print("    Run 'python cf_tcp_tuner.py --generate-sysctl' for remediation commands.")
        return 1
    else:
        print("[+] SUCCESS: TCP stack parameters are tuned to match Windows 10/11.")
        return 0


def generate_sysctl_commands():
    """Output sysctl commands and /etc/sysctl.d configuration."""
    print("=================================================================")
    print("       LINUX SYSCTL TUNING COMMANDS (WINDOWS 10/11 EMULATION)     ")
    print("=================================================================")
    print("# Execute the following commands in your Linux terminal as root:\n")
    print("sudo sysctl -w net.ipv4.ip_default_ttl=128")
    print("sudo sysctl -w net.ipv4.tcp_window_scaling=1")
    print("sudo sysctl -w net.ipv4.tcp_timestamps=0")
    print("sudo sysctl -w net.ipv4.tcp_sack=1")
    print("sudo sysctl -w net.ipv4.tcp_rmem=\"4096 87380 6291456\"")
    print("sudo sysctl -w net.ipv4.tcp_wmem=\"4096 16384 4194304\"\n")
    print("-----------------------------------------------------------------")
    print("# To make these changes permanent across reboots, append to /etc/sysctl.conf:\n")
    print("cat << 'EOF' | sudo tee -a /etc/sysctl.d/99-cloudflare-bypass.conf")
    print("net.ipv4.ip_default_ttl = 128")
    print("net.ipv4.tcp_window_scaling = 1")
    print("net.ipv4.tcp_timestamps = 0")
    print("net.ipv4.tcp_sack = 1")
    print("EOF")
    print("sudo sysctl --system")
    print("=================================================================")


def apply_sysctl():
    """Apply sysctl tuning directly to Linux host."""
    if platform.system() != "Linux":
        print("[!] Error: --apply can only be executed on Linux systems.", file=sys.stderr)
        sys.exit(2)

    commands = [
        ["sysctl", "-w", "net.ipv4.ip_default_ttl=128"],
        ["sysctl", "-w", "net.ipv4.tcp_window_scaling=1"],
        ["sysctl", "-w", "net.ipv4.tcp_timestamps=0"],
        ["sysctl", "-w", "net.ipv4.tcp_sack=1"],
    ]

    for cmd in commands:
        try:
            res = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"[+] Applied: {res.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error applying {cmd}: {e.stderr.strip()}", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print("[!] Permission Denied: You must run this command with 'sudo'.", file=sys.stderr)
            sys.exit(2)

    print("[+] All TCP stack parameters successfully tuned to Windows 10/11 profile.")


def main():
    parser = argparse.ArgumentParser(
        description="TCP Stack & OS Fingerprint Tuner for Anti-Bot Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", "-c", action="store_true", help="Inspect current host TCP/IP stack configuration")
    group.add_argument("--generate-sysctl", "-g", action="store_true", help="Print Linux sysctl commands for Windows emulation")
    group.add_argument("--apply", "-a", action="store_true", help="Apply sysctl parameters directly (Linux root required)")

    args = parser.parse_args()

    if args.check:
        sys.exit(check_current_stack())
    elif args.generate_sysctl:
        generate_sysctl_commands()
        sys.exit(0)
    elif args.apply:
        apply_sysctl()
        sys.exit(0)


if __name__ == "__main__":
    main()
