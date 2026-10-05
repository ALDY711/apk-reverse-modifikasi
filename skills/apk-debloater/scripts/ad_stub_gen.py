#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate smali no-op return stubs and rewarded ad callback bypass stubs.

WHY THIS EXISTS
---------------
When an app gates features behind rewarded video ads (e.g. "Watch ad to unlock HD feature"),
simply removing the ad SDK causes runtime crashes when the app expects an ad callback.

This script outputs smali templates that immediately simulate successful ad completion
without requesting network ad assets or displaying dialogs.

USAGE
-----
  # Generate rewarded ad smali stub
  python ad_stub_gen.py --type rewarded --out ./RewardedAd.smali

  # Generate interstitial ad smali stub
  python ad_stub_gen.py --type interstitial --out ./InterstitialAd.smali

EXIT CODES
----------
  0 = completed successfully
  2 = usage or argument error
"""

import argparse
import sys

REWARDED_STUB = """.class public Lcom/google/android/gms/ads/rewarded/RewardedAd;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public isLoaded()Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method

.method public show(Landroid/app/Activity;Lcom/google/android/gms/ads/rewarded/RewardedAdCallback;)V
    .registers 3
    if-eqz p2, :cond_0
    new-instance v0, Lcom/google/android/gms/ads/rewarded/RewardItemStub;
    invoke-direct {v0}, Lcom/google/android/gms/ads/rewarded/RewardItemStub;-><init>()V
    invoke-virtual {p2, v0}, Lcom/google/android/gms/ads/rewarded/RewardedAdCallback;->onUserEarnedReward(Lcom/google/android/gms/ads/rewarded/RewardItem;)V
    :cond_0
    return-void
.end method
"""

INTERSTITIAL_STUB = """.class public Lcom/google/android/gms/ads/InterstitialAd;
.super Ljava/lang/Object;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public isLoaded()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public show()V
    .registers 1
    return-void
.end method
"""


def main():
    parser = argparse.ArgumentParser(
        prog="ad_stub_gen.py",
        description="Generate smali no-op stubs for ad callbacks",
    )
    parser.add_argument(
        "--type", "-t",
        choices=["rewarded", "interstitial"],
        default="rewarded",
        help="Tipe stub smali yang akan dibuat"
    )
    parser.add_argument("--out", "-o", help="File output smali")

    args = parser.parse_args()

    content = REWARDED_STUB if args.type == "rewarded" else INTERSTITIAL_STUB

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Smali stub ({args.type}) berhasil disimpan ke: {args.out}")
    else:
        print(content)

    sys.exit(0)


if __name__ == "__main__":
    main()
