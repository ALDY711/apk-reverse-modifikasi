# APK Repacker Routing Inventory

## Reference index

| Reference | Purpose |
|---|---|
| `references/apk-signing-schemes.md` | Penjelasan skema penandatanganan V1, V2, V3, V4 dan alasan penolakan instalasi |
| `references/zipalign-and-compression.md` | Aturan 4-byte zipalign dan mode kompresi STORED vs DEFLATED pada Android |

## Script index

| Script | Purpose |
|---|---|
| `scripts/repack_pipeline.py` | Pipeline pengemasan direktori modifikasi menjadi APK, 4-byte zipalign, dan signing |
| `scripts/apk_signer.py` | Penandatanganan biner APK dengan skema V1, V2, V3 dan verifikasi integritas signature |
