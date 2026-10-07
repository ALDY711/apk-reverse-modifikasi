# Cryptographic analysis and decryption — JCA, native ciphers, Keystore, and opaque blobs

A frequent hurdle in reverse engineering is encountering payloads that cannot be read statically: API request/response bodies, cached credentials, configuration blobs in SharedPreferences/DataStore, or asset bundles stored in encrypted form.

The mistake that wastes the most time is attempting to statically reverse engineer custom or standard crypto in disassembled bytecode or decompiled native assembly, before checking if the keys and plaintexts can be intercepted directly at runtime or decoded using standard transformations.


**Load this when:** a captured payload, local store, config or communication is encrypted, or you need to recover cryptographic keys (AES/RSA/HMAC) or decrypt payloads in Android apps.

---

## 1. Decide the cryptographic boundary first

Before attempting complex math or disassembly, identify which boundary the cryptography operates on:

| Observed Symptom | Probable Layer | First-line Approach |
|---|---|---|
| Calls to `javax.crypto.Cipher`, `SecretKeySpec`, `Mac`, or `MessageDigest` exist in dex | **Java JCA Layer** | Runtime hook via `scripts/frida_hook_gen.py` or `apk_cli.py`. Capture plaintext before encryption and after decryption. |
| Key is stored in AndroidKeyStore (`KeyStore.getInstance("AndroidKeyStore")`) | **Hardware/TEE Layer** | Do **not** attempt to extract the private key. Hook `Cipher.init` or `Cipher.doFinal` to extract the plaintext as it flows through. |
| High entropy string in `shared_prefs/*.xml` or `files/` that fails simple base64 decode | **Opaque Config Blob** | Run `scripts/blob_decode.py`. It exhaustively tests cyclic bit shifts, skips, and deflate/zlib/gzip before assuming real crypto. |
| Traffic body is unreadable binary with repeated varints or byte lengths | **Wire Format (Protobuf)** | Run `scripts/protobuf_decode_raw.py` to parse schema-less binary payloads without guessing `.proto` files. |
| Encryption happens inside `.so` (JNI call like `encryptNative`, `signRequest`) | **Native Layer (`.so`)** | Check for standard crypto constants (AES S-box, SHA constants) or hook exported APIs (`EVP_CipherInit_ex`). If obfuscated/VMP, use `scripts/frida_rpc_serve.py`. |
| Server returns 401/403 or refuses to deliver the decrypted content | **Server-side Gate** | The gate is server-side and client patching cannot force server decryption (`membership-and-limits.md`). |

---

## 2. Java Cryptography Architecture (JCA) Interception

Android's Java layer relies on the standard JCA provider (`javax.crypto.*` and `java.security.*`). Because these methods are standard and un-obfuscated across all Android versions, hooking them requires no decompilation of proprietary app logic.

### Standard Hook Targets

1. **Cipher Execution (`javax.crypto.Cipher`):**
   - `Cipher.init(int opmode, Key key, AlgorithmParameterSpec params)`:
     - `opmode`: `1 = ENCRYPT_MODE`, `2 = DECRYPT_MODE`, `3 = WRAP_MODE`, `4 = UNWRAP_MODE`.
     - `key`: Inspect `key.getEncoded()` or `key.getAlgorithm()` to extract raw symmetric keys.
     - `params`: Inspect `IvParameterSpec.getIV()` or `GCMParameterSpec.getIV()`.
   - `Cipher.doFinal(byte[] input)` / `Cipher.doFinal(byte[] input, int offset, int len)`:
     - During `DECRYPT_MODE`: `input` is ciphertext, the return value is **plaintext**.
     - During `ENCRYPT_MODE`: `input` is **plaintext**, the return value is ciphertext.

2. **Symmetric Keys (`javax.crypto.spec.SecretKeySpec`):**
   - Constructor `SecretKeySpec(byte[] key, String algorithm)` directly takes the raw key bytes.

3. **Message Authentication Codes (`javax.crypto.Mac`):**
   - `Mac.init(Key key)` and `Mac.doFinal(byte[] input)` reveal the HMAC secret key and the signed payload (vital for request signing tokens).

4. **Message Digests (`java.security.MessageDigest`):**
   - `MessageDigest.update(byte[] input)` and `MessageDigest.digest()` reveal data being hashed before transmission or storage.

### Automated JCA Monitoring

Generate a ready-to-run Frida hook script using the built-in generator:

```bash
# Generate the crypto monitoring hook via frida_hook_gen.py
python scripts/frida_hook_gen.py --template crypto-monitor --out trace_crypto.js

# Or generate via unified CLI
python apk_cli.py frida-gen --template crypto-monitor --out trace_crypto.js

# Inject into running app
frida -U -f com.target.app -l trace_crypto.js
```

---

## 3. Android KeyStore & Hardware-backed Keys

When an app uses `AndroidKeyStore`, cryptographic keys may be generated inside the Trusted Execution Environment (TEE) or StrongBox Hardware Security Module (HSM).

### The Trap: Extracting Keys that Cannot be Extracted

```java
// If you call this on an AndroidKeyStore entry:
Key key = keyStore.getKey(alias, null);
byte[] raw = key.getEncoded(); // Returns NULL!
```

Key material inside hardware-backed storage is non-exportable by design. Attempting to dump RAM or hook key generators to extract private keys will fail.

### The Solution: Intercept at the Consumer Boundary

Even though the key never leaves hardware, the **data being encrypted or decrypted must pass through userspace memory**.

1. Hook `Cipher.init(int opmode, Key key)`: Identify the alias used and whether it is decrypting.
2. Hook `Cipher.doFinal(byte[] input)`: Capture the return value of `doFinal()`. The decrypted output is completely unencrypted in normal Java heap space.

---

## 4. Native Layer Cryptography (`.so`)

When cryptography is implemented in C/C++ shared libraries (`libnative.so`), analysis moves from JCA hooks to native symbols and memory.

### Step 1: Detect Cryptographic Signatures & Constants

Look for telltale lookup tables and initialization constants in `.rodata`:

* **AES S-Box (256 bytes):**
  `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ...`
* **SHA-256 Initial Hash Values (8x 32-bit words):**
  `0x6a09e667`, `0xbb67ae85`, `0x3c6ef372`, `0xa54ff53a`, `0x510e527f`, `0x9b05688c`, `0x1f83d9ab`, `0x5be0cd19`
* **MD5 Initialization Constants:**
  `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`
* **ChaCha20 Matrix Constants:**
  ASCII `"expand 32-byte k"` (`65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b`)

### Step 2: Hook Standard Native Crypto Exports

If the app statically links or dynamically loads OpenSSL, BoringSSL, or libsodium:

```javascript
// Hook BoringSSL / OpenSSL EVP API
const evpInit = Module.findExportByName(null, "EVP_CipherInit_ex");
if (evpInit) {
    Interceptor.attach(evpInit, {
        onEnter(args) {
            console.log("[*] EVP_CipherInit_ex called");
            // args[3] = key pointer, args[4] = iv pointer
            if (!args[3].isNull()) {
                console.log("  Key: " + hexdump(args[3], { length: 32 }));
            }
        }
    });
}
```

### Step 3: When Native Code is Obfuscated (OLLVM / Custom Linker)

If the native library uses control flow flattening, instruction virtualization, or custom ciphers:
* **Do not disassemble instruction by instruction.**
* Treat the `.so` as an oracle. Expose the function over a local socket using `scripts/frida_rpc_serve.py` or execute the library in an emulated harness like Unidbg (`references/emulation-and-rpc.md`).

---

## 5. Opaque Configuration & Pseudo-Encrypted Blobs

Many applications cache configuration, user state, and remote feature flags as opaque strings inside `shared_prefs/*.xml` or `files/`. Developers often implement light-weight obfuscation instead of full cryptographic ciphers:

```
Pattern: Base64 / Hex  ->  Cyclic Byte Rotation  ->  Deflate / Zlib / Gzip
```

Before assuming an opaque blob requires a cryptographic key:
1. Extract the blob string from XML or disk.
2. Run `scripts/blob_decode.py`:
   ```bash
   python skills/apk-reverse/scripts/blob_decode.py --file cached_config.txt
   ```
3. If successful, the script outputs the exact cyclic shift and compression parameters, allowing you to modify the payload and re-encode it with `--encode`.

---

## 6. Schema-less Protobuf Wire Decoding

Binary communications over gRPC, WebSockets, or HTTP POST often look like unreadable encrypted streams. If the payload does not have TLS or cipher headers, inspect it for protobuf wire-types (varints, length-delimited fields).

Decode unknown binary wire frames using:
```bash
python skills/apk-reverse/scripts/protobuf_decode_raw.py --hex "08 96 01 12 07 74 65 73 74 69 6e 67"
```

The tool reconstructs the field hierarchy without requiring `.proto` schema definitions.

---

## 7. Decryption Verification Checklist

When claiming that a decryption task is complete, verify all four criteria:

- [ ] **Algorithm Identified**: Exact cipher suite, mode, and padding identified (e.g., `AES/CBC/PKCS7Padding`, not just "AES").
- [ ] **Key & IV Recovered**: Symmetric key, IV, or nonce captured and verified against plaintext length.
- [ ] **Offline Reproducibility**: The extracted key successfully decrypts raw captured ciphertext using a standard Python script (`cryptography` or `pycryptodome`).
- [ ] **Round-trip Integrity**: If the goal is tampering or forging requests, the re-encrypted ciphertext is accepted by the application or server without integrity errors.
