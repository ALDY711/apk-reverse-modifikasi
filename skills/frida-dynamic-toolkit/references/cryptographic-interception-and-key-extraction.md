# Cryptographic Interception and Key Extraction with Frida

Dynamic runtime interception is the most reliable technique for extracting cryptographic keys, Initialization Vectors (IVs), and unencrypted plaintexts from Android applications. While static decompilation can be defeated by code obfuscation (DexGuard, ProGuard, OLLVM) or runtime string encryption, cryptographic primitives must inevitably present keys and plaintexts in standard formats when invoking cryptographic APIs.

**Load this when:** an Android app uses dynamic symmetric encryption (AES, DES, 3DES), asymmetric encryption (RSA), hashing/HMAC signatures, or AndroidKeyStore, and you need to intercept keys, IVs, or decrypted data in real time.

---

## 1. Quick Start: Automated Crypto Monitoring

Generate a production-ready Frida interceptor script targeting the Java Cryptography Architecture (JCA):

```bash
# Generate the basic crypto monitor
python skills/frida-dynamic-toolkit/scripts/crypto_monitor.py --out trace_crypto.js

# Generate with complete stack traces (identifies the caller method)
python skills/frida-dynamic-toolkit/scripts/crypto_monitor.py --stack-trace --out trace_crypto.js
```

Attach to a running process or spawn a fresh instance:

```bash
# Spawn and hook from cold start
frida -U -f com.target.app -l trace_crypto.js

# Or attach to an existing process
frida -U -n com.target.app -l trace_crypto.js
```

---

## 2. Java Cryptography Architecture (JCA) Hook Targets

The Java layer of Android uses standard interfaces defined under `javax.crypto.*` and `java.security.*`.

### A. Symmetric Key Initialization (`SecretKeySpec`)

Hooks `javax.crypto.spec.SecretKeySpec` constructors to log symmetric keys for AES, DES, ChaCha20, etc.

```javascript
var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
    console.log("[*] SecretKeySpec Init:");
    console.log("    Algorithm: " + algorithm);
    console.log("    Key (Hex): " + bytesToHex(keyBytes));
    return this.$init(keyBytes, algorithm);
};
```

### B. Initialization Vectors (`IvParameterSpec` & `GCMParameterSpec`)

Captures the IV used for CBC, CTR, and GCM modes:

```javascript
var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
    console.log("[*] IvParameterSpec Init:");
    console.log("    IV (Hex): " + bytesToHex(ivBytes));
    return this.$init(ivBytes);
};

// For AES-GCM:
try {
    var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
    GCMParameterSpec.$init.overload('int', '[B').implementation = function(tagLen, ivBytes) {
        console.log("[*] GCMParameterSpec Init:");
        console.log("    Tag Length: " + tagLen + " bits");
        console.log("    IV (Hex): " + bytesToHex(ivBytes));
        return this.$init(tagLen, ivBytes);
    };
} catch(e) {}
```

### C. Cipher Encryption & Decryption (`Cipher.doFinal`)

Captures data immediately prior to encryption (plaintext) or after decryption (plaintext):

```javascript
var Cipher = Java.use("javax.crypto.Cipher");
Cipher.doFinal.overload('[B').implementation = function(input) {
    var output = this.doFinal(input);
    var opmode = this.opmode.value; // 1 = ENCRYPT, 2 = DECRYPT
    var modeStr = (opmode === 1) ? "ENCRYPT" : (opmode === 2) ? "DECRYPT" : "OTHER(" + opmode + ")";

    console.log("[*] Cipher.doFinal [" + modeStr + "] (" + this.getAlgorithm() + "):");
    if (opmode === 1) {
        console.log("    Plaintext IN  : " + bytesToString(input));
        console.log("    Ciphertext OUT: " + bytesToHex(output));
    } else {
        console.log("    Ciphertext IN : " + bytesToHex(input));
        console.log("    Plaintext OUT : " + bytesToString(output));
    }
    return output;
};
```

### D. HMAC Signatures (`Mac.doFinal`)

Essential for recovering request signing algorithms and secret keys used in API tokens:

```javascript
var Mac = Java.use("javax.crypto.Mac");
Mac.doFinal.overload('[B').implementation = function(input) {
    var output = this.doFinal(input);
    console.log("[*] Mac.doFinal (" + this.getAlgorithm() + "):");
    console.log("    Input Data: " + bytesToString(input));
    console.log("    Output Tag: " + bytesToHex(output));
    return output;
};
```

---

## 3. Android KeyStore & Unexportable Keys

When keys are backed by Hardware TEE / StrongBox:
1. `key.getEncoded()` will return `null` because the private key never leaves secure hardware.
2. **Strategy:** Do not attempt to export the private key. Intercept the payload at `Cipher.doFinal()`. The data decrypted by the hardware module is returned to user memory as normal plaintext bytes.
3. If public key inspection is required, hook `KeyStore.getCertificate(alias).getPublicKey()`.

---

## 4. Native Layer Crypto Interception (`libcrypto.so` / BoringSSL)

If the app executes cryptographic operations inside a native library rather than Java:

```javascript
// Hook BoringSSL / OpenSSL EVP API inside native libraries
function hookNativeEVP() {
    var evpUpdate = Module.findExportByName("libcrypto.so", "EVP_CipherUpdate");
    if (evpUpdate) {
        Interceptor.attach(evpUpdate, {
            onEnter: function(args) {
                // int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
                var inLen = args[4].toInt32();
                if (inLen > 0) {
                    console.log("[Native EVP] Update len=" + inLen);
                    console.log(hexdump(args[3], { length: Math.min(inLen, 64) }));
                }
            }
        });
    }
}
```

---

## 5. Performance and Noise Management

In large applications, background telemetry or image caches frequently invoke cryptographic functions hundreds of times per second.

* **Noise Filtering:** Filter out unwanted algorithms (such as internal HTTPS TLS traffic or cache MD5 hashing) by inspecting `this.getAlgorithm()`:
  ```javascript
  var algo = this.getAlgorithm();
  if (algo.indexOf("MD5") !== -1 || algo.indexOf("SHA-1") !== -1) return output; // Skip noisy caches
  ```
* **Selective Tracing:** Combine with `stack-trace` only when identifying the entry point of the specific business logic method performing the encryption.
