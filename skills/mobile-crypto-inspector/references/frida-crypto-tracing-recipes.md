# Frida Dynamic Cryptography Tracing Recipes

> Kumpulan cuplikan hook Frida untuk melacak, mencegat, dan mengekstraksi material kriptografis (AES, RSA, HMAC, KeyStore) secara dinamis pada runtime aplikasi Android.

---

## 1. Mencegat Kunci AES & Plaintext Runtime (`javax.crypto.Cipher`)

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    
    // Intercept inisialisasi cipher
    Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        var modeStr = (opmode === 1) ? "ENCRYPT" : ((opmode === 2) ? "DECRYPT" : opmode);
        console.log("\n[+] Cipher.init() [Mode: " + modeStr + "]");
        try {
            console.log("    Algorithm: " + key.getAlgorithm());
            var encoded = key.getEncoded();
            if (encoded) {
                console.log("    Key (Hex): " + bytesToHex(encoded));
            }
        } catch (e) {
            console.log("    Key Details: [Hardware-backed / KeyStore]");
        }
        return this.init(opmode, key);
    };

    // Helper konversi byte array ke hex string
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xFF;
            hex += (b < 16 ? "0" : "") + b.toString(16);
        }
        return hex;
    }
});
```

---

## 2. Memantau Operasi Hash & HMAC (`javax.crypto.Mac`)

```javascript
Java.perform(function () {
    var Mac = Java.use("javax.crypto.Mac");

    Mac.doFinal.overload('[B').implementation = function (input) {
        var res = this.doFinal(input);
        console.log("\n[+] Mac.doFinal()");
        console.log("    Algorithm: " + this.getAlgorithm());
        console.log("    Input Hex: " + Java.use("java.util.Arrays").toString(input));
        return res;
    };
});
```

---

## 3. Mencegat Library Kripto Native (OpenSSL / BoringSSL / libcrypto)

Pada aplikasi yang menggunakan library native (`.so`) untuk kriptografi, gunakan `Interceptor` Frida:

```javascript
var evpEncryptInit = Module.findExportByName("libcrypto.so", "EVP_EncryptInit_ex");
if (evpEncryptInit) {
    Interceptor.attach(evpEncryptInit, {
        onEnter: function (args) {
            console.log("\n[+] Native EVP_EncryptInit_ex() called");
            // args[1] = EVP_CIPHER* cipher
            // args[3] = unsigned char* key
            // args[4] = unsigned char* iv
            var keyPtr = args[3];
            var ivPtr = args[4];
            if (!keyPtr.isNull()) {
                console.log("    Key bytes: " + hexdump(keyPtr, { length: 32 }));
            }
            if (!ivPtr.isNull()) {
                console.log("    IV bytes : " + hexdump(ivPtr, { length: 16 }));
            }
        }
    });
}
```
