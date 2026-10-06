# WebAssembly (WASM) Reverse Engineering & Runtime Memory Hooking

This technical reference provides an end-to-end operational guide for analyzing, decompiling, debugging, and hooking WebAssembly (`.wasm`) binary modules compiled into modern Single-Page Applications and WebViews for cryptographic hashing and obfuscation.

---

## 1. WebAssembly Binary Architecture & Memory Model

When web developers compile C/C++, Rust, or Go into WebAssembly, the resulting `.wasm` binary runs inside a sandboxed stack-based virtual machine within the browser engine:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WebAssembly Execution Model                     │
├───────────────────────────────────┬────────────────────────────────────┤
│         JAVASCRIPT RUNTIME        │       WASM VIRTUAL MACHINE         │
├───────────────────────────────────┼────────────────────────────────────┤
│ const wasm = await instantiate(); │ Linear Memory: Uint8Array(65536)   │
│ const ptr = wasm.exports.alloc(); │ ├── Stack Area (Local variables)   │
│ wasm.exports.sign(ptr, length);   │ ├── Heap Area (Strings & Structs)  │
│ const resPtr = wasm.exports.get();│ └── Static Data (Constants, Keys)  │
└───────────────────────────────────┴────────────────────────────────────┘
```

WASM accesses data through a contiguous array of raw bytes called **Linear Memory** (`WebAssembly.Memory`). String parameters and objects are passed across the JS-WASM boundary as **numeric memory pointer offsets** and byte lengths.

---

## 2. Dynamic Runtime Hooking: Capturing Plaintexts & Keys

You can extract all cryptographic keys, input plaintexts, and intermediate hash states in real time by hooking `WebAssembly.instantiate` before the application executes:

```javascript
// Universal WebAssembly Hook & Memory Snooper
(function() {
  'use strict';
  console.log('%c[WASM-Hook]%c Intercepting WebAssembly instantiation...', 'color: #00e5ff; font-weight: bold;', 'color: auto;');

  function dumpMemoryString(memory, ptr, maxLen = 256) {
    if (!memory || !memory.buffer || !ptr) return null;
    const bytes = new Uint8Array(memory.buffer, ptr, maxLen);
    let str = '';
    for (let i = 0; i < bytes.length && bytes[i] !== 0; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    return str;
  }

  const origInstantiate = WebAssembly.instantiate;
  WebAssembly.instantiate = async function(bufferSource, importObject) {
    console.log('%c[WASM INSTANTIATE]%c Module loading...', 'color: #76ff03; font-weight: bold;', 'color: auto;');
    const result = await origInstantiate.call(this, bufferSource, importObject);
    
    const instance = result.instance || result;
    const exports = instance.exports;
    const memory = exports.memory || (importObject && importObject.env && importObject.env.memory);

    console.log('Exported Functions:', Object.keys(exports));

    // Hook all exported functions
    for (const [name, fn] of Object.entries(exports)) {
      if (typeof fn === 'function') {
        const origFn = fn;
        exports[name] = function(...args) {
          console.groupCollapsed(`%c[WASM CALL] ${name}()%c`, 'color: #ff9100; font-weight: bold;', 'color: auto;');
          console.log('Arguments (Raw Pointer/Int):', args);
          
          if (memory) {
            args.forEach((arg, idx) => {
              if (typeof arg === 'number' && arg > 0 && arg < memory.buffer.byteLength) {
                const text = dumpMemoryString(memory, arg);
                if (text && text.length > 2) {
                  console.log(`Arg[${idx}] Pointer 0x${arg.toString(16)} String:`, text);
                }
              }
            });
          }

          const res = origFn.apply(this, args);
          console.log('Return Value (Raw):', res);
          
          if (memory && typeof res === 'number' && res > 0 && res < memory.buffer.byteLength) {
            console.log(`Return Pointer 0x${res.toString(16)} String:`, dumpMemoryString(memory, res));
          }
          console.groupEnd();
          return res;
        };
      }
    }

    return result;
  };
})();
```

---

## 3. Disassembly & Decompilation Toolchain

When static analysis of the `.wasm` binary is required:

### Step 1: Dump the `.wasm` binary from Network Tab
Save the file as `crypto_core.wasm`.

### Step 2: Convert to WebAssembly Text Format (`.wat`) via WABT
```bash
wasm2wat crypto_core.wasm -o crypto_core.wat
```

### Step 3: Decompile to C-like Pseudocode
```bash
wasm-decompile crypto_core.wasm -o crypto_core.dcmp
```

### Step 4: Decompile in Ghidra
1. Open Ghidra -> Create Project.
2. Import `crypto_core.wasm`.
3. Select Language: `WebAssembly:LE:32:default`.
4. Run Auto-Analysis. Ghidra reconstructs full C pseudocode for all hashing functions!

---

## 4. Standalone Replay in Python via `wasmtime`

Once you extract the `.wasm` file, you can execute it directly in Python without running a browser:

```python
# pip install wasmtime
from wasmtime import Store, Module, Instance

store = Store()
module = Module.from_file(store.engine, "crypto_core.wasm")
instance = Instance(store, module, [])

# Call exported signing function
sign_func = instance.exports(store)["sign"]
memory = instance.exports(store)["memory"]

# Write input data to WASM linear memory
input_bytes = b"my_api_request_payload"
memory.write(store, 0x1000, input_bytes)

# Execute
result_ptr = sign_func(store, 0x1000, len(input_bytes))

# Read result hash from memory pointer
output_hash = memory.read(store, result_ptr, 64).decode('utf-8')
print("WASM Generated Signature:", output_hash)
```
