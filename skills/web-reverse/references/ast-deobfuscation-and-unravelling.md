# Abstract Syntax Tree (AST) Deobfuscation & Unravelling Master Guide

This guide details the algorithms, transformations, and techniques required to deobfuscate heavily protected JavaScript code produced by tools such as `javascript-obfuscator`, Obfuscator.io, Terser, and custom proprietary packers.

---

## 1. JavaScript Abstract Syntax Tree (AST) Concepts

JavaScript source code is parsed by engines (Babel, Acorn, Esprima, SWC) into a hierarchical tree of AST nodes conforming to the ESTree specification:

```
Source Code: var x = 10 + 20;
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ VariableDeclaration (kind: "var")                           │
│  └── VariableDeclarator                                     │
│       ├── id: Identifier (name: "x")                        │
│       └── init: BinaryExpression (operator: "+")            │
│            ├── left: NumericLiteral (value: 10)             │
│            └── right: NumericLiteral (value: 20)            │
└─────────────────────────────────────────────────────────────┘
```

Deobfuscation is the systematic traversal and transformation of this tree to replace complex, misleading nodes with clean, human-readable equivalents.

---

## 2. Technique 1: String Array Decoding & Inlining

Most obfuscators extract all string literals into an array, shuffle the array using an Immediately Invoked Function Expression (IIFE), and replace string literals with calls to a decryptor function.

### Typical Obfuscation Pattern:
```javascript
// 1. Array declaration
var _0xa12b = ['\x58\x2d\x53\x69\x67\x6e', '\x50\x4f\x53\x54', '\x2f\x61\x70\x69\x2f\x76\x31'];

// 2. Shift / Rotate IIFE
(function(_0x1b, _0x2c) {
  var _0x3d = function(_0x4e) {
    while (--_0x4e) { _0x1b['push'](_0x1b['shift']()); }
  };
  _0x3d(++_0x2c);
})(_0xa12b, 0x1f4);

// 3. Decryptor function
var _0x5f1c = function(_0x1, _0x2) {
  _0x1 = _0x1 - 0x0;
  return _0xa12b[_0x1];
};

// 4. Obfuscated call
var header = _0x5f1c('0x0'); // Returns 'X-Sign'
```

### Deobfuscation Algorithm:
1. **Identify the Components:** Locate the array declaration node, the IIFE node, and the decryptor function node.
2. **Execute the Setup in an Isolated Sandbox:** Evaluate the array, the rotation IIFE, and the decryptor function inside Node.js `vm.createContext()`.
3. **AST Traversal:** Traverse all `CallExpression` nodes matching the decryptor name (`_0x5f1c`).
4. **Node Replacement:** Call the sandbox decryptor function with the node arguments, extract the resulting string value, and replace the `CallExpression` node with a clean `StringLiteral` node.

```javascript
// Babel AST Visitor Transformation
const visitor = {
  CallExpression(path) {
    if (path.node.callee.name === '_0x5f1c') {
      const argValue = path.node.arguments[0].value;
      const decryptedString = sandboxDecryptor(argValue);
      path.replaceWith(types.stringLiteral(decryptedString));
    }
  }
};
```

---

## 3. Technique 2: Control Flow Flattening Unflattening

Control flow flattening transforms linear sequences of statements into a `while-switch` state machine driven by an array or string of switch cases.

### Typical Flattened Pattern:
```javascript
var _0xstate = '3|1|2|0'['split']('|'), _0xidx = 0;
while (true) {
  switch (_0xstate[_0xidx++]) {
    case '0': return result;
    case '1': var payload = JSON.stringify(data); continue;
    case '2': var signature = md5(payload + secret); continue;
    case '3': var secret = 'k3y_123'; continue;
  }
  break;
}
```

### Unflattening Algorithm:
1. Locate the `WhileStatement` whose test is `true` or `0x1 === 0x1`.
2. Inspect the preceding `VariableDeclaration` to extract the state array/string: `['3', '1', '2', '0']`.
3. Extract all `SwitchCase` statement bodies from the `SwitchStatement` inside the `while` loop into a dictionary mapping case test values to statements.
4. Iterate through the state array in chronological sequence (`3` -> `1` -> `2` -> `0`), stripping `continue` and `break` statements.
5. Replace the entire `WhileStatement` node with a linear `BlockStatement` containing the sequenced statements.

```javascript
// Clean Unflattened Result:
var secret = 'k3y_123';
var payload = JSON.stringify(data);
var signature = md5(payload + secret);
return result;
```

---

## 4. Technique 3: Constant Folding & Expression Simplification

Minifiers and obfuscators replace simple constants with binary arithmetic expressions to confuse static scanners:

| Obfuscated Expression | Constant Folded Result |
|---|---|
| `1 + 2 * 3` | `7` |
| `0x12a ^ 0x12a` | `0` |
| `"hel" + "lo"` | `"hello"` |
| `![]` | `false` |
| `!![]` | `true` |
| `+[]` | `0` |
| `!+[]+!+[]` | `2` |

### AST Visitor for Constant Folding:
```javascript
const visitor = {
  BinaryExpression(path) {
    const { confident, value } = path.evaluate();
    if (confident) {
      path.replaceWith(types.valueToNode(value));
    }
  }
};
```

---

## 5. Technique 4: Member Expression Normalization

Obfuscators convert standard dot property access (`window.fetch`) into bracket notation with hex escape strings:
`window['\x66\x65\x74\x63\x68']` -> `window['fetch']`

### Normalization AST Rule:
If a `MemberExpression` uses computed bracket access (`computed: true`) and the property is a valid JavaScript identifier `StringLiteral` (matching `^[a-zA-Z_$][a-zA-Z0-9_$]*$`), convert it to uncomputed dot notation (`computed: false`).

```javascript
// Before:
document['\x63\x6f\x6f\x6b\x69\x65'] = token;

// After:
document.cookie = token;
```
