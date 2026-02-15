---
ctf: UofTCTF 2026
category: rev
difficulty: hard
points: 500
flag: uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}
techniques:
  - wasm-gc-reverse-engineering
  - struct-analysis
  - function-reference-extraction
tools:
  - binaryen
  - wasm-dis
  - nodejs22+
---

# Will u Accept Some Magic?

## Description

A 500-point reverse engineering challenge featuring a WebAssembly binary compiled from Kotlin using **WASM GC** (Garbage Collection). The challenge hints at "Where did my heap go?" referring to WASM GC's managed memory model.

## Solution

### 1. Initial Analysis

The challenge provides:
- `program.wasm` - A WebAssembly binary with GC features
- `runner.mjs` - A Node.js script to run the WASM module

The program prompts for a 30-character password and validates it character by character using 30 "Processor" objects.

### 2. Environment Setup

WASM GC features require **Node.js v22+**. Standard tools like `wabt` couldn't parse the GC types, so I used `binaryen`'s `wasm-dis` for decompilation:

```bash
wasm-dis program.wasm -o program.wat
```

### 3. Understanding the Validation Structure

Analyzing the decompiled WAT file revealed:

- **30 Processor globals** (`struct $27`) at `global$134` and `global$184-212`
- Each Processor contains function references for:
  - Expected character getter (type `$9`)
  - XOR transformation function
  - Position check function
  - Validation function

### 4. Extracting Expected Characters

The key insight was that each Processor's expected character comes from a function reference stored in **field 2** of the struct. Some functions are reused across multiple positions:

| Function | Char Code | Char | Positions |
|----------|-----------|------|-----------|
| `$135` | 48 | '0' | 0 |
| `$139` | 81 | 'Q' | 1 |
| `$143` | 71 | 'G' | 2 |
| `$147` | 70 | 'F' | 3, 11 |
| `$151` | 67 | 'C' | 4, 17 |
| `$155` | 66 | 'B' | 5, 20 |
| `$159` | 82 | 'R' | 6, 16 |
| `$163` | 69 | 'E' | 7, 8, 26, 29 |
| `$170` | 78 | 'N' | 9, 14 |
| `$174` | 68 | 'D' | 10, 12, 21, 24 |
| `$184` | 79 | 'O' | 13 |
| `$191` | 90 | 'Z' | 15 |
| `$201` | 51 | '3' | 18, 23, 28 |
| `$205` | 57 | '9' | 19 |
| `$215` | 83 | 'S' | 22 |
| `$225` | 77 | 'M' | 25 |
| `$232` | 72 | 'H' | 27 |

### 5. Reconstructing the Password

Mapping Processor globals to their expected character functions:

```
Position: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14
Char:     0  Q  G  F  C  B  R  E  E  N  D  F  D  O  N

Position: 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29
Char:     Z  R  C  3  9  B  D  S  3  D  M  E  H  3  E
```

**Password:** `0QGFCBREENDFDONZRC39BDS3DMEH3E`

### 6. Verification

```bash
node runner.mjs
# Enter: 0QGFCBREENDFDONZRC39BDS3DMEH3E
# Output: Success! Flag: uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}
```

## Flag

```
uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}
```

## Key Techniques

- WASM GC struct analysis
- Function reference extraction
- Global variable mapping
- Character-by-character reconstruction from function pointers

