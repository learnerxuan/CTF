---
ctf: UofTCTF 2026
category: rev
difficulty: hard
points: 500
flag: uoftctf{br1ng_y0ur_0wn_pr0gr4m_but_d0nt_br1ng_fl4g_fi13_r34d3r}
techniques:
  - wasm-reverse-engineering
  - bytecode-validation-bypass
  - control-flow-misalignment
tools:
  - binaryen
  - nodejs
---

# Bring Your Own Program

## Description

We are given a mysterious emulator for an unknown architecture. The service accepts a single line of hex-encoded bytecode, validates it,emulates it, and prints the return value. Our goal is to craft a valid program that leaks the flag from the remote system.

The challenge provides a ZIP archive containing `chal.js`, which implements the emulator and validator logic.

**Connection:** `nc 34.68.181.179 5000`

## Analysis

After reversing `chal.js`, we observe the following:

### Program Format

The emulator expects the following structure:
- **Byte 0:** Number of registers (`nr`), must be between 2 and 64.
- **Byte 1:** Number of constants.
- **Constants table:**
  - `0x01` → float64 (8 bytes)
  - `0x02` → string (u16 length + bytes)
- **Remaining bytes** → bytecode instructions.

The emulator exposes a global object called `caps`, which contains nested maps and functions. One of these functions allows reading arbitrary absolute files from disk (up to 4096 bytes). However, the validator restricts which property keys can be accessed.

The file-read function is stored under numeric key **0**, which is normally forbidden.

## Vulnerability

The validator is **linear** and does not follow control flow. This means we can trick it by placing a jump instruction that causes execution to begin in the middle of another instruction. The validator only checks bytes linearly and never verifies the instruction stream after jumps.

This allows us to:
1. Pass validation using only allowed keys
2. Jump into the middle of an instruction
3. Execute a `GETPROP` with key `0`
4. Retrieve the file-read primitive
5. Read `/flag.txt`

## Exploit Logic

The crafted program performs:
1. Load global `caps`
2. Access nested object via allowed key
3. Jump into middle of a fake instruction
4. Execute forbidden `GETPROP` with key `0`
5. Load string `"/flag.txt"`
6. Call file-read function
7. Return flag

##Final Payload

Send this hex string to the server:

```python
from pwn import *

# Crafted bytecode (example simplified)
payload = "02010100000000000000000200090000002f666c61672e747874..."

p = remote('34.68.181.179', 5000)
p.sendlineafter(b'hex: ', payload.encode())
print(p.recvall().decode())
```

## Summary

This challenge demonstrates a classic **validation vs execution mismatch**. By exploiting the linear validator and abusing instruction alignment, we gain access to forbidden properties and achieve arbitrary file read, leaking the flag.

## Key Techniques

- WebAssembly/custom bytecode reverse engineering
- Linear validator bypass
- Control-flow misalignment exploitation
- Instruction overlapping/smuggling

