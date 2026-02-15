---
ctf: UofTCTF 2026
category: rev
difficulty: easy
points: 47
flag: uoftctf{5ymb01ic_3x3cu7i0n_i5_v3ry_u53fu1}
techniques:
  - upx-unpacking
  - memory-dumping
  - unicorn-emulation
  - symbolic-execution
tools:
  - gdb
  - upx
  - unicorn-engine
  - angr
---

# Symbol of Hope

## Description

"Like a beacon in the dark, Go Go Squid! stands as a symbol of hope to those who seek to be healed."

**Category:** Rev  
**Points:** 47  
**Solves:** 182

We're given a binary called `checker` that validates a flag input and prints "Yes" or "No".

## Solution

### Initial Analysis

The binary is **UPX-packed**, which we can identify from running `strings` on it.

Running the binary shows it expects input and responds with "Yes" or "No".

### Dumping Unpacked Code from Memory

Since the binary unpacks itself at runtime using UPX's self-extraction, we can dump the unpacked code directly from memory using GDB. The binary creates several memory mappings during startup to unpack the actual code.

Using GDB to catch memory mapping system calls and then dump the unpacked sections:

```bash
gdb ./checker
# Set breakpoint after unpacking
b *0x3fe92
run
# Dump memory sections
dump memory unpacked.bin 0x<start> 0x<end>
```

### Reverse Engineering the Transformation

Analyzing the dumped code reveals the flag checking mechanism:

1. **Main function (offset 0x3fe92):** Reads exactly 42 bytes of input using `fgets`, copies to a buffer, then calls a transformation function at offset `0x23b`.

2. **Transformation chain (starting at 0x23b):** A chain of approximately 200 nested functions. Each function:
   - Modifies one specific byte of the input using various operations (`imul`, `add`, `sub`, `xor`, `not`, `rol`, `ror`)
   - Calls the next function in the chain
   - The chain terminates at offset `0x3fe40`

3. **Comparison function (0x3fe40):** Uses `memcmp` to compare the transformed buffer against expected bytes stored in rodata at offset `0x20`.

**Key insight:** Each byte transforms independently. Changing one input byte only affects that same position in the output, not other positions. This means we can **brute-force each position separately**.

### Emulation with Unicorn Engine

We use Python with Unicorn Engine to emulate the transformation function and brute-force each character position:

```python
from unicorn import *
from unicorn.x86_const import *

# Load unpacked binary
with open('unpacked.bin', 'rb') as f:
    code = f.read()

# Expected output (from rodata at 0x20)
expected = bytes([...])  # 42 bytes from binary

flag = bytearray(b'A' * 42)

for pos in range(42):
    print(f"Brute-forcing position {pos}...")
    for c in range(32, 127):
        # Setup emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x0, 0x50000)
        mu.mem_map(0x100000, 1024 * 1024)  # 1MB stack (CRITICAL!)
        mu.mem_write(0x0, code)
        
        # Test character
        test_input = bytearray(flag)
        test_input[pos] = c
        mu.mem_write(0x10000, bytes(test_input))
        
        # Emulate transformation
        mu.reg_write(UC_X86_REG_RDI, 0x10000)
        mu.reg_write(UC_X86_REG_RSP, 0x100000 + 0x100000 - 0x1000)
        mu.emu_start(0x23b, 0x3fe40)
        
        # Check result
        result = mu.mem_read(0x10000, 42)
        if result[pos] == expected[pos]:
            flag[pos] = c
            print(f"Found: {chr(c)}")
            break

print(f"Flag: {flag.decode()}")
```

**Critical Detail:** The deep function call chain (approximately 200 nested calls) requires substantial stack space. Initially using the default 64KB stack caused memory access errors during emulation. Increasing the stack to **1MB** fixed the issue.

### Alternative: Symbolic Execution with angr

The challenge name "Symbol of Hope" and the flag message itself hint that **symbolic execution** is the intended solution approach. Tools like `angr` can automatically solve this:

```python
import angr
import claripy

p = angr.Project('./checker')
flag = claripy.BVS('flag', 42 * 8)

# Setup symbolic execution
state = p.factory.entry_state(stdin=flag)
simgr = p.factory.simulation_manager(state)

# Find path that prints "Yes"
simgr.explore(find=lambda s: b"Yes" in s.posix.dumps(1))

if simgr.found:
    solution = simgr.found[0].posix.dumps(0)
    print(f"Flag: {solution[:42].decode()}")
```

## Flag

```
uoftctf{5ymb01ic_3x3cu7i0n_i5_v3ry_u53fu1}
```

The flag is a leetspeak message: "symbolic execution is very useful" - confirming that symbolic execution tools (or manual position-by-position solving as we did) are the intended approach.

The challenge references:
- "Symbol of Hope" = **symbolic execution**
- "Go Go Squid!" = A Chinese TV show about CTF competitions, hinting at the challenge context

## Key Techniques

- UPX unpacking via memory dumping
- Unicorn Engine emulation
- Per-byte brute-forcing
- Symbolic execution (angr)
- Stack space management in emulation

