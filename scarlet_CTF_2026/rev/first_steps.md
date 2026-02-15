---
ctf: ScarletCTF 2026
category: rev
difficulty: easy
points: 100
flag: RUSEC{well_th4t_was_eZ_WllwnZMjMCjqCsyXNnrtpDomWMU}
techniques:
  - strings
  - rodata-analysis
tools:
  - objdump
  - strings
  - ghidra
---

# first_steps

## Description

Find the flag hidden in the binary!

**Category:** Rev  
**Points:** 100  
**Solves:** 180  
**Author:** s0s.sh

## Solution

This is a beginner reverse engineering challenge. Running the binary gives us a hint pointing to the `.rodata` section (read-only data section in ELF binaries).

### Method 1: Using objdump

We can dump the `.rodata` section using `objdump`:

```bash
objdump -s -j .rodata first_steps
```

This reveals the flag stored as a plaintext string in the binary.

### Method 2: Using strings

The simplest approach:

```bash
strings first_steps | grep RUSEC
```

### Method 3: Hex Editor

Open the binary in a hex editor and search for "RUSEC".

### Method 4: Disassembler

Use a disassembler like Ghidra or IDA to view the `.rodata` section directly.

## Flag

```
RUSEC{well_th4t_was_eZ_WllwnZMjMCjqCsyXNnrtpDomWMU}
```

## Key Techniques

- **Static string analysis**
- **ELF section inspection** (`.rodata`)
- **Basic RE tooling** (`strings`, `objdump`)

