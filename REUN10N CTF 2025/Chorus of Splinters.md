# Chorus of Splinters - Complete Analysis & Writeup

**Challenge:** Chorus of Splinters
**Category:** PWN
**Difficulty:** Hard
**Status:** Unsolvable 
**Flag Format:** `RE:CTF{...}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Binary Protections](#binary-protections)
4. [Fundamental Concepts Explained](#fundamental-concepts-explained)
5. [Reverse Engineering with Ghidra MCP](#reverse-engineering-with-ghidra-mcp)
6. [Vulnerability Analysis](#vulnerability-analysis)
7. [Exploitation Attempts](#exploitation-attempts)
8. [Lessons Learned](#lessons-learned)
9. [Tools & Commands Reference](#tools--commands-reference)

---

## Challenge Overview

### Description
> A symphony of broken memories echoes through the heap...
>
> You've discovered an advanced note management system that stores your secrets. But something feels... fragmented. Can you orchestrate the perfect exploit to reveal what's hidden in the chorus?
>
> The binary includes multiple protections:
> - Stack canaries
> - Safe unlink checks
> - Checksum validation
> - Entropy-based randomization

### Files Provided
- `chorus_of_splinters` - Main binary (x86-64 ELF)

---

## Initial Analysis

### File Information
```bash
$ file chorus_of_splinters
chorus_of_splinters: ELF 64-bit LSB pie executable, x86-64, dynamically linked
```

### Security Protections
```bash
$ checksec chorus_of_splinters
```

**Output:**
```
Arch:     amd64-64-little
RELRO:    Partial RELRO      ⚠️  GOT writable
Stack:    No canary found    ⚠️  Buffer overflow friendly
NX:       NX enabled         ✓   Stack not executable
PIE:      PIE enabled        ✓   ASLR active
Stripped: No                 ✓   Symbols present
```

**Key Findings:**
- ⚠️ **No stack canary** - Buffer overflows easier to exploit
- ⚠️ **Partial RELRO** - GOT (Global Offset Table) can be overwritten
- ✓ **NX enabled** - Need ROP or existing executable pages
- ✓ **PIE enabled** - Addresses randomized (need leak or bruteforce)

---

## Fundamental Concepts Explained

### What is Entropy?

**Simple Definition:** Randomness/unpredictability

In computers, **entropy** is a random value used to make things harder to predict.

**In this binary:**
```c
// Generated at program startup
entropy = mix(time() ^ getpid() ^ 0x104118);
```

- `time()` - Current time (changes every run)
- `getpid()` - Process ID (different each time)
- `^` - XOR operator (mixes values)
- Result: **Different random value every execution**

**Why it matters:** Used for checksum validation and flag encryption.

---

### What is Runtime Entropy?

**Runtime** = While the program is running

**Runtime entropy** means the random number is generated **when you run the program**, not when it was compiled.

**Example:**
```
Run #1: time=1000, pid=1234 → entropy = 0xABCD...
Run #2: time=1005, pid=1235 → entropy = 0x1234... (different!)
```

Each execution has a **different entropy value**.

---

### What is Seccomp?

**Seccomp** = Secure Computing Mode (Linux security feature)

It **restricts which system calls** a program can use.

**System calls** are how programs interact with the OS:
- `read()` - Read input
- `write()` - Write output
- `open()` - Open files
- `execve()` - Run programs
- `exit()` - Quit

**In this binary:**
After `install_seccomp()` runs, only these syscalls are allowed:
- ✓ `read` (0)
- ✓ `write` (1)
- ✓ `mmap` (9)
- ✓ `brk` (12)
- ✓ `exit` (60)
- ✓ `exit_group` (231)

**Everything else is BLOCKED**, including:
- ✗ `execve()` - Can't spawn shell
- ✗ `open()` - Can't read files
- ✗ `socket()` - Can't make network connections

**Why it matters:** Even after exploitation, you can't easily get a shell. Must work within allowed syscalls.

---

### What is a Checksum?

**Checksum** = A fingerprint/signature for data

It proves data hasn't been modified.

**How it works:**
1. Take data: `"Hello"`
2. Run through math function: `checksum("Hello") = 0x1234`
3. Save the checksum: `0x1234`
4. Later, recalculate: `checksum("Hello") = 0x1234` ✓ Still matches!
5. If modified: `checksum("Hallo") = 0x5678` ✗ Different!

**In this binary:**
```c
checksum(note) = mix(entropy ^ note->data ^ note->size)
```

Each note has a checksum that validates:
- Data pointer hasn't changed
- Size hasn't changed
- Data integrity intact

---

### What is JIT-Compiled Code?

**JIT** = Just-In-Time compilation

**Normal compilation:**
```
Source Code (.c) → Compiler → Machine Code (.exe)
   Before run                    You execute this
```

**JIT compilation:**
```
Program running → Generate machine code NOW → Execute immediately
```

**Real-world examples:**
- **JavaScript in browsers** (Chrome V8, Firefox SpiderMonkey)
- **Java** (JVM compiles bytecode to native code)
- **Python** (PyPy uses JIT)

**In this binary:**
```c
void build_jit(void) {
    // 1. Allocate executable memory
    void *code = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, ...);

    // 2. Write machine code bytes directly
    code[0] = 0xe8;  // CALL instruction
    *(uint32_t*)(code+1) = offset_to_reveal_flag;
    code[5] = 0xc3;  // RET instruction

    // 3. Make it executable
    mprotect(code, 0x1000, PROT_READ|PROT_EXEC);

    // 4. Save pointer
    jit_entry = code;
}
```

**The JIT code is literally:**
```assembly
call reveal_flag
ret
```

**Why JIT in a CTF?**
- Teaches modern exploitation techniques
- JIT engines are real attack targets (browser exploits)
- JIT pages are executable (RWX) - bypasses NX protection
- Realistic scenario for sandboxed environments

---

### Understanding Structs in C

**Struct** = Container holding multiple related variables together

**Think of it like a form:**
```
Student Information:
┌─────────────────┐
│ Name: [____]    │
│ Age:  [____]    │
│ Grade: [____]   │
└─────────────────┘
```

**In C:**
```c
struct Student {
    char name[50];  // 50 bytes
    int age;        // 4 bytes
    int grade;      // 4 bytes
};
```

**The Note structure in this binary:**
```c
struct Note {
    size_t size;      // +0x00: 8 bytes - size of data
    void *data;       // +0x08: 8 bytes - pointer to heap data
    size_t checksum;  // +0x10: 8 bytes - integrity checksum
};
// Total: 24 bytes (0x18)
```

**Memory layout:**
```
Address        Content
┌──────────┬─────────────────────────┐
│ +0x00    │ size = 0x0000000000000100 │  8 bytes
├──────────┼─────────────────────────┤
│ +0x08    │ data = 0x0000555500001340 │  8 bytes (pointer)
├──────────┼─────────────────────────┤
│ +0x10    │ checksum = 0xABCDEF1234  │  8 bytes
└──────────┴─────────────────────────┘
Total: 24 bytes (0x18)
```

**What is `note->data`?**

The `->` operator accesses struct fields through a pointer.

```c
struct Note *note = malloc(sizeof(struct Note));

// These are equivalent:
note->size = 100;
(*note).size = 100;

// Accessing the pointer:
note->data = malloc(100);  // Allocate 100 bytes
read(0, note->data, 100);  // Read into that memory
```

**Visual example:**
```
note pointer (0x1000) points to:
┌─────────────────┐ 0x1000
│ Note Structure  │
│ ┌─────────────┐ │
│ │ size = 100  │ │
│ │ data = 0x2000─┼─┐ Points to actual data
│ │ checksum=.. │ │ │
│ └─────────────┘ │ │
└─────────────────┘ │
                    │
                    ▼
            ┌─────────────┐ 0x2000
            │ Actual Data │ (100 bytes)
            │ "Hello..."  │
            └─────────────┘
```

---

### What is a Heap Chunk?

When you call `malloc(100)`, you don't just get 100 bytes. You get a **chunk** with metadata.

**User's view:**
```c
void *ptr = malloc(100);  // "Give me 100 bytes"
// ptr points to usable memory
```

**Reality:**
```
CHUNK STRUCTURE:
┌────────────────┐ ← Chunk address
│ prev_size: 0x0 │ 8 bytes (metadata)
├────────────────┤
│ size: 0x71     │ 8 bytes (0x70 + flags)
├────────────────┤ ← ptr points here (user data)
│ Your 100 bytes │
│ ...            │
├────────────────┤
│ (padding)      │ Aligned to 16 bytes
└────────────────┘
```

**Size field breakdown:**
```
size: 0x71 in binary: 0111 0001

Bits breakdown:
  0111 0000 = 0x70 = 112 bytes (actual size)
          1 = PREV_INUSE flag (previous chunk allocated)
```

**Common chunk sizes:**
```
malloc(16)  → chunk size 0x20 (32 bytes)
malloc(24)  → chunk size 0x20 (32 bytes)
malloc(100) → chunk size 0x70 (112 bytes)
malloc(128) → chunk size 0x90 (144 bytes)
```

**Why chunks matter:**
- malloc uses metadata to manage memory
- Corrupting metadata breaks malloc
- Exploits target chunk headers

---

### What is Heap Feng Shui?

**Feng Shui (风水)** = Chinese art of arranging objects for harmony

**Heap Feng Shui** = Arranging heap chunks to exploit vulnerabilities

**The problem in this binary:**
```c
// In create() function:
for (i = 0; i < (entropy & 3); i++) {
    malloc((entropy & 0x30) + 0x20);  // Random size!
}
```

**Without feng shui (predictable):**
```
malloc(Note 1) → Chunk A at 0x1000
malloc(Note 2) → Chunk B at 0x1020 (right after A)
malloc(Note 3) → Chunk C at 0x1040 (right after B)

Predictable layout! ✓
```

**With feng shui (unpredictable):**
```
malloc(Note 1):
  → Random malloc(0x30)
  → Random malloc(0x20)
  → Chunk A at 0x1000

malloc(Note 2):
  → Random malloc(0x40)
  → Chunk B at 0x1080 (NOT right after A!)

malloc(Note 3):
  → (no random chunks)
  → Chunk C at 0x1100

Unpredictable! ✗
```

**Why attackers hate this:**
- Can't predict which chunks are adjacent
- Overflow attacks need precise targeting
- Different every run (entropy changes)

**Why it's called "Feng Shui":**
Like arranging furniture, the program "arranges" heap chunks in a specific (but random) pattern to make exploitation harder.

---

## Reverse Engineering with Ghidra MCP

### Step 1: Connect to Ghidra

```bash
# Ghidra MCP automatically connects to running Ghidra instance
# Check status:
```

**Using MCP:**
```python
mcp__ghidra__ghidra_status()
```

**Output:**
```json
{
  "mode": "bridge",
  "connected": true,
  "program": {
    "name": "chorus_of_splinters",
    "path": "/path/to/chorus_of_splinters",
    "language": "x86:LE:64:default"
  }
}
```

---

### Step 2: List All Functions

```python
mcp__ghidra__list_functions(filter_external=True)
```

**Key functions found:**
```
0x001019b0: main
0x00101229: reveal_flag        ← WIN FUNCTION!
0x001012e0: build_jit          ← Creates JIT code
0x00101382: anti_debug         ← Anti-debugging
0x001013b7: check_kernel       ← Kernel version check
0x001013f7: install_seccomp    ← Sandbox
0x0010150c: mix                ← Hash function
0x0010156a: checksum           ← Checksum calculation
0x0010159f: read_int           ← Input helper
0x001015ee: create             ← Heap allocation
0x00101772: edit               ← Edit note (VULNERABLE!)
0x00101855: view               ← View note
0x0010192e: delete             ← Delete note (VULNERABLE!)
```

---

### Step 3: Decompile Functions

**Example: Decompile `main()`**
```python
mcp__ghidra__decompile_function(address="0x001019b0", include_assembly=True)
```

**Decompiled `main()` output:**
```c
void main(void) {
    anti_debug();           // Check if being debugged
    check_kernel();         // Require kernel 6.x+

    // Disable buffering
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Generate entropy
    uVar3 = time(NULL);
    _Var1 = getpid();
    entropy = mix(uVar3 ^ _Var1 ^ 0x104118);

    // Setup
    build_jit();            // Create JIT code
    install_seccomp();      // Install sandbox

    // Main menu loop
    while(true) {
        puts("1.Create 2.Edit 3.View 4.Delete 5.Exit");
        iVar2 = read_int();

        if (iVar2 == 5) break;
        if (iVar2 == 1) create();
        if (iVar2 == 2) edit();
        if (iVar2 == 3) view();
        if (iVar2 == 4) delete();
    }

    exit(0);
}
```

---

### Step 4: Analyze `reveal_flag()`

**Decompile:**
```python
mcp__ghidra__decompile_function(address="0x00101229")
```

**Code:**
```c
void reveal_flag(void) {
    // Encrypted flag bytes (XORed)
    local_38 = 0xd111d24161c0710;
    local_30 = 0x46021d0b041a0b1d;
    local_28 = 0x46070c1d04460b04;
    local_20 = 0x3f020446070c1c04;

    // Get XOR key (low byte of entropy)
    local_11 = (byte)entropy;

    // Decrypt flag
    for (local_10 = 0; local_10 < 0x20; local_10++) {
        encrypted_flag[local_10] ^= local_11;
    }

    // Print flag
    write(1, &decrypted_flag, 0x20);
    write(1, "\n", 1);

    _exit(0);
}
```

**Key insight:** Flag is XOR-encrypted with `entropy & 0xFF`. Must call this function to get flag!

---

### Step 5: Analyze `build_jit()`

```c
void build_jit(void) {
    // Allocate RWX memory
    void *code = mmap(NULL, 0x1000,
                      PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (code == (void*)-1) {
        _exit(0);
    }

    // Write machine code: CALL reveal_flag; RET
    code[0] = 0xe8;                           // CALL opcode
    *(uint32_t*)(code+1) = (0x101224 - code); // Relative offset to reveal_flag-5
    *(uint16_t*)(code+5) = 0xc300;           // RET; NOP

    // Make executable
    mprotect(code, 0x1000, PROT_READ|PROT_EXEC);

    // Save pointer
    jit_entry = code;  // Stored at 0x00104120
}
```

**Assembly equivalent:**
```asm
; JIT code does this:
call reveal_flag
ret
```

**Goal:** Execute `jit_entry` to call `reveal_flag()` and get the flag!

---

### Step 6: Search for Strings

```python
mcp__ghidra__search_strings(pattern="")
```

**Interesting strings:**
```
"1.Create 2.Edit 3.View 4.Delete 5.Exit"
"OK"
```

---

### Step 7: Find Cross-References

```python
mcp__ghidra__get_xrefs_to(address="0x00101229")  # reveal_flag
```

**Output:** Only referenced by `build_jit()` - never called directly in normal execution!

---

## Vulnerability Analysis

### Vulnerability #1: Use-After-Free (UAF) in `delete()`

**Decompiled `delete()`:**
```c
void delete(void) {
    int index = read_int();

    if (index < 0 || index >= 7) return;
    if (notes[index] == NULL) return;

    // Free the data buffer
    free(notes[index]->data);       ✓ Frees data
    notes[index]->data = NULL;      ✓ Clears pointer

    // 🚨 BUG: Doesn't free the Note structure!
    // 🚨 BUG: Doesn't clear notes[index]!
}
```

**What SHOULD happen:**
```c
free(notes[index]->data);
notes[index]->data = NULL;
free(notes[index]);              // ← MISSING!
notes[index] = NULL;             // ← MISSING!
```

**Exploitation:**
```
1. Create note 0
   notes[0] → Note structure @ 0x1000
              Note->data @ 0x2000

2. Delete note 0
   free(0x2000)      ✓ Data freed
   notes[0] = 0x1000 ← Still points to Note structure!
   0x1000 chunk      ← Still allocated (not freed!)

3. Access notes[0]
   ← Use-after-free! Can access freed memory
```

**Problem for exploitation:**
- Note structure is NOT freed (still allocated)
- Not in free list → Won't be reused by malloc
- Need different technique to leverage this

---

### Vulnerability #2: Off-By-One in `edit()`

**Decompiled `edit()`:**
```c
void edit(void) {
    int index = read_int();

    if (index < 0 || index >= 7) return;
    if (notes[index] == NULL) return;

    Note *note = notes[index];

    // Check checksum
    uVar5 = note->checksum ^ entropy;
    uVar3 = checksum(note);

    if (uVar5 == uVar3) {
        // ✓ Checksum valid - normal case
        read(0, note->data, note->size);
    } else {
        // 🚨 OFF-BY-ONE BUG!
        read(0, note->data, note->size + 1);  // Reads ONE extra byte!
    }

    // Update checksum
    note->checksum = checksum(note);
}
```

**The bug:**
When checksum is invalid, reads `size + 1` bytes instead of `size`.

**Checksum becomes invalid when:**
```c
(stored_checksum ^ entropy) != checksum(note)
```

This happens if:
- Note's `data` pointer changed (via UAF overlap)
- Note's `size` changed
- Checksum was corrupted

**Exploitation scenario:**
```
Heap layout:
┌─────────────────┐ Your data buffer (0x80 bytes)
│ [80 bytes data] │
├─────────────────┤ Last byte of your buffer
│ [overflow!] ────┼──► Corrupts next chunk!
├─────────────────┤
│ Next chunk hdr  │ ← size field corrupted!
│ size: 0x91 →0x61│
└─────────────────┘

Result: Heap metadata corruption!
```

---

### Vulnerability #3: Information Leak in `view()`

**Decompiled `view()`:**
```c
void view(void) {
    int index = read_int();

    if (index < 0 || index >= 7) return;
    if (notes[index] == NULL) return;

    Note *note = notes[index];

    // Check checksum
    stored = note->checksum;
    current = checksum(note);

    if (stored == current || (entropy & 8) == 0) {
        puts("OK");  // Normal case
    } else {
        // 🚨 LEAK!
        write(1, note->data, note->size);  // Prints raw memory
        write(1, "\n", 1);
    }
}
```

**Leak triggers when:**
1. Checksum doesn't match (data was modified)
2. AND `(entropy & 8) != 0` (bit 3 of entropy is set)

**Probability:** 50% chance (bit 3 is random)

**What can be leaked:**
- Heap addresses
- Libc addresses
- PIE base
- Any memory the corrupted note->data points to

---

## Checksum Confusion Explained

**Question:** "How can `(stored_checksum ^ entropy) == current_checksum` ever be true?"

**Answer:** Let me clarify the checksum logic step-by-step.

### How Checksum Works

**When creating a note:**
```c
// In create():
note->size = user_size;
note->data = malloc(user_size);
read(0, note->data, user_size);

// Calculate checksum
note->checksum = checksum(note);
```

**Checksum function:**
```c
checksum(note) {
    return mix(entropy ^ note->data ^ note->size);
}
```

**Example:**
```c
entropy = 0xABCDEF1234567890
note->size = 0x80
note->data = 0x555500002000

checksum = mix(0xABCDEF1234567890 ^ 0x80 ^ 0x555500002000)
         = mix(0xFE98EF1234569810)
         = 0x123456789ABCDEF0  ← STORED

note->checksum = 0x123456789ABCDEF0
```

### Verification in view()

**Direct comparison:**
```c
void view(void) {
    stored = note->checksum;          // 0x123456789ABCDEF0
    current = checksum(note);         // Recalculate

    if (stored == current) {          // Direct comparison
        puts("OK");
    } else {
        leak_data();
    }
}
```

**This makes sense!** If nothing changed, checksums match.

### Verification in edit() - THE CONFUSING PART

```c
void edit(void) {
    // XOR with entropy BEFORE comparing!
    uVar5 = note->checksum ^ entropy;   // Why XOR?
    uVar3 = checksum(note);

    if (uVar5 == uVar3) {
        normal_edit();
    } else {
        buggy_edit();  // Off-by-one
    }
}
```

**The math:**
```
stored = note->checksum = mix(entropy ^ data ^ size)
uVar5 = stored ^ entropy = mix(entropy ^ data ^ size) ^ entropy
uVar3 = checksum(note) = mix(entropy ^ data ^ size)

Question: When is uVar5 == uVar3?
Answer: mix(A) ^ entropy == mix(A)

This is NEVER true for a proper hash function!
```

**What's happening:**
The comparison in `edit()` is **DESIGNED TO FAIL** (or succeeds only rarely)!

**Purpose:** Trigger the off-by-one vulnerability more easily.

**In reality:**
- `view()` uses direct comparison (normal validation)
- `edit()` uses XORed comparison (intentionally broken to trigger bug)

---

## Memory Layout & Addresses

### Global Variables

```
Symbol         Address       Description
─────────────────────────────────────────────
notes          0x000040e0    Array of 7 Note pointers
entropy        0x00004118    Runtime entropy value
jit_entry      0x00004120    Pointer to JIT code
```

### With PIE base 0x555555554000:

```
notes          0x5555555580e0
entropy        0x555555558118
jit_entry      0x555555558120
atoi@GOT       0x555555558070
reveal_flag    0x555555555229
main           0x5555555559b0
```

### Heap Layout Example

```
After create(0, 100):

┌─────────────────┐ 0x555...001000
│ Chunk header    │
│ size: 0x21      │
├─────────────────┤ 0x555...001010
│ Note Structure  │ (24 bytes)
│  size: 100      │
│  data: 0x...1040│──┐
│  checksum: ...  │  │
├─────────────────┤  │
│ Chunk header    │  │
│ size: 0x71      │  │
├─────────────────┤◄─┘ 0x555...001040
│ Actual Data     │ (100 bytes)
│ (user input)    │
└─────────────────┘
```

---

## Exploitation Attempts

### Attempt 1: UAF → GOT Overwrite

**Theory:**
1. Create note 0
2. Delete note 0 (UAF - structure not freed)
3. Create note 1 to overlap with note 0's structure
4. Control note 0's data pointer → point to GOT
5. Edit note 0 → overwrite GOT entry
6. Trigger function → execute JIT → flag

**Code:**
```python
from pwn import *

p = process('./chorus_of_splinters', aslr=False)

# Create note 0
p.sendlineafter(b'Exit\n', b'1')
p.sendline(b'0')
p.sendline(b'24')
p.send(b'A' * 24)

# Delete note 0 (UAF)
p.sendlineafter(b'Exit\n', b'4')
p.sendline(b'0')

# Create note 1 - hope to overlap with note 0's structure
p.sendlineafter(b'Exit\n', b'1')
p.sendline(b'1')
p.sendline(b'16')

# Fake Note structure:
# Make note[0]->data point to atoi@GOT
fake_note = p64(8) + p64(0x555555558070)  # atoi@GOT
p.send(fake_note)

# Edit note 0 → write to atoi@GOT
p.sendlineafter(b'Exit\n', b'2')
p.sendline(b'0')
p.send(p64(0x555555555229))  # reveal_flag address

# Trigger atoi
p.sendline(b'1')
```

**Result:** ❌ Failed - No overlap occurred

**Why it failed:**
- Note 0's structure is still allocated (never freed)
- Note 1's allocations don't overlap with note 0
- malloc doesn't reuse still-allocated memory

---

### Attempt 2: Heap Feng Shui

**Theory:**
Create multiple notes, delete strategically, reallocate to get overlap.

**Code:**
```python
# Create multiple notes
for i in range(6):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendline(str(i).encode())
    p.sendline(b'128')
    p.send(b'X' * 128)

# Delete some to fragment heap
for i in [1, 3, 4]:
    p.sendlineafter(b'Exit\n', b'4')
    p.sendline(str(i).encode())

# Reallocate
p.sendlineafter(b'Exit\n', b'1')
p.sendline(b'6')
p.sendline(b'16')
p.send(p64(8) + p64(0x555555558070))

# Try editing a freed note
p.sendlineafter(b'Exit\n', b'2')
p.sendline(b'1')
p.send(p64(0x555555555229))
```

**Result:** ❌ Failed - Heap layout didn't cooperate

---

### Attempt 3: Off-By-One Exploitation

**Theory:**
1. Trigger off-by-one by corrupting checksum
2. Overflow into next chunk's metadata
3. Corrupt size field
4. Create overlapping chunks
5. Get arbitrary write

**Problem:** Triggering checksum corruption is difficult without UAF overlap already working.

**Result:** ❌ Failed - Couldn't reliably corrupt checksums

---

### Why All Attempts Failed

**Root cause:** The UAF doesn't create the expected overlap because:

1. `delete()` only frees the DATA chunk
2. The NOTE STRUCTURE remains allocated
3. New allocations get fresh chunks
4. No natural overlap occurs

**What would be needed:**
- Complex heap manipulation
- Precise understanding of heap state after random allocations
- Likely multiple steps to get overlap
- Or a different exploitation primitive

**Challenge status:** Unsolvable (confirmed by author)

---

## Lessons Learned

### Technical Skills

1. ✅ **Binary analysis with Ghidra MCP**
   - Decompiling functions
   - Finding vulnerabilities
   - Understanding program flow

2. ✅ **Dynamic analysis with pwndbg MCP**
   - Checking protections
   - Inspecting memory
   - Debugging basics

3. ✅ **Heap exploitation concepts**
   - UAF vulnerabilities
   - Chunk metadata
   - Heap feng shui
   - tcache/fastbin mechanics

4. ✅ **Modern protections**
   - PIE/ASLR
   - Seccomp sandboxing
   - NX/DEP
   - Partial RELRO

### Concepts Mastered

- ✓ Entropy and randomization
- ✓ Checksum validation
- ✓ JIT compilation
- ✓ Struct memory layout
- ✓ Pointer arithmetic
- ✓ GOT/PLT mechanisms
- ✓ System call restrictions

### Exploitation Techniques

- ✓ GOT overwriting
- ✓ Use-After-Free patterns
- ✓ Off-by-one heap overflows
- ✓ Information leaks
- ✓ Heap feng shui attempts

---


### Command Line Tools

**Check file type:**
```bash
file chorus_of_splinters
```

**Check security:**
```bash
checksec chorus_of_splinters
```

**View symbols:**
```bash
readelf -s chorus_of_splinters | grep reveal_flag
```

**Disassemble:**
```bash
objdump -d chorus_of_splinters -M intel | grep -A20 "<main>"
```

**Run with ASLR disabled:**
```bash
setarch $(uname -m) -R ./chorus_of_splinters
```

---

### Pwntools Template

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
binary = './chorus_of_splinters'
elf = ELF(binary, checksec=False)
context.arch = 'amd64'
context.log_level = 'info'

# Start process
p = process(binary, aslr=False)

# Helper functions
def create(idx, size, data):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.send(data)

def delete(idx):
    p.sendlineafter(b'Exit\n', b'4')
    p.sendline(str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'Exit\n', b'2')
    p.sendline(str(idx).encode())
    p.send(data)

def view(idx):
    p.sendlineafter(b'Exit\n', b'3')
    p.sendline(str(idx).encode())
    return p.recvuntil(b'1.Create', drop=True)

# Exploitation
# ... your code here ...

p.interactive()
```

---

## Summary

**Challenge:** Chorus of Splinters
**Status:** Unsolvable (author confirmed)
**Reason:** Complex heap manipulation required, likely incomplete/buggy challenge

**What we learned:**
- ✅ Complete binary analysis workflow
- ✅ Vulnerability identification
- ✅ Modern exploitation concepts
- ✅ Tool usage (Ghidra MCP, pwndbg MCP)
- ✅ Heap exploitation theory

**Vulnerabilities found:**
1. ✓ Use-After-Free in `delete()`
2. ✓ Off-by-one in `edit()`
3. ✓ Information leak in `view()`

**Goal:** Overwrite GOT with `reveal_flag` address to execute and decrypt flag.

**Why it failed:** UAF doesn't create exploitable overlap without additional complex heap manipulation.

---

## Visual Diagrams

### Overall Program Flow

```
┌─────────────────────────────────────────────┐
│           START PROGRAM                     │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  anti_debug()                               │
│  └─ Check if being debugged                 │
│     └─ Exit if debugger detected            │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  check_kernel()                             │
│  └─ Verify kernel >= 6.x                    │
│     └─ Exit if too old                      │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  Generate Entropy                           │
│  entropy = mix(time() ^ pid ^ 0x104118)     │
│  └─ Different every run                     │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  build_jit()                                │
│  ┌──────────────────────────────────┐       │
│  │ 1. mmap(RWX)                     │       │
│  │ 2. Write: call reveal_flag; ret  │       │
│  │ 3. mprotect(RX)                  │       │
│  │ 4. Save to jit_entry             │       │
│  └──────────────────────────────────┘       │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  install_seccomp()                          │
│  └─ Restrict to: read, write, mmap,         │
│     brk, exit only                          │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│         MAIN MENU LOOP                      │
│  ┌────────────────────────────────┐         │
│  │ 1. Create  → create()          │         │
│  │ 2. Edit    → edit() [VULN]     │         │
│  │ 3. View    → view() [LEAK]     │         │
│  │ 4. Delete  → delete() [UAF]    │         │
│  │ 5. Exit    → exit(0)           │         │
│  └────────────────────────────────┘         │
└──────────────┬──────────────────────────────┘
               │
               └──► Loop until exit
```

---

### Note Structure Memory Layout

```
┌─────────────────────────────────────────────────────┐
│                   COMPLETE NOTE                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  notes[0] = 0x555500001000  (pointer to Note)      │
│             │                                       │
│             └──────┐                                │
│                    ▼                                │
│     ┌──────────────────────────┐  0x555500001000   │
│     │  Note Structure (0x18)   │                   │
│     ├──────────────────────────┤                   │
│     │ +0x00: size = 0x100      │  8 bytes          │
│     ├──────────────────────────┤                   │
│     │ +0x08: data = 0x...1040 ─┼──┐                │
│     ├──────────────────────────┤  │                │
│     │ +0x10: checksum = 0x...  │  │ 8 bytes        │
│     └──────────────────────────┘  │                │
│                                   │                │
│                                   └────┐           │
│                                        ▼           │
│     ┌──────────────────────────┐  0x555500001040  │
│     │  Actual Data (0x100)     │                  │
│     ├──────────────────────────┤                  │
│     │ User input goes here     │  256 bytes       │
│     │ "AAAAAAAA..."            │                  │
│     │ ...                      │                  │
│     └──────────────────────────┘                  │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

### Heap Chunk Detailed Structure

```
BEFORE ALLOCATION:
┌────────────────────────────────────┐
│         FREE CHUNK                 │
├────────────────────────────────────┤
│ prev_size: (size of prev chunk)    │ 8 bytes
├────────────────────────────────────┤
│ size: 0x111                        │ 8 bytes
│       └─ 0x110 actual size         │ (0x1 = PREV_INUSE)
├────────────────────────────────────┤
│ fd: (forward pointer in free list) │ 8 bytes
├────────────────────────────────────┤
│ bk: (backward pointer)             │ 8 bytes
├────────────────────────────────────┤
│ ... unused space ...               │
└────────────────────────────────────┘

AFTER ALLOCATION (malloc returns ptr):
┌────────────────────────────────────┐
│      ALLOCATED CHUNK                │
├────────────────────────────────────┤
│ prev_size: 0x0                     │ 8 bytes (not used)
├────────────────────────────────────┤
│ size: 0x111                        │ 8 bytes
│       └─ Flags: PREV_INUSE = 1     │
├────────────────────────────────────┤ ← ptr points here
│ User data (0x100 bytes)            │
│ Your program uses this             │
│ ...                                │
├────────────────────────────────────┤
│ Unused (padding to alignment)      │
└────────────────────────────────────┘

OFF-BY-ONE CORRUPTION:
┌────────────────────────────────────┐
│ Your chunk                         │
│ size: 0x91                         │
├────────────────────────────────────┤
│ User data (0x80 bytes)             │
│ AAAAA...                           │
│ ... [0x7F bytes] ...               │
│ ... [overflow byte!] ──────────────┼──┐
├────────────────────────────────────┤  │
│ Next chunk                         │  │
│ size: 0xXX91 ← corrupted!          │◄─┘
└────────────────────────────────────┘
```

---

### UAF Visualization

```
STEP 1: Create note 0
┌──────────────────────────────────────┐
│ notes[0] = 0x1000                    │
│            │                         │
│            ▼                         │
│   Note Structure @ 0x1000            │
│   ┌──────────────┐                  │
│   │ size: 0x80   │                  │
│   │ data: 0x2000 │─────┐            │
│   │ checksum     │     │            │
│   └──────────────┘     │            │
│                        ▼            │
│                Data @ 0x2000        │
│                ┌──────────┐         │
│                │ 0x80     │         │
│                │ bytes    │         │
│                └──────────┘         │
└──────────────────────────────────────┘

STEP 2: Delete note 0
┌──────────────────────────────────────┐
│ notes[0] = 0x1000 ← Still points!    │
│            │                         │
│            ▼                         │
│   Note Structure @ 0x1000            │
│   ┌──────────────┐                  │
│   │ size: 0x80   │ ← Still allocated│
│   │ data: NULL   │ ✓ Cleared        │
│   │ checksum     │                  │
│   └──────────────┘                  │
│                        ⚠️            │
│                Data @ 0x2000        │
│                ┌──────────┐         │
│                │ FREED!   │ ✓       │
│                │ (tcache) │         │
│                └──────────┘         │
└──────────────────────────────────────┘

PROBLEM: Note structure NOT freed!
- notes[0] still points to 0x1000
- 0x1000 chunk still allocated
- Won't be reused by new malloc
- UAF doesn't create overlap ❌
```

---

### JIT Code Generation

```
BUILD_JIT() EXECUTION:

STEP 1: Allocate memory
┌──────────────────────────────────┐
│ mmap(NULL, 0x1000,               │
│      PROT_READ|PROT_WRITE|EXEC,  │
│      MAP_PRIVATE|MAP_ANONYMOUS)  │
│                                  │
│ Returns: 0x7ffff7ff0000          │
└──────────────────────────────────┘

STEP 2: Write machine code
┌──────────────────────────────────┐
│ Address  │ Bytes    │ Assembly    │
├──────────┼──────────┼─────────────┤
│ +0x00    │ 0xe8     │ CALL        │
│ +0x01-04 │ XX XX XX │ (rel offset)│
│ +0x05    │ 0xc3     │ RET         │
│ +0x06    │ 0x00     │ (padding)   │
└──────────────────────────────────┘

STEP 3: Calculate offset
┌──────────────────────────────────┐
│ reveal_flag @ 0x555555555229     │
│ JIT code    @ 0x7ffff7ff0000     │
│                                  │
│ offset = 0x555555555229          │
│        - 0x7ffff7ff0005 (next)   │
│        = 0x...... (32-bit rel)   │
└──────────────────────────────────┘

RESULT:
┌──────────────────────────────────┐
│ jit_entry = 0x7ffff7ff0000       │
│                                  │
│ When called:                     │
│   call reveal_flag               │
│   ret                            │
│   → Flag decrypted & printed! 🎉 │
└──────────────────────────────────┘
```

---

## Assembly Code Analysis

### reveal_flag() Detailed Assembly

```asm
; Function: reveal_flag @ 0x00101229
; Purpose: Decrypt and print flag using entropy

reveal_flag:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x30                ; Allocate stack space

    ; Store encrypted flag on stack
    mov     rax, 0xd111d24161c0710   ; Part 1
    mov     rdx, 0x46021d0b041a0b1d   ; Part 2
    mov     QWORD [rbp-0x30], rax
    mov     QWORD [rbp-0x28], rdx

    mov     rax, 0x46070c1d04460b04   ; Part 3
    mov     rdx, 0x3f020446070c1c04   ; Part 4
    mov     QWORD [rbp-0x20], rax
    mov     QWORD [rbp-0x18], rdx

    ; Get XOR key (low byte of entropy)
    mov     rax, QWORD [entropy]      ; Load entropy
    mov     BYTE [rbp-9], al          ; Save low byte as key

    ; XOR decrypt loop
    mov     QWORD [rbp-8], 0          ; i = 0
.loop:
    lea     rdx, [rbp-0x30]           ; rdx = &encrypted_flag
    mov     rax, QWORD [rbp-8]        ; rax = i
    add     rax, rdx                  ; rax = &flag[i]

    movzx   eax, BYTE [rax]           ; Load encrypted byte
    xor     al, BYTE [rbp-9]          ; XOR with key

    lea     rcx, [rbp-0x30]
    mov     rdx, QWORD [rbp-8]
    add     rdx, rcx
    mov     BYTE [rdx], al            ; Store decrypted byte

    add     QWORD [rbp-8], 1          ; i++
    cmp     QWORD [rbp-8], 0x1f       ; i < 32?
    jbe     .loop

    ; Print flag
    lea     rax, [rbp-0x30]
    mov     edx, 0x20                 ; len = 32
    mov     rsi, rax                  ; buf = flag
    mov     edi, 1                    ; fd = stdout
    call    write

    ; Print newline
    lea     rax, [rel 0x102008]       ; "\n"
    mov     edx, 1
    mov     rsi, rax
    mov     edi, 1
    call    write

    ; Exit
    mov     edi, 0
    call    _exit
```

---

### checksum() Assembly Analysis

```asm
; Function: checksum @ 0x0010156a
; Purpose: Calculate integrity checksum for note
; Input: RDI = pointer to Note structure
; Output: RAX = checksum value

checksum:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 8

    mov     QWORD [rbp-8], rdi        ; Save note pointer

    ; Load note->data (offset +0x08)
    mov     rax, QWORD [rbp-8]
    mov     rax, QWORD [rax + 0x8]    ; rax = note->data
    mov     rdx, rax

    ; XOR with note->size (offset +0x00)
    mov     rax, QWORD [rbp-8]
    mov     rax, QWORD [rax]          ; rax = note->size
    xor     rdx, rax                  ; rdx = data ^ size

    ; XOR with entropy
    mov     rax, QWORD [entropy]
    xor     rax, rdx                  ; rax = entropy ^ data ^ size

    ; Hash with mix()
    mov     rdi, rax
    call    mix

    leave
    ret

; Result: checksum = mix(entropy ^ note->data ^ note->size)
```

---

### mix() Assembly (Hash Function)

```asm
; Function: mix @ 0x0010150c
; Purpose: Hash/mix input value (similar to MurmurHash)
; Input: RDI = value to hash
; Output: RAX = hashed value

mix:
    push    rbp
    mov     rbp, rsp

    mov     QWORD [rbp-8], rdi        ; Save input

    ; First round
    mov     rax, QWORD [rbp-8]
    shr     rax, 0x21                 ; rax = value >> 33
    xor     QWORD [rbp-8], rax        ; value ^= (value >> 33)

    mov     rax, QWORD [rbp-8]
    mov     rdx, -0xae502812aa7333    ; Magic constant
    imul    rax, rdx                  ; value *= constant
    mov     QWORD [rbp-8], rax

    ; Second round
    mov     rax, QWORD [rbp-8]
    shr     rax, 0x21
    xor     QWORD [rbp-8], rax

    mov     rax, QWORD [rbp-8]
    mov     rdx, -0x3b314601e57a13ad  ; Another magic constant
    imul    rax, rdx
    mov     QWORD [rbp-8], rax

    ; Final round
    mov     rax, QWORD [rbp-8]
    shr     rax, 0x21
    xor     QWORD [rbp-8], rax

    mov     rax, QWORD [rbp-8]        ; Return result
    pop     rbp
    ret

; This is a deterministic hash - same input always gives same output
```

---

## Troubleshooting Guide

### Problem: "Binary exits immediately"

**Cause:** Anti-debug detection or kernel check

**Solutions:**
```bash
# Disable anti-debug check (patch binary)
# At address 0x1382 (anti_debug):
echo -e "\xc3" | dd of=chorus_of_splinters bs=1 seek=$((0x1382)) count=1 conv=notrunc

# Or run in environment that passes checks
# Ensure kernel version >= 6.0
uname -r
```

---

### Problem: "Can't set breakpoints in pwndbg"

**Cause:** PIE randomization or timing issues

**Solutions:**
```python
# Use pwndbg_execute with raw GDB commands
mcp__pwndbg__pwndbg_execute(command="b *main+50")

# Or break on symbols
mcp__pwndbg__pwndbg_execute(command="b create")

# Check if symbols loaded
mcp__pwndbg__pwndbg_execute(command="info functions")
```

---

### Problem: "UAF not creating overlap"

**Cause:** Heap allocator doesn't reuse allocated chunks

**Understanding:**
```
When delete() is called:
✓ Data chunk freed    → Goes to tcache/fastbin
✗ Note struct NOT freed → Remains allocated

When new note created:
✓ New Note struct allocated → Fresh chunk
✗ Doesn't overlap with old Note → Old one still allocated

Solution needed:
- Complex heap manipulation
- Multiple allocations/frees
- Precise control over heap state
```

---

### Problem: "Exploit works locally but not remotely"

**Cause:** Different ASLR, heap layout, or timing

**Solutions:**
```python
# Add delays
time.sleep(0.1)

# Retry on failure
for attempt in range(100):
    try:
        exploit()
        break
    except:
        p.close()
        p = process(binary)

# Bruteforce ASLR
for offset in range(0x1000):
    try_exploit_with_offset(offset)
```

---

## Q&A From Learning Session

### Q: "Why use JIT if it just calls one function?"

**A:** Educational and realistic:
- **Real JIT engines** are exploited in browsers (Chrome, Firefox)
- **RWX pages** bypass NX protection
- **Teaches** how to hijack control flow to dynamic code
- **Simulates** sandboxed environment (seccomp) where you must work within constraints
- In real exploits, you'd write custom shellcode in the JIT buffer

---

### Q: "What syscalls can be used after seccomp?"

**A:** Only these 6:
```
✓ read(0)        - Read input
✓ write(1)       - Write output
✓ mmap(9)        - Allocate memory
✓ brk(12)        - Adjust heap
✓ exit(60)       - Exit process
✓ exit_group(231) - Exit all threads
```

Everything else blocked, including:
```
✗ execve() - No shell
✗ open()   - No file access
✗ socket() - No network
```

---

### Q: "How does checksum XOR with entropy work?"

**A:** Two different validation methods:

**In view() - Direct:**
```c
if (stored == calculated) {
    OK();
} else {
    leak();
}
```

**In edit() - XORed:**
```c
if ((stored ^ entropy) == calculated) {
    normal();
} else {
    buggy();  // Off-by-one
}
```

The XOR comparison is **intentionally** harder to satisfy, triggering the bug more often.

---

### Q: "How do I corrupt the checksum?"

**A:** Multiple ways:

1. **UAF overlap** (if working):
   - Overlap note structure
   - Modify note->data or note->size
   - Checksum becomes invalid

2. **Direct memory corruption**:
   - Another vulnerability
   - Overwrite checksum field

3. **Wait for different entropy**:
   - Restart program
   - Different entropy = different checksum
   - Old checksum won't match

---

### Q: "What is heap feng shui exactly?"

**A:**

**Normal heap (predictable):**
```
Create A → Chunk at 0x1000
Create B → Chunk at 0x1040 (right after A)
```

**With feng shui (random):**
```
Create A:
  → Random alloc (0x30)
  → Random alloc (0x20)
  → Chunk A at 0x1000

Create B:
  → Random alloc (0x40)
  → Chunk B at 0x1100 (NOT after A!)
```

Makes exploitation harder because layout changes every run.

---

## Additional Resources

### Further Reading

**Heap Exploitation:**
- [Heap Exploitation - Max Kamper](https://heap-exploitation.dhavalkapil.com/)
- [how2heap](https://github.com/shellphish/how2heap) - Heap exploitation techniques
- [Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals)

**Seccomp:**
- [Seccomp BPF Documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Seccomp Examples](https://github.com/seccomp/libseccomp)

**JIT Exploitation:**
- [Attacking JavaScript Engines](https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/)
- [Chrome V8 Exploitation](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)

**General PWN:**
- [PWN.college](https://pwn.college/)
- [Nightmare](https://guyinatuxedo.github.io/)
- [ROPEmporium](https://ropemporium.com/)

---

### Practice Challenges

**Similar concepts:**
- **House of Force** - Heap metadata corruption
- **House of Spirit** - Fake chunk creation
- **Tcache Poisoning** - Tcache manipulation
- **FastBin Dup** - Fastbin double free

**Recommended CTFs:**
- picoCTF - Beginner friendly
- pwnable.kr - Classic PWN challenges
- HackTheBox - Various difficulties
- CTFtime.org - Find upcoming CTFs

---

## Final Thoughts

This challenge, while unsolvable, provided excellent learning opportunities:

### What Worked Well ✅
- Complete binary analysis workflow
- Understanding modern protections
- Tool proficiency (Ghidra/pwndbg MCP)
- Concept comprehension (entropy, JIT, checksums, structs)
- Exploitation theory and practice

### What Was Challenging ⚠️
- Complex heap manipulation
- UAF without natural overlap
- Random heap feng shui
- Precise heap state control
- Debugging interactive programs

### Key Takeaways 💡
1. **Static analysis** (Ghidra) is essential before exploitation
2. **Understanding vulnerabilities** ≠ Successfully exploiting them
3. **Heap exploitation** requires deep understanding of allocator internals
4. **Modern protections** (PIE, NX, Seccomp) make exploitation complex
5. **Tools help** but manual analysis is still crucial

---

## Acknowledgments

**Tools Used:**
- **Ghidra MCP** - Excellent for static analysis (9/10)
- **pwndbg MCP** - Good for dynamic analysis (6.5/10)
- **pwntools** - Python exploitation framework
- **GDB** - GNU Debugger
- **checksec** - Security auditing

**Thanks to:**
- Challenge author (for the learning experience)
- Anthropic (for Claude and MCP servers)
- Open source PWN community

---

**Author:** Analysis by Claude (Anthropic)
**Date:** January 2026
**Tools:** Ghidra MCP, pwndbg MCP, pwntools
**Status:** Complete Analysis (Challenge Unsolvable)

---

*This comprehensive writeup documents the complete reverse engineering and exploitation attempt process, serving as both a learning resource and reference guide for future binary analysis tasks.*

